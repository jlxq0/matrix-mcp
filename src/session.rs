//! Session-management hardening (audit finding #13).
//!
//! Wraps `rmcp`'s `LocalSessionManager` with two complementary defences
//! against authenticated denial-of-service via session flooding:
//!
//! * **Idle TTL** — `LocalSessionManager` is constructed with a
//!   [`SessionConfig`] whose `keep_alive` is set to 30 minutes. rmcp's default
//!   is 5 minutes; we lengthen it so claude.ai's variable tool-call cadence
//!   (sometimes >5 min between calls within a long conversation) doesn't
//!   silently evict sessions and leave the connector wedged in a "connected
//!   but un-handshaken" state. The global [`MAX_SESSIONS`] cap remains the
//!   real defence against session flooding.
//!
//! * **Global session cap** — [`CappedSessionManager`] wraps the inner
//!   manager and rejects `create_session` once the live session count hits
//!   [`MAX_SESSIONS`]. New `initialize` requests receive an HTTP 503 / JSON-RPC
//!   error instead of growing memory without bound.
//!
//! Both mitigations are applied together in `build_router`.

use std::time::Duration;

use futures::Stream;
use rmcp::model::{ClientJsonRpcMessage, ServerJsonRpcMessage};
use rmcp::transport::streamable_http_server::session::{
    RestoreOutcome, ServerSseMessage, SessionId, SessionManager,
    local::{LocalSessionManager, LocalSessionManagerError, SessionTransport},
};
use tracing::warn;

/// Maximum number of concurrent MCP sessions the server will hold.
///
/// Requests that would push the count beyond this limit receive an error
/// from `create_session`. Legitimate claude.ai usage peaks around one or
/// two sessions per user; 256 comfortably covers all expected concurrent
/// users while bounding the worst-case memory from a flooded attacker.
pub const MAX_SESSIONS: usize = 256;

/// Idle timeout applied to each session.
///
/// 30 minutes — longer than rmcp's 5-minute default. claude.ai's MCP
/// connector doesn't always heartbeat within a tight window, and an
/// evicted-too-fast session leaves the connector in a wedged state
/// (UI shows "connected" but every subsequent tool call sends a
/// stale session id, 404s, and silently drops). The global
/// [`MAX_SESSIONS`] cap remains the real defence against an
/// authenticated session flood.
// `Duration::from_mins` is unstable on our MSRV (Rust 1.93); use `from_secs`
// and suppress the clippy lint that would suggest the nicer-named constructor.
#[allow(clippy::duration_suboptimal_units)]
pub const SESSION_KEEP_ALIVE: Duration = Duration::from_secs(30 * 60);

/// Build a `LocalSessionManager` with the tightened idle TTL.
///
/// This is Mitigation A from audit finding #13.
fn inner_manager() -> LocalSessionManager {
    // Both `LocalSessionManager` and `SessionConfig` are `#[non_exhaustive]`,
    // so struct literals are forbidden outside the crate.  We use
    // `Default::default()` to get a value, then mutate the public fields.
    let mut mgr = LocalSessionManager::default();
    mgr.session_config.keep_alive = Some(SESSION_KEEP_ALIVE);
    mgr
}

/// Error returned by [`CappedSessionManager`].
#[derive(Debug)]
pub enum CappedSessionError {
    Inner(LocalSessionManagerError),
    CapReached,
}

impl std::fmt::Display for CappedSessionError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Inner(e) => write!(f, "inner session manager error: {e}"),
            Self::CapReached => write!(
                f,
                "session cap reached ({MAX_SESSIONS} sessions active); try again later"
            ),
        }
    }
}

impl std::error::Error for CappedSessionError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Inner(e) => Some(e),
            Self::CapReached => None,
        }
    }
}

impl From<LocalSessionManagerError> for CappedSessionError {
    fn from(e: LocalSessionManagerError) -> Self {
        Self::Inner(e)
    }
}

impl From<CappedSessionError> for std::io::Error {
    fn from(e: CappedSessionError) -> Self {
        Self::other(e.to_string())
    }
}

/// A thin wrapper around [`LocalSessionManager`] that rejects new sessions
/// once [`MAX_SESSIONS`] are already live (Mitigation B, audit finding #13).
///
/// All methods except `create_session` are pure pass-throughs.
///
/// The cap is enforced atomically: concurrent `create_session` calls
/// serialize on `create_gate`, so the check-then-insert sequence
/// cannot be interleaved by another task. Without the gate, N parallel
/// initialize requests could each read `count = MAX_SESSIONS - 1`,
/// each see room, and each create a session — overshooting the cap
/// by up to N. The gate adds zero contention on the read-heavy
/// session-lookup paths (`has_session`, `accept_message`, etc.) because
/// they do not take it.
pub struct CappedSessionManager {
    inner: LocalSessionManager,
    create_gate: tokio::sync::Mutex<()>,
}

impl CappedSessionManager {
    /// Construct a new `CappedSessionManager` backed by a [`LocalSessionManager`]
    /// configured with the tightened idle TTL (Mitigation A + B combined).
    pub fn new() -> Self {
        Self {
            inner: inner_manager(),
            create_gate: tokio::sync::Mutex::new(()),
        }
    }
}

// Compile-time check that `CappedSessionManager` satisfies the `Send + Sync`
// bounds required by `StreamableHttpService::new`, which wraps the manager in
// an `Arc<M>` shared across threads.
const _: () = {
    const fn assert_send_sync<T: Send + Sync>() {}
    #[allow(dead_code)]
    const fn _check() {
        assert_send_sync::<CappedSessionManager>();
    }
};

impl SessionManager for CappedSessionManager {
    type Error = CappedSessionError;
    type Transport = SessionTransport;

    async fn create_session(&self) -> Result<(SessionId, Self::Transport), Self::Error> {
        // Serialize check-and-create so concurrent initializes cannot
        // all observe `count < MAX_SESSIONS` and then each insert. The
        // gate is held only across the count + inner.create_session
        // call (both fast). Other manager operations don't take it.
        let _create_guard = self.create_gate.lock().await;
        let count = self.inner.sessions.read().await.len();
        if count >= MAX_SESSIONS {
            warn!(
                count,
                limit = MAX_SESSIONS,
                "session cap reached; rejecting new initialize"
            );
            return Err(CappedSessionError::CapReached);
        }
        Ok(self.inner.create_session().await?)
    }

    async fn initialize_session(
        &self,
        id: &SessionId,
        message: ClientJsonRpcMessage,
    ) -> Result<ServerJsonRpcMessage, Self::Error> {
        Ok(self.inner.initialize_session(id, message).await?)
    }

    async fn close_session(&self, id: &SessionId) -> Result<(), Self::Error> {
        Ok(self.inner.close_session(id).await?)
    }

    async fn has_session(&self, id: &SessionId) -> Result<bool, Self::Error> {
        Ok(self.inner.has_session(id).await?)
    }

    async fn create_stream(
        &self,
        id: &SessionId,
        message: ClientJsonRpcMessage,
    ) -> Result<impl Stream<Item = ServerSseMessage> + Send + Sync + 'static, Self::Error> {
        Ok(self.inner.create_stream(id, message).await?)
    }

    async fn accept_message(
        &self,
        id: &SessionId,
        message: ClientJsonRpcMessage,
    ) -> Result<(), Self::Error> {
        Ok(self.inner.accept_message(id, message).await?)
    }

    async fn create_standalone_stream(
        &self,
        id: &SessionId,
    ) -> Result<impl Stream<Item = ServerSseMessage> + Send + Sync + 'static, Self::Error> {
        Ok(self.inner.create_standalone_stream(id).await?)
    }

    async fn resume(
        &self,
        id: &SessionId,
        last_event_id: String,
    ) -> Result<impl Stream<Item = ServerSseMessage> + Send + Sync + 'static, Self::Error> {
        Ok(self.inner.resume(id, last_event_id).await?)
    }

    async fn restore_session(
        &self,
        id: SessionId,
    ) -> Result<RestoreOutcome<Self::Transport>, Self::Error> {
        Ok(self.inner.restore_session(id).await?)
    }
}
