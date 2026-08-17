//! Durable MCP session state.
//!
//! rmcp keeps live sessions in memory ([`crate::session::CappedSessionManager`]).
//! That alone makes every session id disposable: a pod restart, a rollout, or
//! 30 minutes of idle time (`session::SESSION_KEEP_ALIVE`) drops the session,
//! and the next tool call arrives carrying an `Mcp-Session-Id` the server has
//! never heard of. rmcp answers those with `404 Not Found` — which is what the
//! MCP spec requires for a terminated session — and the client is left wedged:
//! the connector still shows "connected", but the first tool call of the next
//! conversation fails, and the recovery path (a fresh `initialize`) is exactly
//! the path our per-identity initialize rate limit guards.
//!
//! rmcp 1.7 offers a way out: give the transport a [`SessionStore`], and an
//! unknown session id is looked up there, re-created, and the `initialize`
//! handshake replayed transparently before the request is served. The client
//! never sees the 404 and never re-authorizes.
//!
//! This module implements that store on the same PVC the matrix-sdk state
//! lives on, so sessions survive restarts and rollouts:
//!
//! * One small JSON file per session under `{store_root}/mcp-sessions/`.
//! * The filename is `sha256(session_id)` in hex — never the raw id, so a
//!   hostile session id can't escape the directory or collide with anything
//!   else on the volume.
//! * Entries older than [`SESSION_STATE_TTL`] are ignored and swept; the
//!   directory is capped at [`MAX_PERSISTED_SESSIONS`] entries.
//!
//! What is stored is the client's `initialize` parameters (protocol version,
//! capabilities, client name) — no tokens, no identity. Authorization is
//! re-checked on every request by [`crate::auth::bearer_auth`] regardless of
//! how the session was obtained, so a restored session grants nothing to a
//! caller who cannot present a live bearer token.

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, SystemTime};

use rmcp::transport::streamable_http_server::session::store::{
    SessionState, SessionStore, SessionStoreError,
};
use sha2::{Digest, Sha256};
use tracing::{debug, warn};

/// How long a persisted session may be resumed after its last write.
///
/// Deliberately far longer than the in-memory idle TTL: the point of the store
/// is to outlive eviction and restarts. claude.ai holds a connector session id
/// across days of a conversation, and resuming it is strictly better for the
/// user than a 404 (which costs a re-`initialize`, and possibly a re-auth).
#[allow(clippy::duration_suboptimal_units)] // `from_days` is unstable on our MSRV.
pub const SESSION_STATE_TTL: Duration = Duration::from_secs(7 * 24 * 60 * 60);

/// Hard cap on persisted session files. Each is well under 1 KiB, so this is
/// a filesystem-inode bound rather than a space bound. Writes past the cap are
/// refused (the session still works in memory; it just won't survive a
/// restart), which keeps a session flood from filling the PVC.
pub const MAX_PERSISTED_SESSIONS: usize = 4096;

/// Sweep expired files every N writes rather than on every write — the sweep
/// is a directory scan, and session creation is not a hot path.
const SWEEP_EVERY_N_WRITES: usize = 64;

/// File-backed [`SessionStore`] rooted at a directory on the PVC.
#[derive(Debug)]
pub struct FileSessionStore {
    dir: PathBuf,
    ttl: Duration,
    max_entries: usize,
    writes: AtomicUsize,
}

impl FileSessionStore {
    /// Create the store directory under `store_root` if it does not exist.
    ///
    /// Returns an error only if the directory cannot be created — that is a
    /// startup misconfiguration (missing/read-only volume), not a runtime
    /// condition.
    pub fn new(store_root: &Path) -> std::io::Result<Self> {
        let dir = store_root.join("mcp-sessions");
        std::fs::create_dir_all(&dir)?;
        Ok(Self {
            dir,
            ttl: SESSION_STATE_TTL,
            max_entries: MAX_PERSISTED_SESSIONS,
            writes: AtomicUsize::new(0),
        })
    }

    /// Test hook: shorten the TTL and cap.
    #[cfg(test)]
    const fn with_limits(mut self, ttl: Duration, max_entries: usize) -> Self {
        self.ttl = ttl;
        self.max_entries = max_entries;
        self
    }

    /// `{dir}/{sha256(session_id)}.json`.
    ///
    /// Hashing is what makes the path safe: session ids come off the wire, so
    /// they must never be treated as path components.
    fn path_for(&self, session_id: &str) -> PathBuf {
        let digest = Sha256::digest(session_id.as_bytes());
        self.dir.join(format!("{}.json", hex::encode(digest)))
    }

    /// True when `modified` is further in the past than the TTL. A file whose
    /// mtime cannot be read, or which claims to be from the future, is treated
    /// as fresh — clock weirdness should not silently drop live sessions.
    fn is_expired(&self, path: &Path) -> bool {
        let Ok(modified) = std::fs::metadata(path).and_then(|m| m.modified()) else {
            return false;
        };
        SystemTime::now()
            .duration_since(modified)
            .is_ok_and(|age| age > self.ttl)
    }

    /// Count entries and delete expired ones. Best-effort: IO errors during
    /// the sweep are logged and ignored, never propagated to the caller.
    fn sweep(&self) -> usize {
        let Ok(entries) = std::fs::read_dir(&self.dir) else {
            return 0;
        };
        let mut live = 0usize;
        for entry in entries.flatten() {
            let path = entry.path();
            if self.is_expired(&path) {
                if let Err(e) = std::fs::remove_file(&path) {
                    debug!(error = %e, "could not sweep expired session file");
                } else {
                    continue;
                }
            }
            live += 1;
        }
        live
    }
}

#[async_trait::async_trait]
impl SessionStore for FileSessionStore {
    async fn load(&self, session_id: &str) -> Result<Option<SessionState>, SessionStoreError> {
        let path = self.path_for(session_id);
        let bytes = match std::fs::read(&path) {
            Ok(b) => b,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(e) => return Err(Box::new(e)),
        };
        if self.is_expired(&path) {
            let _ = std::fs::remove_file(&path);
            return Ok(None);
        }
        match serde_json::from_slice::<SessionState>(&bytes) {
            Ok(state) => {
                debug!("restoring persisted MCP session");
                Ok(Some(state))
            }
            // A state file we can't parse is one an older (or newer) build
            // wrote. Drop it and let the client re-initialize rather than
            // failing the request outright.
            Err(e) => {
                warn!(error = %e, "discarding unparseable persisted session state");
                let _ = std::fs::remove_file(&path);
                Ok(None)
            }
        }
    }

    async fn store(&self, session_id: &str, state: &SessionState) -> Result<(), SessionStoreError> {
        let path = self.path_for(session_id);
        let is_new = !path.exists();
        if self
            .writes
            .fetch_add(1, Ordering::Relaxed)
            .is_multiple_of(SWEEP_EVERY_N_WRITES)
            || is_new
        {
            let live = self.sweep();
            if is_new && live >= self.max_entries {
                warn!(
                    live,
                    cap = self.max_entries,
                    "persisted-session cap reached; this session will not survive a restart"
                );
                return Err(Box::new(std::io::Error::other(
                    "persisted session cap reached",
                )));
            }
        }
        let body = serde_json::to_vec(state)?;
        // Write-then-rename: a crash mid-write leaves the old file intact
        // rather than a truncated one that `load` would have to discard.
        let tmp = path.with_extension("json.tmp");
        std::fs::write(&tmp, &body)?;
        std::fs::rename(&tmp, &path)?;
        Ok(())
    }

    async fn delete(&self, session_id: &str) -> Result<(), SessionStoreError> {
        match std::fs::remove_file(self.path_for(session_id)) {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(Box::new(e)),
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use rmcp::model::InitializeRequestParams;

    use super::*;

    fn state() -> SessionState {
        SessionState::new(InitializeRequestParams::default())
    }

    fn store(dir: &tempfile::TempDir) -> FileSessionStore {
        FileSessionStore::new(dir.path()).unwrap()
    }

    #[tokio::test]
    async fn round_trips_session_state() {
        let dir = tempfile::tempdir().unwrap();
        let s = store(&dir);
        assert!(s.load("sess-1").await.unwrap().is_none());
        s.store("sess-1", &state()).await.unwrap();
        assert!(s.load("sess-1").await.unwrap().is_some());
        s.delete("sess-1").await.unwrap();
        assert!(s.load("sess-1").await.unwrap().is_none());
    }

    /// Deleting a session that was never stored is the normal path when a
    /// client DELETEs a session created before a restart. It must not error.
    #[tokio::test]
    async fn delete_of_unknown_session_is_ok() {
        let dir = tempfile::tempdir().unwrap();
        store(&dir).delete("never-seen").await.unwrap();
    }

    /// Session ids arrive from the network. A traversal attempt must land
    /// inside the store directory like any other id, not above it.
    #[tokio::test]
    async fn hostile_session_id_stays_inside_the_directory() {
        let dir = tempfile::tempdir().unwrap();
        let s = store(&dir);
        let hostile = "../../../../etc/matrix-mcp-pwned";
        s.store(hostile, &state()).await.unwrap();
        let written = s.path_for(hostile);
        assert_eq!(written.parent().unwrap(), s.dir);
        assert!(written.exists());
        assert!(s.load(hostile).await.unwrap().is_some());
    }

    #[tokio::test]
    async fn expired_state_is_not_restored() {
        let dir = tempfile::tempdir().unwrap();
        let s = store(&dir).with_limits(Duration::from_millis(1), MAX_PERSISTED_SESSIONS);
        s.store("sess-1", &state()).await.unwrap();
        tokio::time::sleep(Duration::from_millis(20)).await;
        assert!(
            s.load("sess-1").await.unwrap().is_none(),
            "state past its TTL must not be resumable"
        );
    }

    #[tokio::test]
    async fn cap_refuses_new_sessions_but_not_updates() {
        let dir = tempfile::tempdir().unwrap();
        let s = store(&dir).with_limits(SESSION_STATE_TTL, 2);
        s.store("a", &state()).await.unwrap();
        s.store("b", &state()).await.unwrap();
        assert!(
            s.store("c", &state()).await.is_err(),
            "a fresh session past the cap must be refused"
        );
        // An existing session may still be updated — refusing that would
        // break a session that is already live in memory.
        s.store("a", &state()).await.unwrap();
    }
}
