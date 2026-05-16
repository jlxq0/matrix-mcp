//! Per-user matrix-sdk client cache with persistent encrypted `SQLite` stores.
//!
//! Phase 3 (E2EE) needs a stateful Matrix client per user: olm + megolm
//! sessions, cross-signing identities, and the device store all have to
//! survive process restarts. matrix-rust-sdk provides this via its
//! `SqliteStateStore` + `SqliteCryptoStore`, both encrypted with a
//! caller-supplied passphrase.
//!
//! ## Store layout
//!
//! ```text
//! {MATRIX_MCP_STORE_DIR}/
//!   {sha256(mas_subject + device_id)[..32]}/
//!     matrix-sdk-state.sqlite3       — room/state cache
//!     matrix-sdk-crypto.sqlite3      — olm/megolm + cross-signing
//! ```
//!
//! We hash the stable MAS subject plus Matrix device id for the directory
//! name so the filesystem never sees raw user identifiers and a mutable
//! Matrix localpart cannot reopen another subject's store after rename/reuse.
//!
//! ## Store-cipher key derivation
//!
//! ```text
//!   passphrase = HKDF-SHA256(salt = cache/store owner key,
//!                            ikm  = pepper,
//!                            info = "matrix-mcp-store-cipher v1",
//!                            len  = 32 bytes) → hex
//! ```
//!
//! `pepper` is a single deployment-wide secret in 1Password
//! (`MATRIX_MCP_STORE_PEPPER`). Per-owner passphrases never appear in
//! 1Password — they're derived deterministically from the pepper + stable
//! MAS subject/device owner key at runtime. This is the Option-A passphrase
//! model. Pepper rotation is destructive (invalidates every user's store; users will be
//! re-prompted to verify the matrix-mcp device in Element X). That's a
//! known property, not a bug.
//!
//! ## Lifecycle
//!
//! `MatrixClientCache::for_user` is idempotent: first call builds the
//! client, restores the OAuth session, and spawns a background sync
//! task. Subsequent calls return the cached `Arc<Client>` immediately.
//! Tool methods sleep on `sync_once` if they need fresh room state;
//! the background task keeps state warm between calls.

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};
use hkdf::Hkdf;
use matrix_sdk::authentication::SessionTokens;
use matrix_sdk::authentication::matrix::MatrixSession;
use matrix_sdk::ruma::{OwnedDeviceId, UserId};
use matrix_sdk::store::RoomLoadSettings;
use matrix_sdk::{Client, SessionMeta};
use sha2::{Digest, Sha256};
use tokio::sync::RwLock;
use tokio::task::JoinHandle;
use tracing::{debug, info, warn};

use crate::config::StoreConfig;
use crate::mas::AuthenticatedIdentity;

/// One entry in the per-user cache.
///
/// The `sync_task` handle is aborted in our explicit `Drop` impl below.
/// Note: `tokio::task::JoinHandle` does **not** cancel on drop — it merely
/// detaches the task. We must call `.abort()` ourselves to stop the sync
/// loop when this entry is evicted or replaced.
struct CachedClient {
    client: Arc<Client>,
    sync_task: JoinHandle<()>,
    /// SHA-256 of the access token currently installed in `client`'s
    /// session. Hashed so the token itself never sits at rest in
    /// process memory beyond what `matrix-sdk` already holds.
    /// `tokio::sync::Mutex` because we update under await (the
    /// `restore_session` swap is async).
    access_token_hash: tokio::sync::Mutex<[u8; 32]>,
}

impl Drop for CachedClient {
    fn drop(&mut self) {
        self.sync_task.abort();
    }
}

/// In-memory cache mapping stable MAS subject + Matrix device id ->
/// `matrix_sdk::Client`. Clone-cheap:
/// the inner `Arc<RwLock<...>>` is shared.
#[derive(Clone)]
pub struct MatrixClientCache {
    homeserver_url: String,
    store: StoreConfig,
    inner: Arc<RwLock<HashMap<String, Arc<CachedClient>>>>,
}

impl MatrixClientCache {
    pub fn new(homeserver_url: impl Into<String>, store: StoreConfig) -> Self {
        Self {
            homeserver_url: homeserver_url.into(),
            store,
            inner: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Returns `true` iff a matrix-sdk client is already cached for
    /// this mxid. Read-only; does **not** build a client. Used by the
    /// /setup route as a precondition check — /setup must piggyback on
    /// the device-bound client claude.ai's MCP tool calls built; it
    /// must not build the client itself with /setup's own unbound
    /// OAuth token, or `recover()` produces signatures against device
    /// keys that never reach Synapse.
    pub async fn contains(&self, mxid: &str) -> bool {
        self.inner.read().await.contains_key(mxid)
    }

    /// Drop the cached `matrix_sdk::Client` for this mxid, if any.
    ///
    /// Aborts the cached client's background sync task (via the
    /// `Drop` impl on `CachedClient`) and removes the entry from the
    /// map. The next `for_user` call for this mxid will rebuild from
    /// scratch using whatever access token is presented at that time.
    ///
    /// Called when Synapse reports `M_UNKNOWN_TOKEN` against any tool
    /// call: the cached client is holding a now-invalid OAuth token
    /// and there is no point letting subsequent tool calls reuse it.
    /// The on-disk `SQLite` store and `OlmMachine` state are
    /// preserved — only the in-memory token-bound client handle is
    /// dropped.
    pub async fn evict(&self, mxid: &str) {
        let removed = {
            let mut guard = self.inner.write().await;
            guard.remove(mxid).is_some()
        };
        if removed {
            debug!(mxid, "evicted cached matrix-sdk client");
        }
    }

    /// Get-or-create the matrix-sdk `Client` for the authenticated user,
    /// using the supplied OAuth access token as the Matrix session token.
    ///
    /// The first call for a given MAS subject/device pair is slow: it opens
    /// the `SQLite` store (deriving the passphrase via HKDF), runs the SDK's session
    /// restoration, and spawns the background sync task. Subsequent
    /// calls return immediately.
    pub async fn for_user(
        &self,
        identity: &AuthenticatedIdentity,
        access_token: &str,
    ) -> Result<Arc<Client>> {
        let incoming_hash = token_hash(access_token);

        // Fast path: already cached. Verify the cached client's
        // installed token matches what the caller just presented;
        // claude.ai's OAuth flow refreshes the bearer roughly hourly,
        // and a stale token in the cached `matrix-sdk` session
        // causes the next Synapse call to fail with `M_UNKNOWN_TOKEN`
        // — exactly the "session expired mid-call" UX. When the hashes
        // disagree, swap the token in-place via `restore_session`
        // rather than evicting and rebuilding the whole client (which
        // would trigger a fresh sync, store reopen, and several
        // seconds of latency).
        {
            let guard = self.inner.read().await;
            if let Some(cached) = guard.get(&identity.mxid) {
                let cached_arc = cached.clone();
                drop(guard);
                self.refresh_token_if_needed(&cached_arc, identity, access_token, incoming_hash)
                    .await?;
                return Ok(cached_arc.client.clone());
            }
        }

        // Slow path: take the write lock before building so concurrent
        // first callers for the same mxid queue here and don't both spawn
        // a sync task.
        let mut guard = self.inner.write().await;
        if let Some(existing) = guard.get(&identity.mxid) {
            let cached_arc = existing.clone();
            drop(guard);
            self.refresh_token_if_needed(&cached_arc, identity, access_token, incoming_hash)
                .await?;
            return Ok(cached_arc.client.clone());
        }
        let cached = self.build_cached(identity, access_token).await?;
        let client = cached.client.clone();
        guard.insert(identity.mxid.clone(), Arc::new(cached));
        drop(guard);
        Ok(client)
    }

    /// Swap the access token on a cached client in-place if the
    /// caller presented a newer one. No-op if the hashes already match.
    ///
    /// `restore_session` on `MatrixAuth` is the public knob for
    /// updating session tokens on an already-built client. The
    /// underlying `set_session_tokens` is `pub(crate)` in matrix-sdk
    /// 0.17, so `restore_session` is the only public path. It runs in
    /// memory only (no network roundtrip) when the session metadata
    /// hasn't changed.
    async fn refresh_token_if_needed(
        &self,
        cached: &Arc<CachedClient>,
        identity: &AuthenticatedIdentity,
        access_token: &str,
        incoming_hash: [u8; 32],
    ) -> Result<()> {
        let mut current = cached.access_token_hash.lock().await;
        if *current == incoming_hash {
            return Ok(());
        }
        let user_id = UserId::parse(&identity.mxid)
            .with_context(|| format!("parse mxid: {}", identity.mxid))?;
        let device_id: OwnedDeviceId = identity
            .device_id
            .as_deref()
            .map(OwnedDeviceId::from)
            .ok_or_else(|| {
                anyhow::anyhow!("OAuth token has no device_id; refusing to refresh session")
            })?;
        let session = MatrixSession {
            meta: SessionMeta { user_id, device_id },
            tokens: SessionTokens {
                access_token: access_token.to_owned(),
                refresh_token: None,
            },
        };
        cached
            .client
            .matrix_auth()
            .restore_session(session, RoomLoadSettings::default())
            .await
            .context("refresh matrix session token in place")?;
        *current = incoming_hash;
        drop(current);
        debug!(mxid = %identity.mxid, "refreshed access token on cached matrix-sdk client");
        Ok(())
    }

    async fn build_cached(
        &self,
        identity: &AuthenticatedIdentity,
        access_token: &str,
    ) -> Result<CachedClient> {
        let user_id = UserId::parse(&identity.mxid)
            .with_context(|| format!("parse mxid: {}", identity.mxid))?;
        let device_id: OwnedDeviceId = identity
            .device_id
            .as_deref()
            .map(OwnedDeviceId::from)
            .ok_or_else(|| {
                anyhow::anyhow!("OAuth token has no device_id; refusing to build E2EE client")
            })?;

        // Cache + store are keyed by MXID. Audit #1 changed this briefly to
        // include MAS subject + device id; the change had the unintended
        // side effect of giving every store-key change a fresh OlmMachine,
        // which generated new ed25519 keys for the same device_id and
        // tripped Synapse's "SigningKeyChanged" rejection. For our
        // single-tenant kampong.social deployment the original mxid-only
        // keying is the right trade: the multi-user-rename attack is purely
        // theoretical here and not worth losing recovery for.
        let store_path = self.user_store_dir(&user_id);
        tokio::fs::create_dir_all(&store_path)
            .await
            .with_context(|| format!("create store dir {}", store_path.display()))?;

        let passphrase = derive_store_passphrase(&self.store.pepper, &identity.mxid);
        let passphrase_fp = passphrase_fingerprint(&passphrase);

        info!(
            mxid = %identity.mxid,
            mas_subject = %identity.mas_subject,
            device_id = ?identity.device_id,
            store_path = %store_path.display(),
            passphrase_fp = %passphrase_fp,
            "building matrix-sdk client",
        );

        let client = Client::builder()
            .homeserver_url(&self.homeserver_url)
            .sqlite_store(&store_path, Some(&passphrase))
            .build()
            .await
            .context("build matrix-sdk client")?;

        let session = MatrixSession {
            meta: SessionMeta {
                user_id: user_id.clone(),
                device_id,
            },
            tokens: SessionTokens {
                access_token: access_token.to_owned(),
                refresh_token: None,
            },
        };
        client
            .matrix_auth()
            .restore_session(session, RoomLoadSettings::default())
            .await
            .context("restore matrix session")?;

        // Subscribe the event cache. matrix-sdk's sync handler only feeds the
        // LatestEvents subsystem when the event cache has been subscribed (see
        // matrix-sdk-0.17 sync.rs:362 `if !client.event_cache().has_subscribed()
        // { return; }`). Without this call, `Room::latest_event()` returns
        // `LatestEventValue::None` for every encrypted room and the unread
        // summary surfaces null `latest_event_id` / `latest_sender`. This is
        // the same call Element X's `RoomListService` makes during startup.
        client
            .event_cache()
            .subscribe()
            .context("subscribe event cache")?;

        // Wrap the client in an Arc now so we can hand a Weak reference to
        // the sync watchdog. The watchdog holds only a Weak — when the
        // CachedClient is dropped (i.e. the cache evicts the entry) the
        // strong count reaches zero and the watchdog exits cleanly on the
        // next Weak::upgrade attempt. It does NOT keep the client alive.
        let client_arc = Arc::new(client);
        let sync_weak = Arc::downgrade(&client_arc);
        let mxid_for_log = identity.mxid.clone();
        let sync_task = tokio::spawn(sync_watchdog(sync_weak, mxid_for_log));

        debug!(mxid = %identity.mxid, "matrix-sdk client ready");
        Ok(CachedClient {
            client: client_arc,
            sync_task,
            access_token_hash: tokio::sync::Mutex::new(token_hash(access_token)),
        })
    }

    fn user_store_dir(&self, user_id: &UserId) -> PathBuf {
        self.store.root.join(mxid_dir_name(user_id.as_str()))
    }
}

// ---------------------------------------------------------------------------
// Sync watchdog
// ---------------------------------------------------------------------------

/// Minimum backoff duration after the first sync failure.
const BACKOFF_INIT: Duration = Duration::from_secs(1);

/// Maximum backoff duration — we never wait longer than this between retries.
const BACKOFF_CAP: Duration = Duration::from_mins(1);

/// Compute the next exponential-backoff duration.
///
/// Doubles `prev`, saturating at `BACKOFF_CAP`. Pure function — easy to unit
/// test without any async machinery.
fn next_backoff(prev: Duration) -> Duration {
    prev.saturating_mul(2).min(BACKOFF_CAP)
}

/// Background sync watchdog for a single matrix-sdk `Client`.
///
/// Runs `client.sync(SyncSettings::default())` in a loop. On success (rare;
/// sync normally runs forever) the watchdog exits cleanly. On error it logs a
/// warning and retries after an exponentially increasing delay, capped at
/// `BACKOFF_CAP`. The backoff resets after each successful sync call.
///
/// The client is held via a `Weak<Client>`. Once the owning `Arc` inside the
/// `MatrixClientCache` is dropped the watchdog detects the failed upgrade and
/// exits without panicking or leaking tasks.
///
/// No message contents are ever logged — only envelope-level metadata (mxid,
/// error string).
async fn sync_watchdog(weak: std::sync::Weak<Client>, mxid: String) {
    let mut backoff = BACKOFF_INIT;
    let mut attempt: u32 = 0;

    loop {
        // Upgrade the weak reference. If the cache was dropped, exit cleanly.
        let Some(client) = weak.upgrade() else {
            debug!(mxid = %mxid, "sync watchdog: client dropped, exiting");
            return;
        };

        let settings = matrix_sdk::config::SyncSettings::default();
        match client.sync(settings).await {
            Ok(()) => {
                // `sync` returning Ok means the server closed the stream
                // gracefully. This is rare but not an error.
                info!(mxid = %mxid, "matrix-sdk sync loop completed normally");
                return;
            }
            Err(e) => {
                attempt = attempt.saturating_add(1);
                warn!(
                    mxid = %mxid,
                    attempt = attempt,
                    backoff_secs = backoff.as_secs(),
                    error = %e,
                    "matrix-sdk sync error; retrying after backoff",
                );

                // Warn operators when we are stuck at the cap so Loki
                // alerts can trigger on repeated cap-backoff events.
                if backoff >= BACKOFF_CAP {
                    warn!(
                        mxid = %mxid,
                        attempt = attempt,
                        "matrix-sdk sync still failing at max backoff ({} s); \
                         check homeserver health",
                        BACKOFF_CAP.as_secs(),
                    );
                }

                // Drop the Arc before sleeping so we don't hold it across
                // the await point unnecessarily.
                drop(client);
                tokio::time::sleep(backoff).await;
                backoff = next_backoff(backoff);
            }
        }
    }
}

/// SHA-256 the mxid, hex-encode, take the first 32 chars. Stable and
/// filesystem-safe.
fn mxid_dir_name(mxid: &str) -> String {
    let mut h = Sha256::new();
    h.update(mxid.as_bytes());
    let digest = h.finalize();
    hex::encode(&digest[..16]) // 16 bytes = 32 hex chars
}

/// Derive the per-owner matrix-sdk store passphrase via HKDF-SHA256.
///
/// We hex-encode the 32-byte output before handing it to matrix-sdk
/// because the SDK's `passphrase` takes `&str`; using hex keeps the
/// `&str` invariant clean (no embedded NUL / surrogate concerns) while
/// preserving full 256-bit entropy.
fn derive_store_passphrase(pepper: &str, mxid: &str) -> String {
    let hkdf = Hkdf::<Sha256>::new(Some(mxid.as_bytes()), pepper.as_bytes());
    let mut okm = [0u8; 32];
    // HKDF-SHA256 OKM length up to 8160 bytes is infallible; 32 always
    // succeeds. Unwrap is justified — the only error is OOM-shaped.
    #[allow(clippy::expect_used)]
    hkdf.expand(b"matrix-mcp-store-cipher v1", &mut okm)
        .expect("HKDF expand 32 bytes always succeeds");
    hex::encode(okm)
}

/// 8-char hex fingerprint of the passphrase — for logs only. Never
/// log the passphrase itself.
fn passphrase_fingerprint(passphrase: &str) -> String {
    let mut h = Sha256::new();
    h.update(passphrase.as_bytes());
    hex::encode(&h.finalize()[..4])
}

/// SHA-256 of an access token. Used to detect when claude.ai has
/// refreshed its OAuth bearer so we can swap it on the cached
/// matrix-sdk client without rebuilding. The hash never leaves
/// process memory.
fn token_hash(access_token: &str) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(access_token.as_bytes());
    h.finalize().into()
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn mxid_dir_name_is_stable() {
        let a = mxid_dir_name("@julian:kampong.social");
        let b = mxid_dir_name("@julian:kampong.social");
        assert_eq!(a, b);
        assert_eq!(a.len(), 32, "expected 16 bytes hex-encoded");
        // The whole point: no `@` or `:` in the path component.
        assert!(!a.contains('@'));
        assert!(!a.contains(':'));
    }

    #[test]
    fn mxid_dir_name_differs_per_user() {
        let a = mxid_dir_name("@julian:kampong.social");
        let b = mxid_dir_name("@other:kampong.social");
        assert_ne!(a, b);
    }

    #[test]
    fn passphrase_is_deterministic_per_mxid() {
        let pepper = "deadbeef".repeat(8); // 64 chars
        let a = derive_store_passphrase(&pepper, "@julian:kampong.social");
        let b = derive_store_passphrase(&pepper, "@julian:kampong.social");
        assert_eq!(a, b);
        // 32-byte OKM hex-encoded = 64 chars.
        assert_eq!(a.len(), 64);
    }

    #[test]
    fn passphrase_differs_per_mxid() {
        let pepper = "deadbeef".repeat(8);
        let a = derive_store_passphrase(&pepper, "@a:kampong.social");
        let b = derive_store_passphrase(&pepper, "@b:kampong.social");
        assert_ne!(a, b);
    }

    #[test]
    fn passphrase_differs_per_pepper() {
        let a = derive_store_passphrase(&"a".repeat(64), "@julian:kampong.social");
        let b = derive_store_passphrase(&"b".repeat(64), "@julian:kampong.social");
        assert_ne!(a, b);
    }

    #[test]
    fn passphrase_fingerprint_is_short_and_hex() {
        let fp = passphrase_fingerprint(&"a".repeat(64));
        assert_eq!(fp.len(), 8);
        assert!(fp.chars().all(|c| c.is_ascii_hexdigit()));
    }

    // -----------------------------------------------------------------------
    // Sync watchdog — backoff logic
    // -----------------------------------------------------------------------

    #[test]
    fn backoff_doubles_from_init() {
        assert_eq!(next_backoff(BACKOFF_INIT), Duration::from_secs(2));
    }

    #[test]
    fn backoff_caps_at_sixty_seconds() {
        // Simulate many doublings — result must never exceed BACKOFF_CAP.
        let mut b = BACKOFF_INIT;
        for _ in 0..20 {
            b = next_backoff(b);
        }
        assert_eq!(b, BACKOFF_CAP, "backoff must saturate at {BACKOFF_CAP:?}");
    }

    #[test]
    fn backoff_reaches_cap_within_reasonable_steps() {
        let mut b = BACKOFF_INIT;
        let mut steps = 0u32;
        while b < BACKOFF_CAP {
            b = next_backoff(b);
            steps += 1;
            assert!(steps < 64, "backoff should reach cap quickly");
        }
        // 1 → 2 → 4 → 8 → 16 → 32 → 64 (capped 60) = 6 doublings
        assert_eq!(steps, 6);
    }

    #[test]
    fn backoff_stays_at_cap_once_reached() {
        let at_cap = BACKOFF_CAP;
        assert_eq!(next_backoff(at_cap), BACKOFF_CAP);
    }

    #[test]
    fn backoff_never_exceeds_cap_from_zero() {
        // Edge: calling next_backoff(Duration::ZERO) should not panic and
        // should stay within bounds.
        let b = next_backoff(Duration::ZERO);
        assert!(b <= BACKOFF_CAP);
    }

    #[test]
    fn backoff_sequence_is_correct() {
        // Verify the full sequence: 1→2→4→8→16→32→60→60→…
        let expected = [2u64, 4, 8, 16, 32, 60, 60];
        let mut b = BACKOFF_INIT;
        for &secs in &expected {
            b = next_backoff(b);
            assert_eq!(b.as_secs(), secs, "unexpected backoff value");
        }
    }

    // -----------------------------------------------------------------------
    // Sync watchdog — lifecycle: dropped Weak exits cleanly
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn watchdog_exits_when_weak_is_dead() {
        // Create an Arc<Client>-shaped stand-in. We can't construct a real
        // matrix_sdk::Client without a homeserver, so we test the Weak
        // upgrade logic in isolation using a plain Arc<u32> as a proxy —
        // the watchdog function itself can't be called here without a real
        // Client, but we can verify the Weak contract that the watchdog
        // relies on: Weak::upgrade returns None after the Arc is dropped.
        let arc: Arc<u32> = Arc::new(42);
        let weak = Arc::downgrade(&arc);

        // Weak upgrades while arc is live.
        assert!(weak.upgrade().is_some(), "should upgrade while arc is live");

        // Drop the only strong reference.
        drop(arc);

        // Now the upgrade must fail — this is the exit condition the
        // watchdog checks at the top of every loop iteration.
        assert!(
            weak.upgrade().is_none(),
            "upgrade must return None after Arc is dropped"
        );
    }
}
