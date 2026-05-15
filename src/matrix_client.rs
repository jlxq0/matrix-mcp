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
        // Fast path: already cached. Bind the read guard tightly so it
        // drops before any await — clippy::significant_drop_tightening.
        {
            let guard = self.inner.read().await;
            let owner_key = owner_key(identity)?;
            if let Some(cached) = guard.get(&owner_key) {
                return Ok(cached.client.clone());
            }
        }

        // Slow path: take the write lock *before* building so that concurrent
        // first callers for the same owner queue up here rather than all racing
        // through build_cached. The second (and later) callers will hit the
        // re-check below and return the already-built client without spawning
        // a redundant sync task.
        //
        // Build time is bounded by the SQLite open + one SDK network round-trip
        // (session restoration). Holding the write lock across that await is
        // acceptable — first-use happens at most once per user per process
        // lifetime, and concurrent callers for *different* owners are also
        // serialized here, which is fine given the same frequency.
        let owner_key = owner_key(identity)?;
        let mut guard = self.inner.write().await;
        if let Some(existing) = guard.get(&owner_key) {
            // A concurrent caller already built the client while we waited for
            // the write lock. Return the canonical entry.
            return Ok(existing.client.clone());
        }
        let cached = self
            .build_cached(identity, access_token, &owner_key)
            .await?;
        let client = cached.client.clone();
        guard.insert(owner_key, Arc::new(cached));
        drop(guard);
        Ok(client)
    }

    async fn build_cached(
        &self,
        identity: &AuthenticatedIdentity,
        access_token: &str,
        owner_key: &str,
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

        let store_path = self.user_store_dir(owner_key);
        tokio::fs::create_dir_all(&store_path)
            .await
            .with_context(|| format!("create store dir {}", store_path.display()))?;

        let passphrase = derive_store_passphrase(&self.store.pepper, owner_key);
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
        })
    }

    fn user_store_dir(&self, owner_key: &str) -> PathBuf {
        self.store.root.join(owner_dir_name(owner_key))
    }
}

/// Compose the resource-server ownership key from MAS's non-reassignable
/// subject and the Matrix device id. The device id is included because the
/// `matrix-sdk` `SQLite` crypto store is for one restored Matrix device.
fn owner_key(identity: &AuthenticatedIdentity) -> Result<String> {
    let device_id = identity.device_id.as_deref().ok_or_else(|| {
        anyhow::anyhow!("OAuth token has no device_id; refusing to build E2EE client")
    })?;
    Ok(format!(
        "mas-sub:{} device:{device_id}",
        identity.mas_subject
    ))
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

/// SHA-256 the owner key, hex-encode, take the first 32 chars. Stable and
/// filesystem-safe.
fn owner_dir_name(owner_key: &str) -> String {
    let mut h = Sha256::new();
    h.update(owner_key.as_bytes());
    let digest = h.finalize();
    hex::encode(&digest[..16]) // 16 bytes = 32 hex chars
}

/// Derive the per-owner matrix-sdk store passphrase via HKDF-SHA256.
///
/// We hex-encode the 32-byte output before handing it to matrix-sdk
/// because the SDK's `passphrase` takes `&str`; using hex keeps the
/// `&str` invariant clean (no embedded NUL / surrogate concerns) while
/// preserving full 256-bit entropy.
fn derive_store_passphrase(pepper: &str, owner_key: &str) -> String {
    let hkdf = Hkdf::<Sha256>::new(Some(owner_key.as_bytes()), pepper.as_bytes());
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

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn owner_dir_name_is_stable() {
        let a = owner_dir_name("mas-sub:01JA device:DEVICE");
        let b = owner_dir_name("mas-sub:01JA device:DEVICE");
        assert_eq!(a, b);
        assert_eq!(a.len(), 32, "expected 16 bytes hex-encoded");
        // The whole point: no `@` or `:` in the path component.
        assert!(!a.contains('@'));
        assert!(!a.contains(':'));
    }

    #[test]
    fn owner_dir_name_differs_per_subject() {
        let a = owner_dir_name("mas-sub:01JA device:DEVICE");
        let b = owner_dir_name("mas-sub:01JB device:DEVICE");
        assert_ne!(a, b);
    }

    #[test]
    fn owner_key_ignores_reassignable_mxid() {
        let first = AuthenticatedIdentity {
            mas_subject: "01JA".to_owned(),
            mxid: "@alice:example.test".to_owned(),
            device_id: Some("DEVICE".to_owned()),
            raw_scope: None,
        };
        let second = AuthenticatedIdentity {
            mas_subject: "01JB".to_owned(),
            mxid: "@alice:example.test".to_owned(),
            device_id: Some("DEVICE".to_owned()),
            raw_scope: None,
        };
        assert_ne!(owner_key(&first).unwrap(), owner_key(&second).unwrap());
    }

    #[test]
    fn passphrase_is_deterministic_per_owner() {
        let pepper = "deadbeef".repeat(8); // 64 chars
        let a = derive_store_passphrase(&pepper, "mas-sub:01JA device:DEVICE");
        let b = derive_store_passphrase(&pepper, "mas-sub:01JA device:DEVICE");
        assert_eq!(a, b);
        // 32-byte OKM hex-encoded = 64 chars.
        assert_eq!(a.len(), 64);
    }

    #[test]
    fn passphrase_differs_per_owner() {
        let pepper = "deadbeef".repeat(8);
        let a = derive_store_passphrase(&pepper, "mas-sub:01JA device:DEVICE");
        let b = derive_store_passphrase(&pepper, "mas-sub:01JB device:DEVICE");
        assert_ne!(a, b);
    }

    #[test]
    fn passphrase_differs_per_pepper() {
        let a = derive_store_passphrase(&"a".repeat(64), "mas-sub:01JA device:DEVICE");
        let b = derive_store_passphrase(&"b".repeat(64), "mas-sub:01JA device:DEVICE");
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
