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
//!   {sha256(mxid)[..32]}/
//!     matrix-sdk-state.sqlite3       — room/state cache
//!     matrix-sdk-crypto.sqlite3      — olm/megolm + cross-signing
//! ```
//!
//! We hash the mxid for the directory name so the filesystem never
//! sees raw `@user:host` characters (some are awkward on case-folded
//! filesystems, and ext4 tolerates them but the hash is portable).
//!
//! ## Store-cipher key derivation
//!
//! ```text
//!   passphrase = HKDF-SHA256(salt = mxid,
//!                            ikm  = pepper,
//!                            info = "matrix-mcp-store-cipher v1",
//!                            len  = 32 bytes) → hex
//! ```
//!
//! `pepper` is a single deployment-wide secret in 1Password
//! (`MATRIX_MCP_STORE_PEPPER`). Per-user passphrases never appear in
//! 1Password — they're derived deterministically from the pepper + mxid
//! at runtime. This is the Option-A passphrase model. Pepper rotation
//! is destructive (invalidates every user's store; users will be
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

/// One entry in the per-user cache. The `_sync_task` handle is held only
/// to keep the spawned future alive; we abort it on drop via the
/// `Drop` impl on `JoinHandle` (cancel-on-drop). For single-tenant
/// matrix-mcp the cache lives the lifetime of the process so this
/// effectively never fires; for multi-tenant we'd add idle eviction.
struct CachedClient {
    client: Arc<Client>,
    _sync_task: JoinHandle<()>,
}

/// In-memory cache mapping `mxid → matrix_sdk::Client`. Clone-cheap:
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
    /// The first call for a given mxid is slow: it opens the `SQLite`
    /// store (deriving the passphrase via HKDF), runs the SDK's session
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
            if let Some(cached) = guard.get(&identity.mxid) {
                return Ok(cached.client.clone());
            }
        }

        // Slow path: build it under write lock. We re-check after taking
        // the write lock to avoid two concurrent first-callers both
        // constructing a client.
        let cached = self.build_cached(identity, access_token).await?;
        let client = cached.client.clone();
        let mut guard = self.inner.write().await;
        if let Some(existing) = guard.get(&identity.mxid) {
            // Another task beat us to it while we were building. Drop
            // our just-built client; the existing one is canonical.
            let existing_client = existing.client.clone();
            drop(guard);
            return Ok(existing_client);
        }
        guard.insert(identity.mxid.clone(), Arc::new(cached));
        drop(guard);
        Ok(client)
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

        let store_path = self.user_store_dir(&user_id);
        tokio::fs::create_dir_all(&store_path)
            .await
            .with_context(|| format!("create store dir {}", store_path.display()))?;

        let passphrase = derive_store_passphrase(&self.store.pepper, &identity.mxid);
        let passphrase_fp = passphrase_fingerprint(&passphrase);

        info!(
            mxid = %identity.mxid,
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

        // Spawn a background sync task. matrix-sdk's `sync` future runs
        // until error; on error we log and exit (the cache entry stays,
        // so subsequent tool calls will still use this client — they
        // just won't get fresh server-pushed updates between syncs).
        // Tool methods that need a current view can call `sync_once`
        // explicitly.
        let sync_client = client.clone();
        let mxid_for_log = identity.mxid.clone();
        let sync_task = tokio::spawn(async move {
            let settings = matrix_sdk::config::SyncSettings::default();
            if let Err(e) = sync_client.sync(settings).await {
                warn!(mxid = %mxid_for_log, error = %e, "matrix-sdk sync loop exited");
            }
        });

        debug!(mxid = %identity.mxid, "matrix-sdk client ready");
        Ok(CachedClient {
            client: Arc::new(client),
            _sync_task: sync_task,
        })
    }

    fn user_store_dir(&self, user_id: &UserId) -> PathBuf {
        self.store.root.join(mxid_dir_name(user_id.as_str()))
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

/// Derive the per-user matrix-sdk store passphrase via HKDF-SHA256.
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
}
