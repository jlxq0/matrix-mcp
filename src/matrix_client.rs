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
}
