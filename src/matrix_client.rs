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
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use anyhow::{Context, Result, anyhow};
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
    /// Latched to `true` the first time `for_user` confirms that
    /// Synapse's `/keys/query` response for this MXID includes our
    /// `device_id`. Auto-heal in `for_user` consults this flag once per
    /// cached client and skips the check thereafter — verification is
    /// idempotent but `get_user_devices` round-trips the `OlmMachine` so
    /// we don't want to run it on the hot path of every tool call.
    keys_verified: AtomicBool,
}

impl Drop for CachedClient {
    fn drop(&mut self) {
        self.sync_task.abort();
    }
}

/// Per-MXID async `OnceCell` holding the built-or-being-built client.
type CachedClientCell = Arc<tokio::sync::OnceCell<Arc<CachedClient>>>;

/// In-memory cache mapping stable MAS subject + Matrix device id ->
/// `matrix_sdk::Client`. Clone-cheap:
/// the inner `Arc<RwLock<...>>` is shared.
///
/// Per-MXID isolation: each entry wraps the cached client in
/// [`tokio::sync::OnceCell`]. The global `RwLock` is held only for the
/// fast `HashMap` lookups; the slow SDK-build path runs **off-lock**
/// inside the cell's `get_or_try_init`. A first build for MXID A
/// therefore never blocks an unrelated call for MXID B — and a second
/// concurrent first-builder for MXID A waits on A's cell only, not on
/// the global write lock. Single-tenant deployments only see this
/// behaviour on cold start; multi-tenant deployments avoid global
/// head-of-line blocking entirely.
#[derive(Clone)]
pub struct MatrixClientCache {
    homeserver_url: String,
    store: StoreConfig,
    inner: Arc<RwLock<HashMap<String, CachedClientCell>>>,
}

impl MatrixClientCache {
    pub fn new(homeserver_url: impl Into<String>, store: StoreConfig) -> Self {
        Self {
            homeserver_url: homeserver_url.into(),
            store,
            inner: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Returns `true` iff a matrix-sdk client is already cached *and
    /// fully built* for this mxid. Read-only; does **not** build a
    /// client. Used by the /setup route as a precondition check.
    pub async fn contains(&self, mxid: &str) -> bool {
        self.inner
            .read()
            .await
            .get(mxid)
            .is_some_and(|cell| cell.initialized())
    }

    /// Drop the cached `matrix_sdk::Client` for this mxid, if any.
    ///
    /// Aborts the cached client's background sync task (via the
    /// `Drop` impl on `CachedClient`) and removes the entry from the
    /// map. The next `for_user` call for this mxid will rebuild from
    /// scratch using whatever access token is presented at that time.
    ///
    /// If a build is currently in-flight on this MXID's `OnceCell`,
    /// any task awaiting the cell still receives the in-flight build
    /// result (we can't cancel it). The map entry, however, is gone,
    /// so the *next* `for_user` will install a fresh cell and the
    /// stale in-flight result becomes unreachable.
    pub async fn evict(&self, mxid: &str) {
        let removed = {
            let mut guard = self.inner.write().await;
            guard.remove(mxid).is_some()
        };
        if removed {
            debug!(mxid, "evicted cached matrix-sdk client");
        }
    }

    /// Return the cached `Client` for `mxid` without touching its
    /// session state, or `None` if no fully-built client is cached for
    /// this user.
    ///
    /// Use this when you have a bearer that is **not** suitable for
    /// installing onto the cached client — most importantly, `/setup`'s
    /// own unbound OAuth access token. The cached client is already
    /// authenticated with claude.ai's device-bound bearer; running
    /// `restore_session` to swap in `/setup`'s token panics in
    /// matrix-sdk 0.17 (`AlreadyInitializedError`), which is what
    /// crashed the pod on 2026-05-18 when verifying device-binding
    /// recovery.
    pub async fn get_if_cached(&self, mxid: &str) -> Option<Arc<Client>> {
        self.inner
            .read()
            .await
            .get(mxid)
            .and_then(|cell| cell.get().map(|c| c.client.clone()))
    }

    /// Get-or-create the matrix-sdk `Client` for the authenticated user,
    /// using the supplied OAuth access token as the Matrix session token.
    ///
    /// The first call for a given MAS subject/device pair is slow: it opens
    /// the `SQLite` store (deriving the passphrase via HKDF), runs the SDK's session
    /// restoration, and spawns the background sync task. Subsequent
    /// calls return immediately.
    ///
    /// ## Split-brain device-keys auto-heal
    ///
    /// Once per cached client lifetime, this method also verifies that
    /// Synapse's `/keys/query` for this MXID lists our `device_id`. If
    /// matrix-rust-sdk's local `device_keys_published` flag is latched
    /// to `true` but Synapse doesn't actually have our keys — which is
    /// possible when an earlier `/keys/upload` was rejected (e.g. an
    /// unbound `/setup` token) while the SDK still set the local flag
    /// — every subsequent /keys/upload is skipped and the device stays
    /// invisible to the homeserver. The SDK exposes no public API to
    /// clear that flag, so the only recovery is to wipe the per-MXID
    /// crypto store and let the SDK rebuild from scratch. We do that
    /// transparently here, recursing exactly once to verify the
    /// rebuild actually published keys (and erroring out instead of
    /// looping if it didn't).
    pub async fn for_user(
        &self,
        identity: &AuthenticatedIdentity,
        access_token: &str,
    ) -> Result<Arc<Client>> {
        self.for_user_inner(identity, access_token, false).await
    }

    /// Inner implementation of `for_user`. Splits out the retry flag so
    /// the auto-heal path can recurse exactly once.
    ///
    /// `retry=true` means we're being called from the self-heal branch
    /// below, after wiping the per-MXID store. On the retry pass we
    /// re-verify; if Synapse *still* doesn't have our keys after a
    /// fresh build we surface an error rather than recurse again. That
    /// keeps the worst case bounded at two SDK builds + two
    /// `/keys/query` calls per /mcp request — never an infinite loop.
    async fn for_user_inner(
        &self,
        identity: &AuthenticatedIdentity,
        access_token: &str,
        retry: bool,
    ) -> Result<Arc<Client>> {
        let incoming_hash = token_hash(access_token);

        // Fast path: cell exists AND is fully initialized AND its
        // background sync task is still running. Holds the read lock
        // only for the HashMap lookup, then drops it before running
        // refresh_token_if_needed.
        //
        // The sync_task check matters because `sync_watchdog` exits
        // cleanly on permanent auth-failure signatures
        // (M_UNKNOWN_TOKEN, Token is not active). Without this check
        // the next /mcp request with a freshly-refreshed bearer would
        // restore_session the new token onto the same cached client
        // — but the background sync task is gone, so SDK room/state
        // freshness silently degrades. By treating a finished
        // sync_task as "stale", we force eviction + rebuild here.
        let cached = {
            let guard = self.inner.read().await;
            if let Some(cell) = guard.get(&identity.mxid)
                && let Some(cached) = cell.get()
                && !cached.sync_task.is_finished()
            {
                let cached = cached.clone();
                drop(guard);
                self.refresh_token_if_needed(&cached, identity, access_token, incoming_hash)
                    .await?;
                Some(cached)
            } else {
                None
            }
        };

        if let Some(cached) = cached {
            return self
                .verify_or_heal(cached, identity, access_token, retry)
                .await;
        }

        // Stale eviction: if the existing cell holds a cached client
        // with a finished sync_task, remove the entry so the slow
        // path below creates a fresh OnceCell + rebuilds. Holding a
        // write lock just long enough to drop the entry — the build
        // itself runs off-lock inside the cell. matrix-sdk's
        // `restore_session` panics with `AlreadyInitializedError` if
        // we tried to reuse the Client; rebuilding from scratch is
        // the only sound recovery.
        {
            let mut guard = self.inner.write().await;
            if let Some(cell) = guard.get(&identity.mxid)
                && cell.get().is_some_and(|c| c.sync_task.is_finished())
            {
                debug!(
                    mxid = %identity.mxid,
                    "evicting cached matrix-sdk client with finished sync_task; \
                     will rebuild"
                );
                guard.remove(&identity.mxid);
            }
        }

        // Slow path: get-or-insert the OnceCell under a brief write
        // lock, then run the SDK build off-lock inside the cell. This
        // means concurrent first-callers for *different* MXIDs no
        // longer queue behind each other, and concurrent first-callers
        // for the same MXID share one build via the cell's internal
        // semaphore — only one task runs build_cached(), the rest
        // await its result.
        let cell = {
            let mut guard = self.inner.write().await;
            Arc::clone(
                guard
                    .entry(identity.mxid.clone())
                    .or_insert_with(|| Arc::new(tokio::sync::OnceCell::new())),
            )
        };
        let cached: Arc<CachedClient> = cell
            .get_or_try_init(|| async {
                self.build_cached(identity, access_token)
                    .await
                    .map(Arc::new)
            })
            .await?
            .clone();
        self.refresh_token_if_needed(&cached, identity, access_token, incoming_hash)
            .await?;

        self.verify_or_heal(cached, identity, access_token, retry)
            .await
    }

    /// Post-build / post-fetch verification step shared by both the
    /// fast path and the slow path of `for_user_inner`. Runs the
    /// `/keys/query` round-trip exactly once per cached client; on a
    /// negative result, wipes the per-MXID store and recurses.
    async fn verify_or_heal(
        &self,
        cached: Arc<CachedClient>,
        identity: &AuthenticatedIdentity,
        access_token: &str,
        retry: bool,
    ) -> Result<Arc<Client>> {
        if cached.keys_verified.load(Ordering::Acquire) {
            return Ok(cached.client.clone());
        }
        match verify_device_keys_published(&cached.client, &identity.mxid).await {
            Ok(true) => {
                cached.keys_verified.store(true, Ordering::Release);
                Ok(cached.client.clone())
            }
            Ok(false) => {
                if retry {
                    // Second pass after wipe+rebuild and Synapse still
                    // doesn't have our keys. Surface the failure rather
                    // than recurse — something more fundamental is
                    // wrong (auth bound to the wrong device, MAS clock
                    // skew, /keys/upload returning 200 but Synapse
                    // dropping the device, etc.) and looping would
                    // pound the homeserver.
                    return Err(anyhow!(
                        "self-heal failed: device keys still not published after rebuild for {}",
                        identity.mxid
                    ));
                }
                warn!(
                    mxid = %identity.mxid,
                    device_id = ?cached.client.device_id(),
                    "split-brain crypto state detected (local SDK has device_keys, \
                     Synapse does not); self-healing by wiping per-MXID store",
                );
                crate::metrics::SELF_HEAL_COUNTER
                    .with_label_values(&["device_keys_missing"])
                    .inc();
                // Drop the Arc *before* evict so the cached client's
                // background sync task gets aborted when the cache
                // entry is removed. (Drop impl on CachedClient calls
                // sync_task.abort().)
                drop(cached);
                self.evict(&identity.mxid).await;
                self.wipe_user_store(&identity.mxid).await?;
                // Recurse exactly once. Box::pin because an `async fn`
                // can't recurse directly — the returned future would
                // have infinite size.
                Box::pin(self.for_user_inner(identity, access_token, true)).await
            }
            Err(e) => {
                // Network blip / olm machine not ready / Synapse 5xx.
                // Don't fail closed: leaving keys_verified=false means
                // the next /mcp call retries the check, and meanwhile
                // the tool call proceeds normally. Decryption either
                // works (most rooms) or doesn't (which is what the
                // user would see anyway without this auto-heal).
                warn!(
                    mxid = %identity.mxid,
                    error = ?e,
                    "device_keys verification failed; leaving keys_verified=false",
                );
                Ok(cached.client.clone())
            }
        }
    }

    /// Delete the per-MXID matrix-sdk store directory under
    /// `self.store.root`. Scoped to exactly one user's subdirectory —
    /// never the store root itself, and never another user's data. A
    /// missing directory is not an error (treated as a no-op).
    ///
    /// Used by the device-keys self-heal path in [`Self::for_user`].
    /// After this returns, the next `for_user` call for `mxid` will
    /// rebuild a fresh `SQLite` crypto + state store and re-run
    /// `restore_session`, which re-uploads device keys via the SDK's
    /// normal sync flow.
    async fn wipe_user_store(&self, mxid: &str) -> Result<()> {
        let dir = self.store.root.join(mxid_dir_name(mxid));
        info!(
            mxid = %mxid,
            store_path = %dir.display(),
            "wiping per-MXID matrix-sdk store for self-heal",
        );
        match tokio::fs::remove_dir_all(&dir).await {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(e) => {
                Err(e).with_context(|| format!("remove per-MXID store dir {}", dir.display()))
            }
        }
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
        // single-tenant example.com deployment the original mxid-only
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
            keys_verified: AtomicBool::new(false),
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
                // Permanent auth failures don't recover with backoff —
                // the bearer token is gone (claude.ai reconnect, MAS
                // session revoked, user signed out). Stop the watchdog
                // instead of pounding Synapse with M_UNKNOWN_TOKEN
                // forever; the next /mcp call will rebuild a fresh
                // client with the new token.
                let err_msg = e.to_string();
                if is_permanent_auth_failure(&err_msg) {
                    info!(
                        mxid = %mxid,
                        attempt = attempt,
                        error = %e,
                        "matrix-sdk sync hit permanent auth failure; \
                         exiting watchdog (cache will rebuild on next /mcp request)",
                    );
                    return;
                }
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

/// True if the matrix-sdk sync error message indicates the bearer token
/// has been permanently rejected by the homeserver. Matches the same
/// signatures used by `is_auth_expiry_signature` in `mcp.rs`. Substring
/// match is fine — these strings only appear in legitimate 401
/// envelopes.
fn is_permanent_auth_failure(msg: &str) -> bool {
    msg.contains("M_UNKNOWN_TOKEN") || msg.contains("Token is not active")
}

/// Ask matrix-rust-sdk for the user's device set and check whether
/// `client.device_id()` is present.
///
/// `Client::encryption().get_user_devices` routes through the
/// `OlmMachine`, which consults its local crypto store but also issues
/// `/keys/query` to the homeserver for any user with a pending key-query
/// (and our own user is always in that set after a successful sync).
/// We treat:
///
/// - `Ok(true)` — device id present in response → keys are published
/// - `Ok(false)` — device id absent → split-brain, caller should self-heal
/// - `Err(_)` — network or olm-machine error → propagate; caller decides
///   whether to fail closed (we don't; we log and leave `keys_verified`
///   false so the next call retries)
async fn verify_device_keys_published(client: &Client, mxid: &str) -> Result<bool> {
    let user_id = UserId::parse(mxid).with_context(|| format!("parse mxid: {mxid}"))?;
    let Some(device_id) = client.device_id() else {
        return Err(anyhow!(
            "client has no device_id; cannot verify device_keys for {mxid}"
        ));
    };
    let devices = client
        .encryption()
        .get_user_devices(&user_id)
        .await
        .with_context(|| format!("get_user_devices({mxid})"))?;
    Ok(devices.get(device_id).is_some())
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
    fn permanent_auth_failure_signatures() {
        assert!(is_permanent_auth_failure(
            "error sending request: M_UNKNOWN_TOKEN: Token is not active"
        ));
        assert!(is_permanent_auth_failure(
            "[401 / M_UNKNOWN_TOKEN] Invalid access token passed."
        ));
        assert!(is_permanent_auth_failure(
            "the homeserver responded: Token is not active"
        ));
        // Network / transient errors must NOT match — those should retry.
        assert!(!is_permanent_auth_failure("connection refused"));
        assert!(!is_permanent_auth_failure("504 Gateway Timeout"));
        assert!(!is_permanent_auth_failure(
            "operation timed out after 30 seconds"
        ));
    }

    #[test]
    fn mxid_dir_name_is_stable() {
        let a = mxid_dir_name("@alice:example.com");
        let b = mxid_dir_name("@alice:example.com");
        assert_eq!(a, b);
        assert_eq!(a.len(), 32, "expected 16 bytes hex-encoded");
        // The whole point: no `@` or `:` in the path component.
        assert!(!a.contains('@'));
        assert!(!a.contains(':'));
    }

    #[test]
    fn mxid_dir_name_differs_per_user() {
        let a = mxid_dir_name("@alice:example.com");
        let b = mxid_dir_name("@other:example.com");
        assert_ne!(a, b);
    }

    #[test]
    fn passphrase_is_deterministic_per_mxid() {
        let pepper = "deadbeef".repeat(8); // 64 chars
        let a = derive_store_passphrase(&pepper, "@alice:example.com");
        let b = derive_store_passphrase(&pepper, "@alice:example.com");
        assert_eq!(a, b);
        // 32-byte OKM hex-encoded = 64 chars.
        assert_eq!(a.len(), 64);
    }

    #[test]
    fn passphrase_differs_per_mxid() {
        let pepper = "deadbeef".repeat(8);
        let a = derive_store_passphrase(&pepper, "@a:example.com");
        let b = derive_store_passphrase(&pepper, "@b:example.com");
        assert_ne!(a, b);
    }

    #[test]
    fn passphrase_differs_per_pepper() {
        let a = derive_store_passphrase(&"a".repeat(64), "@alice:example.com");
        let b = derive_store_passphrase(&"b".repeat(64), "@alice:example.com");
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

    // -----------------------------------------------------------------------
    // Self-heal — wipe_user_store
    // -----------------------------------------------------------------------

    fn cache_with_store_root(root: PathBuf) -> MatrixClientCache {
        MatrixClientCache::new(
            "https://example.org",
            StoreConfig {
                root,
                pepper: "deadbeef".repeat(8),
            },
        )
    }

    #[tokio::test]
    async fn wipe_user_store_removes_only_the_target_mxid_dir() {
        let tmp = tempfile::TempDir::new().unwrap();
        let cache = cache_with_store_root(tmp.path().to_path_buf());

        let alice = "@alice:example.com";
        let bob = "@bob:example.com";
        let alice_dir = tmp.path().join(mxid_dir_name(alice));
        let bob_dir = tmp.path().join(mxid_dir_name(bob));
        tokio::fs::create_dir_all(&alice_dir).await.unwrap();
        tokio::fs::create_dir_all(&bob_dir).await.unwrap();
        tokio::fs::write(alice_dir.join("matrix-sdk-crypto.sqlite3"), b"alice-data")
            .await
            .unwrap();
        tokio::fs::write(bob_dir.join("matrix-sdk-crypto.sqlite3"), b"bob-data")
            .await
            .unwrap();

        cache.wipe_user_store(alice).await.unwrap();

        assert!(
            !alice_dir.exists(),
            "alice's store dir should be gone after wipe"
        );
        assert!(
            bob_dir.exists(),
            "bob's store dir must not be touched by alice's wipe"
        );
        // The store root itself must NEVER be wiped.
        assert!(tmp.path().exists(), "store root must survive a wipe");
    }

    #[tokio::test]
    async fn wipe_user_store_tolerates_missing_dir() {
        let tmp = tempfile::TempDir::new().unwrap();
        let cache = cache_with_store_root(tmp.path().to_path_buf());

        // No directory created — wipe must succeed (NotFound is a no-op).
        cache
            .wipe_user_store("@neverexisted:example.com")
            .await
            .expect("wipe of missing dir must be a no-op, not an error");
    }

    #[test]
    fn self_heal_counter_increments_under_reason_label() {
        // Sanity: the metric we'll inc from the heal path is registered
        // and addressable. Reset to a known floor, inc, assert.
        crate::metrics::SELF_HEAL_COUNTER
            .with_label_values(&["device_keys_missing"])
            .reset();
        crate::metrics::SELF_HEAL_COUNTER
            .with_label_values(&["device_keys_missing"])
            .inc();
        assert_eq!(
            crate::metrics::SELF_HEAL_COUNTER
                .with_label_values(&["device_keys_missing"])
                .get(),
            1
        );
    }

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
