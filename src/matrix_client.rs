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
//! We hash the MXID for the directory name so the filesystem never sees raw
//! user identifiers. This deliberately preserves one stable matrix-sdk store
//! for the Matrix device across token refreshes; see `docs/multi-user.md` for
//! the accepted localpart-reassignment tradeoff.
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
//! `pepper` is a single deployment-wide secret
//! (`MATRIX_MCP_STORE_PEPPER`), held wherever you keep secrets. Per-user
//! passphrases are never stored anywhere — they're derived deterministically
//! from the pepper + MXID at runtime. Pepper rotation is destructive (invalidates every user's store; users will be
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

use std::collections::{HashMap, HashSet};
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

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
    /// Live `/channel` sessions, when the channel mount is enabled.
    ///
    /// Held here because the per-user sync task is the only thing that sees
    /// inbound Matrix traffic, and it has no request context of its own to
    /// discover which sessions belong to the identity it syncs for.
    channel: Option<crate::channel::ChannelRegistry>,
    /// Identities whose store this process has already wiped once.
    ///
    /// Deliberately **not** persisted: it bounds a loop within one process,
    /// and a restart is a fresh chance to heal a genuinely new occurrence
    /// rather than a state to carry forward.
    healed: Arc<RwLock<HashSet<String>>>,
}

impl MatrixClientCache {
    pub fn new(homeserver_url: impl Into<String>, store: StoreConfig) -> Self {
        Self {
            homeserver_url: homeserver_url.into(),
            store,
            inner: Arc::new(RwLock::new(HashMap::new())),
            channel: None,
            healed: Arc::new(RwLock::new(HashSet::new())),
        }
    }

    /// This deployment's Secret Storage passphrase for `mxid`.
    ///
    /// Derived, not configured, so it exists for every account without the
    /// operator listing any. See [`derive_recovery_passphrase`].
    #[must_use]
    pub fn recovery_passphrase(&self, mxid: &str) -> String {
        derive_recovery_passphrase(&self.store.pepper, mxid)
    }

    /// Push inbound room messages to the sessions in `registry`.
    ///
    /// Without this the cache behaves exactly as before: clients still sync,
    /// but nothing is pushed anywhere.
    #[must_use]
    pub fn with_channel(mut self, registry: crate::channel::ChannelRegistry) -> Self {
        self.channel = Some(registry);
        self
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

    /// Take this identity's one heal, returning whether it was still
    /// available.
    ///
    /// A free function on the cache rather than a check at the call site so
    /// the claim and the wipe cannot drift apart: whoever wipes must have
    /// claimed, and claiming twice is what the caller reports on.
    async fn claim_heal(&self, mxid: &str) -> bool {
        let mut guard = self.healed.write().await;
        let first = guard.insert(mxid.to_owned());
        drop(guard);
        first
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
                // **Measured before the heal runs, because the heal destroys
                // the evidence.** Today's state — a device Synapse holds no
                // key for — is the only control that says this predicate can
                // return false at all, and it exists once. A verdict logged
                // here survives the wipe that follows.
                info!(
                    mxid = %identity.mxid,
                    device_id = ?cached.client.device_id(),
                    "device keys absent from the homeserver's /keys/query response"
                );
                if retry {
                    // Second pass, after a wipe, a rebuild **and** a bounded
                    // wait for publication. Reaching here means the ceiling
                    // was hit, so the honest report is that we stopped
                    // asking, not that the keys will never arrive.
                    //
                    // Returning the client rather than erroring, on purpose.
                    // The first version raised here and `verify_status`
                    // started failing where it had previously answered, which
                    // turned an unknown into an outage. `keys_verified` stays
                    // false, so the next call re-checks and a late publish is
                    // picked up without another wipe.
                    warn!(
                        mxid = %identity.mxid,
                        device_id = ?cached.client.device_id(),
                        ceiling_secs = PUBLISH_CEILING.as_secs(),
                        "waited for device keys to publish after the rebuild and gave up at the \
                         ceiling. This says the wait expired, NOT that the keys are unpublished: \
                         the next call will look again"
                    );
                    crate::metrics::SELF_HEAL_COUNTER
                        .with_label_values(&["publish_wait_expired"])
                        .inc();
                    return Ok(cached.client.clone());
                }
                // **At most one heal per identity per process.** A second
                // demand is a report rather than a second wipe: an
                // unexplained recurrence then surfaces as "the heal was
                // needed twice" instead of as a crypto store being wiped in a
                // loop. What set the SDK's `shared` flag on a device Synapse
                // never keyed is unmeasured, so this bound is what makes the
                // fix survivable without that answer.
                if !self.claim_heal(&identity.mxid).await {
                    warn!(
                        mxid = %identity.mxid,
                        device_id = ?cached.client.device_id(),
                        "device keys still unpublished and this identity has already been \
                         healed once in this process; refusing a second wipe. Something \
                         re-creates the split-brain state and wiping again would loop"
                    );
                    crate::metrics::SELF_HEAL_COUNTER
                        .with_label_values(&["refused_second_heal"])
                        .inc();
                    return Ok(cached.client.clone());
                }
                // **Never wipe a store whose contents cannot be restored.**
                // The wipe discards olm and megolm state and is cheap only
                // because key backup restores it. Checked per identity here
                // rather than assumed fleet-wide, because it differs per bot.
                if !key_backup_is_recoverable(&cached.client).await {
                    warn!(
                        mxid = %identity.mxid,
                        device_id = ?cached.client.device_id(),
                        "device keys are unpublished, and there is no recoverable key backup \
                         for this identity; refusing to wipe. Wiping would discard message \
                         history with nothing to restore it from, which is worse than the \
                         unverified state it would clear"
                    );
                    crate::metrics::SELF_HEAL_COUNTER
                        .with_label_values(&["refused_no_key_backup"])
                        .inc();
                    return Ok(cached.client.clone());
                }
                warn!(
                    mxid = %identity.mxid,
                    device_id = ?cached.client.device_id(),
                    "split-brain crypto state detected (the homeserver holds no device keys \
                     for this device); self-healing by wiping per-MXID store",
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
                let rebuilt = Box::pin(self.for_user_inner(identity, access_token, true)).await?;

                // **Wait for the publish rather than assuming it.** The
                // rebuilt client uploads its new device keys from the
                // background sync loop, not from `for_user`, so checking
                // immediately measures nothing: the first version of this
                // re-checked 531 ms after the wipe and reported its own
                // impatience as "device keys still not published after
                // rebuild". The device had in fact published, and a call
                // hours later answered normally.
                //
                // Polling the observable rather than sleeping once: the
                // original fault was a single check at a single moment, and a
                // fixed sleep is that fault with a larger constant.
                let mxid = identity.mxid.clone();
                let waited = wait_for_publish(
                    || verify_device_keys_published(&rebuilt, &mxid),
                    PUBLISH_CEILING,
                    PUBLISH_POLL_INTERVAL,
                )
                .await;
                match waited {
                    PublishWait::Published => {
                        info!(
                            mxid = %identity.mxid,
                            "device keys published after the rebuild; self-heal complete"
                        );
                        crate::metrics::SELF_HEAL_COUNTER
                            .with_label_values(&["published_after_rebuild"])
                            .inc();
                    }
                    PublishWait::Expired => {
                        warn!(
                            mxid = %identity.mxid,
                            ceiling_secs = PUBLISH_CEILING.as_secs(),
                            "stopped waiting for device keys to publish after the rebuild. The \
                             wait expired; this is not a statement that they are unpublished, \
                             and the next call will look again"
                        );
                        crate::metrics::SELF_HEAL_COUNTER
                            .with_label_values(&["publish_wait_expired"])
                            .inc();
                    }
                    PublishWait::CheckFailed => {
                        warn!(
                            mxid = %identity.mxid,
                            "the publication check failed while waiting after the rebuild; \
                             leaving keys_verified false so the next call re-checks"
                        );
                    }
                }
                Ok(rebuilt)
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

        // Import the cross-signing identity for accounts this deployment set
        // up itself. Same call `/setup` makes; only the source of the secret
        // differs. Best-effort — a failure costs E2EE, not the session.
        {
            let passphrase = derive_recovery_passphrase(&self.store.pepper, &identity.mxid);
            match client.encryption().recovery().recover(&passphrase).await {
                Ok(()) => {
                    info!(
                        mxid = %identity.mxid,
                        "imported cross-signing identity from the configured recovery key"
                    );
                    // Refresh the cached identity so `verify_status` reflects
                    // the signature that was just uploaded.
                    if let Some(me) = client.user_id() {
                        let _ = client.encryption().request_user_identity(me).await;
                    }
                }
                // Expected whenever this deployment did not create the
                // identity — a human's Secret Storage is locked with their own
                // key, not ours, and `/setup` is the route for those. Nothing
                // is changed by the failure, so it is not a warning.
                Err(e) => debug!(
                    mxid = %identity.mxid,
                    error = %e,
                    "no deployment-owned Secret Storage to import for this account"
                ),
            }
        }

        // Turn inbound room messages into channel events. Registered before
        // the sync task starts so the first sync response is already covered;
        // matrix-sdk dispatches to handlers from the sync loop, so this is
        // inert until that task runs.
        if let Some(registry) = self.channel.clone() {
            crate::channel::install_event_handler(&client, identity.mxid.clone(), registry);
        }

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

/// How long a rebuilt client is given to publish its device keys.
///
/// **Chosen, not derived, and the distinction matters.** The two numbers I
/// have bound it from opposite sides and neither is the publish latency: 531
/// ms is known too short, because that is what the first version waited and it
/// reported a failure that later turned out to have published; and a healthy
/// client on this deployment took 1.19 s from build to first tool call with no
/// key publication in that path at all. The actual latency has not been
/// measured, because measuring it means wiping a live store.
///
/// So this is a ceiling picked to be comfortably past a homeserver round trip
/// on a healthy link, not a value read off anything. If it is ever hit, the
/// log says the **wait** expired rather than that keys are unpublished, and
/// the number is then the thing to revisit.
const PUBLISH_CEILING: Duration = Duration::from_secs(20);

/// How often the wait re-asks.
///
/// The fault being fixed was a single check at a single moment, so this polls
/// the observable rather than sleeping once and looking again. A sleep of any
/// length is the same fault with a larger constant.
const PUBLISH_POLL_INTERVAL: Duration = Duration::from_millis(500);

/// What a bounded wait for publication concluded.
///
/// **`Expired` is deliberately not `NotPublished`.** At the ceiling we know
/// only that we stopped asking, which is a different claim from the
/// homeserver not having the keys, and conflating the two is the confusion
/// that cost this repair an evening: a *never* read as a slow *not yet*, and
/// then a slow *not yet* reported as a *never*.
#[derive(Debug, PartialEq, Eq)]
enum PublishWait {
    /// The homeserver announced the device within the ceiling.
    Published,
    /// The ceiling was reached with the device still unannounced. **Says
    /// nothing about whether it ever will be.**
    Expired,
    /// The check itself failed. Neither a yes nor a no.
    CheckFailed,
}

/// Poll `check` until it answers true, the ceiling is reached, or it errors.
///
/// A free function over a closure so the loop is testable without a
/// homeserver: the parent needs a live `Client`, and the thing worth pinning
/// is that a late yes is still a yes and that running out of patience is
/// reported as its own outcome.
async fn wait_for_publish<F, Fut>(
    mut check: F,
    ceiling: Duration,
    interval: Duration,
) -> PublishWait
where
    F: FnMut() -> Fut,
    Fut: std::future::Future<Output = Result<bool>>,
{
    let started = Instant::now();
    loop {
        match check().await {
            Ok(true) => return PublishWait::Published,
            Ok(false) => {}
            Err(e) => {
                warn!(error = ?e, "device-key publication check failed while waiting");
                return PublishWait::CheckFailed;
            }
        }
        // Checked after the attempt, so the ceiling bounds the waiting rather
        // than the number of attempts: a check is always made at least once.
        if started.elapsed() >= ceiling {
            return PublishWait::Expired;
        }
        tokio::time::sleep(interval).await;
    }
}

/// Whether **Synapse** holds device keys for this client's device.
///
/// **This function's own doc comment used to state the mechanism wrongly, and
/// that is why the predicate looked correct.** It said
/// `Client::encryption().get_user_devices` consults the local crypto store
/// "but also issues `/keys/query` to the homeserver for any user with a
/// pending key-query". It does not: the call is `OlmMachine::get_user_devices`,
/// which is `self.store().get_user_devices(...)`, and `wait_if_user_pending`
/// only waits for a query already in flight rather than starting one.
///
/// Outcomes: `Ok(true)` the homeserver announces this device; `Ok(false)` it
/// does not, and the caller should heal; `Err` a network or olm-machine
/// failure, propagated so the caller leaves `keys_verified` false and retries
/// rather than failing closed.
///
/// **The first version of this asked the local store and could not fail.** It
/// was `get_user_devices(own_user).get(own_device_id).is_some()`, and
/// `Encryption::get_user_devices` reads `OlmMachine::get_user_devices`, which
/// is `self.store().get_user_devices(...)` with no homeserver round trip. The
/// SDK's own note on that function says *"This method will include our own
/// device which is always present in the store"*, and the memory store asserts
/// it: `.expect("Invalid state: Should always have a own device")`.
///
/// So the predicate was invariantly `true` for the case it existed to detect:
/// it returned `Ok(true)` for a device Synapse has never held a key for, the
/// verified flag latched, and the heal below never ran. **Its negative branch
/// was unreachable**, which is why nothing exercised the machinery it guards
/// and why no unit test could have caught it — the fault needs a live
/// homeserver disagreeing with a live store.
///
/// Forcing the `/keys/query` first is the shape `secret_store.rs` already uses
/// after uploading a signature, for the same reason: the store answers what we
/// believe, and only a query answers what the server has.
async fn verify_device_keys_published(client: &Client, mxid: &str) -> Result<bool> {
    let user_id = UserId::parse(mxid).with_context(|| format!("parse mxid: {mxid}"))?;
    let Some(device_id) = client.device_id() else {
        return Err(anyhow!(
            "client has no device_id; cannot verify device_keys for {mxid}"
        ));
    };
    // Ask the homeserver and read **its** answer. The store is not consulted
    // at all: it holds our own device unconditionally, so any path through it
    // returns true regardless of what Synapse has.
    let mut request = matrix_sdk::ruma::api::client::keys::get_keys::v3::Request::new();
    request.device_keys.insert(user_id.clone(), Vec::new());
    let response = client
        .send(request)
        .await
        .with_context(|| format!("keys_query({mxid})"))?;

    Ok(device_in_keys_response(&response, &user_id, device_id))
}

/// Whether a `/keys/query` response announces this device.
///
/// Split from the request because the request needs a live `Client` and this
/// is the judgement: **absence from the response is the negative.** The old
/// predicate had no reachable negative at all, so the one thing worth pinning
/// is that a homeserver saying nothing about the user, or nothing about the
/// device, reads as *not published* rather than as *no information*.
fn device_in_keys_response(
    response: &matrix_sdk::ruma::api::client::keys::get_keys::v3::Response,
    user_id: &matrix_sdk::ruma::UserId,
    device_id: &matrix_sdk::ruma::DeviceId,
) -> bool {
    response
        .device_keys
        .get(user_id)
        .is_some_and(|devices| devices.contains_key(device_id))
}

/// Whether this identity has a recoverable key backup on the server.
///
/// **Refusing the heal without one is a hard precondition.** Wiping the
/// per-MXID store discards olm and megolm state, which is cheap to lose only
/// because key backup restores it — the figure on this PR is ~12 s for 924
/// keys across 31 rooms. With no backup there is nothing to restore from, and
/// **a heal that destroys history to clear a shield is worse than the shield**.
///
/// Checked per identity immediately before wiping rather than assumed
/// fleet-wide: it differs per bot, and at least one account on this
/// deployment has no cross-signing keys at all.
async fn key_backup_is_recoverable(client: &Client) -> bool {
    match client.encryption().backups().exists_on_server().await {
        Ok(exists) => exists,
        Err(e) => {
            warn!(error = %e, "could not determine whether a key backup exists; refusing to wipe");
            false
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
/// Per-account Secret Storage passphrase, derived rather than configured.
///
/// ## Why derived
///
/// `/setup` is a browser flow: sign in at MAS, paste the recovery key Element
/// produced. An account with no human can never do that, so a bot's
/// cross-signing identity would live only in this deployment's store — lose
/// the volume and it is stranded, because the homeserver still holds a master
/// key and `bootstrap_cross_signing` rightly refuses to mint a second.
///
/// An operator-maintained list of per-account passphrases would fix that, and
/// was the first attempt. It is the wrong shape: this server accepts any
/// active token, so anyone can connect any number of accounts, and a feature
/// that needs the operator to add a line before each one works is not really
/// available to them. Deriving it from the pepper — exactly as
/// [`derive_store_passphrase`] already does for the store cipher — makes it
/// automatic for every account, with nothing to configure and no new secret.
///
/// ## Why this grants nobody anything new
///
/// The pepper already decrypts every per-user store, and those stores hold the
/// same cross-signing private keys this passphrase protects. Anyone who has
/// the pepper could already read them. Rotating the pepper is already
/// documented as destructive to the stores; it is equally destructive here.
///
/// ## Why it never touches a human's identity
///
/// It is only ever *written* by `bootstrap_cross_signing`, which refuses to
/// run on an account that already has a cross-signing identity. Reading is a
/// `recover()` attempt that simply fails when this deployment did not set the
/// Secret Storage up, which is the case for every human user — their storage
/// is locked with their own key and is left untouched.
fn derive_recovery_passphrase(pepper: &str, mxid: &str) -> String {
    let hkdf = Hkdf::<Sha256>::new(Some(mxid.as_bytes()), pepper.as_bytes());
    let mut okm = [0u8; 32];
    #[allow(clippy::expect_used)]
    hkdf.expand(b"matrix-mcp-recovery v1", &mut okm)
        .expect("HKDF expand 32 bytes always succeeds");
    hex::encode(okm)
}

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
    #[tokio::test]
    async fn a_late_publish_is_still_a_publish() {
        // The whole defect in one test. The first version checked once, 531 ms
        // after the wipe, and reported "device keys still not published after
        // rebuild" for a device that had in fact published: a call hours later
        // answered normally. A yes that arrives on the third look is a yes.
        let attempts = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let a = attempts.clone();
        let out = wait_for_publish(
            || {
                let n = a.fetch_add(1, Ordering::Relaxed);
                async move { Ok(n >= 2) }
            },
            Duration::from_secs(5),
            Duration::from_millis(1),
        )
        .await;
        assert_eq!(out, PublishWait::Published);
        assert_eq!(
            attempts.load(Ordering::Relaxed),
            3,
            "it stopped asking before the answer changed"
        );
    }

    #[tokio::test]
    async fn running_out_of_patience_is_its_own_outcome() {
        // `Expired` is deliberately not `NotPublished`. At the ceiling we know
        // only that we stopped asking, and reporting that as "the keys are not
        // published" is the confusion that cost this repair an evening.
        let out = wait_for_publish(
            || async { Ok(false) },
            Duration::from_millis(20),
            Duration::from_millis(1),
        )
        .await;
        assert_eq!(out, PublishWait::Expired);
        assert_ne!(out, PublishWait::Published);
    }

    #[tokio::test]
    async fn the_observable_is_checked_at_least_once_even_at_a_zero_ceiling() {
        // The ceiling bounds the waiting, not the number of attempts. A zero
        // ceiling must still ask once, or a fast publish would be reported as
        // expired without anybody having looked.
        let attempts = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let a = attempts.clone();
        let out = wait_for_publish(
            || {
                a.fetch_add(1, Ordering::Relaxed);
                async { Ok(true) }
            },
            Duration::ZERO,
            Duration::from_millis(1),
        )
        .await;
        assert_eq!(out, PublishWait::Published);
        assert_eq!(attempts.load(Ordering::Relaxed), 1);
    }

    #[tokio::test]
    async fn a_failing_check_is_neither_a_yes_nor_a_no() {
        // A network failure during the wait must not be counted as "not
        // published", which would send a healthy device round the heal again.
        let out = wait_for_publish(
            || async { Err(anyhow!("network")) },
            Duration::from_secs(5),
            Duration::from_millis(1),
        )
        .await;
        assert_eq!(out, PublishWait::CheckFailed);
    }

    #[test]
    fn a_keys_query_that_omits_the_device_reads_as_not_published() {
        use matrix_sdk::ruma::api::client::keys::get_keys::v3::Response;
        use matrix_sdk::ruma::{device_id, user_id};

        let me = user_id!("@a:example.org");
        let mine = device_id!("MATRIXMCP-TEST1234");

        // The live state this exists for: Synapse holds no device keys, so
        // the user does not appear in the response at all.
        let empty = Response::new();
        assert!(
            !device_in_keys_response(&empty, me, mine),
            "an empty response read as published"
        );

        // Present user, other devices, ours absent. Distinct from the case
        // above because a homeserver that knows the user but not the device
        // is the state after a device is created and never uploads.
        let mut other_device = Response::new();
        other_device
            .device_keys
            .entry(me.to_owned())
            .or_default()
            .insert(
                device_id!("SOMEOTHERDEVICE").to_owned(),
                serde_json::from_str("{}").unwrap(),
            );
        assert!(
            !device_in_keys_response(&other_device, me, mine),
            "a response listing only another device read as published"
        );

        // The control, or every assertion above passes against a predicate
        // that is invariantly false — which is the mirror of the bug being
        // fixed, where it was invariantly true.
        let mut published = Response::new();
        published
            .device_keys
            .entry(me.to_owned())
            .or_default()
            .insert(mine.to_owned(), serde_json::from_str("{}").unwrap());
        assert!(
            device_in_keys_response(&published, me, mine),
            "a response announcing our device read as not published"
        );
    }

    #[tokio::test]
    async fn an_identity_gets_exactly_one_heal_per_process() {
        // The bound that makes this fix survivable without knowing what set
        // the SDK's `shared` flag. A heal firing on every rebuild would wipe
        // a crypto store in a loop; the second demand has to be a report.
        let dir = tempfile::tempdir().unwrap();
        let cache = cache_with_store_root(dir.path().to_path_buf());

        assert!(
            cache.claim_heal("@a:example.org").await,
            "first heal refused"
        );
        assert!(
            !cache.claim_heal("@a:example.org").await,
            "a second wipe was allowed for the same identity"
        );
        // The bound is per identity, not global: one bot looping must not
        // deny another its single repair.
        assert!(
            cache.claim_heal("@b:example.org").await,
            "another identity was denied because the first had healed"
        );
    }

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

    #[test]
    fn recovery_and_store_passphrases_are_different_secrets() {
        // Same pepper, same account, different HKDF info strings. If these
        // ever collided, the Secret Storage passphrase would be the store
        // cipher key, and one leak would be two.
        let store = derive_store_passphrase("pepper", "@a:example.com");
        let recovery = derive_recovery_passphrase("pepper", "@a:example.com");
        assert_ne!(store, recovery);
        assert_eq!(recovery.len(), 64, "32 bytes hex-encoded");
    }

    #[test]
    fn recovery_passphrase_is_per_account_and_stable() {
        // Stable, so a redeployment recovers what an earlier one created;
        // per-account, so one account's secret is not another's.
        let a1 = derive_recovery_passphrase("pepper", "@a:example.com");
        let a2 = derive_recovery_passphrase("pepper", "@a:example.com");
        let b = derive_recovery_passphrase("pepper", "@b:example.com");
        assert_eq!(a1, a2);
        assert_ne!(a1, b);
        // And it follows the pepper, which is why pepper rotation is
        // documented as destructive.
        assert_ne!(
            a1,
            derive_recovery_passphrase("other-pepper", "@a:example.com")
        );
    }
}
