//! Browser-based setup flow for importing Matrix Secret Storage
//! cross-signing keys.
//!
//! Rationale: when matrix-mcp's OAuth token isn't device-bound or
//! cross-signing isn't set up for the matrix-mcp device, the user
//! needs to provide their Matrix Secret Storage recovery key once.
//! Asking for it through claude.ai's chat would leave it in the
//! user's chat history forever. This flow takes it via a one-off
//! HTTPS form instead.
//!
//! ## Flow
//!
//! ```text
//!  GET /setup
//!      ↓
//!  GET /setup/login           — generate state + PKCE verifier
//!      ↓
//!  302 to MAS /authorize       — authorization_code grant with PKCE
//!      ↓
//!  (MAS auto-approves; user already signed in at id.example.com)
//!      ↓
//!  GET /setup/callback?code=…&state=…
//!      ↓
//!  exchange code → token; introspect → stable MAS subject + mxid
//!      ↓
//!  store (MAS subject, mxid, device id, token) in setup_sessions, set session_id cookie
//!      ↓
//!  302 /setup/form             — password-type input
//!      ↓
//!  POST /setup/recover         — calls recovery().recover(&key)
//!      ↓
//!  success page
//! ```
//!
//! ## State
//!
//! Two in-memory maps with TTLs. Nothing persists.
//!
//! - **PKCE state** (`pkce_states`): `state_token → code_verifier`.
//!   5-minute TTL. Used to bind a callback back to the originating
//!   authorize request and to PKCE-verify it.
//! - **Setup session** (`sessions`): `session_id → (MAS subject, mxid,
//!   device id, access_token, csrf_token, created_at)`. 30-minute TTL.
//!   Held only long enough to render the form and process one POST. The
//!   `session_id` is a random 48-char value carried in a
//!   `__Secure-`-prefixed cookie scoped to `Path=/setup`.
//!
//! ## Why we don't reuse the MCP introspection cache
//!
//! The matrix-sdk `Client` expects the bearer token presented for
//! introspection to be a "Matrix-side" token. The token issued by
//! the /setup OAuth dance is the same shape (it's the same MAS), but
//! we keep the setup session and the MCP request entirely separate
//! so a logged-in /setup browser tab can't be replayed against /mcp
//! and vice-versa.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::{Context, Result, anyhow};
use axum::Form;
use axum::extract::{Query, State};
use axum::http::StatusCode;
use axum::response::{Html, IntoResponse, Redirect, Response};
use axum_extra::extract::CookieJar;
use axum_extra::extract::cookie::{Cookie, SameSite};
use base64::Engine;
use rand::distributions::Alphanumeric;
use rand::{Rng, thread_rng};
use serde::Deserialize;
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use tokio::sync::RwLock;
use tokio::time::timeout;
use tracing::{Instrument as _, debug, info_span, warn};

use crate::audit::{self, SetupExtras, outcome};
use crate::config::Config;
use crate::mas::MasIntrospectionClient;
use crate::matrix_client::MatrixClientCache;

/// Name of the setup-session cookie.
///
/// We use `__Secure-` (not `__Host-`) so we can restrict the path to
/// `/setup`. The `__Host-` prefix would also work here but browser spec
/// requires `Path=/` on `__Host-` cookies — setting `Path=/setup` would
/// cause the browser to silently reject the cookie entirely. `__Secure-`
/// gives us Secure-only without the path restriction, and we don't set a
/// Domain attribute, so the scope remains tight.
const SESSION_COOKIE: &str = "__Secure-matrix_mcp_setup";
#[allow(clippy::duration_suboptimal_units)] // clippy suggests from_mins; unstable on 1.93.
const PKCE_TTL: Duration = Duration::from_secs(300);
/// Maximum number of OAuth PKCE states retained at once. The /setup/login
/// endpoint is intentionally public, so this hard cap bounds memory usage and
/// keeps pruning work constant-time with respect to attacker traffic.
const PKCE_MAX_PENDING: usize = 256;
#[allow(clippy::duration_suboptimal_units)]
const SESSION_TTL: Duration = Duration::from_secs(1800);
/// Maximum number of setup sessions retained at once. Sessions are created on
/// the OAuth callback (after a successful MAS authentication), so this cap is
/// reachable only by authenticated users; 64 is ample for any real workload.
const SESSIONS_MAX_PENDING: usize = 64;
/// Maximum number of encrypted rooms for which key-backup downloads are
/// attempted after a successful recovery. Caps background network + store work
/// for users with a very large room list.
const KEY_BACKUP_MAX_ROOMS: usize = 200;
/// Per-room timeout for key-backup download so a single slow room cannot stall
/// the whole backfill task.
#[allow(clippy::duration_suboptimal_units)] // from_secs(15) is clearer than from_mins here
const KEY_BACKUP_ROOM_TIMEOUT: Duration = Duration::from_secs(15);

/// Shared state for the /setup handlers. Cheap to clone — Arc inside.
#[derive(Clone)]
pub struct SetupState {
    pub config: Config,
    pub mas: MasIntrospectionClient,
    pub clients: MatrixClientCache,
    pub pkce_states: Arc<RwLock<HashMap<String, PendingPkce>>>,
    pub sessions: Arc<RwLock<HashMap<String, SetupSession>>>,
    /// Shared key-backup-pull gate. Threaded through here so two
    /// concurrent `/setup/recover` invocations can't double-pull the
    /// same room and a global concurrency limit applies across both
    /// /setup and the MCP `request_room_keys` tool.
    pub key_backup_gate: crate::key_backup_gate::KeyBackupGate,
}

#[derive(Clone)]
pub struct PendingPkce {
    pub verifier: String,
    pub created_at: Instant,
}

#[derive(Clone)]
pub struct SetupSession {
    /// Stable MAS subject from the introspection. No longer used by
    /// /setup/recover (which uses the cached client directly via
    /// `MatrixClientCache::get_if_cached`), but kept on the session
    /// for audit/logging context and forward compatibility.
    #[allow(dead_code)]
    pub mas_subject: String,
    pub mxid: String,
    // Kept in the session for audit/logging context; /setup/recover
    // fills the AuthenticatedIdentity's device_id from `config.device_id`
    // (the per-PVC value from `<store_root>/.device-id`) so the
    // recovery imports land in the same matrix-sdk store claude.ai's
    // MCP tool calls use.
    #[allow(dead_code)]
    pub device_id: Option<String>,
    /// `/setup`'s own (unbound) OAuth access token. Stored on the
    /// session at callback time but no longer routed into the cached
    /// matrix-sdk client — see the comment in `recover` for why. Kept
    /// here so the session shape stays compatible with rolling
    /// deploys and so a future flow that needs a `/setup`-scoped
    /// token (e.g. unbound MAS calls) doesn't have to reintroduce the
    /// field.
    #[allow(dead_code)]
    pub access_token: String,
    pub created_at: Instant,
    /// 32-char random alphanumeric CSRF token, bound to this session.
    /// Generated at callback time, injected into the form as a hidden
    /// input, and verified in constant time before processing the POST.
    pub csrf_token: String,
}

impl SetupState {
    pub fn new(
        config: Config,
        mas: MasIntrospectionClient,
        clients: MatrixClientCache,
        key_backup_gate: crate::key_backup_gate::KeyBackupGate,
    ) -> Self {
        Self {
            config,
            mas,
            clients,
            pkce_states: Arc::new(RwLock::new(HashMap::new())),
            sessions: Arc::new(RwLock::new(HashMap::new())),
            key_backup_gate,
        }
    }
}

// ---------- handlers ----------

#[allow(clippy::unused_async)]
pub async fn index() -> impl IntoResponse {
    Html(LANDING_HTML)
}

pub async fn login(State(state): State<SetupState>) -> Response {
    let span = info_span!(
        "setup.step",
        step = "login",
        outcome = tracing::field::Empty
    );
    // Check config before allocating any PKCE state so misconfigured
    // deployments don't leak entries into the bounded map.
    let Some(creds) = state.config.introspection.as_ref() else {
        return error_page(
            StatusCode::INTERNAL_SERVER_ERROR,
            "matrix-mcp has no introspection credentials configured; /setup is unavailable.",
        );
    };

    let verifier = random_alnum(64);
    let challenge_bytes = Sha256::digest(verifier.as_bytes());
    let challenge = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(challenge_bytes);
    let state_token = random_alnum(32);

    {
        let mut guard = state.pkce_states.write().await;
        if !insert_pending_pkce(
            &mut guard,
            state_token.clone(),
            PendingPkce {
                verifier,
                created_at: Instant::now(),
            },
        ) {
            warn!(
                pending_pkce = guard.len(),
                max_pending_pkce = PKCE_MAX_PENDING,
                "rejecting setup login because pending PKCE state map is full"
            );
            return error_page(
                StatusCode::TOO_MANY_REQUESTS,
                "Too many setup sign-in attempts are pending. Wait a few minutes and try again.",
            );
        }
    }

    let redirect_uri = format!("{}/setup/callback", state.config.resource_url);
    // MAS quirk: every OAuth endpoint is under `/oauth2/*` EXCEPT
    // `/authorize`, which sits at the issuer root. Confirmed against
    // the live discovery document — authorization_endpoint is the
    // odd one out. TODO(setup): fetch
    // /.well-known/openid-configuration once at startup and cache
    // the endpoint URLs from `authorization_endpoint` /
    // `token_endpoint` so a future MAS path tweak doesn't 404 us
    // again.
    // MUST request the device scope alongside the Matrix C-S API scope.
    // Per MSC3861, every MAS access token is bound to exactly one Matrix
    // device, decided at /authorize time via the
    // `urn:matrix:org.matrix.msc2967.client:device:<id>` scope. Without it,
    // /setup intentionally does NOT request a device scope. claude.ai's
    // MCP connector is the device-binding session: it requests
    // `urn:matrix:org.matrix.msc2967.client:device:MATRIXMCPCONNECTOR`,
    // its tool calls register the device's ed25519 keys with Synapse, and
    // /setup re-uses claude.ai's already-built matrix-sdk client (keyed by
    // mxid in `MatrixClientCache`). The recovery key import in `recover()`
    // therefore signs the device that claude.ai's session put on file —
    // which is the device claude.ai's `verify_status` checks.
    //
    // If /setup *also* requested `device:MATRIXMCPCONNECTOR`, MAS would
    // issue a second OAuth session bound to the same Matrix device, and
    // the two sessions' /keys/upload calls would fight over Synapse's
    // device record (whoever uploads last wins; recover()'s signature
    // ends up referencing whichever ed25519 was current at signing time,
    // which may not be the one Synapse keeps).
    //
    // Pre-condition for /setup to succeed: claude.ai's connector must
    // already have completed its OAuth + first tool call (so the
    // matrix-sdk client is cached). /setup will surface a clear error
    // otherwise.
    let authorize_url = format!(
        "{auth}/authorize?response_type=code&client_id={client_id}&redirect_uri={redirect_uri}\
         &code_challenge={challenge}&code_challenge_method=S256&state={state_tok}\
         &scope=openid+urn%3Amatrix%3Aorg.matrix.msc2967.client%3Aapi%3A%2A",
        auth = state.config.authorization_server,
        client_id = url_encode(&creds.client_id),
        redirect_uri = url_encode(&redirect_uri),
        challenge = url_encode(&challenge),
        state_tok = url_encode(&state_token),
    );

    span.record("outcome", "ok");
    Redirect::temporary(&authorize_url).into_response()
}

#[derive(Deserialize)]
pub struct CallbackParams {
    pub code: Option<String>,
    pub state: Option<String>,
    pub error: Option<String>,
    pub error_description: Option<String>,
}

pub async fn callback(
    State(state): State<SetupState>,
    Query(params): Query<CallbackParams>,
    jar: CookieJar,
) -> Response {
    let span = info_span!(
        "setup.step",
        step = "callback",
        mxid = tracing::field::Empty,
        outcome = tracing::field::Empty
    );
    if let Some(err) = &params.error {
        let desc = params.error_description.as_deref().unwrap_or("");
        return error_page(
            StatusCode::BAD_REQUEST,
            &format!("MAS returned an OAuth error: {err} — {desc}"),
        );
    }
    let Some(code) = params.code else {
        return error_page(StatusCode::BAD_REQUEST, "Missing `code` in callback.");
    };
    let Some(state_token) = params.state else {
        return error_page(StatusCode::BAD_REQUEST, "Missing `state` in callback.");
    };

    let pkce = {
        let mut guard = state.pkce_states.write().await;
        prune_expired_pkce(&mut guard);
        guard.remove(&state_token)
    };
    let Some(pkce) = pkce else {
        return error_page(
            StatusCode::BAD_REQUEST,
            "Unknown or expired state — start over from /setup.",
        );
    };

    match exchange_and_introspect(&state, &code, &pkce.verifier).await {
        Ok((identity, access_token)) => {
            let mxid = identity.mxid.clone();
            let session_id = random_alnum(48);
            let csrf_token = random_alnum(32);
            {
                let mut guard = state.sessions.write().await;
                if !insert_pending_session(
                    &mut guard,
                    session_id.clone(),
                    SetupSession {
                        mas_subject: identity.mas_subject,
                        mxid: mxid.clone(),
                        device_id: identity.device_id,
                        access_token,
                        created_at: Instant::now(),
                        csrf_token: csrf_token.clone(),
                    },
                ) {
                    warn!(
                        pending_sessions = guard.len(),
                        max_pending_sessions = SESSIONS_MAX_PENDING,
                        "rejecting setup callback because session map is full"
                    );
                    return error_page(
                        StatusCode::TOO_MANY_REQUESTS,
                        "Too many active setup sessions. Wait 30 minutes and try again.",
                    );
                }
            }
            let cookie = build_session_cookie(&session_id);
            debug!(mxid = %mxid, "setup session created");
            span.record("mxid", mxid.as_str());
            span.record("outcome", "ok");
            audit::setup_event(
                "setup_callback",
                Some(&mxid),
                outcome::OK,
                SetupExtras::default(),
            );
            (jar.add(cookie), Redirect::to("/setup/form")).into_response()
        }
        Err(e) => {
            warn!(error = %e, "setup token exchange failed");
            span.record("outcome", "error");
            audit::setup_event(
                "setup_callback",
                None,
                outcome::ERROR,
                SetupExtras {
                    error_class: Some("token_exchange"),
                    ..SetupExtras::default()
                },
            );
            error_page(
                StatusCode::INTERNAL_SERVER_ERROR,
                &format!("Failed to complete sign-in: {e:#}"),
            )
        }
    }
}

pub async fn form(State(state): State<SetupState>, jar: CookieJar) -> Response {
    let Some(session) = current_session(&state, &jar).await else {
        return Redirect::to("/setup").into_response();
    };
    Html(form_html(&session.mxid, &session.csrf_token)).into_response()
}

#[derive(Deserialize)]
pub struct RecoverForm {
    pub recovery_key: String,
    /// CSRF token injected into the form as a hidden input by `form()`.
    pub csrf_token: String,
}

// 100+ lines because the recover handler is intrinsically multi-step
// (auth → key import → audit → spawn back-fill task → cookie invalidate
// → success page). Splitting just to satisfy clippy would make the
// flow harder to follow. The handler stays inline.
#[allow(clippy::too_many_lines)]
pub async fn recover(
    State(state): State<SetupState>,
    jar: CookieJar,
    Form(form): Form<RecoverForm>,
) -> Response {
    let Some(session) = current_session(&state, &jar).await else {
        return Redirect::to("/setup").into_response();
    };

    let span = info_span!(
        "setup.step",
        step = "recover",
        mxid = %session.mxid,
        outcome = tracing::field::Empty,
    );

    // CSRF check: compare the submitted token against the session-bound
    // token in constant time to avoid timing side-channels.
    let token_matches = session
        .csrf_token
        .as_bytes()
        .ct_eq(form.csrf_token.as_bytes())
        .unwrap_u8()
        == 1;
    if !token_matches {
        warn!(mxid = %session.mxid, "setup_recover: CSRF token mismatch");
        span.record("outcome", "denied");
        audit::setup_event(
            "setup_recover",
            Some(&session.mxid),
            outcome::DENIED,
            SetupExtras {
                error_class: Some("csrf"),
                ..SetupExtras::default()
            },
        );
        return error_page(
            StatusCode::FORBIDDEN,
            "Invalid or missing CSRF token. Please go back and try again.",
        );
    }

    let key = form.recovery_key.trim().to_owned();
    if key.is_empty() {
        span.record("outcome", "error");
        return error_page(
            StatusCode::BAD_REQUEST,
            "Recovery key was empty. Paste it from your password manager and try again.",
        );
    }

    // Pre-condition: claude.ai's MCP connector must have already built
    // the matrix-sdk client for this user via a real tool call (e.g.
    // list_joined_rooms). /setup itself does an OAuth flow without a
    // `device:...` scope, so its access token is unbound; if /setup
    // built the matrix-sdk client first, the SDK would attempt
    // /keys/upload with that unbound token, Synapse would reject the
    // call with 400 "must pass device_id when authenticating", and
    // recover()'s self-signature would reference ed25519 keys that
    // never landed on the homeserver — producing a cryptographically
    // valid local signature attached to a device that doesn't exist
    // server-side. The trap is invisible (the /setup UI says
    // "Unlocked", `verify_status` reports cross_signed=false, and the
    // signature appears on Synapse pointing at the wrong device pubkey).
    //
    // We avoid the trap by refusing /setup outright unless the
    // per-mxid SDK cache already has an entry. If absent, the user is
    // told to run a Matrix tool from claude.ai first. This is the
    // single safety net that makes /setup's design invariant
    // ("piggyback on claude.ai's client") explicit and enforced.
    if !state.clients.contains(&session.mxid).await {
        span.record("outcome", "precondition");
        return error_page(
            StatusCode::PRECONDITION_REQUIRED,
            "matrix-mcp's Matrix client isn't built yet for your account. \
             In claude.ai, run any matrix-mcp tool — e.g. ask Claude to use \
             `list_joined_rooms` — then return here to /setup and try again. \
             (Why: /setup imports your cross-signing keys into the same SDK \
             instance claude.ai's connector uses. If claude.ai hasn't \
             triggered the client to be built yet, /setup has nothing to \
             attach the keys to. \
             \
             Most likely cause: claude.ai's connector is holding a revoked \
             bearer (typical after signing out the matrix-mcp device in \
             Element) and is silently failing every tool call. Go to \
             claude.ai → Settings → Connectors → remove and re-add \
             \"claude.ai Matrix\", then re-run a tool, then come back here.)",
        );
    }

    // Cache HIT is guaranteed by the `contains()` check above. We must
    // not route through `for_user(&identity, &session.access_token)`:
    // `/setup`'s OAuth access token is different from claude.ai's
    // bearer (a separate OAuth grant against MAS), and `for_user`'s
    // fast path would call `refresh_token_if_needed` → `restore_session`
    // to swap it onto the cached client. In matrix-sdk 0.17 that
    // panics with `AlreadyInitializedError` because the client's auth
    // slot is already set from claude.ai's tool call, taking the pod
    // down (verified 2026-05-18 during device-binding recovery).
    //
    // `get_if_cached` returns the cached client untouched. The client
    // is already authenticated with claude.ai's device-bound bearer;
    // `encryption().recovery().recover()` calls below run against
    // Synapse using that bearer, not the unbound `/setup` token —
    // which is exactly what we want, because the recovery operation
    // needs a device-scoped session.
    // Defensive: precondition was checked above; the `else` branch is
    // unreachable unless the cache was evicted in the gap between
    // `contains()` and this call (e.g. Synapse returned
    // `M_UNKNOWN_TOKEN` to a concurrent tool call in that window and
    // triggered eviction).
    let Some(client) = state.clients.get_if_cached(&session.mxid).await else {
        return error_page(
            StatusCode::PRECONDITION_REQUIRED,
            "matrix-mcp's Matrix client was evicted between the \
             precondition check and this call. Run any matrix-mcp \
             tool in claude.ai and try /setup again.",
        );
    };

    match client.encryption().recovery().recover(&key).await {
        Ok(()) => {
            span.record("outcome", "ok");
            audit::setup_event(
                "setup_recover",
                Some(&session.mxid),
                outcome::OK,
                SetupExtras::default(),
            );
            // matrix-sdk's `recovery().recover()` already signs this
            // device via `/keys/signatures/upload` as part of its
            // import flow — see the SDK log line "Successfully signed
            // our own device, the device is now verified". An earlier
            // version of this code also called
            // `bootstrap_cross_signing(None)` here, but that uploads
            // *new* cross-signing public keys via the UIAA-protected
            // `/keys/device_signing/upload` endpoint, which 401s when
            // private keys are already imported. The redundant call
            // was harmless (recover already signed) but noisy. Removed.
            //
            // Force a /keys/query so the local user-identity cache
            // reflects the freshly-uploaded signature for the next
            // verify_status call.
            if let Some(me) = client.user_id() {
                let _ = client.encryption().request_user_identity(me).await;
            }

            // Pull historical megolm sessions from server-side key
            // backup so /messages on E2EE rooms can decrypt history.
            // matrix-sdk does NOT auto-fetch from backup; we have to
            // ask per room. Done in a spawned task so the user gets
            // the success page immediately — back-fill happens in the
            // background.
            //
            // Bounded to KEY_BACKUP_MAX_ROOMS rooms with a per-room
            // timeout of KEY_BACKUP_ROOM_TIMEOUT to cap background
            // network and store work even for users with a very large
            // room list.
            let mxid_for_log = session.mxid.clone();
            let client_for_download = client.clone();
            let key_backup_gate = state.key_backup_gate.clone();
            let download_span = info_span!(
                "setup.step",
                step = "key_backup_download",
                mxid = %mxid_for_log,
                outcome = tracing::field::Empty,
            );
            let download_span_for_record = download_span.clone();
            tokio::spawn(
                async move {
                    let all_rooms = client_for_download.joined_rooms();
                    let encrypted_rooms: Vec<_> = all_rooms
                        .iter()
                        .filter(|r| r.encryption_state().is_encrypted())
                        .collect();

                    let total_encrypted = encrypted_rooms.len();
                    if total_encrypted > KEY_BACKUP_MAX_ROOMS {
                        warn!(
                            mxid = %mxid_for_log,
                            total_encrypted_rooms = total_encrypted,
                            cap = KEY_BACKUP_MAX_ROOMS,
                            "capped key-backup download to {KEY_BACKUP_MAX_ROOMS} rooms; \
                             user has {total_encrypted} encrypted rooms"
                        );
                    }

                    let mut total = 0usize;
                    let mut succeeded = 0usize;
                    let mut failed = 0usize;
                    let mut skipped_cooldown = 0usize;
                    let mut skipped_gate_busy = 0usize;
                    for room in encrypted_rooms.iter().take(KEY_BACKUP_MAX_ROOMS) {
                        total += 1;
                        let room_id = room.room_id().to_owned();
                        // Goes through the shared KeyBackupGate so a
                        // second concurrent /setup/recover invocation
                        // can't double-pull the same room and our
                        // global concurrency cap also applies to the
                        // MCP `request_room_keys` tool.
                        let permit = match key_backup_gate.try_acquire(&room_id) {
                            Ok(Some(p)) => p,
                            Ok(None) => {
                                skipped_cooldown += 1;
                                debug!(
                                    mxid = %mxid_for_log,
                                    %room_id,
                                    "skip: per-room cooldown active"
                                );
                                continue;
                            }
                            Err(busy) => {
                                skipped_gate_busy += 1;
                                debug!(
                                    mxid = %mxid_for_log,
                                    %room_id,
                                    "skip: {busy}"
                                );
                                continue;
                            }
                        };
                        let result = timeout(KEY_BACKUP_ROOM_TIMEOUT, async {
                            client_for_download
                                .encryption()
                                .backups()
                                .download_room_keys_for_room(&room_id)
                                .await
                        })
                        .await;
                        match result {
                            Ok(Ok(())) => {
                                succeeded += 1;
                                permit.record_success();
                                debug!(mxid = %mxid_for_log, %room_id, "backed-up keys downloaded");
                            }
                            Ok(Err(e)) => {
                                failed += 1;
                                warn!(
                                    mxid = %mxid_for_log,
                                    %room_id,
                                    error = %e,
                                    "failed to download room keys from backup"
                                );
                            }
                            Err(_elapsed) => {
                                failed += 1;
                                warn!(
                                    mxid = %mxid_for_log,
                                    %room_id,
                                    timeout_secs = KEY_BACKUP_ROOM_TIMEOUT.as_secs(),
                                    "timed out downloading room keys from backup"
                                );
                            }
                        }
                        drop(permit);
                    }
                    let _ = (skipped_cooldown, skipped_gate_busy);
                    let dl_outcome = if failed == 0 {
                        outcome::OK
                    } else {
                        outcome::ERROR
                    };
                    download_span_for_record.record("outcome", dl_outcome);
                    tracing::info!(
                        mxid = %mxid_for_log,
                        total_encrypted_rooms = total,
                        succeeded,
                        failed,
                        "key-backup history download complete"
                    );
                    audit::setup_event(
                        "setup_history_download",
                        Some(&mxid_for_log),
                        dl_outcome,
                        SetupExtras {
                            rooms_total: Some(total),
                            rooms_succeeded: Some(succeeded),
                            rooms_failed: Some(failed),
                            error_class: None,
                        },
                    );
                }
                .instrument(download_span),
            );

            // Invalidate the session cookie so reload doesn't replay.
            {
                let mut sessions = state.sessions.write().await;
                if let Some(sid) = jar.get(SESSION_COOKIE).map(|c| c.value().to_owned()) {
                    sessions.remove(&sid);
                }
            }
            // Must match the Path set in build_session_cookie so the browser
            // actually removes the cookie (a mismatch means the Set-Cookie
            // deletion is for a different path-scoped cookie).
            let mut expired = Cookie::from(SESSION_COOKIE);
            expired.set_path("/setup");
            let cleared = jar.remove(expired);
            (cleared, Html(SUCCESS_HTML)).into_response()
        }
        Err(e) => {
            warn!(mxid = %session.mxid, error = %e, "recovery import failed");
            span.record("outcome", "error");
            audit::setup_event(
                "setup_recover",
                Some(&session.mxid),
                outcome::ERROR,
                SetupExtras {
                    error_class: Some("recovery_import"),
                    ..SetupExtras::default()
                },
            );
            error_page(
                StatusCode::BAD_REQUEST,
                &format!(
                    "Couldn't import the cross-signing keys: {e}. \
                     Double-check the recovery key you pasted (the same string Element X \
                     showed you when you first enabled cross-signing) and try again."
                ),
            )
        }
    }
}

// ---------- helpers ----------

async fn current_session(state: &SetupState, jar: &CookieJar) -> Option<SetupSession> {
    let cookie = jar.get(SESSION_COOKIE)?;
    let session_id = cookie.value().to_owned();
    let mut guard = state.sessions.write().await;
    prune_expired_sessions(&mut guard);
    guard.get(&session_id).cloned()
}

/// Insert a new pending PKCE entry, enforcing the hard cap.
///
/// Returns `true` on success. If the map is at or above `PKCE_MAX_PENDING`,
/// expired entries are pruned first; if it's still full after pruning,
/// the insert is rejected and `false` is returned.
fn insert_pending_pkce(
    map: &mut HashMap<String, PendingPkce>,
    state_token: String,
    pending: PendingPkce,
) -> bool {
    if map.len() >= PKCE_MAX_PENDING {
        prune_expired_pkce(map);
    }
    if map.len() >= PKCE_MAX_PENDING {
        return false;
    }
    map.insert(state_token, pending);
    true
}

/// Insert a new pending session entry, enforcing the hard cap.
///
/// Returns `true` on success. If the map is at or above `SESSIONS_MAX_PENDING`,
/// expired entries are pruned first; if it's still full after pruning,
/// the insert is rejected and `false` is returned.
fn insert_pending_session(
    map: &mut HashMap<String, SetupSession>,
    session_id: String,
    session: SetupSession,
) -> bool {
    if map.len() >= SESSIONS_MAX_PENDING {
        prune_expired_sessions(map);
    }
    if map.len() >= SESSIONS_MAX_PENDING {
        return false;
    }
    map.insert(session_id, session);
    true
}

fn prune_expired_pkce(map: &mut HashMap<String, PendingPkce>) {
    let now = Instant::now();
    map.retain(|_, v| now.duration_since(v.created_at) < PKCE_TTL);
}

fn prune_expired_sessions(map: &mut HashMap<String, SetupSession>) {
    let now = Instant::now();
    map.retain(|_, v| now.duration_since(v.created_at) < SESSION_TTL);
}

async fn exchange_and_introspect(
    state: &SetupState,
    code: &str,
    verifier: &str,
) -> Result<(crate::mas::AuthenticatedIdentity, String)> {
    let creds = state
        .config
        .introspection
        .as_ref()
        .ok_or_else(|| anyhow!("introspection credentials missing on Config"))?;
    let redirect_uri = format!("{}/setup/callback", state.config.resource_url);
    let token_url = format!("{}/oauth2/token", state.config.authorization_server);

    let http = reqwest::Client::builder()
        .timeout(Duration::from_secs(10))
        .user_agent(concat!("matrix-mcp/", env!("CARGO_PKG_VERSION")))
        .build()
        .context("build setup http client")?;

    let params = [
        ("grant_type", "authorization_code"),
        ("code", code),
        ("redirect_uri", redirect_uri.as_str()),
        ("client_id", creds.client_id.as_str()),
        ("code_verifier", verifier),
    ];
    let resp = http
        .post(&token_url)
        .basic_auth(&creds.client_id, Some(&creds.client_secret))
        .form(&params)
        .send()
        .await
        .context("POST /oauth2/token")?;
    let status = resp.status();
    let body = resp.text().await.context("read token body")?;
    if !status.is_success() {
        return Err(anyhow!("MAS /oauth2/token {status}: {body}"));
    }
    let parsed: TokenResponse =
        serde_json::from_str(&body).with_context(|| format!("parse token body: {body}"))?;

    // Introspect the freshly-issued token to get the stable MAS subject,
    // device id, and mxid. Reuses the existing MasIntrospectionClient so we
    // go through the same auth + username-parsing path as /mcp.
    let identity = state
        .mas
        .introspect(&parsed.access_token)
        .await
        .map_err(|e| anyhow!("introspect setup token: {e}"))?
        .ok_or_else(|| anyhow!("MAS rejected the freshly-issued setup token"))?;
    Ok((identity, parsed.access_token))
}

#[derive(Deserialize)]
struct TokenResponse {
    access_token: String,
    #[allow(dead_code)]
    token_type: Option<String>,
    #[allow(dead_code)]
    expires_in: Option<i64>,
    #[allow(dead_code)]
    refresh_token: Option<String>,
}

fn build_session_cookie(session_id: &str) -> Cookie<'static> {
    // No explicit max-age: the cookie expires when the browser tab
    // closes (session cookie). matrix-mcp's server-side session map
    // is the actual authority on freshness; the cookie just carries
    // the session id. Closing the tab is a clean "forget about my
    // setup attempt" signal.
    //
    // Path=/setup: restricts the cookie to the /setup subtree so it
    // is never sent to /mcp or any other endpoint. `__Secure-` prefix
    // (rather than `__Host-`) is intentional — `__Host-` would require
    // Path=/ by browser spec, silently dropping a Path=/setup cookie.
    let mut c = Cookie::new(SESSION_COOKIE.to_owned(), session_id.to_owned());
    c.set_path("/setup");
    c.set_http_only(true);
    c.set_secure(true);
    c.set_same_site(SameSite::Lax);
    c
}

fn random_alnum(len: usize) -> String {
    let mut rng = thread_rng();
    (0..len).map(|_| rng.sample(Alphanumeric) as char).collect()
}

fn url_encode(s: &str) -> String {
    use std::fmt::Write as _;
    const UNRESERVED: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ\
        abcdefghijklmnopqrstuvwxyz0123456789-_.~";
    let mut out = String::with_capacity(s.len());
    for &b in s.as_bytes() {
        if UNRESERVED.contains(&b) {
            out.push(b as char);
        } else {
            let _ = write!(out, "%{b:02X}");
        }
    }
    out
}

// ---------- HTML ----------
// Kept inline; the templates are short and styling stays
// dark-on-dark to match the rest of the example.com estate.

fn page(title: &str, body: &str) -> String {
    format!(
        r#"<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="robots" content="noindex,nofollow">
<title>{title}</title>
<style>
  body {{ background:#111; color:#eee; font:14px/1.5 system-ui,sans-serif; max-width: 38rem; margin: 4rem auto; padding: 0 1rem; }}
  h1 {{ font-size: 1.3rem; margin: 0 0 1rem; }}
  p {{ color: #bbb; }}
  code {{ background:#222; padding: 0 0.3em; border-radius: 3px; }}
  label {{ display: block; margin: 1rem 0 0.25rem; color:#bbb; }}
  input[type=password], input[type=text] {{
    width: 100%; padding: 0.6rem; background:#1a1a1a; color:#eee;
    border: 1px solid #333; border-radius: 4px; font-family: ui-monospace,monospace;
    box-sizing: border-box;
  }}
  button, a.btn {{
    display: inline-block; margin-top: 1.5rem; padding: 0.6rem 1.2rem;
    background:#3a6df0; color:white; border:0; border-radius: 4px;
    cursor: pointer; text-decoration: none; font: inherit;
  }}
  button:hover, a.btn:hover {{ background:#2a5dd0; }}
  .err {{ color: #f88; background:#2a1010; padding: 0.6rem 0.8rem; border-radius: 4px; }}
</style>
</head>
<body>
{body}
</body>
</html>
"#
    )
}

const LANDING_HTML: &str = r#"<!doctype html><html lang="en"><head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="robots" content="noindex,nofollow">
<title>matrix-mcp setup</title>
<style>
body { background:#111; color:#eee; font:14px/1.5 system-ui,sans-serif; max-width: 38rem; margin: 4rem auto; padding: 0 1rem; }
h1 { font-size: 1.3rem; margin: 0 0 1rem; }
p { color: #bbb; }
code { background:#222; padding: 0 0.3em; border-radius: 3px; }
a.btn { display:inline-block; margin-top:1.5rem; padding:0.6rem 1.2rem; background:#3a6df0; color:#fff; border-radius:4px; text-decoration:none; }
a.btn:hover { background:#2a5dd0; }
</style></head><body>
<h1>matrix-mcp — unlock E2EE</h1>
<p>Sign in once so matrix-mcp can import your cross-signing keys from
Matrix Secret Storage. You'll be redirected to <code>id.example.com</code>
to authenticate, then back here to paste your recovery key.</p>
<p>The recovery key is used once and not stored on this server. The
imported cross-signing private keys are encrypted at rest with a
per-user key derived from a server-wide secret.</p>
<a class="btn" href="/setup/login">Sign in</a>
</body></html>"#;

const SUCCESS_HTML: &str = r#"<!doctype html><html lang="en"><head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="robots" content="noindex,nofollow">
<title>matrix-mcp — unlocked</title>
<style>
body { background:#111; color:#eee; font:14px/1.5 system-ui,sans-serif; max-width: 38rem; margin: 4rem auto; padding: 0 1rem; }
h1 { font-size: 1.3rem; margin: 0 0 1rem; }
p { color: #bbb; }
code { background:#222; padding:0 0.3em; border-radius:3px; }
</style></head><body>
<h1>✓ Unlocked</h1>
<p>Cross-signing private keys imported. matrix-mcp will self-sign its
device on the next sync (≤30 s). Head back to claude.ai and call
<code>verify_status</code> — it should now report
<code>cross_signed: true</code>.</p>
<p>Historical message decryption: matrix-mcp is now downloading your
megolm session backup in the background — one request per encrypted
room, up to 200 rooms. For a busy account this can take a minute or
two. Re-running <code>read_recent_messages</code> on the same room a
minute later should show previously-undecryptable history as
<code>status: decrypted</code>.</p>
<p>You can close this tab.</p>
</body></html>"#;

fn form_html(mxid: &str, csrf_token: &str) -> String {
    let mxid_safe = html_escape(mxid);
    // csrf_token is random alphanumeric — no escaping needed, but use
    // html_escape defensively in case the alphabet ever widens.
    let csrf_safe = html_escape(csrf_token);
    page(
        "matrix-mcp — recovery key",
        &format!(
            r#"<h1>Paste your recovery key</h1>
<p>Signed in as <code>{mxid_safe}</code>. Paste the Matrix Secret
Storage recovery key (the 48-character <code>Esso&nbsp;…</code> string)
or the security passphrase you set up in Element X when you first
enabled cross-signing.</p>
<form method="POST" action="/setup/recover" autocomplete="off">
<input type="hidden" name="csrf_token" value="{csrf_safe}">
<label for="recovery_key">Recovery key</label>
<input type="password" id="recovery_key" name="recovery_key" required autofocus
       autocomplete="off" spellcheck="false" inputmode="text">
<button type="submit">Unlock E2EE</button>
</form>
<p style="margin-top:2rem;font-size:0.85rem;color:#888">The key is sent
once to matrix-mcp over HTTPS and never logged, never stored. Only the
derived cross-signing private keys are persisted, encrypted on disk.</p>"#
        ),
    )
}

fn error_page(status: StatusCode, msg: &str) -> Response {
    let escaped = html_escape(msg);
    let body = format!(
        r#"<h1>Something went wrong</h1>
<p class="err">{escaped}</p>
<a class="btn" href="/setup">Start over</a>"#
    );
    (status, Html(page("matrix-mcp — error", &body))).into_response()
}

fn html_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#39;")
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn html_escape_handles_common_chars() {
        assert_eq!(
            html_escape("<script>alert(1)</script>"),
            "&lt;script&gt;alert(1)&lt;/script&gt;"
        );
        assert_eq!(html_escape("a&b"), "a&amp;b");
        assert_eq!(html_escape(r#""'"#), "&quot;&#39;");
    }

    #[test]
    fn url_encode_matches_pct_encoding() {
        assert_eq!(url_encode("hello world"), "hello%20world");
        assert_eq!(url_encode("urn:matrix:..."), "urn%3Amatrix%3A...");
        assert_eq!(url_encode("a-b_c.d~e"), "a-b_c.d~e");
    }

    #[test]
    fn pkce_pruning_drops_expired_entries() {
        let mut map = HashMap::new();
        map.insert(
            "fresh".to_owned(),
            PendingPkce {
                verifier: "x".into(),
                created_at: Instant::now(),
            },
        );
        map.insert(
            "stale".to_owned(),
            PendingPkce {
                verifier: "y".into(),
                // Synthesize a clearly-expired created_at without
                // risking an underflow on systems where Instant::now()
                // is close to the monotonic clock origin (CI). Use
                // checked_sub and fall back to the earliest instant.
                created_at: Instant::now()
                    .checked_sub(PKCE_TTL + Duration::from_secs(1))
                    .unwrap_or_else(Instant::now),
            },
        );
        prune_expired_pkce(&mut map);
        assert!(map.contains_key("fresh"));
        assert!(!map.contains_key("stale"));
    }

    #[test]
    fn random_alnum_produces_correct_length() {
        let s = random_alnum(64);
        assert_eq!(s.len(), 64);
        assert!(s.chars().all(|c| c.is_ascii_alphanumeric()));
    }

    #[test]
    fn pkce_challenge_matches_rfc7636_example() {
        // RFC 7636 Appendix B.
        let verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
        let challenge_bytes = Sha256::digest(verifier.as_bytes());
        let challenge = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(challenge_bytes);
        assert_eq!(challenge, "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM");
    }

    // --- Fix A: PKCE map cap tests ---

    #[test]
    fn pkce_insert_rejects_when_cap_is_full() {
        let mut map = HashMap::new();
        // Fill to exactly the cap with fresh (non-expired) entries.
        for i in 0..PKCE_MAX_PENDING {
            assert!(
                insert_pending_pkce(
                    &mut map,
                    format!("state-{i}"),
                    PendingPkce {
                        verifier: "x".into(),
                        created_at: Instant::now(),
                    },
                ),
                "insert #{i} should succeed"
            );
        }
        assert_eq!(map.len(), PKCE_MAX_PENDING);

        // One more must be rejected.
        assert!(
            !insert_pending_pkce(
                &mut map,
                "overflow".into(),
                PendingPkce {
                    verifier: "x".into(),
                    created_at: Instant::now(),
                },
            ),
            "insert beyond cap should return false"
        );
        assert_eq!(map.len(), PKCE_MAX_PENDING);
        assert!(!map.contains_key("overflow"));
    }

    #[test]
    fn pkce_insert_prunes_expired_entries_before_enforcing_cap() {
        let expired_at = Instant::now()
            .checked_sub(PKCE_TTL + Duration::from_secs(1))
            .unwrap_or_else(Instant::now);
        let mut map = HashMap::new();
        // Fill with entries that are all past the TTL.
        for i in 0..PKCE_MAX_PENDING {
            map.insert(
                format!("stale-{i}"),
                PendingPkce {
                    verifier: "x".into(),
                    created_at: expired_at,
                },
            );
        }
        assert_eq!(map.len(), PKCE_MAX_PENDING);

        // A fresh insert should succeed: prune clears all stale entries first.
        assert!(
            insert_pending_pkce(
                &mut map,
                "fresh".into(),
                PendingPkce {
                    verifier: "x".into(),
                    created_at: Instant::now(),
                },
            ),
            "insert should succeed after pruning expired entries"
        );
        assert_eq!(map.len(), 1);
        assert!(map.contains_key("fresh"));
    }

    // --- Fix A: sessions map cap tests ---

    #[test]
    fn session_insert_rejects_when_cap_is_full() {
        let mut map = HashMap::new();
        // Fill to exactly the cap with fresh sessions.
        for i in 0..SESSIONS_MAX_PENDING {
            assert!(
                insert_pending_session(
                    &mut map,
                    format!("sid-{i}"),
                    SetupSession {
                        mas_subject: format!("mas-sub-{i}"),
                        mxid: format!("@user{i}:example.com"),
                        device_id: None,
                        access_token: "tok".into(),
                        csrf_token: "dummy".into(),
                        created_at: Instant::now(),
                    },
                ),
                "session insert #{i} should succeed"
            );
        }
        assert_eq!(map.len(), SESSIONS_MAX_PENDING);

        // One more must be rejected.
        assert!(
            !insert_pending_session(
                &mut map,
                "overflow".into(),
                SetupSession {
                    mas_subject: "mas-sub-overflow".into(),
                    mxid: "@overflow:example.com".into(),
                    device_id: None,
                    access_token: "tok".into(),
                    csrf_token: "dummy".into(),
                    created_at: Instant::now(),
                },
            ),
            "session insert beyond cap should return false"
        );
        assert_eq!(map.len(), SESSIONS_MAX_PENDING);
        assert!(!map.contains_key("overflow"));
    }

    #[test]
    fn session_insert_prunes_expired_entries_before_enforcing_cap() {
        let expired_at = Instant::now()
            .checked_sub(SESSION_TTL + Duration::from_secs(1))
            .unwrap_or_else(Instant::now);
        let mut map = HashMap::new();
        // Fill with entries that are all past the TTL.
        for i in 0..SESSIONS_MAX_PENDING {
            map.insert(
                format!("stale-{i}"),
                SetupSession {
                    mas_subject: format!("mas-sub-stale-{i}"),
                    mxid: format!("@stale{i}:example.com"),
                    device_id: None,
                    access_token: "tok".into(),
                    csrf_token: "dummy".into(),
                    created_at: expired_at,
                },
            );
        }
        assert_eq!(map.len(), SESSIONS_MAX_PENDING);

        // A fresh insert should succeed: prune clears all stale entries first.
        assert!(
            insert_pending_session(
                &mut map,
                "fresh".into(),
                SetupSession {
                    mas_subject: "mas-sub-fresh".into(),
                    mxid: "@fresh:example.com".into(),
                    device_id: None,
                    access_token: "tok".into(),
                    csrf_token: "dummy".into(),
                    created_at: Instant::now(),
                },
            ),
            "session insert should succeed after pruning expired entries"
        );
        assert_eq!(map.len(), 1);
        assert!(map.contains_key("fresh"));
    }

    #[test]
    fn csrf_token_mismatch_is_detected() {
        // Constant-time comparison: different lengths always differ;
        // same length with one char changed also differs.
        let stored = b"AbCdEfGhIjKlMnOpQrStUvWxYz012345";
        let correct = b"AbCdEfGhIjKlMnOpQrStUvWxYz012345";
        let wrong = b"AbCdEfGhIjKlMnOpQrStUvWxYz012346";
        assert_eq!(stored.ct_eq(correct).unwrap_u8(), 1);
        assert_eq!(stored.ct_eq(wrong).unwrap_u8(), 0);
    }
}
