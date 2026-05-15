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
//!  (MAS auto-approves; user already signed in at id.kampong.social)
//!      ↓
//!  GET /setup/callback?code=…&state=…
//!      ↓
//!  exchange code → token; introspect → mxid
//!      ↓
//!  store (mxid, token) in setup_sessions, set session_id cookie
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
//! - **Setup session** (`sessions`): `session_id → (mxid,
//!   access_token, created_at)`. 30-minute TTL. Held only long enough
//!   to render the form and process one POST. The `session_id` is a
//!   random 32-byte value carried in a `__Host-`-prefixed cookie.
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
use tokio::sync::RwLock;
use tracing::{debug, warn};

use crate::config::Config;
use crate::mas::MasIntrospectionClient;
use crate::matrix_client::MatrixClientCache;

/// Name of the setup-session cookie. The `__Host-` prefix forces the
/// browser to scope it to this exact host, HTTPS-only, with no Domain
/// attribute — closes a slew of CSRF/scope footguns.
const SESSION_COOKIE: &str = "__Host-matrix_mcp_setup";
#[allow(clippy::duration_suboptimal_units)] // clippy suggests from_mins; unstable on 1.93.
const PKCE_TTL: Duration = Duration::from_secs(300);
#[allow(clippy::duration_suboptimal_units)]
const SESSION_TTL: Duration = Duration::from_secs(1800);

/// Shared state for the /setup handlers. Cheap to clone — Arc inside.
#[derive(Clone)]
pub struct SetupState {
    pub config: Config,
    pub mas: MasIntrospectionClient,
    pub clients: MatrixClientCache,
    pub pkce_states: Arc<RwLock<HashMap<String, PendingPkce>>>,
    pub sessions: Arc<RwLock<HashMap<String, SetupSession>>>,
}

#[derive(Clone)]
pub struct PendingPkce {
    pub verifier: String,
    pub created_at: Instant,
}

#[derive(Clone)]
pub struct SetupSession {
    pub mxid: String,
    pub access_token: String,
    pub created_at: Instant,
}

impl SetupState {
    pub fn new(config: Config, mas: MasIntrospectionClient, clients: MatrixClientCache) -> Self {
        Self {
            config,
            mas,
            clients,
            pkce_states: Arc::new(RwLock::new(HashMap::new())),
            sessions: Arc::new(RwLock::new(HashMap::new())),
        }
    }
}

// ---------- handlers ----------

#[allow(clippy::unused_async)]
pub async fn index() -> impl IntoResponse {
    Html(LANDING_HTML)
}

pub async fn login(State(state): State<SetupState>) -> Response {
    let verifier = random_alnum(64);
    let challenge_bytes = Sha256::digest(verifier.as_bytes());
    let challenge = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(challenge_bytes);
    let state_token = random_alnum(32);

    {
        let mut guard = state.pkce_states.write().await;
        prune_expired_pkce(&mut guard);
        guard.insert(
            state_token.clone(),
            PendingPkce {
                verifier,
                created_at: Instant::now(),
            },
        );
    }

    let Some(creds) = state.config.introspection.as_ref() else {
        return error_page(
            StatusCode::INTERNAL_SERVER_ERROR,
            "matrix-mcp has no introspection credentials configured; /setup is unavailable.",
        );
    };

    let redirect_uri = format!("{}/setup/callback", state.config.resource_url);
    // MAS quirk: every OAuth endpoint is under `/oauth2/*` EXCEPT
    // `/authorize`, which sits at the issuer root. Confirmed against
    // the live discovery document — authorization_endpoint is the
    // odd one out. TODO(setup): fetch
    // /.well-known/openid-configuration once at startup and cache
    // the endpoint URLs from `authorization_endpoint` /
    // `token_endpoint` so a future MAS path tweak doesn't 404 us
    // again.
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
        Ok((mxid, access_token)) => {
            let session_id = random_alnum(48);
            {
                let mut guard = state.sessions.write().await;
                prune_expired_sessions(&mut guard);
                guard.insert(
                    session_id.clone(),
                    SetupSession {
                        mxid: mxid.clone(),
                        access_token,
                        created_at: Instant::now(),
                    },
                );
            }
            let cookie = build_session_cookie(&session_id);
            debug!(mxid = %mxid, "setup session created");
            (jar.add(cookie), Redirect::to("/setup/form")).into_response()
        }
        Err(e) => {
            warn!(error = %e, "setup token exchange failed");
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
    Html(form_html(&session.mxid)).into_response()
}

#[derive(Deserialize)]
pub struct RecoverForm {
    pub recovery_key: String,
}

pub async fn recover(
    State(state): State<SetupState>,
    jar: CookieJar,
    Form(form): Form<RecoverForm>,
) -> Response {
    let Some(session) = current_session(&state, &jar).await else {
        return Redirect::to("/setup").into_response();
    };
    let key = form.recovery_key.trim().to_owned();
    if key.is_empty() {
        return error_page(
            StatusCode::BAD_REQUEST,
            "Recovery key was empty. Paste it from your password manager and try again.",
        );
    }

    let identity = crate::mas::AuthenticatedIdentity {
        mxid: session.mxid.clone(),
        device_id: Some(crate::oauth_metadata::MATRIX_MCP_DEVICE_ID.to_owned()),
        raw_scope: None,
    };
    let client = match state
        .clients
        .for_user(&identity, &session.access_token)
        .await
    {
        Ok(c) => c,
        Err(e) => {
            return error_page(
                StatusCode::INTERNAL_SERVER_ERROR,
                &format!("Could not build the Matrix client for your session: {e:#}"),
            );
        }
    };

    match client.encryption().recovery().recover(&key).await {
        Ok(()) => {
            // Force a /keys/query so the user-identity cache reflects
            // the new self-signature on the next verify_status call.
            if let Some(me) = client.user_id() {
                let _ = client.encryption().request_user_identity(me).await;
            }

            // Pull historical megolm sessions from server-side key
            // backup so /messages on E2EE rooms can decrypt history.
            // matrix-sdk does NOT auto-fetch from backup; we have to
            // ask per room. Done in a spawned task so the user gets
            // the success page immediately — back-fill happens in the
            // background.
            let mxid_for_log = session.mxid.clone();
            let client_for_download = client.clone();
            tokio::spawn(async move {
                let rooms = client_for_download.joined_rooms();
                let mut total = 0usize;
                let mut succeeded = 0usize;
                let mut failed = 0usize;
                for room in &rooms {
                    if !room.encryption_state().is_encrypted() {
                        continue;
                    }
                    total += 1;
                    let room_id = room.room_id().to_owned();
                    match client_for_download
                        .encryption()
                        .backups()
                        .download_room_keys_for_room(&room_id)
                        .await
                    {
                        Ok(()) => {
                            succeeded += 1;
                            debug!(mxid = %mxid_for_log, %room_id, "backed-up keys downloaded");
                        }
                        Err(e) => {
                            failed += 1;
                            warn!(
                                mxid = %mxid_for_log,
                                %room_id,
                                error = %e,
                                "failed to download room keys from backup"
                            );
                        }
                    }
                }
                tracing::info!(
                    mxid = %mxid_for_log,
                    total_encrypted_rooms = total,
                    succeeded,
                    failed,
                    "key-backup history download complete"
                );
            });

            // Invalidate the session cookie so reload doesn't replay.
            {
                let mut sessions = state.sessions.write().await;
                if let Some(sid) = jar.get(SESSION_COOKIE).map(|c| c.value().to_owned()) {
                    sessions.remove(&sid);
                }
            }
            let cleared = jar.remove(Cookie::from(SESSION_COOKIE));
            (cleared, Html(SUCCESS_HTML)).into_response()
        }
        Err(e) => {
            warn!(mxid = %session.mxid, error = %e, "recovery import failed");
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
) -> Result<(String, String)> {
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

    // Introspect the freshly-issued token to get the mxid. Reuses the
    // existing MasIntrospectionClient so we go through the same auth +
    // username-parsing path as /mcp.
    let identity = state
        .mas
        .introspect(&parsed.access_token)
        .await
        .map_err(|e| anyhow!("introspect setup token: {e}"))?
        .ok_or_else(|| anyhow!("MAS rejected the freshly-issued setup token"))?;
    Ok((identity.mxid, parsed.access_token))
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
    let mut c = Cookie::new(SESSION_COOKIE.to_owned(), session_id.to_owned());
    c.set_path("/");
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
// dark-on-dark to match the rest of the kampong.social estate.

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
Matrix Secret Storage. You'll be redirected to <code>id.kampong.social</code>
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
room. For a busy account this can take a minute or two. Re-running
<code>read_recent_messages</code> on the same room a minute later
should show previously-undecryptable history as
<code>status: decrypted</code>.</p>
<p>You can close this tab.</p>
</body></html>"#;

fn form_html(mxid: &str) -> String {
    let mxid_safe = html_escape(mxid);
    page(
        "matrix-mcp — recovery key",
        &format!(
            r#"<h1>Paste your recovery key</h1>
<p>Signed in as <code>{mxid_safe}</code>. Paste the Matrix Secret
Storage recovery key (the 48-character <code>Esso&nbsp;…</code> string)
or the security passphrase you set up in Element X when you first
enabled cross-signing.</p>
<form method="POST" action="/setup/recover" autocomplete="off">
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
}
