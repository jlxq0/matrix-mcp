//! `GET /token/introspect` — audit endpoint for the calling bearer.
//!
//! Returns envelope state for the bearer that was just used to
//! authenticate the request: the identity MAS reports for it, its
//! expiry (when MAS shared it), and matrix-mcp's own last-used record
//! (timestamp + client IP from `X-Forwarded-For`).
//!
//! ## Purpose
//!
//! Lets the bearer's owner verify, without scraping operator-side
//! logs, that:
//!
//! - The session is bound to the expected `mxid` + `device_id`.
//! - The token hasn't been silently re-issued against a different MAS
//!   session (the `device_id` would shift).
//! - Recent activity originates from the expected IP. A surprise IP
//!   here is a strong "someone else is riding my bearer" signal.
//!
//! ## Auth
//!
//! Protected by [`crate::auth::bearer_auth`]. A request without a
//! valid bearer gets `401` from the middleware before the handler
//! ever runs.
//!
//! ## Privacy
//!
//! The endpoint returns *the caller's own* envelope data only. The
//! bearer hash and IP it returns are already known to the caller
//! (they presented the bearer; they're connecting from that IP). No
//! cross-tenant visibility.

use axum::Json;
use axum::extract::{Request, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use serde::Serialize;

use crate::audit;
use crate::auth::{AccessToken, AuthState};
use crate::last_used::LastUsedRecord;
use crate::mas::AuthenticatedIdentity;

/// JSON body returned by `GET /token/introspect`.
#[derive(Debug, Serialize)]
pub struct TokenIntrospectResponse {
    /// Matrix user id MAS reports for this bearer (e.g.
    /// `@alice:example.com`).
    pub mxid: String,
    /// Matrix device id MAS reports for this bearer. `None` only on
    /// tokens that lack a `urn:matrix:org.matrix.msc2967.client:device:…`
    /// scope (rare; `/setup` flow synthetic identities).
    pub device_id: Option<String>,
    /// Raw OAuth scope string MAS shared with us. `None` when MAS
    /// omitted the field (it usually doesn't).
    pub scope: Option<String>,
    /// Token expiry (Unix epoch seconds) as reported by MAS. `None`
    /// when MAS omitted `exp` from the introspection response.
    pub exp: Option<i64>,
    /// Short `sha256(bearer)[..8]` hex — the same identifier the
    /// operator-side audit log uses, so a user can cross-reference
    /// without ever exposing the bearer.
    pub token_hash: String,
    /// Most recent activity for this bearer. `None` only if the pod
    /// just rolled and this is the first call (the auth middleware
    /// writes this record before the handler runs).
    pub last_used: Option<LastUsedRecord>,
}

/// Handler for `GET /token/introspect`. Reads identity + token from
/// request extensions (populated by [`crate::auth::bearer_auth`]) and
/// composes the JSON response.
#[allow(clippy::unused_async)] // axum handlers must be async
pub async fn handler(State(state): State<AuthState>, request: Request) -> Response {
    let Some(identity) = request.extensions().get::<AuthenticatedIdentity>().cloned() else {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            "auth middleware did not populate identity\n",
        )
            .into_response();
    };
    let Some(token) = request.extensions().get::<AccessToken>().cloned() else {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            "auth middleware did not populate access token\n",
        )
            .into_response();
    };
    let token_hash = audit::token_hash(&token.0);
    let last_used = state.last_used.get(&token_hash);
    Json(TokenIntrospectResponse {
        mxid: identity.mxid,
        device_id: identity.device_id,
        scope: identity.raw_scope,
        exp: identity.exp,
        token_hash,
        last_used,
    })
    .into_response()
}
