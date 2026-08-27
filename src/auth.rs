//! Axum middleware: extract the `Authorization: Bearer <token>` header,
//! introspect against MAS, and attach the resulting `AuthenticatedIdentity`
//! to the request extensions so downstream handlers can read it.

use axum::body::Body;
use axum::extract::State;
use axum::http::{HeaderValue, Request, StatusCode, header};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use subtle::ConstantTimeEq;
use tracing::{debug, warn};

use crate::audit::{self, outcome};
use crate::config::Config;
use crate::last_used::{self, LastUsedTracker};
use crate::mas::{AuthenticatedIdentity, IntrospectionError, MasIntrospectionClient};
use crate::oauth_metadata::www_authenticate_header;
use std::sync::Arc;

/// Newtype around the raw OAuth access token, stashed on request extensions
/// by `bearer_auth`. Per MSC3861, the OAuth access token issued by MAS is
/// the same token Synapse accepts on `/_matrix/*` endpoints, so tools that
/// talk to the homeserver re-use this verbatim. Wrapping it in a dedicated
/// type avoids accidental collisions with other `String` extensions.
#[derive(Clone)]
pub struct AccessToken(pub String);

impl std::fmt::Debug for AccessToken {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_tuple("AccessToken").field(&"<redacted>").finish()
    }
}

/// State the auth middleware needs. Cheap to clone: the inner `Arc`s in
/// `MasIntrospectionClient` and `LastUsedTracker` make the actual data
/// shared.
#[derive(Clone)]
pub struct AuthState {
    pub config: Config,
    pub mas: MasIntrospectionClient,
    /// Per-bearer last-used tracker. Written by [`bearer_auth`] on every
    /// successful introspect, read by the `/token/introspect` endpoint.
    pub last_used: Arc<LastUsedTracker>,
}

/// Middleware function plugged in via `axum::middleware::from_fn_with_state`.
pub async fn bearer_auth(
    State(state): State<AuthState>,
    mut request: Request<Body>,
    next: Next,
) -> Response {
    let Some(token) = extract_bearer(request.headers().get(header::AUTHORIZATION)) else {
        return unauthorized(&state.config);
    };

    let started = std::time::Instant::now();
    let token_hash = audit::token_hash(&token);
    // Don't overwrite the last_used record when the request itself
    // is `/token/introspect` — the whole point of that endpoint is to
    // return what the LAST real use was. If we recorded here, the act
    // of checking the audit signal would immediately overwrite it
    // with the auditor's own request, hiding the prior (potentially
    // attacker-driven) use the owner is trying to detect.
    //
    // We use `eq_ignore_ascii_case` and an exact-path check rather
    // than `starts_with` so unrelated future paths like
    // `/token/introspect/foo` would not inherit the skip.
    let is_introspect_path = request.uri().path() == "/token/introspect";
    match state.mas.introspect(&token).await {
        Ok(Some(identity)) => {
            debug!(mxid = %identity.mxid, "authenticated request");
            audit::introspect(&token_hash, outcome::ACTIVE, started, Some(&identity.mxid));
            // Record last-used for the audit/introspect endpoint. IP comes
            // from `X-Forwarded-For`, but only the entry **N positions from
            // the right** where N is the number of trusted proxies in front
            // of us — Traefik appends what it saw, so that entry is the
            // real client IP. The leftmost entry can be set by any HTTP
            // client and is therefore spoofable by an attacker holding a
            // stolen bearer; never use it as an audit signal.
            if !is_introspect_path {
                let xff = request
                    .headers()
                    .get("x-forwarded-for")
                    .and_then(|v| v.to_str().ok());
                // How many proxies actually appeared, beside how many we
                // trust. The hop count is a claim about the topology that
                // nothing in this process can check; this is what makes it
                // falsifiable from outside.
                last_used::observe_ingress_chain(xff, state.config.trusted_proxy_hops);
                let client_ip = last_used::parse_client_ip(xff, state.config.trusted_proxy_hops);
                state.last_used.record(&token_hash, client_ip);
            }
            // Stash both the identity and the raw OAuth token on the request
            // extensions. rmcp's streamable-http tower layer wraps the
            // request's `Parts` (including our extensions) into the tool
            // handler's `RequestContext.extensions`. A `task_local!` is
            // tempting but doesn't survive the rmcp session worker spawn.
            //
            // The token round-trips because per MSC3861 it doubles as the
            // Matrix access token: homeserver tools re-present it on every
            // `/_matrix/*` call.
            request.extensions_mut().insert(identity);
            request.extensions_mut().insert(AccessToken(token));
            next.run(request).await
        }
        Ok(None) => {
            debug!("token rejected by MAS introspection");
            audit::introspect(&token_hash, outcome::INACTIVE, started, None);
            unauthorized(&state.config)
        }
        // A token minted for a different resource is a *client* problem, not
        // an upstream failure: RFC 6750 / OAuth 2.1 §5.3 and the MCP
        // authorization spec both require 401 so the client re-runs the
        // authorization flow with the right `resource`. Returning 500 here
        // (the old behaviour) left the client retrying a token that would
        // never work.
        Err(IntrospectionError::AudienceMismatch { expected }) => {
            warn!(%expected, "token audience does not name this MCP server");
            audit::introspect(&token_hash, outcome::INACTIVE, started, None);
            unauthorized(&state.config)
        }
        Err(e) => {
            warn!(error = %e, "MAS introspection failure");
            audit::introspect(&token_hash, outcome::ERROR, started, None);
            internal_error()
        }
    }
}

/// Extract the bearer token from an `Authorization` header.
///
/// Two security-relevant details:
/// 1. The scheme prefix check is constant-time to avoid leaking via timing
///    how close a malformed scheme was to "Bearer". (Pure paranoia at this
///    scale, but free.)
/// 2. Only ASCII bearer values are accepted; non-ASCII tokens are rejected.
fn extract_bearer(header: Option<&HeaderValue>) -> Option<String> {
    let raw = header?.to_str().ok()?;
    let raw = raw.trim();
    let (scheme, value) = raw.split_once(' ')?;
    // Constant-time comparison of "Bearer" vs supplied scheme. Case-sensitive
    // per RFC 6750 §2.1.
    if scheme.as_bytes().ct_eq(b"Bearer").unwrap_u8() != 1 {
        return None;
    }
    let token = value.trim();
    if token.is_empty() {
        return None;
    }
    Some(token.to_owned())
}

fn unauthorized(config: &Config) -> Response {
    let header_value = www_authenticate_header(config);
    let value =
        HeaderValue::from_str(&header_value).unwrap_or_else(|_| HeaderValue::from_static("Bearer"));
    let mut response = (StatusCode::UNAUTHORIZED, "unauthorized\n").into_response();
    response
        .headers_mut()
        .insert(header::WWW_AUTHENTICATE, value);
    response
}

fn internal_error() -> Response {
    (
        StatusCode::INTERNAL_SERVER_ERROR,
        "introspection upstream error\n",
    )
        .into_response()
}

/// Convenience: extract `AuthenticatedIdentity` from a request's extensions.
/// Returns `None` only if the middleware wasn't applied — a misconfiguration
/// of the router, not a runtime input error.
///
/// Used by phase 1.3's tool handlers; tolerated dead-code here.
#[allow(dead_code)]
pub fn identity_from(request: &Request<Body>) -> Option<&AuthenticatedIdentity> {
    request.extensions().get::<AuthenticatedIdentity>()
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use axum::body::to_bytes;
    use axum::http::HeaderValue;

    use super::*;

    #[test]
    fn extracts_well_formed_bearer() {
        let h = HeaderValue::from_static("Bearer abc.def.ghi");
        assert_eq!(extract_bearer(Some(&h)).as_deref(), Some("abc.def.ghi"));
    }

    #[test]
    fn rejects_lowercase_scheme() {
        let h = HeaderValue::from_static("bearer abc");
        assert!(extract_bearer(Some(&h)).is_none());
    }

    #[test]
    fn rejects_basic_scheme() {
        let h = HeaderValue::from_static("Basic dXNlcjpwYXNz");
        assert!(extract_bearer(Some(&h)).is_none());
    }

    #[test]
    fn rejects_empty_token() {
        let h = HeaderValue::from_static("Bearer ");
        assert!(extract_bearer(Some(&h)).is_none());
    }

    #[test]
    fn rejects_missing_header() {
        assert!(extract_bearer(None).is_none());
    }

    #[test]
    fn trims_whitespace_around_token() {
        let h = HeaderValue::from_static("Bearer   xyz   ");
        assert_eq!(extract_bearer(Some(&h)).as_deref(), Some("xyz"));
    }

    fn test_config() -> Config {
        Config::new(
            "https://example.test",
            "https://auth.example.test",
            "https://matrix.example.test",
            "example.test",
            std::net::SocketAddr::from(([0, 0, 0, 0], 3000)),
        )
        .unwrap()
    }

    #[tokio::test]
    async fn unauthorized_response_has_www_authenticate() {
        let r = unauthorized(&test_config());
        assert_eq!(r.status(), StatusCode::UNAUTHORIZED);
        let h = r.headers().get(header::WWW_AUTHENTICATE).unwrap();
        let s = h.to_str().unwrap();
        assert!(s.contains("resource_metadata="));
        assert!(s.contains("/.well-known/oauth-protected-resource"));
        // Drain body to keep the type happy in async context
        let _ = to_bytes(r.into_body(), 1024).await.unwrap();
    }
}
