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

use crate::config::Config;
use crate::mas::{AuthenticatedIdentity, MasIntrospectionClient};
use crate::oauth_metadata::www_authenticate_header;

/// State the auth middleware needs. Cheap to clone: the inner `Arc`s in
/// `MasIntrospectionClient` make the actual data shared.
#[derive(Clone)]
pub struct AuthState {
    pub config: Config,
    pub mas: MasIntrospectionClient,
}

/// Middleware function plugged in via `axum::middleware::from_fn_with_state`.
pub async fn bearer_auth(
    State(state): State<AuthState>,
    mut request: Request<Body>,
    next: Next,
) -> Response {
    let Some(token) = extract_bearer(request.headers().get(header::AUTHORIZATION)) else {
        return unauthorized(&state.config.resource_url);
    };

    match state.mas.introspect(&token).await {
        Ok(Some(identity)) => {
            debug!(mxid = %identity.mxid, "authenticated request");
            // Stash the identity on request extensions. rmcp's streamable-http
            // tower layer wraps the request's `Parts` (including our extension)
            // into the tool handler's `RequestContext.extensions`, where the
            // tool reads it via `mcp::identity_from_ctx`. A `task_local!` is
            // tempting but doesn't survive the rmcp session worker spawn.
            request.extensions_mut().insert(identity);
            next.run(request).await
        }
        Ok(None) => {
            debug!("token rejected by MAS introspection");
            unauthorized(&state.config.resource_url)
        }
        Err(e) => {
            warn!(error = %e, "MAS introspection failure");
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

fn unauthorized(resource_url: &str) -> Response {
    let header_value = www_authenticate_header(resource_url);
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

    #[tokio::test]
    async fn unauthorized_response_has_www_authenticate() {
        let r = unauthorized("https://example.test");
        assert_eq!(r.status(), StatusCode::UNAUTHORIZED);
        let h = r.headers().get(header::WWW_AUTHENTICATE).unwrap();
        let s = h.to_str().unwrap();
        assert!(s.contains("resource_metadata="));
        assert!(s.contains("/.well-known/oauth-protected-resource"));
        // Drain body to keep the type happy in async context
        let _ = to_bytes(r.into_body(), 1024).await.unwrap();
    }
}
