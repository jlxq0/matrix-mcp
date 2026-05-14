//! MCP endpoint stub. Phase 1.1 deliverable: respond 401 with a proper
//! `WWW-Authenticate` header so claude.ai's OAuth discovery kicks in.
//!
//! Token validation, framework integration, and tool dispatch land in
//! subsequent phase 1 PRs.

use axum::extract::State;
use axum::http::{HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};

use crate::config::Config;
use crate::oauth_metadata::www_authenticate_header;

#[allow(clippy::unused_async)]
pub async fn mcp_handler(State(cfg): State<Config>) -> Response {
    // Until phase 1.2 lands the introspection middleware, every request is
    // unauthorised and gets bounced through the OAuth discovery dance.
    let header_value = www_authenticate_header(&cfg.resource_url);
    let value = HeaderValue::from_str(&header_value).unwrap_or_else(|_| {
        // resource_url is validated at startup; a non-ASCII or control
        // character here means someone bypassed `Config::from_env`. Fall back
        // to a safe constant so we never panic in a request handler.
        HeaderValue::from_static("Bearer")
    });

    let mut response = (StatusCode::UNAUTHORIZED, "unauthorized\n").into_response();
    response
        .headers_mut()
        .insert(header::WWW_AUTHENTICATE, value);
    response
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use std::net::SocketAddr;

    use axum::Router;
    use axum::body::Body;
    use axum::http::{Method, Request, StatusCode};
    use axum::routing::{get, post};
    use tower::ServiceExt;

    use super::*;

    fn test_config() -> Config {
        Config::new(
            "https://example.test",
            "https://auth.example.test",
            SocketAddr::from(([0, 0, 0, 0], 3000)),
        )
        .unwrap()
    }

    fn app() -> Router {
        Router::new()
            .route("/mcp", get(mcp_handler).post(mcp_handler))
            .with_state(test_config())
    }

    #[tokio::test]
    async fn mcp_get_returns_401_with_www_authenticate() {
        let response = app()
            .oneshot(Request::builder().uri("/mcp").body(Body::empty()).unwrap())
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        let www_auth = response
            .headers()
            .get(header::WWW_AUTHENTICATE)
            .expect("WWW-Authenticate header missing")
            .to_str()
            .unwrap();
        assert!(www_auth.starts_with("Bearer "), "got: {www_auth}");
        assert!(
            www_auth.contains("resource_metadata="),
            "resource_metadata parameter missing in: {www_auth}"
        );
        assert!(
            www_auth.contains("/.well-known/oauth-protected-resource"),
            "metadata URL wrong in: {www_auth}"
        );
    }

    #[tokio::test]
    async fn mcp_post_returns_401_too() {
        // claude.ai posts JSON-RPC; both verbs need to bounce through the
        // discovery dance until authenticated.
        let response = Router::new()
            .route("/mcp", post(mcp_handler))
            .with_state(test_config())
            .oneshot(
                Request::builder()
                    .method(Method::POST)
                    .uri("/mcp")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }
}
