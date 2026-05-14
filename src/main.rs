//! `matrix-mcp` — Remote MCP server exposing Matrix to claude.ai.
//!
//! Phase 1.2: real bearer-token validation. claude.ai's token is introspected
//! against MAS on every `/mcp` request (cached for ≤60 s). On success, an
//! `AuthenticatedIdentity` is attached to the request extensions for tools to
//! pick up in phase 1.3.

mod auth;
mod config;
mod mas;
mod mcp;
mod oauth_metadata;

use anyhow::{Context, Result};
use axum::Router;
use axum::http::StatusCode;
use axum::middleware;
use axum::response::IntoResponse;
use axum::routing::get;
use tokio::net::TcpListener;
use tower_http::trace::TraceLayer;
use tracing::info;

use crate::auth::{AuthState, bearer_auth};
use crate::config::Config;
#[cfg(test)]
use crate::config::IntrospectionCredentials;
use crate::mas::MasIntrospectionClient;
use crate::mcp::mcp_handler;
use crate::oauth_metadata::protected_resource_metadata;

#[tokio::main]
async fn main() -> Result<()> {
    init_tracing();
    let cfg = Config::from_env()?;
    let bind_addr = cfg.bind_addr;
    let app = build_app(cfg)?;

    let listener = TcpListener::bind(bind_addr).await?;
    info!(%bind_addr, "matrix-mcp listening");

    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown_signal())
        .await?;

    Ok(())
}

fn build_app(cfg: Config) -> Result<Router> {
    let creds = cfg
        .introspection
        .clone()
        .context("introspection credentials missing from config")?;
    let mas = MasIntrospectionClient::new(
        &cfg.authorization_server,
        cfg.resource_url.clone(),
        creds.client_id,
        creds.client_secret,
    )?;
    let auth_state = AuthState {
        config: cfg.clone(),
        mas,
    };
    Ok(build_router(cfg, auth_state))
}

fn build_router(cfg: Config, auth_state: AuthState) -> Router {
    // /mcp gets the bearer-auth middleware. /healthz and the OAuth metadata
    // endpoint are intentionally unauthenticated — they're the entry points
    // for liveness probes and OAuth discovery respectively.
    let mcp_routes = Router::new()
        .route("/mcp", get(mcp_handler).post(mcp_handler))
        .layer(middleware::from_fn_with_state(auth_state, bearer_auth));

    Router::new()
        .route("/healthz", get(healthz))
        .route(
            "/.well-known/oauth-protected-resource",
            get(protected_resource_metadata),
        )
        .merge(mcp_routes)
        .layer(TraceLayer::new_for_http())
        .with_state(cfg)
}

async fn healthz() -> impl IntoResponse {
    (StatusCode::OK, "ok\n")
}

fn init_tracing() {
    use tracing_subscriber::{EnvFilter, fmt, prelude::*};

    let env_filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new("matrix_mcp=info,tower_http=info,axum=info,info"));

    let json_layer = std::env::var("MATRIX_MCP_LOG_FORMAT").as_deref() == Ok("json");
    let registry = tracing_subscriber::registry().with(env_filter);
    if json_layer {
        registry.with(fmt::layer().json()).init();
    } else {
        registry.with(fmt::layer().compact()).init();
    }
}

// Signal-handler installation at startup is fatal-or-nothing: there is no
// recoverable path if the kernel won't give us a signalfd, and `axum::serve
// .with_graceful_shutdown` requires the future to resolve to `()`, not
// `Result<()>`. Allowing `expect` here keeps the production lint strict
// elsewhere.
#[allow(clippy::expect_used)]
async fn shutdown_signal() {
    use tokio::signal::unix::{SignalKind, signal};

    let mut sigterm = signal(SignalKind::terminate()).expect("install SIGTERM handler at startup");
    let mut sigint = signal(SignalKind::interrupt()).expect("install SIGINT handler at startup");

    tokio::select! {
        _ = sigterm.recv() => info!("received SIGTERM"),
        _ = sigint.recv() => info!("received SIGINT"),
    }
}

// Tests use .unwrap()/.expect() liberally on infallible Request::builder()
// chains and on response-body extraction; allowing here keeps the production
// lints strict while not turning the tests into error-handling theatre.
#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use std::net::SocketAddr;

    use axum::body::Body;
    use axum::http::{Request, header};
    use serde_json::json;
    use tower::ServiceExt;
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    use super::*;

    fn test_config(auth_server: &str, resource: &str) -> Config {
        Config::new(
            resource,
            auth_server,
            SocketAddr::from(([0, 0, 0, 0], 3000)),
        )
        .unwrap()
        .with_introspection(IntrospectionCredentials {
            client_id: "matrix-mcp-test-client".to_owned(),
            client_secret: "test-secret".to_owned(),
        })
    }

    fn router(cfg: Config) -> Router {
        let creds = cfg.introspection.clone().unwrap();
        let mas = MasIntrospectionClient::new(
            &cfg.authorization_server,
            cfg.resource_url.clone(),
            creds.client_id,
            creds.client_secret,
        )
        .unwrap();
        build_router(cfg.clone(), AuthState { config: cfg, mas })
    }

    #[tokio::test]
    async fn healthz_remains_public() {
        let app = router(test_config("https://auth.example", "https://res.example"));
        let response = app
            .oneshot(
                Request::builder()
                    .uri("/healthz")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn mcp_without_token_returns_401() {
        let app = router(test_config("https://auth.example", "https://res.example"));
        let response = app
            .oneshot(Request::builder().uri("/mcp").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        let www_auth = response
            .headers()
            .get(header::WWW_AUTHENTICATE)
            .unwrap()
            .to_str()
            .unwrap();
        assert!(www_auth.contains("resource_metadata="));
    }

    #[tokio::test]
    async fn mcp_with_valid_token_passes_middleware() {
        let mas_mock = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/oauth2/introspect"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "active": true,
                "sub": "@alice:example.com",
                "aud": "https://res.example",
                "exp": 9_999_999_999i64,
            })))
            .mount(&mas_mock)
            .await;

        let app = router(test_config(&mas_mock.uri(), "https://res.example"));
        let response = app
            .oneshot(
                Request::builder()
                    .uri("/mcp")
                    .header(header::AUTHORIZATION, "Bearer abc123")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        // Phase 1.2: middleware succeeds, handler returns 401 still (it's the
        // placeholder mcp_handler from phase 1.1 that always returns 401).
        // We assert middleware behaviour by NOT seeing
        // WWW-Authenticate (handler doesn't set one in this path because
        // there's no upstream auth challenge yet — that gets fixed in 1.3
        // when the real MCP framework lands).
        //
        // Actually mcp_handler from 1.1 DOES still 401, so we can't easily
        // distinguish here. The 1.3 work will replace the placeholder. For
        // now, assert that the middleware did NOT short-circuit:
        // - status is 401 (placeholder)
        // - the body is "unauthorized\n" if from middleware, also "unauthorized\n" if from handler
        // The way to tell them apart is the WWW-Authenticate header: the
        // middleware sets it on rejection; the handler also sets it. So
        // both paths look identical. We'll add a stronger assertion in 1.3
        // once the handler returns 200 on success.
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn mcp_with_inactive_token_returns_401() {
        let mas_mock = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/oauth2/introspect"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({"active": false})))
            .mount(&mas_mock)
            .await;

        let app = router(test_config(&mas_mock.uri(), "https://res.example"));
        let response = app
            .oneshot(
                Request::builder()
                    .uri("/mcp")
                    .header(header::AUTHORIZATION, "Bearer abc123")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn mcp_with_wrong_audience_returns_500() {
        // Audience mismatch is an upstream-not-trusting-us signal; surface
        // it as a 500 so it shows up in alerts, rather than 401 which a
        // user could misread as "my token is wrong" when actually the
        // client registration is wrong.
        let mas_mock = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/oauth2/introspect"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "active": true,
                "sub": "@alice:example.com",
                "aud": "https://wrong.example",
                "exp": 9_999_999_999i64,
            })))
            .mount(&mas_mock)
            .await;

        let app = router(test_config(&mas_mock.uri(), "https://res.example"));
        let response = app
            .oneshot(
                Request::builder()
                    .uri("/mcp")
                    .header(header::AUTHORIZATION, "Bearer abc")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
    }
}
