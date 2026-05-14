//! `matrix-mcp` — Remote MCP server exposing Matrix to claude.ai.
//!
//! Phase 1.1: OAuth 2.0 Protected Resource Metadata + a `/mcp` endpoint
//! that returns 401 with a `WWW-Authenticate` header, so claude.ai's
//! discovery flow finds our MAS. No token validation yet; that lands in
//! phase 1.2. See `docs/plan.md` for the phase roadmap.

mod config;
mod mcp;
mod oauth_metadata;

use anyhow::Result;
use axum::Router;
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::routing::get;
use tokio::net::TcpListener;
use tower_http::trace::TraceLayer;
use tracing::info;

use crate::config::Config;
use crate::mcp::mcp_handler;
use crate::oauth_metadata::protected_resource_metadata;

#[tokio::main]
async fn main() -> Result<()> {
    init_tracing();
    let cfg = Config::from_env()?;
    let bind_addr = cfg.bind_addr;
    let app = build_router(cfg);

    let listener = TcpListener::bind(bind_addr).await?;
    info!(%bind_addr, "matrix-mcp listening");

    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown_signal())
        .await?;

    Ok(())
}

fn build_router(cfg: Config) -> Router {
    Router::new()
        .route("/healthz", get(healthz))
        .route(
            "/.well-known/oauth-protected-resource",
            get(protected_resource_metadata),
        )
        .route("/mcp", get(mcp_handler).post(mcp_handler))
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
    use axum::http::Request;
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

    #[tokio::test]
    async fn healthz_returns_ok() {
        let app = build_router(test_config());
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
        let body = axum::body::to_bytes(response.into_body(), 1024)
            .await
            .unwrap();
        assert_eq!(&body[..], b"ok\n");
    }

    #[tokio::test]
    async fn unknown_route_404() {
        let app = build_router(test_config());
        let response = app
            .oneshot(Request::builder().uri("/nope").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn oauth_metadata_route_wired() {
        let app = build_router(test_config());
        let response = app
            .oneshot(
                Request::builder()
                    .uri("/.well-known/oauth-protected-resource")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn mcp_route_returns_401() {
        let app = build_router(test_config());
        let response = app
            .oneshot(Request::builder().uri("/mcp").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }
}
