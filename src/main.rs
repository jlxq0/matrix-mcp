//! `matrix-mcp` — Remote MCP server exposing Matrix to claude.ai.
//!
//! Phase 0 = skeleton. This binary boots an Axum HTTP server on `:3000` with
//! a single `/healthz` endpoint. No Matrix, no OAuth, no MCP yet. Subsequent
//! phases stack on top: see `docs/plan.md`.

use std::net::SocketAddr;

use anyhow::Result;
use axum::{Router, http::StatusCode, response::IntoResponse, routing::get};
use tokio::net::TcpListener;
use tower_http::trace::TraceLayer;
use tracing::info;

#[tokio::main]
async fn main() -> Result<()> {
    init_tracing();
    let addr: SocketAddr = "0.0.0.0:3000".parse()?;
    let app = build_router();

    let listener = TcpListener::bind(addr).await?;
    info!(%addr, "matrix-mcp listening");

    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown_signal())
        .await?;

    Ok(())
}

fn build_router() -> Router {
    Router::new()
        .route("/healthz", get(healthz))
        .layer(TraceLayer::new_for_http())
}

async fn healthz() -> impl IntoResponse {
    (StatusCode::OK, "ok\n")
}

fn init_tracing() {
    use tracing_subscriber::{EnvFilter, fmt, prelude::*};

    let env_filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new("matrix_mcp=info,tower_http=info,axum=info,info"));

    // JSON in production (sent to Loki via Alloy); pretty in dev.
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

// Tests use .unwrap() liberally on infallible Request::builder() chains
// and on response body extraction; allowing here keeps the production
// `unwrap_used = deny` lint strict while not turning the tests into
// error-handling theatre.
#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use axum::body::Body;
    use axum::http::Request;
    use tower::ServiceExt;

    use super::*;

    #[tokio::test]
    async fn healthz_returns_ok() {
        let app = build_router();
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
        let app = build_router();
        let response = app
            .oneshot(Request::builder().uri("/nope").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }
}
