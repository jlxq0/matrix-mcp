// matrix-sdk's `Client::sync()` produces a deeply-generic Future. The
// default `Send` auto-trait recursion limit (128) overflows during
// trait resolution. Bump it; this is the documented workaround in
// matrix-sdk's own README.
#![recursion_limit = "512"]

//! `matrix-mcp` — Remote MCP server exposing Matrix to claude.ai.
//!
//! Phase 1.3: real MCP framework wired up. `/mcp` is served by
//! `rmcp::transport::streamable_http_server::StreamableHttpService` behind
//! the bearer-auth middleware. First tool: `whoami` — returns the MXID +
//! device id read from the authenticated token. No Matrix calls yet.

mod audit;
mod auth;
mod config;
mod mas;
mod matrix_client;
mod mcp;
mod metrics;
mod oauth_metadata;
mod rate_limit;
mod session;
mod setup;

use std::sync::Arc;

use anyhow::{Context, Result};
use axum::Router;
use axum::http::StatusCode;
use axum::middleware;
use axum::response::IntoResponse;
use axum::routing::get;
use rmcp::transport::streamable_http_server::{StreamableHttpServerConfig, StreamableHttpService};
use tokio::net::TcpListener;
use tower_http::trace::TraceLayer;
use tracing::info;

use crate::auth::{AuthState, bearer_auth};
use crate::config::Config;
#[cfg(test)]
use crate::config::IntrospectionCredentials;
use crate::mas::MasIntrospectionClient;
use crate::matrix_client::MatrixClientCache;
use crate::mcp::MatrixMcpService;
use crate::oauth_metadata::protected_resource_metadata;
use crate::rate_limit::Limiter;

#[tokio::main]
async fn main() -> Result<()> {
    init_tracing();
    metrics::init();
    let cfg = Config::from_env()?;
    let bind_addr = cfg.bind_addr;
    let metrics_bind_addr = cfg.metrics_bind_addr;
    let app = build_app(cfg)?;

    let listener = TcpListener::bind(bind_addr).await?;
    info!(%bind_addr, "matrix-mcp listening (public)");

    // Internal-only metrics listener. Distinct port so the public Service
    // can omit it; Alloy scrapes via the pod IP using the
    // `prometheus.io/scrape` annotation. Bound to the pod IP via the K8s
    // downward API (POD_IP env var) so even without NetworkPolicy the
    // listener isn't broadly reachable from sibling pods — defence in depth
    // rather than relying solely on Service/NetworkPolicy configuration.
    // Falls back to 127.0.0.1 in local dev (no K8s). No auth on this
    // listener — adding auth would require Alloy reconfiguration.
    let metrics_listener = TcpListener::bind(metrics_bind_addr).await?;
    info!(%metrics_bind_addr, "matrix-mcp metrics listening (internal)");
    let metrics_app = Router::new().route("/metrics", get(metrics::metrics_handler));

    tokio::select! {
        result = axum::serve(listener, app).with_graceful_shutdown(shutdown_signal()) => {
            result?;
        }
        result = axum::serve(metrics_listener, metrics_app)
            .with_graceful_shutdown(shutdown_signal()) => {
            result?;
        }
        () = shutdown_signal() => {}
    }

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
        cfg.server_name.clone(),
    )?;
    let auth_state = AuthState {
        config: cfg.clone(),
        mas: mas.clone(),
    };
    let store = cfg.store.clone().context(
        "E2EE store config missing — set MATRIX_MCP_STORE_DIR and MATRIX_MCP_STORE_PEPPER",
    )?;
    let clients = MatrixClientCache::new(cfg.homeserver_url.clone(), store);
    let setup_state = setup::SetupState::new(cfg.clone(), mas, clients.clone());
    let limiter = Arc::new(
        Limiter::new(cfg.rate_limit_reads_per_min, cfg.rate_limit_writes_per_min).context(
            "rate-limit quotas must be > 0; check MATRIX_MCP_RATE_LIMIT_{READS,WRITES}_PER_MIN",
        )?,
    );
    Ok(build_router(cfg, auth_state, clients, setup_state, limiter))
}

fn build_router(
    cfg: Config,
    auth_state: AuthState,
    clients: MatrixClientCache,
    setup_state: setup::SetupState,
    limiter: Arc<Limiter>,
) -> Router {
    // rmcp's StreamableHttpService is a tower::Service that handles all the
    // MCP transport details (initialize, tools/list, tools/call, SSE
    // upgrades). We nest it under /mcp behind our bearer-auth middleware.
    //
    // `allowed_hosts` is the rmcp DNS-rebinding defence: only Host headers
    // matching one of these strings are accepted. We seed it with localhost
    // (for dev), 127.0.0.1 / ::1, plus the host of our resource_url
    // (production public hostname).
    let resource_host = parse_host(&cfg.resource_url);
    let mut allowed_hosts: Vec<String> = vec!["localhost".into(), "127.0.0.1".into(), "::1".into()];
    if let Some(h) = resource_host {
        allowed_hosts.push(h);
    }
    // Mitigation A + B (audit finding #13): use a CappedSessionManager that
    // applies a 60 s idle TTL (down from rmcp's 300 s default) and hard-caps
    // the global session count at session::MAX_SESSIONS (256).
    let mcp_service = StreamableHttpService::new(
        move || Ok(MatrixMcpService::new(clients.clone(), Arc::clone(&limiter))),
        Arc::new(session::CappedSessionManager::new()),
        StreamableHttpServerConfig::default().with_allowed_hosts(allowed_hosts),
    );

    let mcp_routes = Router::new()
        .nest_service("/mcp", mcp_service)
        .layer(middleware::from_fn_with_state(auth_state, bearer_auth));

    // /setup is a small browser-rendered flow with its own state
    // (PKCE map + setup-session map). Sub-router so its state doesn't
    // bleed into the parent.
    let setup_routes = Router::new()
        .route("/setup", get(setup::index))
        .route("/setup/login", get(setup::login))
        .route("/setup/callback", get(setup::callback))
        .route("/setup/form", get(setup::form))
        .route("/setup/recover", axum::routing::post(setup::recover))
        .with_state(setup_state);

    Router::new()
        .route("/health", get(health))
        .route(
            "/.well-known/oauth-protected-resource",
            get(protected_resource_metadata),
        )
        .merge(setup_routes)
        .merge(mcp_routes)
        .layer(TraceLayer::new_for_http())
        .with_state(cfg)
}

async fn health() -> impl IntoResponse {
    (StatusCode::OK, "ok\n")
}

/// Best-effort `https://host:port/path` → `host[:port]` extraction.
/// Returns `None` if the URL doesn't have an authority.
fn parse_host(url: &str) -> Option<String> {
    let after_scheme = url.split("://").nth(1)?;
    let authority = after_scheme
        .split(['/', '?', '#'])
        .next()
        .unwrap_or(after_scheme);
    if authority.is_empty() {
        None
    } else {
        Some(authority.to_owned())
    }
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
    use serde_json::{Value, json};
    use tower::ServiceExt;
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    use super::*;

    fn test_config(auth_server: &str, resource: &str) -> Config {
        test_config_with_homeserver(auth_server, resource, "https://matrix.example.test")
    }

    fn test_config_with_homeserver(auth_server: &str, resource: &str, homeserver: &str) -> Config {
        Config::new(
            resource,
            auth_server,
            homeserver,
            "example.test",
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
            cfg.server_name.clone(),
        )
        .unwrap();
        // Tests use a throwaway temp dir + pepper for the E2EE store;
        // none of the kept tests actually go through `client_for`, but
        // build_router needs a `MatrixClientCache` either way.
        let store = crate::config::StoreConfig {
            root: std::env::temp_dir().join(format!("matrix-mcp-test-{}", std::process::id())),
            pepper: "a".repeat(64),
        };
        let clients = MatrixClientCache::new(cfg.homeserver_url.clone(), store);
        let setup_state = setup::SetupState::new(cfg.clone(), mas.clone(), clients.clone());
        // Wide-open limiter for tests — we don't exercise rate-limit
        // behaviour here; dedicated tests live in `rate_limit::tests`.
        let limiter = Arc::new(crate::rate_limit::Limiter::new(100_000, 100_000).unwrap());
        build_router(
            cfg.clone(),
            AuthState { config: cfg, mas },
            clients,
            setup_state,
            limiter,
        )
    }

    /// Active-token introspection body that audiences correctly for our test
    /// resource URL.
    fn active_introspection_body() -> Value {
        json!({
            "active": true,
            "sub": "01JABCDEFGHJKMNPQRSTVWXYZ0",
            "username": "alice",
            "aud": "https://res.example",
            "device_id": "matrix-mcp-test-device",
            "scope": "openid urn:matrix:org.matrix.msc2967.client:api:*",
            "exp": 9_999_999_999i64,
        })
    }

    /// A minimal initialize-and-call-whoami JSON-RPC body. The MCP protocol
    /// requires `initialize` before tool calls in stateful mode, but in
    /// stateless mode each request stands alone. The default
    /// `StreamableHttpServerConfig` is stateful, so we issue `initialize` once
    /// to capture the session id, then issue `tools/call`.
    async fn initialize_then_call_whoami(
        app: &Router,
    ) -> Result<(StatusCode, Value), anyhow::Error> {
        let init_body = json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {
                "protocolVersion": "2025-06-18",
                "capabilities": {},
                "clientInfo": {"name": "matrix-mcp-test", "version": "0.0.1"}
            }
        });
        let init_response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/mcp")
                    .header("Host", "localhost")
                    .header("Content-Type", "application/json")
                    .header("Accept", "application/json, text/event-stream")
                    .header(header::AUTHORIZATION, "Bearer test-token")
                    .body(Body::from(serde_json::to_vec(&init_body)?))
                    .unwrap(),
            )
            .await?;

        let session_id = init_response
            .headers()
            .get("mcp-session-id")
            .map(|h| h.to_str().unwrap_or("").to_owned());

        let call_body = json!({
            "jsonrpc": "2.0",
            "id": 2,
            "method": "tools/call",
            "params": {"name": "whoami", "arguments": {}}
        });
        let mut request_builder = Request::builder()
            .method("POST")
            .uri("/mcp")
            .header("Host", "localhost")
            .header("Content-Type", "application/json")
            .header("Accept", "application/json, text/event-stream")
            .header(header::AUTHORIZATION, "Bearer test-token");
        if let Some(sid) = &session_id {
            request_builder = request_builder.header("mcp-session-id", sid);
        }
        let call_response = app
            .clone()
            .oneshot(
                request_builder
                    .body(Body::from(serde_json::to_vec(&call_body)?))
                    .unwrap(),
            )
            .await?;

        let status = call_response.status();
        let body = axum::body::to_bytes(call_response.into_body(), 64 * 1024).await?;
        let parsed = parse_response_body(&body)?;
        Ok((status, parsed))
    }

    /// Streamable HTTP returns either JSON or SSE; this helper extracts the
    /// JSON-RPC body either way.
    fn parse_response_body(body: &[u8]) -> Result<Value, anyhow::Error> {
        let text = std::str::from_utf8(body)?;
        // SSE frames look like "event: message\ndata: { ... }\n\n". Strip
        // to the first JSON object we can find.
        if let Some(idx) = text.find('{') {
            let candidate = &text[idx..];
            // Trim any trailing SSE event terminator
            let end = candidate.rfind('}').map_or(candidate.len(), |i| i + 1);
            Ok(serde_json::from_str(&candidate[..end])?)
        } else {
            anyhow::bail!("no JSON payload in response: {text}")
        }
    }

    #[tokio::test]
    async fn health_remains_public() {
        let app = router(test_config("https://auth.example", "https://res.example"));
        let response = app
            .oneshot(
                Request::builder()
                    .uri("/health")
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
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/mcp")
                    .body(Body::empty())
                    .unwrap(),
            )
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
    async fn whoami_returns_authenticated_mxid() {
        let mas_mock = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/oauth2/introspect"))
            .respond_with(ResponseTemplate::new(200).set_body_json(active_introspection_body()))
            .mount(&mas_mock)
            .await;

        let app = router(test_config(&mas_mock.uri(), "https://res.example"));
        let (status, body) = initialize_then_call_whoami(&app).await.unwrap();
        assert_eq!(status, StatusCode::OK, "body: {body}");

        // body shape: {"jsonrpc":"2.0","id":2,"result":{"content":[...],"structuredContent":{...}}}
        // The whoami tool returned a structured result containing mxid + device_id.
        let result = &body["result"];
        let structured = &result["structuredContent"];
        // server_name in test_config_with_homeserver is "example.test"
        assert_eq!(structured["mxid"], "@alice:example.test", "body: {body}");
        assert_eq!(
            structured["device_id"], "matrix-mcp-test-device",
            "body: {body}"
        );
    }

    // The Phase-2 Matrix tool integration tests (list_joined_rooms /
    // read_recent_messages / send_text_message) have been removed:
    // Phase-3 routes every tool through `matrix-sdk`, whose minimum
    // viable test setup involves an encrypted SQLite store, a sync
    // loop, and a real-enough homeserver — beyond what `wiremock`
    // can realistically replay. The MCP routing layer is still
    // covered by `whoami` above; the SDK-backed tools get exercised
    // in production smoke testing.

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
                    .method("POST")
                    .uri("/mcp")
                    .header("Content-Type", "application/json")
                    .header(header::AUTHORIZATION, "Bearer abc123")
                    .body(Body::from(
                        r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}"#,
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }
}
