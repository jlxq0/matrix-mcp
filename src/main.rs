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
mod audit_room;
mod auth;
mod channel;
mod config;
mod content_sandbox;
mod device_identity;
mod key_backup_gate;
mod last_used;
mod mas;
mod matrix_client;
mod mcp;
mod metrics;
mod oauth_metadata;
mod rate_limit;
mod session;
mod session_store;
mod setup;
mod telemetry;
mod token_introspect;
mod url_safety;

use std::sync::Arc;

use anyhow::{Context, Result};
use axum::Router;
use axum::body::Body;
use axum::extract::State;
use axum::http::{Method, Request, StatusCode};
use axum::middleware::{self, Next};
use axum::response::IntoResponse;
use axum::routing::get;
use rmcp::transport::streamable_http_server::session::store::SessionStore;
use rmcp::transport::streamable_http_server::{StreamableHttpServerConfig, StreamableHttpService};
use tokio::net::TcpListener;
use tower_http::trace::TraceLayer;
use tracing::info;

use crate::auth::{AccessToken, AuthState, bearer_auth};
use crate::config::Config;
#[cfg(test)]
use crate::config::IntrospectionCredentials;
use crate::mas::MasIntrospectionClient;
use crate::matrix_client::MatrixClientCache;
use crate::mcp::MatrixMcpService;
use crate::oauth_metadata::protected_resource_metadata;
use crate::rate_limit::Limiter;
use crate::rate_limit::{
    INITIALIZE_REFILL_INTERVAL, InitializeLimiter, MAX_INITIALIZES_PER_IDENTITY,
};

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
        cfg.authorization_server_base(),
        cfg.resource_url.clone(),
        creds.client_id,
        creds.client_secret,
        cfg.server_name.clone(),
    )?;
    let auth_state = AuthState {
        config: cfg.clone(),
        mas: mas.clone(),
        last_used: last_used::LastUsedTracker::new(),
    };
    let store = cfg.store.clone().context(
        "E2EE store config missing — set MATRIX_MCP_STORE_DIR and MATRIX_MCP_STORE_PEPPER",
    )?;
    let store_root = store.root.clone();
    // Shared by the channel mount (which registers sessions) and the client
    // cache (whose sync tasks push to them).
    let channel_registry = channel::ChannelRegistry::new();
    let clients = MatrixClientCache::new(cfg.homeserver_url.clone(), store)
        .with_channel(channel_registry.clone());
    // Shared across SetupState (recover flow) and MatrixMcpService
    // (request_room_keys tool + auto-pull helper) so all room-key
    // backup pulls go through the same concurrency cap + per-room
    // cooldown.
    let key_backup_gate = key_backup_gate::KeyBackupGate::new();
    let setup_state = setup::SetupState::new(
        cfg.clone(),
        mas.clone(),
        clients.clone(),
        key_backup_gate.clone(),
    );
    let limiter = Arc::new(
        Limiter::new(cfg.rate_limit_reads_per_min, cfg.rate_limit_writes_per_min).context(
            "rate-limit quotas must be > 0; check MATRIX_MCP_RATE_LIMIT_{READS,WRITES}_PER_MIN",
        )?,
    );
    let download_max_bytes = cfg.download_max_bytes;
    let tts = cfg.tts.clone().map(Arc::new);
    // Durable MCP sessions live on the same PVC as the matrix-sdk stores, so
    // a rollout or an idle-eviction doesn't 404 a client's session id. A
    // failure to create the directory is a volume misconfiguration: log it and
    // run without persistence rather than refusing to boot.
    let session_store: Option<Arc<dyn SessionStore>> =
        match session_store::FileSessionStore::new(&store_root) {
            Ok(store) => Some(Arc::new(store)),
            Err(e) => {
                tracing::warn!(
                    error = %e,
                    "could not open the durable session directory; MCP sessions \
                     will not survive a restart"
                );
                None
            }
        };
    Ok(build_router(
        cfg,
        auth_state,
        clients,
        mas,
        setup_state,
        limiter,
        download_max_bytes,
        key_backup_gate,
        tts,
        session_store,
        channel_registry,
    ))
}

/// Build the per-session service factory for one mount.
///
/// `StreamableHttpService` constructs a fresh service for every MCP session,
/// so everything the service needs is cloned into the factory once here and
/// then per-session out of it. `channel = Some(..)` produces the `/channel`
/// surface; `None` produces the full `/mcp` one.
#[allow(clippy::too_many_arguments)]
fn service_factory(
    clients: MatrixClientCache,
    mas: MasIntrospectionClient,
    limiter: Arc<Limiter>,
    download_max_bytes: u64,
    upload_max_bytes: usize,
    key_backup_gate: key_backup_gate::KeyBackupGate,
    tts: Option<Arc<crate::config::TtsConfig>>,
    deployment: crate::mcp::Deployment,
    channel: Option<channel::ChannelRegistry>,
) -> impl Fn() -> Result<MatrixMcpService, std::io::Error> + Send + Sync + 'static {
    move || {
        let service = MatrixMcpService::new(
            clients.clone(),
            mas.clone(),
            Arc::clone(&limiter),
            download_max_bytes,
            upload_max_bytes,
            key_backup_gate.clone(),
            tts.clone(),
            deployment.clone(),
        );
        Ok(match &channel {
            Some(registry) => service.into_channel_mode(registry.clone()),
            None => service,
        })
    }
}

#[allow(clippy::too_many_arguments)]
fn build_router(
    cfg: Config,
    auth_state: AuthState,
    clients: MatrixClientCache,
    mas: MasIntrospectionClient,
    setup_state: setup::SetupState,
    limiter: Arc<Limiter>,
    download_max_bytes: u64,
    key_backup_gate: key_backup_gate::KeyBackupGate,
    tts: Option<Arc<crate::config::TtsConfig>>,
    session_store: Option<Arc<dyn SessionStore>>,
    channel_registry: channel::ChannelRegistry,
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
    let upload_max_bytes = cfg.upload_max_bytes;
    let mut allowed_hosts: Vec<String> = vec!["localhost".into(), "127.0.0.1".into(), "::1".into()];
    if let Some(h) = resource_host {
        allowed_hosts.push(h);
    }
    // Session pool defences (audit finding #13 + secscan #83350ed0):
    // - CappedSessionManager applies a 30-minute idle TTL and hard-caps the
    //   global session count at session::MAX_SESSIONS (256).
    // - InitializeLimiter (below) rate-limits *fresh* MCP session creation
    //   per identity so one bearer token can't cheaply fill the global pool.
    //
    // `session_store` makes sessions durable: an `Mcp-Session-Id` the process
    // has no in-memory record of (pod restart, rollout, idle eviction) is
    // reloaded from the PVC and its `initialize` handshake replayed, instead
    // of 404-ing the client into a re-handshake it may be rate-limited out of.
    // Both mounts get the same transport configuration. `StreamableHttpService`
    // consumes its config, so the builder runs once per mount.
    let make_http_config = |mount: &str, store: Option<Arc<dyn SessionStore>>| {
        let mut c = StreamableHttpServerConfig::default().with_allowed_hosts(allowed_hosts.clone());
        if !cfg.allowed_origins.is_empty() {
            info!(origins = ?cfg.allowed_origins, "Origin validation enabled for {mount}");
            c = c.with_allowed_origins(cfg.allowed_origins.clone());
        }
        c.session_store = store;
        c
    };
    let http_config = make_http_config("/mcp", session_store.clone());
    let channel_http_config = make_http_config("/channel", session_store);

    // `/setup` lives next to `/mcp` on the same public origin.
    let deployment = crate::mcp::Deployment {
        server_name: cfg.server_name.clone(),
        setup_url: format!(
            "{}/setup",
            cfg.resource_url
                .strip_suffix("/mcp")
                .unwrap_or(&cfg.resource_url)
                .trim_end_matches('/')
        ),
    };
    let mcp_service = StreamableHttpService::new(
        service_factory(
            clients.clone(),
            mas.clone(),
            Arc::clone(&limiter),
            download_max_bytes,
            upload_max_bytes,
            key_backup_gate.clone(),
            tts.clone(),
            deployment.clone(),
            None,
        ),
        Arc::new(session::CappedSessionManager::new()),
        http_config,
    );

    // `/channel` — same auth, same stores, same clients; a narrower tool
    // surface and the `claude/channel` capability. See `channel.rs`.
    let channel_service = StreamableHttpService::new(
        service_factory(
            clients,
            mas,
            limiter,
            download_max_bytes,
            upload_max_bytes,
            key_backup_gate,
            tts,
            deployment,
            Some(channel_registry),
        ),
        Arc::new(session::CappedSessionManager::new()),
        channel_http_config,
    );

    // Per-identity initialize-rate-limit. See
    // `rate_limit::INITIALIZE_REFILL_INTERVAL` for why the refill is decoupled
    // from the session idle TTL: a 429 here lands on the user's *first tool
    // call* after a reconnect, which is the worst possible place for it.
    let initialize_limiter = Arc::new(InitializeLimiter::new(
        INITIALIZE_REFILL_INTERVAL,
        MAX_INITIALIZES_PER_IDENTITY,
    ));

    // `/token/introspect` shares the bearer-auth middleware with `/mcp`
    // and reads `state.last_used`, so it lives in this sub-router. The
    // explicit `.with_state(auth_state.clone())` is what makes
    // `State<AuthState>` extractable in the handler; `from_fn_with_state`
    // alone wires state into the middleware only.
    //
    // Middleware order matters: bearer_auth attaches AccessToken +
    // AuthenticatedIdentity to the request extensions; the initialize
    // limiter reads those, so it must run AFTER bearer_auth. Axum's
    // .layer() applies bottom-up, so the limiter goes first here.
    let mcp_routes = Router::new()
        .nest_service("/mcp", mcp_service)
        .nest_service("/channel", channel_service)
        .route("/token/introspect", get(token_introspect::handler))
        .layer(middleware::from_fn_with_state(
            initialize_limiter,
            initialize_rate_limit,
        ))
        .layer(middleware::from_fn_with_state(
            auth_state.clone(),
            bearer_auth,
        ))
        .with_state(auth_state);

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
        // RFC 9728 §3.1 path-inserted location for the `{origin}/mcp`
        // resource. Strict clients (LangDock) follow the `resource_metadata`
        // pointer here; lenient ones (claude.ai) hit the root above. Both
        // return the same document with `resource = {origin}/mcp`.
        .route(
            "/.well-known/oauth-protected-resource/mcp",
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

/// Middleware that rejects fresh MCP session creation when the caller's
/// per-identity initialize bucket is exhausted. Runs only on POSTs to
/// /mcp without an `mcp-session-id` header — i.e., the initialize call
/// rmcp uses to mint a fresh session. Tool calls (which carry the
/// session id) flow through untouched, since they're already gated by
/// the tool-level [`crate::rate_limit::Limiter`].
async fn initialize_rate_limit(
    State(limiter): State<Arc<InitializeLimiter>>,
    request: Request<Body>,
    next: Next,
) -> axum::response::Response {
    if !is_fresh_mcp_session_request(&request) {
        return next.run(request).await;
    }
    // bearer_auth ran upstream and attached these. If they're missing
    // it's a routing misconfiguration, not an attacker — fail closed.
    let Some(token) = request.extensions().get::<AccessToken>() else {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            "authenticated request missing token extension\n",
        )
            .into_response();
    };
    let Some(identity) = request
        .extensions()
        .get::<crate::mas::AuthenticatedIdentity>()
    else {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            "authenticated request missing identity extension\n",
        )
            .into_response();
    };
    let bearer_hash = crate::audit::token_hash(&token.0);
    if limiter
        .check(&bearer_hash, Some(identity.mas_subject.as_str()))
        .is_err()
    {
        return initialize_rate_limited();
    }
    next.run(request).await
}

/// The 429 for an exhausted initialize bucket.
///
/// Shaped for MCP clients rather than for `curl`: a JSON-RPC error body (with
/// the same `-32029` code the tool layer uses for rate limits) so the client
/// surfaces a real message instead of "unexpected response", and `Retry-After`
/// so it knows when the next slot frees up rather than hammering.
fn initialize_rate_limited() -> axum::response::Response {
    let retry_after_secs = INITIALIZE_REFILL_INTERVAL.as_secs();
    let body = serde_json::json!({
        "jsonrpc": "2.0",
        "id": serde_json::Value::Null,
        "error": {
            "code": crate::audit::RATE_LIMITED_CODE,
            "message": format!(
                "too many MCP session handshakes for this identity; retry in {retry_after_secs}s"
            ),
        }
    });
    let mut response = (StatusCode::TOO_MANY_REQUESTS, axum::Json(body)).into_response();
    response.headers_mut().insert(
        axum::http::header::RETRY_AFTER,
        axum::http::HeaderValue::from(retry_after_secs),
    );
    response
}

fn is_fresh_mcp_session_request(request: &Request<Body>) -> bool {
    request.method() == Method::POST && request.headers().get("mcp-session-id").is_none()
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

    // Optional OTLP layer — present only when OTEL_EXPORTER_OTLP_ENDPOINT is
    // set. Returns None in local dev / CI so there is no behaviour change.
    let otel_layer = telemetry::try_build_otel_layer();

    let json_layer = std::env::var("MATRIX_MCP_LOG_FORMAT").as_deref() == Ok("json");
    let registry = tracing_subscriber::registry()
        .with(env_filter)
        .with(otel_layer);
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
        router_with_session_store(cfg, None)
    }

    fn router_with_session_store(
        cfg: Config,
        session_store: Option<Arc<dyn SessionStore>>,
    ) -> Router {
        let creds = cfg.introspection.clone().unwrap();
        let mas = MasIntrospectionClient::new(
            cfg.authorization_server_base(),
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
        let key_backup_gate = key_backup_gate::KeyBackupGate::new();
        let setup_state = setup::SetupState::new(
            cfg.clone(),
            mas.clone(),
            clients.clone(),
            key_backup_gate.clone(),
        );
        // Wide-open limiter for tests — we don't exercise rate-limit
        // behaviour here; dedicated tests live in `rate_limit::tests`.
        let limiter = Arc::new(crate::rate_limit::Limiter::new(100_000, 100_000).unwrap());
        build_router(
            cfg.clone(),
            AuthState {
                config: cfg,
                mas: mas.clone(),
                last_used: crate::last_used::LastUsedTracker::new(),
            },
            clients,
            mas,
            setup_state,
            limiter,
            5 * 1024 * 1024, // default 5 MiB cap in tests
            key_backup_gate,
            None,
            session_store,
            channel::ChannelRegistry::new(),
        )
    }

    /// `initialize` against an arbitrary mount, returning the parsed result.
    ///
    /// The channel tests need the initialize *result* itself rather than a
    /// subsequent tool call, because the capability declaration is what is
    /// under test.
    async fn initialize_on(app: &Router, uri: &str) -> Result<Value, anyhow::Error> {
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
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri(uri)
                    .header("Host", "localhost")
                    .header("Content-Type", "application/json")
                    .header("Accept", "application/json, text/event-stream")
                    .header(header::AUTHORIZATION, "Bearer test-token")
                    .body(Body::from(serde_json::to_vec(&init_body)?))
                    .unwrap(),
            )
            .await?;
        let body = axum::body::to_bytes(response.into_body(), 256 * 1024).await?;
        parse_response_body(&body)
    }

    /// `tools/list` against a mount, returning the advertised tool names.
    async fn tool_names_on(app: &Router, uri: &str) -> Result<Vec<String>, anyhow::Error> {
        let init = app
            .clone()
            .oneshot({
                let body = json!({
                    "jsonrpc": "2.0", "id": 1, "method": "initialize",
                    "params": {"protocolVersion": "2025-06-18", "capabilities": {},
                               "clientInfo": {"name": "t", "version": "1"}}
                });
                Request::builder()
                    .method("POST")
                    .uri(uri)
                    .header("Host", "localhost")
                    .header("Content-Type", "application/json")
                    .header("Accept", "application/json, text/event-stream")
                    .header(header::AUTHORIZATION, "Bearer test-token")
                    .body(Body::from(serde_json::to_vec(&body)?))
                    .unwrap()
            })
            .await?;
        let session_id = init
            .headers()
            .get("mcp-session-id")
            .map(|h| h.to_str().unwrap_or("").to_owned());
        let list_body = json!({"jsonrpc": "2.0", "id": 2, "method": "tools/list"});
        let mut builder = Request::builder()
            .method("POST")
            .uri(uri)
            .header("Host", "localhost")
            .header("Content-Type", "application/json")
            .header("Accept", "application/json, text/event-stream")
            .header(header::AUTHORIZATION, "Bearer test-token");
        if let Some(sid) = &session_id {
            builder = builder.header("mcp-session-id", sid);
        }
        let response = app
            .clone()
            .oneshot(
                builder
                    .body(Body::from(serde_json::to_vec(&list_body)?))
                    .unwrap(),
            )
            .await?;
        let bytes = axum::body::to_bytes(response.into_body(), 1024 * 1024).await?;
        let parsed = parse_response_body(&bytes)?;
        Ok(parsed["result"]["tools"]
            .as_array()
            .cloned()
            .unwrap_or_default()
            .iter()
            .filter_map(|t| t["name"].as_str().map(str::to_owned))
            .collect())
    }

    async fn mas_backed_router() -> (MockServer, Router) {
        let mas_mock = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/oauth2/introspect"))
            .respond_with(ResponseTemplate::new(200).set_body_json(active_introspection_body()))
            .mount(&mas_mock)
            .await;
        let app = router(test_config(&mas_mock.uri(), "https://res.example"));
        (mas_mock, app)
    }

    #[tokio::test]
    async fn channel_mount_declares_the_channel_capability() {
        let (_mas, app) = mas_backed_router().await;
        let body = initialize_on(&app, "/channel").await.unwrap();
        let experimental = &body["result"]["capabilities"]["experimental"];
        assert!(
            experimental
                .get(crate::channel::CHANNEL_CAPABILITY)
                .is_some(),
            "the capability declaration is the entire registration mechanism; \
             without it a client silently never becomes a channel. body: {body}"
        );
    }

    #[tokio::test]
    async fn the_main_mount_never_declares_the_channel_capability() {
        // The reason /channel is a separate mount at all: existing clients on
        // /mcp must not be turned into channels and pushed to.
        let (_mas, app) = mas_backed_router().await;
        let body = initialize_on(&app, "/mcp").await.unwrap();
        let experimental = &body["result"]["capabilities"]["experimental"];
        assert!(
            experimental
                .get(crate::channel::CHANNEL_CAPABILITY)
                .is_none(),
            "body: {body}"
        );
    }

    #[tokio::test]
    async fn channel_mount_offers_only_the_scoped_tools() {
        let (_mas, app) = mas_backed_router().await;
        let channel_tools = tool_names_on(&app, "/channel").await.unwrap();
        let full_tools = tool_names_on(&app, "/mcp").await.unwrap();

        assert!(
            !channel_tools.is_empty(),
            "channel mount advertised no tools"
        );
        assert!(
            channel_tools.len() < full_tools.len(),
            "channel {} vs full {}: the scoped surface is the point",
            channel_tools.len(),
            full_tools.len()
        );
        for name in &channel_tools {
            assert!(
                crate::channel::CHANNEL_TOOLS.contains(&name.as_str()),
                "{name} is advertised on /channel but is not in CHANNEL_TOOLS"
            );
        }
        // Removal from the router, not a check at call time, is what keeps
        // list and call from drifting — so an excluded tool must be absent.
        assert!(!channel_tools.iter().any(|n| n == "room_ban"));
        assert!(full_tools.iter().any(|n| n == "room_ban"));
    }

    #[tokio::test]
    async fn every_channel_tool_is_actually_advertised() {
        // The test above runs advertised ⊆ CHANNEL_TOOLS, and that direction
        // cannot see a name added to the const and never wired to the mount:
        // the advertised list is simply shorter, and every entry in it still
        // checks out. The symptom of that bug is indistinguishable from not
        // having the tool at all — the model is told it exists and every call
        // fails — so assert the other direction, over the real router.
        let (_mas, app) = mas_backed_router().await;
        let channel_tools = tool_names_on(&app, "/channel").await.unwrap();
        for name in crate::channel::CHANNEL_TOOLS {
            assert!(
                channel_tools.iter().any(|n| n == name),
                "{name} is in CHANNEL_TOOLS but /channel does not advertise it; \
                 advertised: {channel_tools:?}"
            );
        }
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
    fn initialize_request(token: &str, id: u32) -> Result<Request<Body>, anyhow::Error> {
        let init_body = json!({
            "jsonrpc": "2.0",
            "id": id,
            "method": "initialize",
            "params": {
                "protocolVersion": "2025-06-18",
                "capabilities": {},
                "clientInfo": {"name": "matrix-mcp-test", "version": "0.0.1"}
            }
        });
        Ok(Request::builder()
            .method("POST")
            .uri("/mcp")
            .header("Host", "localhost")
            .header("Content-Type", "application/json")
            .header("Accept", "application/json, text/event-stream")
            .header(header::AUTHORIZATION, format!("Bearer {token}"))
            .body(Body::from(serde_json::to_vec(&init_body)?))
            .unwrap())
    }

    async fn initialize_then_call_whoami(
        app: &Router,
    ) -> Result<(StatusCode, Value), anyhow::Error> {
        let init_response = app
            .clone()
            .oneshot(initialize_request("test-token", 1)?)
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
    async fn repeated_initializes_are_rate_limited_per_identity() {
        let mas_mock = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/oauth2/introspect"))
            .respond_with(ResponseTemplate::new(200).set_body_json(active_introspection_body()))
            .mount(&mas_mock)
            .await;

        let app = router(test_config(&mas_mock.uri(), "https://res.example"));
        // Burn the entire per-identity initialize burst.
        for id in 1..=MAX_INITIALIZES_PER_IDENTITY {
            let response = app
                .clone()
                .oneshot(initialize_request("test-token", id).unwrap())
                .await
                .unwrap();
            assert_eq!(
                response.status(),
                StatusCode::OK,
                "init {id} should succeed"
            );
        }
        // The next fresh-session initialize from the same identity is
        // denied with 429 BEFORE rmcp ever sees it.
        let response = app
            .oneshot(initialize_request("test-token", MAX_INITIALIZES_PER_IDENTITY + 1).unwrap())
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::TOO_MANY_REQUESTS);
    }

    /// Durable sessions: a session id minted by one process must keep working
    /// after that process is gone.
    ///
    /// Without the store, the second router has never heard of the session id
    /// and rmcp answers `404` — which is what left claude.ai wedged after
    /// every rollout: the connector holds a session id the server has
    /// forgotten, and recovering costs a fresh `initialize` (which the
    /// per-identity limiter may refuse).
    #[tokio::test]
    async fn session_survives_a_server_restart() {
        let mas_mock = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/oauth2/introspect"))
            .respond_with(ResponseTemplate::new(200).set_body_json(active_introspection_body()))
            .mount(&mas_mock)
            .await;

        let dir = tempfile::tempdir().unwrap();
        let cfg = || test_config(&mas_mock.uri(), "https://res.example");
        let store = || -> Option<Arc<dyn SessionStore>> {
            Some(Arc::new(
                session_store::FileSessionStore::new(dir.path()).unwrap(),
            ))
        };

        // Process 1: handshake, capture the session id.
        let first = router_with_session_store(cfg(), store());
        let init = first
            .oneshot(initialize_request("test-token", 1).unwrap())
            .await
            .unwrap();
        assert_eq!(init.status(), StatusCode::OK);
        let session_id = init
            .headers()
            .get("mcp-session-id")
            .expect("stateful mode must mint a session id")
            .to_str()
            .unwrap()
            .to_owned();

        // Process 2: same PVC, no in-memory state.
        let second = router_with_session_store(cfg(), store());
        let call_body = json!({
            "jsonrpc": "2.0",
            "id": 2,
            "method": "tools/call",
            "params": {"name": "whoami", "arguments": {}}
        });
        let response = second
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/mcp")
                    .header("Host", "localhost")
                    .header("Content-Type", "application/json")
                    .header("Accept", "application/json, text/event-stream")
                    .header(header::AUTHORIZATION, "Bearer test-token")
                    .header("mcp-session-id", &session_id)
                    .body(Body::from(serde_json::to_vec(&call_body).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(
            response.status(),
            StatusCode::OK,
            "a persisted session must be restored, not 404-ed"
        );
        let bytes = axum::body::to_bytes(response.into_body(), 64 * 1024)
            .await
            .unwrap();
        let parsed = parse_response_body(&bytes).unwrap();
        assert_eq!(
            parsed["result"]["structuredContent"]["mxid"], "@alice:example.test",
            "body: {parsed}"
        );
    }

    /// The same flow without a store is the behaviour we are fixing: the
    /// restored-session path is what makes the test above pass, not some
    /// incidental statelessness in the transport.
    #[tokio::test]
    async fn unknown_session_without_a_store_is_rejected() {
        let mas_mock = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/oauth2/introspect"))
            .respond_with(ResponseTemplate::new(200).set_body_json(active_introspection_body()))
            .mount(&mas_mock)
            .await;

        let app = router(test_config(&mas_mock.uri(), "https://res.example"));
        let call_body = json!({
            "jsonrpc": "2.0",
            "id": 2,
            "method": "tools/call",
            "params": {"name": "whoami", "arguments": {}}
        });
        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/mcp")
                    .header("Host", "localhost")
                    .header("Content-Type", "application/json")
                    .header("Accept", "application/json, text/event-stream")
                    .header(header::AUTHORIZATION, "Bearer test-token")
                    .header("mcp-session-id", "a-session-nobody-remembers")
                    .body(Body::from(serde_json::to_vec(&call_body).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }

    /// A 429 on the handshake lands on the user's first tool call, so it has
    /// to be legible to an MCP client: JSON-RPC error body + `Retry-After`.
    #[tokio::test]
    async fn initialize_rate_limit_response_is_client_readable() {
        let response = initialize_rate_limited();
        assert_eq!(response.status(), StatusCode::TOO_MANY_REQUESTS);
        assert!(response.headers().contains_key(header::RETRY_AFTER));
        let bytes = axum::body::to_bytes(response.into_body(), 16 * 1024)
            .await
            .unwrap();
        let body: Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(body["jsonrpc"], "2.0");
        assert_eq!(body["error"]["code"], crate::audit::RATE_LIMITED_CODE);
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

    #[tokio::test]
    async fn token_introspect_returns_envelope_for_active_bearer() {
        let mas_mock = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/oauth2/introspect"))
            .respond_with(ResponseTemplate::new(200).set_body_json(active_introspection_body()))
            .mount(&mas_mock)
            .await;

        let app = router(test_config(&mas_mock.uri(), "https://res.example"));
        let response = app
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri("/token/introspect")
                    .header(header::AUTHORIZATION, "Bearer test-token")
                    // XFF chain shape: the leftmost entry is what the
                    // external client claimed (spoofable), 10.0.0.1 is
                    // what our trusted upstream proxy (Traefik in
                    // production) appended. With trusted_proxy_hops=1
                    // we record `10.0.0.1`, not the spoofable leftmost.
                    .header("X-Forwarded-For", "203.0.113.7, 10.0.0.1")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let bytes = axum::body::to_bytes(response.into_body(), 16 * 1024)
            .await
            .unwrap();
        let body: Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(body["mxid"], "@alice:example.test", "body: {body}");
        assert_eq!(body["device_id"], "matrix-mcp-test-device");
        assert_eq!(body["exp"], 9_999_999_999i64);
        // The bearer in this test is the literal string "test-token";
        // its truncated SHA-256 hex (16 chars) is deterministic.
        assert!(
            body["token_hash"]
                .as_str()
                .is_some_and(|s| s.len() == 16 && s.chars().all(|c| c.is_ascii_hexdigit())),
            "expected 16 hex-char token_hash, got: {}",
            body["token_hash"]
        );
        // The /token/introspect call itself MUST NOT update last_used —
        // otherwise the act of checking the audit signal would
        // immediately overwrite it and hide any prior (potentially
        // attacker-driven) use the owner is trying to detect. With no
        // prior tool calls recorded, last_used is null on first read.
        assert!(
            body["last_used"].is_null(),
            "last_used should be null on first /token/introspect (no prior real use); got: {body}"
        );
    }

    #[tokio::test]
    async fn token_introspect_without_bearer_returns_401() {
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
                    .method("GET")
                    .uri("/token/introspect")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }
}
