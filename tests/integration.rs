//! Integration tests for matrix-mcp — Phase 10.1.
//!
//! These tests spin up a real Postgres + MAS + Synapse stack via
//! testcontainers and run the full claude.ai-shaped flow against it:
//! DCR → authorize → token → introspect → MCP initialize → tools/call.
//!
//! # Running
//!
//! ```text
//! cargo test --features=integration --test integration -- --nocapture
//! ```
//!
//! Docker must be running on the test machine. Container pull + startup
//! takes 30–120 s depending on your internet connection and hardware.
//!
//! # Why feature-gated?
//!
//! Container lifecycle adds 60–120 s to every run. That is unacceptable
//! for the default `cargo test` loop (run dozens of times per coding
//! session). We gate behind `--features=integration` so CI's standard
//! `cargo test --quiet` job never pays the container tax.
//!
//! # Stack topology
//!
//! ```
//! ┌──────────────────────────────────────────────────────────────┐
//! │  test process                                                │
//! │                                                              │
//! │  Postgres (testcontainers, localhost:{pg_port})              │
//! │    │                                                         │
//! │    ├── MAS (testcontainers, localhost:{mas_port})            │
//! │    │    ├── /oauth2/introspect  ◄──── matrix-mcp auth       │
//! │    │    └── /oauth2/token       ◄──── token exchange        │
//! │    │                                                         │
//! │    └── Synapse (testcontainers, localhost:{syn_port})        │
//! │         └── /_matrix/client/v3/*  ◄──── matrix-mcp tools    │
//! │                                                              │
//! │  matrix-mcp (in-process via axum test server)               │
//! │         └── /mcp   ◄──── reqwest HTTP client in tests       │
//! └──────────────────────────────────────────────────────────────┘
//! ```
//!
//! # Implementation status
//!
//! Phase 10.1 scaffolding — the container stack wiring is documented and
//! partially stubbed. The happy-path and rejection tests are marked
//! `#[ignore]` with a `TODO` message until the full stack is wired up.
//! See `INTEGRATION.md` at the project root for the manual bring-up
//! procedure that covers the same scenario.
//!
//! The scaffolding compiles under `--features=integration` so the build
//! gate is always green, and reviewers can see exactly where each piece
//! needs filling in.

#![cfg(feature = "integration")]

// ── imports ─────────────────────────────────────────────────────────────────

use std::collections::HashMap;
use std::time::Duration;

use testcontainers::core::WaitFor;
use testcontainers::runners::SyncRunner as _;
use testcontainers::{ContainerRequest, GenericImage, ImageExt as _};
use testcontainers_modules::postgres::Postgres;

// ── image tags ───────────────────────────────────────────────────────────────

/// MAS image tag.
///
/// Pinned to a specific release so CI is deterministic. Bump this
/// deliberately when updating MAS in production; doing so here first gives
/// you a preview of any API changes before they hit the cluster.
///
/// Latest release: check https://github.com/element-hq/matrix-authentication-service/releases
const MAS_IMAGE: &str = "ghcr.io/element-hq/matrix-authentication-service";
const MAS_TAG: &str = "v0.13.0";

/// Synapse image tag. Pinned to the same series used in our Gruyere cluster.
/// Check: https://hub.docker.com/r/matrixdotorg/synapse/tags
const SYNAPSE_IMAGE: &str = "docker.io/matrixdotorg/synapse";
const SYNAPSE_TAG: &str = "v1.129.0";

// ── helpers ──────────────────────────────────────────────────────────────────

/// Minimal Postgres container with `matrix_mcp_test` as the database,
/// and a separate schema for MAS and Synapse.
fn postgres_container() -> ContainerRequest<Postgres> {
    Postgres::default()
        .with_db_name("matrix_mcp_test")
        .with_user("matrix_mcp_test")
        .with_password("testpassword")
        // Wait until Postgres signals it is ready to accept connections.
        .with_wait_for(WaitFor::message_on_stderr(
            "database system is ready to accept connections",
        ))
}

/// MAS container pointed at the Postgres database exposed on `pg_host:pg_port`.
///
/// MAS requires a configuration file; we inject it via environment variables
/// that MAS's `--config-from-env` / `--config` path supports. In practice
/// the simplest approach is to mount a minimal `config.yaml` via a bind
/// mount or config file injected as an env var — testcontainers supports
/// both. This stub uses environment variables for the flat settings that
/// MAS reads from the environment (DATABASE_URL, etc.).
///
/// TODO: Fill in the full MAS config mounting once the stack wiring is
/// validated. The config must include:
/// - `database.url` — `postgres://matrix_mcp_test:testpassword@{pg_host}:{pg_port}/matrix_mcp_test`
/// - `clients` section with a pre-registered client for matrix-mcp's
///   introspection credential (client_id + client_secret)
/// - `matrix.homeserver` pointing at the Synapse container
/// - `matrix.server_name` = "localhost"
fn mas_container(pg_host: &str, pg_port: u16) -> ContainerRequest<GenericImage> {
    GenericImage::new(MAS_IMAGE, MAS_TAG)
        .with_wait_for(WaitFor::message_on_stdout("listening"))
        .with_env_var(
            "MAS_DATABASE__URI",
            format!(
                "postgres://matrix_mcp_test:testpassword@{pg_host}:{pg_port}/matrix_mcp_test"
            ),
        )
        // Minimal server config. MAS will reject this and refuse to start
        // without a real config file — this is a placeholder that documents
        // where the config injection goes. Replace with a file mount.
        .with_env_var("MAS_SERVER__ISSUER", "http://localhost:8080")
        .with_env_var("MAS_MATRIX__HOMESERVER", "http://localhost:8008")
        .with_env_var("MAS_MATRIX__SERVER_NAME", "localhost")
}

/// Synapse container configured for MSC3861 delegated auth (MAS as OIDC issuer).
///
/// In MSC3861 mode, Synapse does NOT handle its own registration or password
/// auth — all of that is delegated to MAS. The homeserver.yaml must include:
///
/// ```yaml
/// experimental_features:
///   msc3861:
///     enabled: true
///     issuer: http://{mas_host}:{mas_port}/
///     client_id: synapse-client
///     client_secret: synapse-secret
///     admin_token: synapse-admin-token
/// ```
///
/// TODO: Inject homeserver.yaml via a bind mount or --config-path flag.
fn synapse_container(mas_host: &str, mas_port: u16) -> ContainerRequest<GenericImage> {
    GenericImage::new(SYNAPSE_IMAGE, SYNAPSE_TAG)
        .with_wait_for(WaitFor::message_on_stdout("SynapseWorker now listening"))
        .with_env_var("SYNAPSE_SERVER_NAME", "localhost")
        .with_env_var("SYNAPSE_REPORT_STATS", "no")
        // Tells Synapse to use MAS as the auth backend. In practice the full
        // config must be file-mounted; this env var is just documentation.
        .with_env_var(
            "SYNAPSE_MSC3861_ISSUER",
            format!("http://{mas_host}:{mas_port}/"),
        )
}

// ── tests ────────────────────────────────────────────────────────────────────

/// Smoke: Postgres container starts and accepts a connection.
///
/// This test does NOT require MAS or Synapse. It verifies that the
/// testcontainers plumbing itself works in this project's build setup.
/// If this fails, the Docker daemon is not running or the Postgres image
/// cannot be pulled.
#[test]
fn postgres_container_starts() {
    let container = postgres_container()
        .start()
        .expect("Postgres container failed to start");

    let host_port = container
        .get_host_port_ipv4(5432)
        .expect("could not get Postgres host port");

    assert!(host_port > 0, "Postgres should bind a non-zero host port");

    // The container drops when `container` goes out of scope (RAII).
}

/// Happy-path integration test: bearer token introspection → whoami →
/// list_joined_rooms.
///
/// Full stack: Postgres + MAS + Synapse + matrix-mcp (in-process).
///
/// Steps:
/// 1. Start Postgres.
/// 2. Start MAS pointed at Postgres with a pre-registered `matrix-mcp`
///    introspection client and a test user.
/// 3. Start Synapse pointed at Postgres + MAS for MSC3861 auth.
/// 4. Register a Matrix user via MAS (out-of-band admin API).
/// 5. Issue an OAuth access token for that user via MAS token endpoint
///    (simulating what claude.ai does after the OAuth dance).
/// 6. Start matrix-mcp (in-process, test port) pointed at MAS + Synapse.
/// 7. POST `mcp/initialize` with the access token as Bearer.
/// 8. POST `tools/call` `whoami` — verify the returned mxid matches.
/// 9. POST `tools/call` `list_joined_rooms` — verify it returns an empty list
///    (the test user has not joined any rooms yet).
///
/// # TODO
///
/// The full three-container wiring with config file injection is not yet
/// implemented. The config requirements and expected API calls are
/// documented inline so the implementation can be completed incrementally.
/// See `INTEGRATION.md` for the manual procedure that validates the same
/// scenario against a real cluster.
#[test]
#[ignore = "TODO: wire MAS + Synapse config injection (see INTEGRATION.md)"]
fn happy_path_whoami_and_list_rooms() {
    // ── 1. Postgres ─────────────────────────────────────────────────────────
    let _pg = postgres_container()
        .start()
        .expect("Postgres container failed to start");
    let pg_port = _pg.get_host_port_ipv4(5432).expect("Postgres port");

    // ── 2. MAS ──────────────────────────────────────────────────────────────
    // TODO: inject a real config file via .with_copy_to() or .with_mount()
    // that includes:
    //   - database.url pointing at pg_port
    //   - clients[] with id="matrix-mcp-test", secret="test-secret"
    //   - matrix.server_name = "localhost"
    //   - matrix.homeserver = http://localhost:{syn_port}
    let _mas = mas_container("host.docker.internal", pg_port)
        .start()
        .expect("MAS container failed to start");
    let mas_port = _mas.get_host_port_ipv4(8080).expect("MAS port");

    // ── 3. Synapse ───────────────────────────────────────────────────────────
    // TODO: inject homeserver.yaml with msc3861 block pointing at mas_port.
    let _syn = synapse_container("host.docker.internal", mas_port)
        .start()
        .expect("Synapse container failed to start");
    let syn_port = _syn.get_host_port_ipv4(8008).expect("Synapse port");

    // ── 4. Register test user via MAS admin API ──────────────────────────────
    // POST http://localhost:{mas_port}/api/admin/v1/users
    // Body: { "username": "testuser", "password": "testpass", ... }
    // TODO: issue the HTTP request once MAS is running.
    let _test_mxid = format!("@testuser:localhost");

    // ── 5. Issue access token for testuser via MAS token endpoint ────────────
    // POST http://localhost:{mas_port}/oauth2/token
    //   grant_type=password, username=testuser, password=testpass,
    //   client_id=matrix-mcp-test, client_secret=test-secret,
    //   scope="openid urn:matrix:org.matrix.msc2967.client:api:* urn:matrix:org.matrix.msc3814"
    //          + device scope
    // TODO: issue the HTTP request once MAS is running.
    let _test_token = "TODO-issue-token-from-mas";

    // ── 6. matrix-mcp (in-process) ───────────────────────────────────────────
    // Build a Config pointing at the MAS + Synapse containers, bind to a
    // random free port, and spawn the axum server in a background tokio task.
    //
    // Config fields needed:
    //   resource_url   = "http://localhost:{mcp_port}"
    //   auth_server    = "http://localhost:{mas_port}"
    //   homeserver_url = "http://localhost:{syn_port}"
    //   server_name    = "localhost"
    //   introspection_client_id     = "matrix-mcp-test"
    //   introspection_client_secret = "test-secret"
    //   store_dir      = tmp_dir.path()
    //   store_pepper   = "test-pepper-do-not-use-in-production"
    //
    // TODO: start the server once MAS + Synapse are wired up.
    let _mcp_port = 0u16; // placeholder

    // ── 7–9. MCP calls ───────────────────────────────────────────────────────
    // POST http://localhost:{mcp_port}/mcp
    //   Authorization: Bearer {test_token}
    //   Content-Type: application/json
    //   Body: { "jsonrpc": "2.0", "method": "initialize", "id": 1, "params": {...} }
    //
    // Then tools/call whoami, then tools/call list_joined_rooms.
    //
    // TODO: issue requests once matrix-mcp is running.

    // Placeholder assertion so the test structure is visible.
    assert!(
        syn_port > 0 && mas_port > 0,
        "container ports should be non-zero"
    );
}

/// Rejection test: invalid bearer token → 401.
///
/// Does NOT require a full stack — only matrix-mcp + MAS for introspection.
/// MAS returns `{ "active": false }` for an unknown token; matrix-mcp must
/// respond with HTTP 401.
///
/// # TODO
///
/// Wire up the MAS container (or replace with a wiremock stub that returns
/// `active: false`) and start matrix-mcp in-process.
#[test]
#[ignore = "TODO: wire MAS introspection stub (see INTEGRATION.md)"]
fn invalid_bearer_returns_401() {
    // Option A: Use testcontainers to start a real MAS (heavyweight but
    // accurate). Wire the same way as happy_path_whoami_and_list_rooms.
    //
    // Option B: Use wiremock (already a dev-dep) to stub the MAS
    // /oauth2/introspect endpoint. This is lighter and does not need Docker.
    //
    // The wiremock approach would look like:
    //
    // ```
    // let mock_server = wiremock::MockServer::start().await;
    // wiremock::Mock::given(wiremock::matchers::method("POST"))
    //     .and(wiremock::matchers::path("/oauth2/introspect"))
    //     .respond_with(
    //         wiremock::ResponseTemplate::new(200)
    //             .set_body_json(serde_json::json!({ "active": false })),
    //     )
    //     .mount(&mock_server)
    //     .await;
    // // ... start matrix-mcp pointed at mock_server.uri() ...
    // // ... send Bearer "not-a-real-token" to /mcp ...
    // // ... assert HTTP 401 ...
    // ```
    //
    // TODO: pick approach A or B and implement.
    let _placeholder: HashMap<String, String> = HashMap::new();
    assert!(true, "placeholder — implement in follow-up");
}

/// Verify that the integration feature gate compiles cleanly and that the
/// testcontainers + testcontainers-modules deps are present and importable.
/// This test always passes; it exists to catch feature-gate compile errors
/// before any container infrastructure is needed.
#[test]
fn feature_gate_compiles() {
    // Just importing the containers at the top of this file is enough.
    // If testcontainers or testcontainers-modules are missing or mis-gated,
    // the import at the top of this file will fail at compile time.
    let _pg_default_port: u16 = 5432;
    let _mas_image: &str = MAS_IMAGE;
    let _syn_image: &str = SYNAPSE_IMAGE;
    // Verify Duration is accessible (used by wait-for helpers).
    let _timeout = Duration::from_secs(120);
    // Verify GenericImage is constructable without starting it.
    let _img = GenericImage::new("alpine", "latest");
    assert_eq!(
        _mas_image,
        "ghcr.io/element-hq/matrix-authentication-service"
    );
}
