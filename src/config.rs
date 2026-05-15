//! Process-level configuration.
//!
//! Config construction is split into a pure constructor (`Config::new`)
//! and an env-var wrapper (`Config::from_env`). Tests build Config directly
//! and never touch process-global env state — Rust 2024 makes `set_var`
//! unsafe (correctly: it's racy under multi-threaded test harnesses), and
//! we forbid `unsafe_code` at the crate root, so this split is the clean
//! way to keep both invariants.

use std::net::SocketAddr;
use std::path::PathBuf;
use std::str::FromStr;

use anyhow::{Context, Result};

/// Public URL of this MCP server, used as the OAuth `resource` identifier
/// (RFC 8707) and as the `resource` field in the protected-resource metadata
/// document (RFC 9728).
const ENV_RESOURCE_URL: &str = "MATRIX_MCP_RESOURCE_URL";
/// Issuer URL of the authorization server (MAS) that mints tokens for this
/// resource.
const ENV_AUTH_SERVER_URL: &str = "MATRIX_MCP_AUTHORIZATION_SERVER";
/// Bind address, defaults to `0.0.0.0:3000` for container deployment.
const ENV_BIND_ADDR: &str = "MATRIX_MCP_BIND_ADDR";
/// Separate bind for the cluster-internal `/metrics` endpoint. Default
/// `0.0.0.0:9090`. Kept off the public Service via deployment manifests
/// (containerPort is exposed; Service.ports doesn't include it).
const ENV_METRICS_BIND_ADDR: &str = "MATRIX_MCP_METRICS_BIND_ADDR";
/// OAuth client id we authenticate with against MAS's introspection endpoint.
/// Issued out-of-band (pre-registered or via `DCR`).
const ENV_INTROSPECTION_CLIENT_ID: &str = "MATRIX_MCP_INTROSPECTION_CLIENT_ID";
/// OAuth client secret paired with the id above. Loaded from 1Password via
/// `ExternalSecret` in production.
const ENV_INTROSPECTION_CLIENT_SECRET: &str = "MATRIX_MCP_INTROSPECTION_CLIENT_SECRET";
/// Public URL of the Matrix homeserver this MCP server talks to. We
/// configure this directly rather than running .well-known discovery on
/// every call — there is exactly one homeserver per matrix-mcp instance
/// (currently `example.com` → `https://matrix.example.com`).
const ENV_HOMESERVER_URL: &str = "MATRIX_MCP_HOMESERVER_URL";
/// Matrix server name — the right-hand side of every MXID on this
/// homeserver (e.g. `example.com`). Distinct from the homeserver
/// URL: the URL is `https://matrix.example.com`, the server name
/// is `example.com`. We need this to reconstruct the MXID from
/// MAS's introspection `username` field (MAS uses ULID-shaped `sub`s,
/// not MXIDs).
const ENV_SERVER_NAME: &str = "MATRIX_MCP_SERVER_NAME";
/// Root directory for per-user encrypted Matrix stores. In production
/// this points at a PVC mount (Longhorn); each user gets a subdirectory
/// named `sha256(mxid)[..32]`.
const ENV_STORE_DIR: &str = "MATRIX_MCP_STORE_DIR";
/// Pepper used to derive per-user store-cipher keys via
/// `HKDF-SHA256(salt=mxid, ikm=pepper)`. Stored in 1Password, loaded as
/// a Kubernetes Secret. Compromise of this single value compromises
/// every user's on-disk crypto store, so it's the Option-A passphrase
/// model's whole trust anchor — handled with care.
const ENV_STORE_PEPPER: &str = "MATRIX_MCP_STORE_PEPPER";

#[derive(Debug, Clone)]
pub struct Config {
    /// Our own public URL (e.g. `https://matrix-mcp.example.com`). Never
    /// trailing-slashed — RFC 8707 resource indicators are compared as
    /// strings, and trailing slash mismatches are a real footgun.
    pub resource_url: String,
    /// Authorization server (issuer). No trailing slash, same reason.
    pub authorization_server: String,
    /// TCP bind address for the public API (rmcp + setup + health + .well-known).
    pub bind_addr: SocketAddr,
    /// TCP bind for the cluster-internal metrics endpoint. Kept off
    /// the public Service so the metrics blob isn't internet-visible.
    pub metrics_bind_addr: SocketAddr,
    /// Matrix homeserver base URL (no trailing slash). Phase-2+ tools talk
    /// to `{homeserver_url}/_matrix/client/...`.
    pub homeserver_url: String,
    /// Matrix server name (right-hand side of MXIDs), e.g.
    /// `example.com`. Used to reconstruct `@user:server` from MAS's
    /// `username` introspection claim.
    pub server_name: String,
    /// Optional introspection credentials. `None` is the Phase 0/1.1 mode
    /// where we haven't wired auth yet; from Phase 1.2 onward `from_env`
    /// requires them.
    pub introspection: Option<IntrospectionCredentials>,
    /// Phase-3 E2EE persistent state config. `None` means this binary
    /// was built or configured without E2EE (e.g. unit tests, Phase 1/2
    /// smoke deploys); in production `from_env` requires it.
    pub store: Option<StoreConfig>,
}

#[derive(Clone)]
pub struct StoreConfig {
    /// Root directory for per-user encrypted `SQLite` stores. Each mxid
    /// gets a subdirectory `sha256(mxid)[..32]/`.
    pub root: PathBuf,
    /// 32+ byte secret used as HKDF input keying material. The per-user
    /// store-cipher passphrase is `HKDF-SHA256(salt=mxid, ikm=pepper,
    /// info="matrix-mcp-store-cipher v1")`. Held in a `String` rather
    /// than a zeroize-on-drop wrapper because matrix-sdk's
    /// `SqliteStoreConfig::passphrase` already takes `&str`; we'd lose
    /// the wrapper at that boundary anyway.
    pub pepper: String,
}

impl std::fmt::Debug for StoreConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("StoreConfig")
            .field("root", &self.root)
            .field("pepper", &"<redacted>")
            .finish()
    }
}

#[derive(Clone)]
pub struct IntrospectionCredentials {
    pub client_id: String,
    pub client_secret: String,
}

// Manual Debug to avoid leaking the client secret into logs.
impl std::fmt::Debug for IntrospectionCredentials {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("IntrospectionCredentials")
            .field("client_id", &self.client_id)
            .field("client_secret", &"<redacted>")
            .finish()
    }
}

impl Config {
    /// Pure constructor. Validates URLs are absolute http(s) and strips
    /// trailing slashes. Used directly by tests; `from_env` wraps it.
    pub fn new(
        resource_url: impl Into<String>,
        authorization_server: impl Into<String>,
        homeserver_url: impl Into<String>,
        server_name: impl Into<String>,
        bind_addr: SocketAddr,
    ) -> Result<Self> {
        let resource_url = strip_trailing_slash(resource_url.into());
        let authorization_server = strip_trailing_slash(authorization_server.into());
        let homeserver_url = strip_trailing_slash(homeserver_url.into());
        let server_name = server_name.into();
        if server_name.is_empty() {
            anyhow::bail!("{ENV_SERVER_NAME} must not be empty");
        }
        if server_name.starts_with("http") {
            anyhow::bail!(
                "{ENV_SERVER_NAME} must be a Matrix server name (e.g. `example.com`), \
                 not a URL — got `{server_name}`"
            );
        }
        validate_url(&resource_url, ENV_RESOURCE_URL)?;
        validate_url(&authorization_server, ENV_AUTH_SERVER_URL)?;
        validate_url(&homeserver_url, ENV_HOMESERVER_URL)?;
        Ok(Self {
            resource_url,
            authorization_server,
            bind_addr,
            metrics_bind_addr: SocketAddr::from(([0, 0, 0, 0], 9090)),
            server_name,
            homeserver_url,
            introspection: None,
            store: None,
        })
    }

    /// Builder-style: attach introspection credentials.
    #[must_use]
    pub fn with_introspection(mut self, creds: IntrospectionCredentials) -> Self {
        self.introspection = Some(creds);
        self
    }

    /// Builder-style: attach E2EE store config. Required in production
    /// `from_env` boot; optional in tests where no real matrix-sdk
    /// client is built.
    #[must_use]
    pub fn with_store(mut self, store: StoreConfig) -> Self {
        self.store = Some(store);
        self
    }

    /// Load from environment variables. Missing required vars are fatal at
    /// startup — we refuse to boot rather than silently fall back to a
    /// development default in production.
    pub fn from_env() -> Result<Self> {
        let resource_url = require_env(ENV_RESOURCE_URL)?;
        let authorization_server = require_env(ENV_AUTH_SERVER_URL)?;
        let homeserver_url = require_env(ENV_HOMESERVER_URL)?;
        let server_name = require_env(ENV_SERVER_NAME)?;
        let bind_addr_str = std::env::var(ENV_BIND_ADDR).unwrap_or_else(|_| "0.0.0.0:3000".into());
        let bind_addr = SocketAddr::from_str(&bind_addr_str)
            .with_context(|| format!("invalid {ENV_BIND_ADDR}: {bind_addr_str}"))?;
        let metrics_bind_addr_str =
            std::env::var(ENV_METRICS_BIND_ADDR).unwrap_or_else(|_| "0.0.0.0:9090".into());
        let metrics_bind_addr = SocketAddr::from_str(&metrics_bind_addr_str)
            .with_context(|| format!("invalid {ENV_METRICS_BIND_ADDR}: {metrics_bind_addr_str}"))?;
        let client_id = require_env(ENV_INTROSPECTION_CLIENT_ID)?;
        let client_secret = require_env(ENV_INTROSPECTION_CLIENT_SECRET)?;
        let store_root = PathBuf::from(require_env(ENV_STORE_DIR)?);
        let pepper = require_env(ENV_STORE_PEPPER)?;
        if pepper.len() < 32 {
            anyhow::bail!(
                "{ENV_STORE_PEPPER} must be at least 32 bytes of high-entropy material \
                 (got {len} bytes). Generate one with `openssl rand -hex 32`.",
                len = pepper.len()
            );
        }
        let mut cfg = Self::new(
            resource_url,
            authorization_server,
            homeserver_url,
            server_name,
            bind_addr,
        )?;
        cfg.metrics_bind_addr = metrics_bind_addr;
        Ok(cfg
            .with_introspection(IntrospectionCredentials {
                client_id,
                client_secret,
            })
            .with_store(StoreConfig {
                root: store_root,
                pepper,
            }))
    }
}

fn require_env(key: &str) -> Result<String> {
    std::env::var(key).with_context(|| format!("required env var {key} is not set"))
}

fn validate_url(url: &str, key: &str) -> Result<()> {
    if !url.starts_with("https://") && !url.starts_with("http://") {
        anyhow::bail!("{key} must be an absolute http(s) URL, got: {url}");
    }
    Ok(())
}

fn strip_trailing_slash(mut url: String) -> String {
    while url.ends_with('/') {
        url.pop();
    }
    url
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    fn bind() -> SocketAddr {
        SocketAddr::from(([0, 0, 0, 0], 3000))
    }

    #[test]
    fn pure_constructor_succeeds_on_valid_input() {
        let cfg = Config::new(
            "https://example.test",
            "https://auth.example.test",
            "https://matrix.example.test",
            "example.test",
            bind(),
        )
        .unwrap();
        assert_eq!(cfg.resource_url, "https://example.test");
        assert_eq!(cfg.authorization_server, "https://auth.example.test");
        assert_eq!(cfg.homeserver_url, "https://matrix.example.test");
    }

    #[test]
    fn strips_trailing_slashes() {
        let cfg = Config::new(
            "https://example.test/",
            "https://auth.example.test///",
            "https://matrix.example.test/",
            "example.test",
            bind(),
        )
        .unwrap();
        assert_eq!(cfg.resource_url, "https://example.test");
        assert_eq!(cfg.authorization_server, "https://auth.example.test");
        assert_eq!(cfg.homeserver_url, "https://matrix.example.test");
    }

    #[test]
    fn rejects_non_url_resource() {
        let err = Config::new(
            "not-a-url",
            "https://auth.example.test",
            "https://matrix.example.test",
            "example.test",
            bind(),
        )
        .unwrap_err();
        let msg = format!("{err:#}");
        assert!(msg.contains("must be an absolute"), "error was: {msg}");
    }

    #[test]
    fn rejects_non_url_auth_server() {
        let err = Config::new(
            "https://example.test",
            "ftp://auth.example.test",
            "https://matrix.example.test",
            "example.test",
            bind(),
        )
        .unwrap_err();
        let msg = format!("{err:#}");
        assert!(msg.contains("must be an absolute"), "error was: {msg}");
    }

    #[test]
    fn rejects_non_url_homeserver() {
        let err = Config::new(
            "https://example.test",
            "https://auth.example.test",
            "not-a-url",
            "example.test",
            bind(),
        )
        .unwrap_err();
        let msg = format!("{err:#}");
        assert!(msg.contains("must be an absolute"), "error was: {msg}");
    }

    #[test]
    fn http_is_allowed_for_dev() {
        // We allow http:// so that local dev against a non-TLS MAS works.
        // Production requires https in operator policy, enforced elsewhere.
        let cfg = Config::new(
            "http://localhost:3000",
            "http://localhost:8080",
            "http://localhost:8008",
            "localhost",
            bind(),
        )
        .unwrap();
        assert_eq!(cfg.resource_url, "http://localhost:3000");
        assert_eq!(cfg.homeserver_url, "http://localhost:8008");
    }
}
