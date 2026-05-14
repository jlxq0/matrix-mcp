//! Process-level configuration.
//!
//! Config construction is split into a pure constructor (`Config::new`)
//! and an env-var wrapper (`Config::from_env`). Tests build Config directly
//! and never touch process-global env state — Rust 2024 makes `set_var`
//! unsafe (correctly: it's racy under multi-threaded test harnesses), and
//! we forbid `unsafe_code` at the crate root, so this split is the clean
//! way to keep both invariants.

use std::net::SocketAddr;
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
/// OAuth client id we authenticate with against MAS's introspection endpoint.
/// Issued out-of-band (pre-registered or via `DCR`).
const ENV_INTROSPECTION_CLIENT_ID: &str = "MATRIX_MCP_INTROSPECTION_CLIENT_ID";
/// OAuth client secret paired with the id above. Loaded from 1Password via
/// `ExternalSecret` in production.
const ENV_INTROSPECTION_CLIENT_SECRET: &str = "MATRIX_MCP_INTROSPECTION_CLIENT_SECRET";

#[derive(Debug, Clone)]
pub struct Config {
    /// Our own public URL (e.g. `https://matrix-mcp.kampong.social`). Never
    /// trailing-slashed — RFC 8707 resource indicators are compared as
    /// strings, and trailing slash mismatches are a real footgun.
    pub resource_url: String,
    /// Authorization server (issuer). No trailing slash, same reason.
    pub authorization_server: String,
    /// TCP bind address.
    pub bind_addr: SocketAddr,
    /// Optional introspection credentials. `None` is the Phase 0/1.1 mode
    /// where we haven't wired auth yet; from Phase 1.2 onward `from_env`
    /// requires them.
    pub introspection: Option<IntrospectionCredentials>,
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
        bind_addr: SocketAddr,
    ) -> Result<Self> {
        let resource_url = strip_trailing_slash(resource_url.into());
        let authorization_server = strip_trailing_slash(authorization_server.into());
        validate_url(&resource_url, ENV_RESOURCE_URL)?;
        validate_url(&authorization_server, ENV_AUTH_SERVER_URL)?;
        Ok(Self {
            resource_url,
            authorization_server,
            bind_addr,
            introspection: None,
        })
    }

    /// Builder-style: attach introspection credentials.
    #[must_use]
    pub fn with_introspection(mut self, creds: IntrospectionCredentials) -> Self {
        self.introspection = Some(creds);
        self
    }

    /// Load from environment variables. Missing required vars are fatal at
    /// startup — we refuse to boot rather than silently fall back to a
    /// development default in production.
    pub fn from_env() -> Result<Self> {
        let resource_url = require_env(ENV_RESOURCE_URL)?;
        let authorization_server = require_env(ENV_AUTH_SERVER_URL)?;
        let bind_addr_str = std::env::var(ENV_BIND_ADDR).unwrap_or_else(|_| "0.0.0.0:3000".into());
        let bind_addr = SocketAddr::from_str(&bind_addr_str)
            .with_context(|| format!("invalid {ENV_BIND_ADDR}: {bind_addr_str}"))?;
        let client_id = require_env(ENV_INTROSPECTION_CLIENT_ID)?;
        let client_secret = require_env(ENV_INTROSPECTION_CLIENT_SECRET)?;
        Ok(
            Self::new(resource_url, authorization_server, bind_addr)?.with_introspection(
                IntrospectionCredentials {
                    client_id,
                    client_secret,
                },
            ),
        )
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
        let cfg = Config::new("https://example.test", "https://auth.example.test", bind()).unwrap();
        assert_eq!(cfg.resource_url, "https://example.test");
        assert_eq!(cfg.authorization_server, "https://auth.example.test");
    }

    #[test]
    fn strips_trailing_slashes() {
        let cfg = Config::new(
            "https://example.test/",
            "https://auth.example.test///",
            bind(),
        )
        .unwrap();
        assert_eq!(cfg.resource_url, "https://example.test");
        assert_eq!(cfg.authorization_server, "https://auth.example.test");
    }

    #[test]
    fn rejects_non_url_resource() {
        let err = Config::new("not-a-url", "https://auth.example.test", bind()).unwrap_err();
        let msg = format!("{err:#}");
        assert!(msg.contains("must be an absolute"), "error was: {msg}");
    }

    #[test]
    fn rejects_non_url_auth_server() {
        let err =
            Config::new("https://example.test", "ftp://auth.example.test", bind()).unwrap_err();
        let msg = format!("{err:#}");
        assert!(msg.contains("must be an absolute"), "error was: {msg}");
    }

    #[test]
    fn http_is_allowed_for_dev() {
        // We allow http:// so that local dev against a non-TLS MAS works.
        // Production requires https in operator policy, enforced elsewhere.
        let cfg = Config::new("http://localhost:3000", "http://localhost:8080", bind()).unwrap();
        assert_eq!(cfg.resource_url, "http://localhost:3000");
    }
}
