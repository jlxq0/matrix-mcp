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
/// Separate bind for the cluster-internal `/metrics` endpoint.
///
/// Default resolution order (defence-in-depth — never binds `0.0.0.0`
/// unless an operator explicitly sets this var):
///
/// 1. If `MATRIX_MCP_METRICS_BIND_ADDR` is set, use that value verbatim.
/// 2. If `POD_IP` is set (injected by the K8s downward API), bind to
///    `{POD_IP}:9090` — reachable by Alloy via the pod IP annotation but
///    not broadly reachable from sibling pods on other nodes.
/// 3. Otherwise (local dev, no K8s), fall back to `127.0.0.1:9090`.
const ENV_METRICS_BIND_ADDR: &str = "MATRIX_MCP_METRICS_BIND_ADDR";
/// Kubernetes downward-API pod IP. Injected via `fieldRef: status.podIP` in
/// the deployment manifest. Used to derive the metrics bind address so the
/// listener is reachable by Alloy (which targets the pod IP) but not broadly
/// accessible across all pod-network peers.
const ENV_POD_IP: &str = "POD_IP";
/// OAuth client id we authenticate with against MAS's introspection endpoint.
/// Issued out-of-band (pre-registered or via `DCR`).
const ENV_INTROSPECTION_CLIENT_ID: &str = "MATRIX_MCP_INTROSPECTION_CLIENT_ID";
/// OAuth client secret paired with the id above. Supplied by the operator via
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
/// this points at a PVC mount (Longhorn); each owner key (stable MAS
/// subject + device id) gets a subdirectory named `sha256(owner_key)[..32]`.
const ENV_STORE_DIR: &str = "MATRIX_MCP_STORE_DIR";
/// Pepper used to derive per-user store-cipher keys via
/// `HKDF-SHA256(salt=mxid, ikm=pepper)`. Held in your secret manager, loaded as
/// a Kubernetes Secret. Compromise of this single value compromises
/// every user's on-disk crypto store, so it's the Option-A passphrase
/// model's whole trust anchor — handled with care.
const ENV_STORE_PEPPER: &str = "MATRIX_MCP_STORE_PEPPER";
/// Per-identity read quota (per minute). Reads = `whoami`,
/// `list_joined_rooms`, `read_recent_messages`, `verify_status`.
const ENV_RATE_LIMIT_READS: &str = "MATRIX_MCP_RATE_LIMIT_READS_PER_MIN";
/// Per-identity write quota (per minute). Writes = `send_text_message`
/// + future side-effectful tools.
const ENV_RATE_LIMIT_WRITES: &str = "MATRIX_MCP_RATE_LIMIT_WRITES_PER_MIN";
/// Maximum number of bytes allowed for a single `download_attachment`
/// fetch. Attachments whose declared size exceeds this cap are rejected
/// before any media I/O occurs. Default: 5 MiB.
const ENV_DOWNLOAD_MAX_BYTES: &str = "MATRIX_MCP_DOWNLOAD_MAX_BYTES";
/// Maximum number of bytes that `send_image_from_url` will fetch from a
/// remote HTTPS URL before uploading to the homeserver media repo.
/// Default: 10 MiB. Set higher only if the homeserver allows larger uploads.
pub const ENV_UPLOAD_MAX_BYTES: &str = "MATRIX_MCP_UPLOAD_MAX_BYTES";
/// Number of trusted proxies in front of matrix-mcp. Used by the
/// `/token/introspect` audit endpoint to pick the trustworthy entry
/// out of `X-Forwarded-For`. Default 1 (assumes Traefik in front in
/// production).
const ENV_TRUSTED_PROXY_HOPS: &str = "MATRIX_MCP_TRUSTED_PROXY_HOPS";
/// Comma-separated list of browser origins allowed to talk to `/mcp`
/// (`Origin` header validation, MCP Streamable HTTP §"Security & Endpoint").
///
/// Empty (the default) disables `Origin` checking. That is deliberate: the
/// DNS-rebinding attack the rule targets is against servers bound to
/// localhost, and every non-browser MCP client (Claude Desktop, VS Code,
/// Cursor, CLI tools) either omits `Origin` or sends an app-private value that
/// no allow-list can enumerate ahead of time — so a default allow-list would
/// break those clients rather than protect this deployment. Set it when the
/// only clients are browser-based, e.g.
/// `MATRIX_MCP_ALLOWED_ORIGINS=https://claude.ai`.
const ENV_ALLOWED_ORIGINS: &str = "MATRIX_MCP_ALLOWED_ORIGINS";
/// Base URL of an OpenAI-compatible TTS endpoint (Chatterbox /
/// `POST /v1/audio/speech`). Optional — if unset, the
/// `send_tts_voice_message` tool returns `invalid_params`.
const ENV_TTS_BASE_URL: &str = "MATRIX_MCP_TTS_BASE_URL";
/// Bearer token sent to the TTS endpoint above. Must be set if (and
/// only if) `MATRIX_MCP_TTS_BASE_URL` is set.
const ENV_TTS_BEARER_TOKEN: &str = "MATRIX_MCP_TTS_BEARER_TOKEN";

const DEFAULT_RATE_LIMIT_READS: u32 = 60;
const DEFAULT_RATE_LIMIT_WRITES: u32 = 30;
const DEFAULT_DOWNLOAD_MAX_BYTES: u64 = 5 * 1024 * 1024;
pub const DEFAULT_UPLOAD_MAX_BYTES: usize = 10 * 1024 * 1024; // 10 MiB
const DEFAULT_TRUSTED_PROXY_HOPS: usize = 1;

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
    /// Per-minute read quota (Phase 6.1). 0 is rejected at parse time.
    pub rate_limit_reads_per_min: u32,
    /// Per-minute write quota (Phase 6.1). 0 is rejected at parse time.
    pub rate_limit_writes_per_min: u32,
    /// Maximum attachment size (bytes) that `download_attachment` will
    /// fetch. Declared size is checked against this cap before any
    /// network I/O; downloads whose info.size exceeds it are rejected
    /// with `invalid_params`. Default: 5 MiB.
    pub download_max_bytes: u64,
    /// Maximum image size (bytes) that `send_image_from_url` will fetch
    /// from a remote URL before uploading to the homeserver media repo.
    /// Defaults to 10 MiB.
    pub upload_max_bytes: usize,
    /// Number of trusted proxies in front of matrix-mcp. Used to pick
    /// the real client IP out of `X-Forwarded-For` for the
    /// `/token/introspect` audit endpoint. Defaults to 1 (Traefik in
    /// front in production); set to 0 in dev / direct-hosted setups so
    /// that an attacker-supplied XFF header is never recorded as the
    /// client IP.
    pub trusted_proxy_hops: usize,
    /// Persistent Matrix device id for this matrix-mcp instance. Resolved
    /// from `<store_root>/.device-id` at startup, with one-shot env-var
    /// bootstrap and random fallback. See [`crate::device_identity`].
    /// Advertised in the protected-resource metadata as the
    /// device-binding OAuth scope claude.ai requests.
    pub device_id: String,
    /// Browser origins accepted on `/mcp`. Empty disables `Origin`
    /// validation (rmcp still validates `Host` against `allowed_hosts`).
    /// See [`ENV_ALLOWED_ORIGINS`].
    pub allowed_origins: Vec<String>,
    /// Optional TTS endpoint config. When `Some`, `send_tts_voice_message`
    /// posts text to `{base_url}/audio/speech` and forwards the
    /// returned audio as a Matrix voice message. When `None`, the
    /// tool returns `invalid_params`.
    pub tts: Option<TtsConfig>,
}

#[derive(Clone)]
pub struct TtsConfig {
    /// e.g. `https://tts.oddie.media/v1`. Trailing slash stripped.
    pub base_url: String,
    /// Bearer token. Logged as `<redacted>`.
    pub bearer_token: String,
}

impl std::fmt::Debug for TtsConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TtsConfig")
            .field("base_url", &self.base_url)
            .field("bearer_token", &"<redacted>")
            .finish()
    }
}

#[derive(Clone)]
pub struct StoreConfig {
    /// Root directory for per-user encrypted `SQLite` stores. Each stable
    /// MAS subject/device owner key gets a subdirectory
    /// `sha256(owner_key)[..32]/`.
    pub root: PathBuf,
    /// 32+ byte secret used as HKDF input keying material. The per-user
    /// store-cipher passphrase is `HKDF-SHA256(salt=owner_key, ikm=pepper,
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
        // NOT slash-stripped: this value is an OAuth *issuer identifier*, not
        // a base URL. RFC 8414 §3.3 (and the MCP authorization spec, which
        // cites it) has clients compare the `issuer` in the fetched metadata
        // against this string exactly — `https://as.example/` and
        // `https://as.example` are different identifiers, and a strict client
        // MUST refuse the metadata on a mismatch. MAS publishes its issuer
        // with a trailing slash, so configure it with one. Use
        // [`Self::authorization_server_base`] when concatenating endpoint
        // paths.
        let authorization_server = authorization_server.into().trim().to_owned();
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
            metrics_bind_addr: SocketAddr::from(([127, 0, 0, 1], 9090)),
            server_name,
            homeserver_url,
            introspection: None,
            store: None,
            rate_limit_reads_per_min: DEFAULT_RATE_LIMIT_READS,
            rate_limit_writes_per_min: DEFAULT_RATE_LIMIT_WRITES,
            download_max_bytes: DEFAULT_DOWNLOAD_MAX_BYTES,
            upload_max_bytes: DEFAULT_UPLOAD_MAX_BYTES,
            trusted_proxy_hops: DEFAULT_TRUSTED_PROXY_HOPS,
            // Tests and `from_env` overwrite this; the placeholder makes
            // it obvious in any accidental dump that resolution hasn't
            // run yet.
            device_id: "UNRESOLVED".to_owned(),
            allowed_origins: Vec::new(),
            tts: None,
        })
    }

    /// The authorization server URL with any trailing slash removed, for
    /// building endpoint URLs (`{base}/oauth2/token`). Never advertise this
    /// form — [`Self::authorization_server`] is the identifier clients compare
    /// against the AS metadata document.
    #[must_use]
    pub fn authorization_server_base(&self) -> &str {
        self.authorization_server.trim_end_matches('/')
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

    /// Builder-style: attach TTS endpoint config. Unset on boot if
    /// the operator hasn't set both `MATRIX_MCP_TTS_BASE_URL` and
    /// `MATRIX_MCP_TTS_BEARER_TOKEN`.
    #[must_use]
    pub fn with_tts(mut self, tts: TtsConfig) -> Self {
        self.tts = Some(tts);
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
        // Resolve the metrics bind address — never defaults to 0.0.0.0.
        // Preference order:
        //   1. MATRIX_MCP_METRICS_BIND_ADDR (operator override, parsed as-is)
        //   2. POD_IP:9090 (downward-API injection in K8s — Alloy targets this)
        //   3. 127.0.0.1:9090 (local dev fallback; no K8s)
        let explicit_addr = std::env::var(ENV_METRICS_BIND_ADDR).ok();
        let pod_ip = std::env::var(ENV_POD_IP).ok();
        let metrics_bind_addr =
            resolve_metrics_bind_addr(explicit_addr.as_deref(), pod_ip.as_deref())?;
        let client_id = require_env(ENV_INTROSPECTION_CLIENT_ID)?;
        let client_secret = require_env(ENV_INTROSPECTION_CLIENT_SECRET)?;
        let store_root = PathBuf::from(require_env(ENV_STORE_DIR)?);
        let pepper = require_env(ENV_STORE_PEPPER)?;
        // Resolve the per-PVC Matrix device id. See `crate::device_identity`
        // for the full lifecycle (PVC-persisted, one-shot env bootstrap,
        // random fallback on fresh PVC).
        let bootstrap_device_id =
            std::env::var(crate::device_identity::ENV_BOOTSTRAP_DEVICE_ID).ok();
        let device_id =
            crate::device_identity::resolve_device_id(&store_root, bootstrap_device_id.as_deref())
                .context("resolve matrix device id")?;
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
        cfg.rate_limit_reads_per_min =
            parse_rate_limit(ENV_RATE_LIMIT_READS, DEFAULT_RATE_LIMIT_READS)?;
        cfg.rate_limit_writes_per_min =
            parse_rate_limit(ENV_RATE_LIMIT_WRITES, DEFAULT_RATE_LIMIT_WRITES)?;
        cfg.download_max_bytes = parse_download_max_bytes()?;
        cfg.upload_max_bytes = parse_upload_max_bytes()?;
        cfg.trusted_proxy_hops = parse_trusted_proxy_hops()?;
        cfg.device_id = device_id;
        cfg.allowed_origins = parse_allowed_origins(std::env::var(ENV_ALLOWED_ORIGINS).ok());
        if let Some(tts) = parse_tts_config()? {
            cfg = cfg.with_tts(tts);
        }
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

/// Split `MATRIX_MCP_ALLOWED_ORIGINS` on commas, trimming whitespace and
/// dropping empties. Entries are passed to rmcp verbatim; it compares them per
/// RFC 6454 `(scheme, host, port)`, so each must carry a scheme
/// (`https://claude.ai`, not `claude.ai`). `"null"` matches a browser's
/// `Origin: null`.
fn parse_allowed_origins(raw: Option<String>) -> Vec<String> {
    raw.map(|v| {
        v.split(',')
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(str::to_owned)
            .collect()
    })
    .unwrap_or_default()
}

/// `(MATRIX_MCP_TTS_BASE_URL, MATRIX_MCP_TTS_BEARER_TOKEN)` should
/// either both be set or both be unset. A partial configuration is
/// almost certainly an ESO race during a rollout (one env var
/// landed before the other) — we log a warning and treat TTS as
/// disabled instead of crashlooping the pod, so the rest of the
/// server stays available while the secret catches up.
fn parse_tts_config() -> Result<Option<TtsConfig>> {
    let url = std::env::var(ENV_TTS_BASE_URL).ok();
    let token = std::env::var(ENV_TTS_BEARER_TOKEN).ok();
    match (url, token) {
        (None, None) => Ok(None),
        (Some(url), Some(token)) if !token.is_empty() => {
            let base_url = strip_trailing_slash(url);
            validate_url(&base_url, ENV_TTS_BASE_URL)?;
            Ok(Some(TtsConfig {
                base_url,
                bearer_token: token,
            }))
        }
        (Some(_), Some(_)) => {
            tracing::warn!(
                "{ENV_TTS_BEARER_TOKEN} is set but empty — disabling TTS \
                 (send_tts_voice_message will return invalid_params)"
            );
            Ok(None)
        }
        (Some(_), None) => {
            tracing::warn!(
                "{ENV_TTS_BASE_URL} is set but {ENV_TTS_BEARER_TOKEN} is not — \
                 disabling TTS (send_tts_voice_message will return invalid_params)"
            );
            Ok(None)
        }
        (None, Some(_)) => {
            tracing::warn!(
                "{ENV_TTS_BEARER_TOKEN} is set but {ENV_TTS_BASE_URL} is not — \
                 disabling TTS (send_tts_voice_message will return invalid_params)"
            );
            Ok(None)
        }
    }
}

/// Resolve the metrics listener bind address from the environment inputs.
///
/// Priority order (defence-in-depth — never returns `0.0.0.0` by default):
///
/// 1. `explicit_addr` — the value of `MATRIX_MCP_METRICS_BIND_ADDR` if set.
///    Parsed verbatim; allows an operator to override with any address.
/// 2. `pod_ip` — the value of `POD_IP` (K8s downward-API injection). When
///    present, binds to `{pod_ip}:9090`. Alloy can still reach it via the pod
///    IP annotation, but the listener is not visible on every pod-network peer.
/// 3. Fallback — `127.0.0.1:9090`. Used in local dev where no K8s is present.
fn resolve_metrics_bind_addr(
    explicit_addr: Option<&str>,
    pod_ip: Option<&str>,
) -> Result<SocketAddr> {
    let addr_str: String = explicit_addr.map_or_else(
        || pod_ip.map_or_else(|| "127.0.0.1:9090".to_owned(), |ip| format!("{ip}:9090")),
        str::to_owned,
    );
    SocketAddr::from_str(&addr_str)
        .with_context(|| format!("invalid {ENV_METRICS_BIND_ADDR}: {addr_str}"))
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

fn parse_rate_limit(key: &str, default: u32) -> Result<u32> {
    let Ok(raw) = std::env::var(key) else {
        return Ok(default);
    };
    let n: u32 = raw
        .parse()
        .with_context(|| format!("{key} must be a positive integer, got `{raw}`"))?;
    if n == 0 {
        anyhow::bail!("{key} must be > 0 (use a large value like 100000 to effectively disable)");
    }
    Ok(n)
}

fn parse_download_max_bytes() -> Result<u64> {
    let Ok(raw) = std::env::var(ENV_DOWNLOAD_MAX_BYTES) else {
        return Ok(DEFAULT_DOWNLOAD_MAX_BYTES);
    };
    raw.parse().with_context(|| {
        format!("{ENV_DOWNLOAD_MAX_BYTES} must be a non-negative integer, got `{raw}`")
    })
}

fn parse_trusted_proxy_hops() -> Result<usize> {
    let Ok(raw) = std::env::var(ENV_TRUSTED_PROXY_HOPS) else {
        return Ok(DEFAULT_TRUSTED_PROXY_HOPS);
    };
    raw.parse().with_context(|| {
        format!("{ENV_TRUSTED_PROXY_HOPS} must be a non-negative integer, got `{raw}`")
    })
}

fn parse_upload_max_bytes() -> Result<usize> {
    let Ok(raw) = std::env::var(ENV_UPLOAD_MAX_BYTES) else {
        return Ok(DEFAULT_UPLOAD_MAX_BYTES);
    };
    let n: usize = raw.parse().with_context(|| {
        format!("{ENV_UPLOAD_MAX_BYTES} must be a positive integer (bytes), got `{raw}`")
    })?;
    if n == 0 {
        anyhow::bail!(
            "{ENV_UPLOAD_MAX_BYTES} must be > 0              (use a large value to effectively remove the cap)"
        );
    }
    Ok(n)
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
            "https://auth.example.test",
            "https://matrix.example.test/",
            "example.test",
            bind(),
        )
        .unwrap();
        assert_eq!(cfg.resource_url, "https://example.test");
        assert_eq!(cfg.homeserver_url, "https://matrix.example.test");
    }

    /// The AS issuer is compared byte-for-byte by clients (RFC 8414 §3.3), so
    /// a configured trailing slash must survive into the metadata document —
    /// while endpoint URLs built from it must not double up on slashes.
    #[test]
    fn authorization_server_keeps_its_trailing_slash() {
        let cfg = Config::new(
            "https://example.test",
            "https://auth.example.test/",
            "https://matrix.example.test",
            "example.test",
            bind(),
        )
        .unwrap();
        assert_eq!(cfg.authorization_server, "https://auth.example.test/");
        assert_eq!(cfg.authorization_server_base(), "https://auth.example.test");
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

    // --- metrics bind address resolution ---

    #[test]
    fn metrics_bind_defaults_to_loopback_without_pod_ip() {
        // No MATRIX_MCP_METRICS_BIND_ADDR, no POD_IP → loopback fallback.
        let addr = resolve_metrics_bind_addr(None, None).unwrap();
        assert_eq!(addr, SocketAddr::from(([127, 0, 0, 1], 9090)));
    }

    #[test]
    fn metrics_bind_uses_pod_ip_when_present() {
        // POD_IP set, no explicit override → bind to pod IP.
        let addr = resolve_metrics_bind_addr(None, Some("10.42.3.7")).unwrap();
        assert_eq!(addr, SocketAddr::from(([10, 42, 3, 7], 9090)));
    }

    #[test]
    fn metrics_bind_explicit_overrides_pod_ip() {
        // Explicit MATRIX_MCP_METRICS_BIND_ADDR wins over POD_IP.
        let addr = resolve_metrics_bind_addr(Some("0.0.0.0:9091"), Some("10.42.3.7")).unwrap();
        assert_eq!(addr, SocketAddr::from(([0, 0, 0, 0], 9091)));
    }

    #[test]
    fn metrics_bind_explicit_without_pod_ip() {
        // Explicit addr, no POD_IP.
        let addr = resolve_metrics_bind_addr(Some("192.168.1.5:9090"), None).unwrap();
        assert_eq!(addr, SocketAddr::from(([192, 168, 1, 5], 9090)));
    }

    #[test]
    fn metrics_bind_invalid_explicit_addr_is_an_error() {
        let err = resolve_metrics_bind_addr(Some("not-an-addr"), None).unwrap_err();
        let msg = format!("{err:#}");
        assert!(msg.contains("invalid"), "error was: {msg}");
    }

    #[test]
    fn config_new_metrics_default_is_loopback() {
        // Config::new is used by tests / local dev — must default to loopback.
        let cfg = Config::new(
            "https://example.test",
            "https://auth.example.test",
            "https://matrix.example.test",
            "example.test",
            bind(),
        )
        .unwrap();
        assert_eq!(
            cfg.metrics_bind_addr,
            SocketAddr::from(([127, 0, 0, 1], 9090)),
            "Config::new must default to loopback, not 0.0.0.0"
        );
    }
}
