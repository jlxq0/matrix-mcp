//! OAuth 2.0 Protected Resource Metadata (RFC 9728).
//!
//! claude.ai discovers our authorization server by following the
//! `WWW-Authenticate` header on a 401 to this document. We expose the
//! minimum required to drive the dance: `resource`, `authorization_servers`,
//! `bearer_methods_supported`, and a list of scopes claude needs to request
//! to operate on the user's behalf.

use axum::Json;
use axum::extract::State;
use axum::response::IntoResponse;
use serde::Serialize;

use crate::config::Config;

/// Matches RFC 9728 §3.2. Optional fields are omitted with
/// `#[serde(skip_serializing_if = "Option::is_none")]` to keep the document
/// terse and stable.
#[derive(Debug, Serialize)]
pub struct ProtectedResourceMetadata {
    pub resource: String,
    pub authorization_servers: Vec<String>,
    pub bearer_methods_supported: Vec<&'static str>,
    pub scopes_supported: Vec<String>,
}

/// The canonical resource identifier for this MCP server: the full endpoint
/// URL, including the `/mcp` path. RFC 9728 §3.3 and the MCP authorization
/// spec require the `resource` field to match the URL the client actually
/// connects to. claude.ai tolerates the bare origin; stricter clients (e.g.
/// `LangDock`) reject anything that isn't the exact endpoint. `resource_url`
/// is the origin and `/mcp` is where [`crate::main`] nests the MCP service.
pub fn mcp_resource(resource_url: &str) -> String {
    format!("{resource_url}/mcp")
}

/// The scopes a client must hold to drive this server. Shared by the RFC 9728
/// `scopes_supported` field and the `scope` parameter of the
/// `WWW-Authenticate` challenge, so the two can never drift.
pub fn required_scopes(cfg: &Config) -> Vec<String> {
    vec![
        "openid".to_owned(),
        // Matrix C-S API access scope (MSC3861). Issues an
        // OAuth token Synapse accepts on `/_matrix/*`.
        "urn:matrix:org.matrix.msc2967.client:api:*".to_owned(),
        // Device-binding scope (MSC2967). When the client
        // requests this, MAS creates the device under the
        // authorising user's account and binds the issued
        // token to it. Without this, the token is "deviceless"
        // and matrix-sdk can't use it for E2EE (no vodozemac
        // identity to attach, no cross-signing target).
        format!(
            "urn:matrix:org.matrix.msc2967.client:device:{}",
            cfg.device_id
        ),
    ]
}

impl ProtectedResourceMetadata {
    pub fn from_config(cfg: &Config) -> Self {
        Self {
            resource: mcp_resource(&cfg.resource_url),
            authorization_servers: vec![cfg.authorization_server.clone()],
            bearer_methods_supported: vec!["header"],
            scopes_supported: required_scopes(cfg),
        }
    }
}

#[allow(clippy::unused_async)] // Axum requires async handlers.
pub async fn protected_resource_metadata(State(cfg): State<Config>) -> impl IntoResponse {
    Json(ProtectedResourceMetadata::from_config(&cfg))
}

#[derive(Debug, Serialize)]
pub struct AuthorizationServerMetadata {
    pub issuer: String,
    pub authorization_endpoint: String,
    pub token_endpoint: String,
    pub registration_endpoint: String,
    pub response_types_supported: Vec<&'static str>,
    pub grant_types_supported: Vec<&'static str>,
    pub code_challenge_methods_supported: Vec<&'static str>,
    pub token_endpoint_auth_methods_supported: Vec<&'static str>,
    pub scopes_supported: Vec<String>,
}

impl AuthorizationServerMetadata {
    pub fn from_config(cfg: &Config) -> Self {
        let mas = cfg.authorization_server.trim_end_matches('/');
        Self {
            // RFC 8414: issuer must match the origin this document is served from.
            issuer: cfg.resource_url.clone(),
            authorization_endpoint: format!("{mas}/authorize"),
            token_endpoint: format!("{mas}/oauth2/token"),
            registration_endpoint: format!("{mas}/oauth2/registration"),
            response_types_supported: vec!["code"],
            grant_types_supported: vec!["authorization_code", "refresh_token"],
            code_challenge_methods_supported: vec!["S256"],
            token_endpoint_auth_methods_supported: vec!["none"],
            scopes_supported: ProtectedResourceMetadata::from_config(cfg).scopes_supported,
        }
    }
}

#[allow(clippy::unused_async)]
pub async fn authorization_server_metadata(State(cfg): State<Config>) -> impl IntoResponse {
    Json(AuthorizationServerMetadata::from_config(&cfg))
}

/// Build the `WWW-Authenticate` value our 401 responses set when no valid
/// token is presented. Clients parse `resource_metadata` and walk back to
/// discover the authorization server.
///
/// We point at the RFC 9728 §3.1 *path-inserted* metadata URL
/// (`/.well-known/oauth-protected-resource/mcp`) — the well-known location
/// for the `{origin}/mcp` resource. We also serve the metadata at the bare
/// `/.well-known/oauth-protected-resource` for clients that probe the root.
///
/// The `scope` parameter (RFC 6750 §3) is the MCP authorization spec's
/// preferred way to tell a client what to ask for: clients that read it
/// request exactly these scopes instead of guessing from `scopes_supported`.
/// Without it, a client that never fetches the metadata document (or one that
/// drops the dynamic device scope) authorizes without device binding and
/// silently loses E2EE.
pub fn www_authenticate_header(cfg: &Config) -> String {
    let resource_url = &cfg.resource_url;
    let scope = required_scopes(cfg).join(" ");
    format!(
        r#"Bearer resource_metadata="{resource_url}/.well-known/oauth-protected-resource/mcp", scope="{scope}""#
    )
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use std::net::SocketAddr;

    use axum::Router;
    use axum::body::Body;
    use axum::http::{Request, StatusCode};
    use axum::routing::get;
    use serde_json::Value;
    use tower::ServiceExt;

    use super::*;

    fn test_config() -> Config {
        let mut cfg = Config::new(
            "https://example.test",
            "https://auth.example.test",
            "https://matrix.example.test",
            "example.test",
            SocketAddr::from(([0, 0, 0, 0], 3000)),
        )
        .unwrap();
        cfg.device_id = "TESTDEVICE".to_owned();
        cfg
    }

    fn router_with_cfg(cfg: Config) -> Router {
        Router::new()
            .route(
                "/.well-known/oauth-protected-resource",
                get(protected_resource_metadata),
            )
            .with_state(cfg)
    }

    #[tokio::test]
    async fn metadata_endpoint_returns_expected_shape() {
        let app = router_with_cfg(test_config());
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

        let body = axum::body::to_bytes(response.into_body(), 4096)
            .await
            .unwrap();
        let json: Value = serde_json::from_slice(&body).unwrap();

        assert_eq!(json["resource"], "https://example.test/mcp");
        assert_eq!(
            json["authorization_servers"][0],
            "https://auth.example.test"
        );
        assert_eq!(json["bearer_methods_supported"][0], "header");
        let scopes = json["scopes_supported"].as_array().unwrap();
        assert!(
            scopes
                .iter()
                .any(|s| s == "urn:matrix:org.matrix.msc2967.client:api:*"),
            "C-S api scope missing in {json}"
        );
        // Device-binding scope: without this in the metadata, claude.ai
        // requests a deviceless token and E2EE breaks. Regression lock.
        assert!(
            scopes
                .iter()
                .any(|s| s == "urn:matrix:org.matrix.msc2967.client:device:TESTDEVICE"),
            "device scope missing or wrong shape in {json}"
        );
    }

    #[test]
    fn www_authenticate_includes_resource_metadata_url() {
        let header = www_authenticate_header(&test_config());
        assert!(header.starts_with("Bearer "));
        assert!(header.contains(
            r#"resource_metadata="https://example.test/.well-known/oauth-protected-resource/mcp""#
        ));
    }

    /// MCP authorization spec: servers SHOULD include `scope` in the
    /// challenge, and clients treat it as authoritative. The dynamic device
    /// scope has to be in there or the client authorizes deviceless and E2EE
    /// breaks.
    #[test]
    fn www_authenticate_includes_required_scopes() {
        let header = www_authenticate_header(&test_config());
        assert!(
            header.contains(r#"scope=""#),
            "no scope parameter: {header}"
        );
        assert!(header.contains("urn:matrix:org.matrix.msc2967.client:api:*"));
        assert!(header.contains("urn:matrix:org.matrix.msc2967.client:device:TESTDEVICE"));
    }

    #[test]
    fn from_config_strips_extra_data() {
        let meta = ProtectedResourceMetadata::from_config(&test_config());
        assert_eq!(meta.resource, "https://example.test/mcp");
        assert_eq!(meta.authorization_servers.len(), 1);
        assert!(meta.bearer_methods_supported.contains(&"header"));
    }

    #[test]
    fn as_metadata_advertises_mas_registration() {
        let meta = AuthorizationServerMetadata::from_config(&test_config());
        assert_eq!(meta.issuer, "https://example.test");
        assert_eq!(
            meta.registration_endpoint,
            "https://auth.example.test/oauth2/registration"
        );
        assert_eq!(meta.authorization_endpoint, "https://auth.example.test/authorize");
    }
}
