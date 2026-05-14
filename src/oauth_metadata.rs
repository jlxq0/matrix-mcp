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

/// Fixed Matrix device id this matrix-mcp instance pins itself to.
///
/// Why a constant: MSC2967 requires the device-binding OAuth scope to
/// be `urn:matrix:org.matrix.msc2967.client:device:<DEVICE_ID>` with a
/// concrete id (no wildcard). The connector client (claude.ai today)
/// reads scopes from our protected-resource metadata and requests them
/// verbatim, so the device id is whatever we *advertise* — there is
/// no negotiation step. matrix-mcp is single-tenant for now, so a
/// single device id is fine. When we onboard a second user we'll
/// need to derive a per-user device id (e.g. `MATRIXMCP<short-hash>`)
/// and serve a per-request metadata document, or use a different
/// device-binding flow entirely.
///
/// The id is ASCII, Crockford-base32-ish, ≤ 32 chars so Synapse's
/// device-id surface doesn't complain. Element X will surface this
/// string in the device list, so it's deliberately recognisable.
pub const MATRIX_MCP_DEVICE_ID: &str = "MATRIXMCPCONNECTOR";

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

impl ProtectedResourceMetadata {
    pub fn from_config(cfg: &Config) -> Self {
        Self {
            resource: cfg.resource_url.clone(),
            authorization_servers: vec![cfg.authorization_server.clone()],
            bearer_methods_supported: vec!["header"],
            scopes_supported: vec![
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
                format!("urn:matrix:org.matrix.msc2967.client:device:{MATRIX_MCP_DEVICE_ID}"),
            ],
        }
    }
}

#[allow(clippy::unused_async)] // Axum requires async handlers.
pub async fn protected_resource_metadata(State(cfg): State<Config>) -> impl IntoResponse {
    Json(ProtectedResourceMetadata::from_config(&cfg))
}

/// Build the `WWW-Authenticate` value our 401 responses set when no valid
/// token is presented. claude.ai parses `resource_metadata` and walks back
/// to discover the authorization server.
pub fn www_authenticate_header(resource_url: &str) -> String {
    format!(r#"Bearer resource_metadata="{resource_url}/.well-known/oauth-protected-resource""#)
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
        Config::new(
            "https://example.test",
            "https://auth.example.test",
            "https://matrix.example.test",
            "example.test",
            SocketAddr::from(([0, 0, 0, 0], 3000)),
        )
        .unwrap()
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

        assert_eq!(json["resource"], "https://example.test");
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
                .any(|s| s == "urn:matrix:org.matrix.msc2967.client:device:MATRIXMCPCONNECTOR"),
            "device scope missing in {json}"
        );
    }

    #[test]
    fn www_authenticate_includes_resource_metadata_url() {
        let header = www_authenticate_header("https://example.test");
        assert!(header.starts_with("Bearer "));
        assert!(header.contains(
            r#"resource_metadata="https://example.test/.well-known/oauth-protected-resource""#
        ));
    }

    #[test]
    fn from_config_strips_extra_data() {
        let meta = ProtectedResourceMetadata::from_config(&test_config());
        assert_eq!(meta.resource, "https://example.test");
        assert_eq!(meta.authorization_servers.len(), 1);
        assert!(meta.bearer_methods_supported.contains(&"header"));
    }
}
