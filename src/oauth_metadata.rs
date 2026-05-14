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
    pub scopes_supported: Vec<&'static str>,
}

impl ProtectedResourceMetadata {
    pub fn from_config(cfg: &Config) -> Self {
        Self {
            resource: cfg.resource_url.clone(),
            authorization_servers: vec![cfg.authorization_server.clone()],
            bearer_methods_supported: vec!["header"],
            scopes_supported: vec![
                "openid",
                // The Matrix C-S API scope minted by MAS via MSC3861. Claude
                // requests this so the token MAS issues is directly usable
                // against Synapse's client-server endpoints.
                "urn:matrix:org.matrix.msc2967.client:api:*",
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
        assert!(
            json["scopes_supported"]
                .as_array()
                .unwrap()
                .iter()
                .any(|s| s == "urn:matrix:org.matrix.msc2967.client:api:*"),
            "matrix scope missing in {json}"
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
