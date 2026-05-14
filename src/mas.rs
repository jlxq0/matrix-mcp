//! Client for the MAS OAuth 2.0 Token Introspection endpoint (RFC 7662) +
//! a small in-memory cache of validated responses.
//!
//! Responsibilities:
//! - Authenticate to MAS as a registered client (`client_id` + `client_secret`).
//! - POST the user's bearer token to `/oauth2/introspect`.
//! - Parse `active`, `sub`, `scope`, `aud`, `device_id` from the response.
//! - Validate the audience matches our resource URL (RFC 8707 binding).
//! - Cache positive results for 60 s OR until the token expires, whichever
//!   is sooner. Negative results are not cached (a fresh token presented
//!   immediately should not be rejected because a stale failure cached it).
//!
//! Non-goals (yet):
//! - Refresh token handling (claude.ai owns that; we only see access tokens)
//! - Token revocation propagation other than via cache TTL expiry

use std::collections::HashMap;
use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use serde::Deserialize;
use sha2::{Digest, Sha256};
use thiserror::Error;
use tracing::{debug, warn};

/// Maximum age of a cached introspection result. Bounded so revocations
/// propagate in at most this window even if a token's own `exp` is later.
///
/// `from_secs(60)` over `from_mins(1)` because the latter is unstable
/// on stable Rust as of 1.93. Clippy's nudge is correct in spirit, but
/// hitting an unstable API is worse than the readability win.
#[allow(clippy::duration_suboptimal_units)]
const MAX_CACHE_TTL: Duration = Duration::from_secs(60);

/// Soft cap on the cache size. Above this, the next miss triggers a sweep
/// of expired entries. We never expect to be over this in normal operation
/// (one user, one device, one or two refresh cycles per hour).
const CACHE_SOFT_CAP: usize = 256;

/// What MAS sent us back. The fields we actually care about; MAS may include
/// more.
#[derive(Debug, Deserialize, Clone)]
pub struct IntrospectionResponse {
    pub active: bool,
    pub sub: Option<String>,
    #[allow(dead_code)] // Surfaced in audit logs in phase 1.4; field-validated below.
    pub scope: Option<String>,
    pub aud: Option<AudField>,
    pub exp: Option<i64>,
    pub device_id: Option<String>,
}

/// `aud` in JWT-land can be either a single string or an array. MAS today
/// emits a single string when there's one audience; we still accept both
/// shapes so the code survives a future schema change.
#[derive(Debug, Deserialize, Clone)]
#[serde(untagged)]
pub enum AudField {
    Single(String),
    Multi(Vec<String>),
}

impl AudField {
    pub fn matches(&self, expected: &str) -> bool {
        match self {
            Self::Single(s) => s == expected,
            Self::Multi(xs) => xs.iter().any(|s| s == expected),
        }
    }
}

/// What our auth layer hands to the rest of the application after a
/// successful introspection. Stable across token refreshes for the same
/// user/device — only what the tool layer needs to act.
///
/// `device_id` and `raw_scope` are unread today; the `whoami` tool added in
/// phase 1.3 starts reading both.
#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct AuthenticatedIdentity {
    pub mxid: String,
    pub device_id: Option<String>,
    pub raw_scope: Option<String>,
}

#[derive(Debug, Error)]
pub enum IntrospectionError {
    #[error("audience mismatch: token aud does not include {expected}")]
    AudienceMismatch { expected: String },
    #[error("MAS HTTP error: {0}")]
    Http(#[from] reqwest::Error),
    #[error("MAS introspection endpoint returned non-2xx: {status}")]
    Upstream { status: u16 },
}

#[derive(Clone, Debug)]
pub struct MasIntrospectionClient {
    http: reqwest::Client,
    introspection_url: String,
    expected_audience: String,
    client_id: String,
    client_secret: String,
    cache: Arc<RwLock<HashMap<[u8; 32], CacheEntry>>>,
}

#[derive(Clone, Debug)]
struct CacheEntry {
    identity: AuthenticatedIdentity,
    expires_at: Instant,
}

impl MasIntrospectionClient {
    /// Build a client. The introspection URL is derived from the
    /// authorization-server URL plus `/oauth2/introspect`, which is the path
    /// MAS exposes (and the RFC 7662 convention).
    pub fn new(
        authorization_server: &str,
        expected_audience: String,
        client_id: String,
        client_secret: String,
    ) -> Result<Self> {
        let introspection_url = format!("{authorization_server}/oauth2/introspect");
        let http = reqwest::Client::builder()
            .timeout(Duration::from_secs(5))
            .user_agent(concat!("matrix-mcp/", env!("CARGO_PKG_VERSION")))
            .build()
            .context("build reqwest client")?;
        Ok(Self {
            http,
            introspection_url,
            expected_audience,
            client_id,
            client_secret,
            cache: Arc::new(RwLock::new(HashMap::new())),
        })
    }

    /// Validate a bearer token. Returns `Ok(Some(identity))` on success,
    /// `Ok(None)` if MAS reports the token is inactive or mis-audienced,
    /// `Err` only for transport/upstream failures.
    pub async fn introspect(
        &self,
        token: &str,
    ) -> Result<Option<AuthenticatedIdentity>, IntrospectionError> {
        let key = hash_token(token);

        if let Some(hit) = self.cache_lookup(&key) {
            debug!("introspection cache hit");
            return Ok(Some(hit));
        }

        let response = self
            .http
            .post(&self.introspection_url)
            .basic_auth(&self.client_id, Some(&self.client_secret))
            .form(&[("token", token)])
            .send()
            .await?;

        if !response.status().is_success() {
            return Err(IntrospectionError::Upstream {
                status: response.status().as_u16(),
            });
        }

        let body: IntrospectionResponse = response.json().await?;

        if !body.active {
            return Ok(None);
        }
        // RFC 8707 resource indicator validation: the token MUST have been
        // issued with us in mind. If MAS hands back a token whose `aud`
        // doesn't include our resource URL, refuse it.
        let Some(aud) = &body.aud else {
            warn!("MAS returned active token without aud claim");
            return Ok(None);
        };
        if !aud.matches(&self.expected_audience) {
            return Err(IntrospectionError::AudienceMismatch {
                expected: self.expected_audience.clone(),
            });
        }
        let Some(mxid) = body.sub.clone() else {
            warn!("MAS returned active token without sub");
            return Ok(None);
        };

        let identity = AuthenticatedIdentity {
            mxid,
            device_id: body.device_id.clone(),
            raw_scope: body.scope.clone(),
        };

        self.cache_insert(key, &identity, body.exp);

        Ok(Some(identity))
    }

    fn cache_lookup(&self, key: &[u8; 32]) -> Option<AuthenticatedIdentity> {
        // Bind the guard explicitly + drop early to satisfy
        // clippy::significant_drop_in_scrutinee. The guard is short-lived
        // either way; making it explicit keeps the next reader on rails.
        let guard = self.cache.read().ok()?;
        let result = guard
            .get(key)
            .and_then(|entry| (entry.expires_at > Instant::now()).then(|| entry.identity.clone()));
        drop(guard);
        result
    }

    fn cache_insert(
        &self,
        key: [u8; 32],
        identity: &AuthenticatedIdentity,
        token_exp: Option<i64>,
    ) {
        let token_ttl = token_exp.and_then(|exp| {
            let secs = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .ok()?
                .as_secs();
            // Cap at i64::MAX to make the subtraction safe; in practice
            // `now` is nowhere near that.
            let now = i64::try_from(secs).ok()?;
            if exp <= now {
                return None;
            }
            // exp - now is positive here, so the cast back to u64 is safe.
            let remaining = u64::try_from(exp - now).ok()?;
            Some(Duration::from_secs(remaining))
        });
        let ttl = token_ttl.unwrap_or(MAX_CACHE_TTL).min(MAX_CACHE_TTL);
        let entry = CacheEntry {
            identity: identity.clone(),
            expires_at: Instant::now() + ttl,
        };

        let Ok(mut guard) = self.cache.write() else {
            return;
        };

        if guard.len() >= CACHE_SOFT_CAP {
            // Cheap sweep: drop expired entries on overflow. Saves us from a
            // dedicated background task at this scale.
            let now = Instant::now();
            guard.retain(|_, e| e.expires_at > now);
        }
        guard.insert(key, entry);
    }
}

fn hash_token(token: &str) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(token.as_bytes());
    hasher.finalize().into()
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use serde_json::json;
    use wiremock::matchers::{body_string_contains, header, method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    use super::*;

    async fn server() -> MockServer {
        MockServer::start().await
    }

    fn client_against(server_uri: &str) -> MasIntrospectionClient {
        MasIntrospectionClient::new(
            server_uri,
            "https://matrix-mcp.example.test".to_owned(),
            "matrix-mcp-client".to_owned(),
            "secret-shh".to_owned(),
        )
        .unwrap()
    }

    fn active_response_body(aud: &str) -> serde_json::Value {
        json!({
            "active": true,
            "sub": "@julian:kampong.social",
            "scope": "openid urn:matrix:org.matrix.msc2967.client:api:*",
            "aud": aud,
            "device_id": "matrix-mcp-test-device",
            "exp": i64::try_from(
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_secs(),
            )
            .unwrap()
                + 300,
        })
    }

    #[tokio::test]
    async fn happy_path_returns_identity() {
        let mock = server().await;
        Mock::given(method("POST"))
            .and(path("/oauth2/introspect"))
            .and(header(
                "authorization",
                "Basic bWF0cml4LW1jcC1jbGllbnQ6c2VjcmV0LXNoaA==",
            ))
            .and(body_string_contains("token=abc123"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(active_response_body("https://matrix-mcp.example.test")),
            )
            .expect(1)
            .mount(&mock)
            .await;

        let client = client_against(&mock.uri());
        let identity = client.introspect("abc123").await.unwrap().unwrap();
        assert_eq!(identity.mxid, "@julian:kampong.social");
        assert_eq!(
            identity.device_id.as_deref(),
            Some("matrix-mcp-test-device")
        );
    }

    #[tokio::test]
    async fn inactive_returns_none() {
        let mock = server().await;
        Mock::given(method("POST"))
            .and(path("/oauth2/introspect"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({"active": false})))
            .mount(&mock)
            .await;
        let client = client_against(&mock.uri());
        assert!(client.introspect("xxx").await.unwrap().is_none());
    }

    #[tokio::test]
    async fn audience_mismatch_errors() {
        let mock = server().await;
        Mock::given(method("POST"))
            .and(path("/oauth2/introspect"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(active_response_body("https://wrong.example.test")),
            )
            .mount(&mock)
            .await;
        let client = client_against(&mock.uri());
        let err = client.introspect("abc").await.unwrap_err();
        assert!(matches!(err, IntrospectionError::AudienceMismatch { .. }));
    }

    #[tokio::test]
    async fn multi_aud_array_accepted_if_resource_is_in_list() {
        let mock = server().await;
        Mock::given(method("POST"))
            .and(path("/oauth2/introspect"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "active": true,
                "sub": "@julian:kampong.social",
                "aud": ["https://other.example.test", "https://matrix-mcp.example.test"],
                "exp": i64::try_from(
                    std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .unwrap()
                        .as_secs(),
                )
                .unwrap()
                    + 300,
            })))
            .mount(&mock)
            .await;
        let client = client_against(&mock.uri());
        let identity = client.introspect("abc").await.unwrap().unwrap();
        assert_eq!(identity.mxid, "@julian:kampong.social");
    }

    #[tokio::test]
    async fn caches_positive_result() {
        let mock = server().await;
        Mock::given(method("POST"))
            .and(path("/oauth2/introspect"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(active_response_body("https://matrix-mcp.example.test")),
            )
            // The same token introspected twice → MAS should be hit ONCE.
            .expect(1)
            .mount(&mock)
            .await;
        let client = client_against(&mock.uri());
        let first = client.introspect("abc").await.unwrap();
        let second = client.introspect("abc").await.unwrap();
        assert!(first.is_some());
        assert!(second.is_some());
    }

    #[tokio::test]
    async fn cache_respects_short_token_exp() {
        // Token-exp shorter than MAX_CACHE_TTL → cache TTL clamps to exp.
        // We give the token exp=now+1s, then wait 2s, then introspect again
        // and expect MAS to be hit a SECOND time (cache miss).
        let mock = server().await;
        let now = i64::try_from(
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
        )
        .unwrap();
        let body = json!({
            "active": true,
            "sub": "@julian:kampong.social",
            "aud": "https://matrix-mcp.example.test",
            "exp": now + 1,
        });
        Mock::given(method("POST"))
            .and(path("/oauth2/introspect"))
            .respond_with(ResponseTemplate::new(200).set_body_json(body))
            // Two introspects with a 2s gap should hit MAS BOTH times because
            // the cache entry expired in between.
            .expect(2)
            .mount(&mock)
            .await;

        let client = client_against(&mock.uri());
        let first = client.introspect("short-lived").await.unwrap();
        assert!(first.is_some(), "first call must succeed");
        tokio::time::sleep(std::time::Duration::from_millis(1_500)).await;
        let second = client.introspect("short-lived").await.unwrap();
        assert!(second.is_some(), "second call must re-fetch");
        // The .expect(2) assertion on the mock verifies MAS was hit twice;
        // if the cache wrongly kept the entry past `exp`, MAS would only see 1.
    }

    #[tokio::test]
    async fn negative_result_not_cached() {
        // An inactive token must NOT be cached as a denial: a freshly-valid
        // token presented immediately after should not inherit the deny.
        let mock = server().await;
        Mock::given(method("POST"))
            .and(path("/oauth2/introspect"))
            // Two introspects with the same token → MAS must be hit both times
            // when the first returned inactive.
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({"active": false})))
            .expect(2)
            .mount(&mock)
            .await;

        let client = client_against(&mock.uri());
        let first = client.introspect("xxx").await.unwrap();
        let second = client.introspect("xxx").await.unwrap();
        assert!(first.is_none());
        assert!(second.is_none());
        // Mock's .expect(2) enforces no-caching of negative results.
    }

    #[tokio::test]
    async fn upstream_5xx_surfaces_as_error() {
        let mock = server().await;
        Mock::given(method("POST"))
            .and(path("/oauth2/introspect"))
            .respond_with(ResponseTemplate::new(503))
            .mount(&mock)
            .await;
        let client = client_against(&mock.uri());
        let err = client.introspect("abc").await.unwrap_err();
        assert!(matches!(err, IntrospectionError::Upstream { status: 503 }));
    }

    #[tokio::test]
    async fn missing_aud_returns_none() {
        let mock = server().await;
        Mock::given(method("POST"))
            .and(path("/oauth2/introspect"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "active": true,
                "sub": "@julian:kampong.social",
                "exp": 9_999_999_999i64,
            })))
            .mount(&mock)
            .await;
        let client = client_against(&mock.uri());
        let result = client.introspect("abc").await.unwrap();
        assert!(result.is_none());
    }

    #[test]
    fn hash_token_is_deterministic_and_collision_resistant() {
        // Sanity: same input → same hash; different inputs → different.
        let a = hash_token("token-a");
        let b = hash_token("token-a");
        let c = hash_token("token-b");
        assert_eq!(a, b);
        assert_ne!(a, c);
        assert_eq!(a.len(), 32);
    }

    #[test]
    fn aud_field_matches_single() {
        let single = AudField::Single("https://x".to_owned());
        assert!(single.matches("https://x"));
        assert!(!single.matches("https://y"));
    }

    #[test]
    fn aud_field_matches_multi() {
        let multi = AudField::Multi(vec!["https://x".into(), "https://y".into()]);
        assert!(multi.matches("https://x"));
        assert!(multi.matches("https://y"));
        assert!(!multi.matches("https://z"));
    }
}
