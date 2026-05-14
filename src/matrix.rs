//! Thin HTTP client for the Matrix client-server API.
//!
//! Phase 2 (plaintext rooms only) needs exactly three endpoints:
//!
//! 1. `GET  /_matrix/client/v3/joined_rooms`        — list joined rooms
//! 2. `GET  /_matrix/client/v3/rooms/{id}/messages` — paginated event history
//! 3. `PUT  /_matrix/client/v3/rooms/{id}/send/m.room.message/{txn}` — send
//!
//! We deliberately avoid pulling in `matrix-rust-sdk` here: it's a fat
//! dependency that pulls vodozemac, sqlite, the whole event store, and an
//! active sync loop — none of which are useful for stateless tool calls.
//! Phase 3 (E2EE) will bring in the SDK's crypto layer when we actually
//! need it.
//!
//! All methods take a `bearer` token explicitly. Per MSC3861, the OAuth
//! access token issued by MAS is the same token Synapse accepts on
//! `/_matrix/*` endpoints, so we just round-trip the user's bearer token.

use std::time::Duration;

use anyhow::{Context, Result};
use rand::Rng;
use rand::distributions::Alphanumeric;
use rmcp::schemars::{self, JsonSchema};
use serde::{Deserialize, Serialize};
use tracing::debug;

/// A thin wrapper around `reqwest::Client` that knows our homeserver base
/// URL. Cheap to clone — `reqwest::Client` is internally `Arc<...>` already.
#[derive(Debug, Clone)]
pub struct HomeserverClient {
    http: reqwest::Client,
    base_url: String,
}

impl HomeserverClient {
    /// Build a new client. `base_url` is the homeserver URL with no
    /// trailing slash, e.g. `https://matrix.example.com`.
    pub fn new(base_url: impl Into<String>) -> Result<Self> {
        let http = reqwest::Client::builder()
            // Tools should not hang the MCP request forever on a slow
            // homeserver: 30s is plenty for any single API call we make.
            .timeout(Duration::from_secs(30))
            .user_agent(concat!("matrix-mcp/", env!("CARGO_PKG_VERSION")))
            .build()
            .context("build homeserver http client")?;
        Ok(Self {
            http,
            base_url: base_url.into(),
        })
    }

    /// Return the room IDs of every room the bearer's user has joined.
    pub async fn joined_rooms(&self, bearer: &str) -> Result<Vec<String>> {
        let url = format!("{}/_matrix/client/v3/joined_rooms", self.base_url);
        let resp = self
            .http
            .get(&url)
            .bearer_auth(bearer)
            .send()
            .await
            .context("GET /joined_rooms")?;
        let status = resp.status();
        let bytes = resp.bytes().await.context("read /joined_rooms body")?;
        if !status.is_success() {
            anyhow::bail!(
                "/joined_rooms returned {status}: {}",
                String::from_utf8_lossy(&bytes)
            );
        }
        let parsed: JoinedRoomsResponse = serde_json::from_slice(&bytes)
            .with_context(|| format!("decode /joined_rooms body: {:?}", &bytes))?;
        debug!(count = parsed.joined_rooms.len(), "fetched joined rooms");
        Ok(parsed.joined_rooms)
    }

    /// Fetch the most recent `limit` events from `room_id`, newest first.
    ///
    /// Uses the `/messages` endpoint with `dir=b` (backwards from current
    /// position). The caller is responsible for understanding that events
    /// may be filtered server-side by visibility rules.
    pub async fn recent_messages(
        &self,
        bearer: &str,
        room_id: &str,
        limit: u32,
    ) -> Result<Vec<RoomEvent>> {
        let url = format!(
            "{}/_matrix/client/v3/rooms/{}/messages",
            self.base_url,
            urlencode(room_id),
        );
        let resp = self
            .http
            .get(&url)
            .bearer_auth(bearer)
            .query(&[("dir", "b"), ("limit", &limit.to_string())])
            .send()
            .await
            .context("GET /messages")?;
        let status = resp.status();
        let bytes = resp.bytes().await.context("read /messages body")?;
        if !status.is_success() {
            anyhow::bail!(
                "/messages returned {status}: {}",
                String::from_utf8_lossy(&bytes)
            );
        }
        let parsed: MessagesResponse = serde_json::from_slice(&bytes)
            .with_context(|| format!("decode /messages body: {:?}", &bytes))?;
        Ok(parsed.chunk)
    }

    /// Send a plaintext `m.text` message body to `room_id`. Returns the
    /// resulting event ID.
    ///
    /// Use a fresh transaction id per call (Synapse de-duplicates identical
    /// txn ids on retry). We pick a 32-char alnum suffix on a millisecond
    /// timestamp — collision-free in practice, even under concurrent calls.
    pub async fn send_text_message(
        &self,
        bearer: &str,
        room_id: &str,
        body: &str,
    ) -> Result<String> {
        let txn_id = new_txn_id();
        let url = format!(
            "{}/_matrix/client/v3/rooms/{}/send/m.room.message/{}",
            self.base_url,
            urlencode(room_id),
            urlencode(&txn_id),
        );
        let payload = serde_json::json!({
            "msgtype": "m.text",
            "body": body,
        });
        let resp = self
            .http
            .put(&url)
            .bearer_auth(bearer)
            .json(&payload)
            .send()
            .await
            .context("PUT /send/m.room.message")?;
        let status = resp.status();
        let bytes = resp.bytes().await.context("read /send body")?;
        if !status.is_success() {
            anyhow::bail!(
                "/send returned {status}: {}",
                String::from_utf8_lossy(&bytes)
            );
        }
        let parsed: SendResponse = serde_json::from_slice(&bytes)
            .with_context(|| format!("decode /send body: {:?}", &bytes))?;
        debug!(event_id = %parsed.event_id, "sent message");
        Ok(parsed.event_id)
    }
}

#[derive(Deserialize)]
struct JoinedRoomsResponse {
    joined_rooms: Vec<String>,
}

#[derive(Deserialize)]
struct MessagesResponse {
    chunk: Vec<RoomEvent>,
}

#[derive(Deserialize)]
struct SendResponse {
    event_id: String,
}

/// One event from the Matrix `/messages` chunk. Fields are deliberately
/// loose — Matrix events are heterogenous, and we want to preserve the
/// content verbatim for the LLM to interpret rather than imposing strict
/// schemas. Tools that care about a specific event type (e.g.
/// `m.room.message`) inspect `event_type` and `content` themselves.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct RoomEvent {
    #[serde(rename = "type")]
    pub event_type: String,
    pub event_id: String,
    pub sender: String,
    #[serde(default)]
    pub origin_server_ts: Option<u64>,
    /// Free-form event content. Schemars renders this as `Any`, which is
    /// fine for the LLM — it can read whatever the homeserver returns.
    #[serde(default)]
    #[schemars(with = "serde_json::Value")]
    pub content: serde_json::Value,
}

/// Percent-encode a path segment. Matrix room IDs (e.g. `!abc:server`) and
/// event IDs (`$abc`) contain characters that must be escaped before
/// concatenating into a URL. We hand-roll this rather than pulling in
/// `urlencoding` for the same reason we skipped `matrix-rust-sdk`: one
/// less dep, one less audit/license/CVE surface.
fn urlencode(segment: &str) -> String {
    use std::fmt::Write as _;
    const UNRESERVED: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ\
        abcdefghijklmnopqrstuvwxyz0123456789-_.~";
    let mut out = String::with_capacity(segment.len());
    for &b in segment.as_bytes() {
        if UNRESERVED.contains(&b) {
            out.push(b as char);
        } else {
            // `write!` to a `String` is infallible; `expect` here is purely
            // to satisfy clippy::write_with_newline pedantry. Treating it
            // as an unwrap would be just as correct.
            let _ = write!(out, "%{b:02X}");
        }
    }
    out
}

fn new_txn_id() -> String {
    let ts = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_millis());
    let suffix: String = rand::thread_rng()
        .sample_iter(&Alphanumeric)
        .take(16)
        .map(char::from)
        .collect();
    format!("m{ts}.{suffix}")
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use serde_json::json;
    use wiremock::matchers::{bearer_token, method, path, path_regex, query_param};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    use super::*;

    #[tokio::test]
    async fn joined_rooms_round_trip() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/_matrix/client/v3/joined_rooms"))
            .and(bearer_token("user-token"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "joined_rooms": [
                    "!abc:example.com",
                    "!def:example.com",
                ]
            })))
            .mount(&server)
            .await;

        let client = HomeserverClient::new(server.uri()).unwrap();
        let rooms = client.joined_rooms("user-token").await.unwrap();
        assert_eq!(rooms, vec!["!abc:example.com", "!def:example.com"]);
    }

    #[tokio::test]
    async fn joined_rooms_propagates_error() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/_matrix/client/v3/joined_rooms"))
            .respond_with(ResponseTemplate::new(401).set_body_json(json!({
                "errcode": "M_UNKNOWN_TOKEN",
                "error": "Invalid access token",
            })))
            .mount(&server)
            .await;

        let client = HomeserverClient::new(server.uri()).unwrap();
        let err = client.joined_rooms("bad-token").await.unwrap_err();
        let msg = format!("{err:#}");
        assert!(msg.contains("401"), "error was: {msg}");
        assert!(
            msg.contains("M_UNKNOWN_TOKEN"),
            "expected upstream payload echoed, got: {msg}"
        );
    }

    #[tokio::test]
    async fn recent_messages_pulls_with_dir_b() {
        let server = MockServer::start().await;
        // Note the URL-encoded room id: `!` is escaped, `:` is escaped.
        Mock::given(method("GET"))
            .and(path_regex(
                "^/_matrix/client/v3/rooms/%21abc%3Aexample.com/messages$",
            ))
            .and(query_param("dir", "b"))
            .and(query_param("limit", "5"))
            .and(bearer_token("user-token"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "chunk": [
                    {
                        "type": "m.room.message",
                        "event_id": "$evt1",
                        "sender": "@alice:example.com",
                        "origin_server_ts": 1_700_000_000_000u64,
                        "content": {"msgtype": "m.text", "body": "hello"}
                    }
                ],
                "start": "t1",
                "end": "t2"
            })))
            .mount(&server)
            .await;

        let client = HomeserverClient::new(server.uri()).unwrap();
        let events = client
            .recent_messages("user-token", "!abc:example.com", 5)
            .await
            .unwrap();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].event_type, "m.room.message");
        assert_eq!(events[0].sender, "@alice:example.com");
        assert_eq!(events[0].content["body"], "hello");
    }

    #[tokio::test]
    async fn send_text_message_returns_event_id() {
        let server = MockServer::start().await;
        Mock::given(method("PUT"))
            .and(path_regex(
                "^/_matrix/client/v3/rooms/%21abc%3Aexample.com/send/m\\.room\\.message/.+$",
            ))
            .and(bearer_token("user-token"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "event_id": "$sent.evt",
            })))
            .mount(&server)
            .await;

        let client = HomeserverClient::new(server.uri()).unwrap();
        let id = client
            .send_text_message("user-token", "!abc:example.com", "Hello, world!")
            .await
            .unwrap();
        assert_eq!(id, "$sent.evt");
    }

    #[test]
    fn urlencode_escapes_matrix_id_special_chars() {
        assert_eq!(urlencode("!abc:example.com"), "%21abc%3Aexample.com");
        assert_eq!(urlencode("$evt.id"), "%24evt.id");
        assert_eq!(urlencode("plain-segment_42.x"), "plain-segment_42.x");
    }

    #[test]
    fn new_txn_id_is_unique_within_a_burst() {
        let a = new_txn_id();
        let b = new_txn_id();
        assert_ne!(a, b);
        assert!(a.starts_with('m'));
    }
}
