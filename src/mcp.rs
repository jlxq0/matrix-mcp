//! MCP service implementation using the `rmcp` crate's Streamable HTTP
//! transport. Tools defined here are dispatched per JSON-RPC `tools/call`.
//!
//! Per-request authenticated identity is propagated by `auth::bearer_auth`,
//! which inserts an `AuthenticatedIdentity` plus an `AccessToken` into
//! `request.extensions`. The rmcp streamable-http tower layer then injects
//! the original `http::request::Parts` (with our extensions on it) into
//! the tool's `RequestContext.extensions`. Tools read them via the
//! `identity_from_ctx` and `token_from_ctx` helpers. A `task_local` won't
//! work here because the rmcp session worker runs in a separately-spawned
//! task that doesn't inherit task-locals.

use std::sync::Arc;

use rmcp::handler::server::router::tool::ToolRouter;
use rmcp::handler::server::wrapper::Parameters;
use rmcp::model::{ServerCapabilities, ServerInfo};
use rmcp::service::{RequestContext, RoleServer};
use rmcp::{ErrorData, ServerHandler, schemars, tool, tool_handler, tool_router};
use serde::{Deserialize, Serialize};

use crate::auth::AccessToken;
use crate::mas::AuthenticatedIdentity;
use crate::matrix::{HomeserverClient, RoomEvent};

/// The MCP service. Per-session state is intentionally minimal: just a
/// reference to the shared `HomeserverClient`. The per-request identity +
/// token come from `RequestContext.extensions` (which rmcp populates with
/// the original HTTP `Parts`).
///
/// Phase 3 will add a per-user crypto store cache here for E2EE.
#[derive(Debug, Clone)]
pub struct MatrixMcpService {
    homeserver: Arc<HomeserverClient>,
    tool_router: ToolRouter<Self>,
}

impl MatrixMcpService {
    pub fn new(homeserver: Arc<HomeserverClient>) -> Self {
        Self {
            homeserver,
            tool_router: Self::tool_router(),
        }
    }
}

#[derive(Debug, Serialize, schemars::JsonSchema)]
pub struct WhoamiResult {
    /// Matrix user id (e.g. `@julian:kampong.social`).
    pub mxid: String,
    /// Matrix device id the OAuth token is bound to, if any.
    pub device_id: Option<String>,
}

#[derive(Debug, Serialize, schemars::JsonSchema)]
pub struct JoinedRoomsResult {
    /// Matrix room IDs the authenticated user has joined. Order is
    /// server-defined; not stable across calls.
    pub room_ids: Vec<String>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct ReadRecentMessagesParams {
    /// Matrix room id, e.g. `!abc:kampong.social`.
    pub room_id: String,
    /// Maximum number of events to return. Defaults to 20 if omitted.
    /// The homeserver may return fewer.
    #[serde(default = "default_message_limit")]
    pub limit: u32,
}

const fn default_message_limit() -> u32 {
    20
}

#[derive(Debug, Serialize, schemars::JsonSchema)]
pub struct ReadRecentMessagesResult {
    /// Matrix events, newest first.
    pub events: Vec<RoomEvent>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct SendTextMessageParams {
    /// Matrix room id, e.g. `!abc:kampong.social`.
    pub room_id: String,
    /// Plaintext message body to send as `m.room.message` / `m.text`.
    pub body: String,
}

#[derive(Debug, Serialize, schemars::JsonSchema)]
pub struct SendTextMessageResult {
    /// The Matrix event id the homeserver assigned to the sent message.
    pub event_id: String,
}

#[tool_router]
impl MatrixMcpService {
    /// Identity sanity-check. Returns the authenticated MXID and bound
    /// device id without any Matrix calls — useful for verifying the
    /// OAuth + introspection chain in isolation.
    #[tool(description = "Return the authenticated Matrix user id and device id.")]
    #[allow(clippy::unused_self, clippy::needless_pass_by_value)]
    fn whoami(
        &self,
        ctx: RequestContext<RoleServer>,
    ) -> Result<rmcp::model::CallToolResult, ErrorData> {
        let id = identity_from_ctx(&ctx).ok_or_else(missing_identity_err)?;
        structured_result(&WhoamiResult {
            mxid: id.mxid,
            device_id: id.device_id,
        })
    }

    /// List the rooms the authenticated user has joined. Returns just the
    /// room IDs; use `read_recent_messages` to get content.
    #[tool(description = "List Matrix room IDs the authenticated user has joined.")]
    #[allow(clippy::needless_pass_by_value)]
    async fn list_joined_rooms(
        &self,
        ctx: RequestContext<RoleServer>,
    ) -> Result<rmcp::model::CallToolResult, ErrorData> {
        let token = token_from_ctx(&ctx).ok_or_else(missing_token_err)?;
        let rooms = self
            .homeserver
            .joined_rooms(&token.0)
            .await
            .map_err(|e| upstream_err("joined_rooms", &e))?;
        structured_result(&JoinedRoomsResult { room_ids: rooms })
    }

    /// Read recent events from a Matrix room. Returns newest-first.
    /// Plaintext messages only — this phase does not decrypt E2EE rooms.
    #[tool(description = "Read recent events (newest first) from a Matrix room.")]
    #[allow(clippy::needless_pass_by_value)]
    async fn read_recent_messages(
        &self,
        ctx: RequestContext<RoleServer>,
        Parameters(params): Parameters<ReadRecentMessagesParams>,
    ) -> Result<rmcp::model::CallToolResult, ErrorData> {
        let token = token_from_ctx(&ctx).ok_or_else(missing_token_err)?;
        let events = self
            .homeserver
            .recent_messages(&token.0, &params.room_id, params.limit)
            .await
            .map_err(|e| upstream_err("recent_messages", &e))?;
        structured_result(&ReadRecentMessagesResult { events })
    }

    /// Send a plaintext text message to a Matrix room. Returns the
    /// resulting event id. Does NOT encrypt; sending to an E2EE-only room
    /// will succeed at the API level but the message will be visible
    /// only as a plaintext event mixed into an encrypted room (the
    /// homeserver will accept it; clients may render it as a system
    /// notice). Phase 3 adds proper E2EE.
    #[tool(description = "Send a plaintext text message to a Matrix room. Returns the event id.")]
    #[allow(clippy::needless_pass_by_value)]
    async fn send_text_message(
        &self,
        ctx: RequestContext<RoleServer>,
        Parameters(params): Parameters<SendTextMessageParams>,
    ) -> Result<rmcp::model::CallToolResult, ErrorData> {
        let token = token_from_ctx(&ctx).ok_or_else(missing_token_err)?;
        let event_id = self
            .homeserver
            .send_text_message(&token.0, &params.room_id, &params.body)
            .await
            .map_err(|e| upstream_err("send_text_message", &e))?;
        structured_result(&SendTextMessageResult { event_id })
    }
}

// `#[tool_handler]` auto-implements `call_tool`, `list_tools`, and `get_tool`
// by delegating to the `tool_router` field. Our hand-written `get_info`
// is preserved (the macro only generates `get_info` when not present).
#[tool_handler(router = self.tool_router)]
impl ServerHandler for MatrixMcpService {
    fn get_info(&self) -> ServerInfo {
        ServerInfo::new(ServerCapabilities::builder().enable_tools().build()).with_instructions(
            "Matrix MCP server for kampong.social. Reads and sends \
                 messages in plaintext (non-E2EE) rooms on behalf of the \
                 authenticated user. E2EE support arrives in a later phase.",
        )
    }
}

// ---------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------

/// Read the authenticated identity from an rmcp `RequestContext`.
///
/// The auth middleware puts an `AuthenticatedIdentity` on the axum request
/// extensions; rmcp's streamable-http tower layer then wraps the request's
/// `Parts` into `ctx.extensions` for tool handlers. Returns `None` only if
/// the middleware wasn't applied — a router misconfiguration.
pub fn identity_from_ctx(ctx: &RequestContext<RoleServer>) -> Option<AuthenticatedIdentity> {
    let parts = ctx.extensions.get::<http::request::Parts>()?;
    parts.extensions.get::<AuthenticatedIdentity>().cloned()
}

/// Read the raw OAuth access token from an rmcp `RequestContext`. Same
/// source as `identity_from_ctx`; used by tools that need to re-present
/// the bearer to the homeserver (per MSC3861 the OAuth access token IS
/// the Matrix access token).
pub fn token_from_ctx(ctx: &RequestContext<RoleServer>) -> Option<AccessToken> {
    let parts = ctx.extensions.get::<http::request::Parts>()?;
    parts.extensions.get::<AccessToken>().cloned()
}

fn structured_result<T: Serialize>(value: &T) -> Result<rmcp::model::CallToolResult, ErrorData> {
    let json = serde_json::to_value(value)
        .map_err(|e| ErrorData::internal_error(format!("serialize tool result: {e}"), None))?;
    Ok(rmcp::model::CallToolResult::structured(json))
}

fn missing_identity_err() -> ErrorData {
    ErrorData::internal_error(
        "no authenticated identity in request context; router misconfiguration",
        None,
    )
}

fn missing_token_err() -> ErrorData {
    ErrorData::internal_error(
        "no access token in request context; router misconfiguration",
        None,
    )
}

fn upstream_err(tool: &str, err: &anyhow::Error) -> ErrorData {
    // Pull the chain into a single string. We surface the underlying status
    // and Matrix errcode (if any) to the caller — they're often the only
    // signal the LLM needs to retry or surface to the user.
    ErrorData::internal_error(format!("{tool}: {err:#}"), None)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use std::sync::Arc;

    use super::*;

    fn dummy_service() -> MatrixMcpService {
        let hs = Arc::new(HomeserverClient::new("http://localhost").unwrap());
        MatrixMcpService::new(hs)
    }

    #[test]
    fn service_constructs_with_tool_router() {
        let svc = dummy_service();
        let info = svc.get_info();
        assert!(info.capabilities.tools.is_some());
    }

    #[test]
    fn default_message_limit_is_sensible() {
        // Reads should default to a non-trivial but bounded number of events.
        let n = default_message_limit();
        assert!((10..=100).contains(&n), "limit was {n}");
    }
}
