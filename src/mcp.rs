//! MCP service implementation using the `rmcp` crate's Streamable HTTP
//! transport. Tools defined here are dispatched per JSON-RPC `tools/call`.
//!
//! Per-request authenticated identity is propagated by `auth::bearer_auth`,
//! which inserts an `AuthenticatedIdentity` plus an `AccessToken` into
//! `request.extensions`. The rmcp streamable-http tower layer then injects
//! the original `http::request::Parts` (with our extensions on it) into
//! the tool's `RequestContext.extensions`. Tools read them via the
//! `identity_from_ctx` and `token_from_ctx` helpers.
//!
//! Phase 3: tools are SDK-backed (`matrix-rust-sdk`) so they read and write
//! both plaintext and E2EE rooms transparently. The per-user `Client` is
//! fetched from `MatrixClientCache` on first use; cross-call state lives
//! in the encrypted `SQLite` store.

use std::sync::Arc;

use matrix_sdk::Room;
use matrix_sdk::room::MessagesOptions;
use matrix_sdk::ruma::OwnedRoomId;
use matrix_sdk::ruma::api::Direction;
use matrix_sdk::ruma::events::room::message::RoomMessageEventContent;
use rmcp::handler::server::router::tool::ToolRouter;
use rmcp::handler::server::wrapper::Parameters;
use rmcp::model::{ServerCapabilities, ServerInfo};
use rmcp::service::{RequestContext, RoleServer};
use rmcp::{ErrorData, ServerHandler, schemars, tool, tool_handler, tool_router};
use serde::{Deserialize, Serialize};
use tracing::warn;

use crate::auth::AccessToken;
use crate::mas::AuthenticatedIdentity;
use crate::matrix_client::MatrixClientCache;

/// The MCP service. Per-session state is a reference to the shared
/// `MatrixClientCache`. The per-request identity + token come from
/// `RequestContext.extensions` (which rmcp populates with the original
/// HTTP `Parts`).
#[derive(Clone)]
pub struct MatrixMcpService {
    clients: MatrixClientCache,
    tool_router: ToolRouter<Self>,
}

impl std::fmt::Debug for MatrixMcpService {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MatrixMcpService").finish()
    }
}

impl MatrixMcpService {
    pub fn new(clients: MatrixClientCache) -> Self {
        Self {
            clients,
            tool_router: Self::tool_router(),
        }
    }
}

// ----- result + parameter types -----

#[derive(Debug, Serialize, schemars::JsonSchema)]
pub struct WhoamiResult {
    pub mxid: String,
    pub device_id: Option<String>,
}

#[derive(Debug, Serialize, schemars::JsonSchema)]
pub struct JoinedRoom {
    pub room_id: String,
    pub display_name: Option<String>,
    pub topic: Option<String>,
    /// True if the room is end-to-end encrypted. matrix-mcp can still
    /// read/send in encrypted rooms iff this device is cross-signed —
    /// see `verify_status`.
    pub encrypted: bool,
}

#[derive(Debug, Serialize, schemars::JsonSchema)]
pub struct JoinedRoomsResult {
    pub rooms: Vec<JoinedRoom>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct ReadRecentMessagesParams {
    /// Matrix room id, e.g. `!abc:example.com`.
    pub room_id: String,
    /// Maximum number of events to return. Defaults to 20 if omitted.
    #[serde(default = "default_message_limit")]
    pub limit: u32,
}

const fn default_message_limit() -> u32 {
    20
}

#[derive(Debug, Serialize, schemars::JsonSchema)]
pub struct ReadEvent {
    pub event_id: Option<String>,
    pub sender: Option<String>,
    pub origin_server_ts: Option<u64>,
    /// One of `plaintext`, `decrypted`, `unable_to_decrypt`.
    pub status: &'static str,
    /// The raw decrypted JSON of the event. `null` for events that
    /// could not be decrypted.
    pub event: Option<serde_json::Value>,
}

#[derive(Debug, Serialize, schemars::JsonSchema)]
pub struct ReadRecentMessagesResult {
    pub events: Vec<ReadEvent>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct SendTextMessageParams {
    /// Matrix room id, e.g. `!abc:example.com`.
    pub room_id: String,
    /// Message body. Rendered as Markdown for the `formatted_body` and
    /// kept as-is for the plaintext `body`. E2EE rooms are encrypted
    /// automatically by the SDK iff this device is cross-signed.
    pub body: String,
}

#[derive(Debug, Serialize, schemars::JsonSchema)]
pub struct SendTextMessageResult {
    pub event_id: String,
}

#[derive(Debug, Serialize, schemars::JsonSchema)]
pub struct VerifyStatusResult {
    /// True if this matrix-mcp device has been cross-signed by the
    /// user's master key (i.e. verified in Element X / Cinny / etc).
    pub cross_signed: bool,
    /// True if the user has set up cross-signing at all (i.e. has a
    /// master key).
    pub user_has_master_key: bool,
    /// Human-readable hint about what's needed next, if anything.
    pub message: String,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct RecoverParams {
    /// The Matrix Secret Storage recovery key — either the 48-character
    /// base58 string (often shown as four groups of 12 chars separated
    /// by spaces, e.g. `Esso ABCD…`) or the security passphrase you
    /// set up when you first enabled cross-signing. matrix-mcp uses
    /// this once to fetch the cross-signing private keys from
    /// server-side secret storage; after this call, the matrix-mcp
    /// device signs itself with your master key on the next sync.
    /// The key itself is never persisted by matrix-mcp.
    pub recovery_key: String,
}

#[derive(Debug, Serialize, schemars::JsonSchema)]
pub struct RecoverResult {
    /// True iff secret storage opened, the cross-signing private keys
    /// were imported into the local `OlmMachine`, and a self-signature
    /// was uploaded. `verify_status` should report `cross_signed: true`
    /// within ~one sync cycle (≤30s).
    pub ok: bool,
    pub message: String,
}

#[tool_router]
impl MatrixMcpService {
    /// Identity sanity-check. Returns the authenticated MXID and bound
    /// device id without any Matrix calls.
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

    /// List the rooms the authenticated user has joined. Each entry
    /// reports the room id, display name, topic, and whether the room
    /// is end-to-end encrypted.
    #[tool(description = "List Matrix rooms the authenticated user has joined.")]
    #[allow(clippy::needless_pass_by_value)]
    async fn list_joined_rooms(
        &self,
        ctx: RequestContext<RoleServer>,
    ) -> Result<rmcp::model::CallToolResult, ErrorData> {
        let client = self.client_for(&ctx).await?;
        let rooms = client.joined_rooms().iter().map(summarize_room).collect();
        structured_result(&JoinedRoomsResult { rooms })
    }

    /// Read recent events from a Matrix room (newest first). The SDK
    /// decrypts E2EE rooms iff this device is cross-signed. Events
    /// that could not be decrypted are reported with
    /// `status: "unable_to_decrypt"` and a null event body.
    #[tool(description = "Read recent events (newest first) from a Matrix room.")]
    #[allow(clippy::needless_pass_by_value)]
    async fn read_recent_messages(
        &self,
        ctx: RequestContext<RoleServer>,
        Parameters(params): Parameters<ReadRecentMessagesParams>,
    ) -> Result<rmcp::model::CallToolResult, ErrorData> {
        let client = self.client_for(&ctx).await?;
        let room_id: OwnedRoomId = params.room_id.parse().map_err(|e| {
            ErrorData::invalid_params(format!("invalid room_id {}: {e}", params.room_id), None)
        })?;
        let room = client
            .get_room(&room_id)
            .ok_or_else(|| ErrorData::invalid_params(format!("not joined to {room_id}"), None))?;

        let mut opts = MessagesOptions::new(Direction::Backward);
        opts.limit = params.limit.into();
        let messages = room
            .messages(opts)
            .await
            .map_err(|e| ErrorData::internal_error(format!("fetch /messages: {e}"), None))?;

        let events = messages
            .chunk
            .into_iter()
            .map(|tle| {
                let raw = tle.raw();
                let value: serde_json::Value =
                    raw.deserialize_as().unwrap_or(serde_json::Value::Null);
                let (status, body) = match &tle.kind {
                    matrix_sdk::deserialized_responses::TimelineEventKind::PlainText { .. } => {
                        ("plaintext", Some(value.clone()))
                    }
                    matrix_sdk::deserialized_responses::TimelineEventKind::Decrypted(_) => {
                        ("decrypted", Some(value.clone()))
                    }
                    matrix_sdk::deserialized_responses::TimelineEventKind::UnableToDecrypt {
                        ..
                    } => ("unable_to_decrypt", None),
                };
                ReadEvent {
                    event_id: value
                        .get("event_id")
                        .and_then(|v| v.as_str())
                        .map(str::to_owned),
                    sender: value
                        .get("sender")
                        .and_then(|v| v.as_str())
                        .map(str::to_owned),
                    origin_server_ts: value
                        .get("origin_server_ts")
                        .and_then(serde_json::Value::as_u64),
                    status,
                    event: body,
                }
            })
            .collect();
        structured_result(&ReadRecentMessagesResult { events })
    }

    /// Send a text message to a Matrix room. The SDK renders the body
    /// as Markdown (for `formatted_body`) while keeping it as plain
    /// text in `body`. E2EE rooms are encrypted automatically iff this
    /// device is cross-signed.
    #[tool(description = "Send a text message to a Matrix room (markdown-rendered).")]
    #[allow(clippy::needless_pass_by_value)]
    async fn send_text_message(
        &self,
        ctx: RequestContext<RoleServer>,
        Parameters(params): Parameters<SendTextMessageParams>,
    ) -> Result<rmcp::model::CallToolResult, ErrorData> {
        let client = self.client_for(&ctx).await?;
        let room_id: OwnedRoomId = params.room_id.parse().map_err(|e| {
            ErrorData::invalid_params(format!("invalid room_id {}: {e}", params.room_id), None)
        })?;
        let room = client
            .get_room(&room_id)
            .ok_or_else(|| ErrorData::invalid_params(format!("not joined to {room_id}"), None))?;

        let content = RoomMessageEventContent::text_markdown(&params.body);
        let response = room
            .send(content)
            .await
            .map_err(|e| ErrorData::internal_error(format!("room.send: {e}"), None))?;
        structured_result(&SendTextMessageResult {
            event_id: response.response.event_id.to_string(),
        })
    }

    /// Unlock E2EE for the matrix-mcp device using your Matrix Secret
    /// Storage recovery key (or security phrase). This is the same
    /// flow Element X uses on first login: matrix-mcp opens secret
    /// storage on the homeserver, decrypts the cross-signing private
    /// keys with the recovery key, hands them to the local
    /// `OlmMachine`, and the SDK auto-signs the device on the next
    /// sync. No SAS emoji compare with another device required.
    ///
    /// The recovery key is used once and not persisted. The imported
    /// cross-signing private keys go into matrix-mcp's encrypted
    /// `SQLite` store under the per-user HKDF-derived passphrase.
    #[tool(
        description = "Unlock E2EE: provide your Matrix Secret Storage recovery key / security \
                       phrase so matrix-mcp can self-sign its device using your master key. \
                       Same flow Element X uses on first login."
    )]
    #[allow(clippy::needless_pass_by_value)]
    async fn recover_with_key(
        &self,
        ctx: RequestContext<RoleServer>,
        Parameters(params): Parameters<RecoverParams>,
    ) -> Result<rmcp::model::CallToolResult, ErrorData> {
        let client = self.client_for(&ctx).await?;
        let encryption = client.encryption();
        encryption
            .recovery()
            .recover(&params.recovery_key)
            .await
            .map_err(|e| {
                ErrorData::internal_error(
                    format!(
                        "recover failed: {e}. Check that you pasted the correct security key / \
                         phrase (the one Element X showed you when you first enabled \
                         cross-signing)."
                    ),
                    None,
                )
            })?;
        // The SDK uploads the self-signature on the next sync; force a
        // /keys/query so verify_status flips quickly when the caller
        // checks back.
        if let Some(me) = client.user_id() {
            let _ = encryption.request_user_identity(me).await;
        }
        structured_result(&RecoverResult {
            ok: true,
            message: "Secret storage opened and cross-signing keys imported. The matrix-mcp \
                      device will self-sign on the next sync (≤30s). Call `verify_status` \
                      after a few seconds to confirm `cross_signed: true`."
                .to_owned(),
        })
    }

    /// Report whether this matrix-mcp device is verified (cross-signed)
    /// by the authenticated user. If not, no message in E2EE rooms can
    /// be decrypted and outgoing messages to E2EE rooms will be
    /// undecryptable to anyone else.
    #[tool(
        description = "Report the cross-signing / verification status of this matrix-mcp device."
    )]
    #[allow(clippy::needless_pass_by_value)]
    async fn verify_status(
        &self,
        ctx: RequestContext<RoleServer>,
    ) -> Result<rmcp::model::CallToolResult, ErrorData> {
        let client = self.client_for(&ctx).await?;
        let me = client
            .user_id()
            .ok_or_else(|| ErrorData::internal_error("no user_id on client", None))?
            .to_owned();
        let encryption = client.encryption();

        // OAuth-restored matrix-sdk sessions don't always populate
        // the local `OlmMachine` with the user's cross-signing identity
        // — `get_user_identity` then returns None even though the
        // master key exists on the homeserver. `request_user_identity`
        // forces a /keys/query against the homeserver and refreshes
        // the cached identity. Fall back to `get_user_identity` in
        // case `request_user_identity` returned None due to a
        // transient query error; that path will still pick up an
        // already-cached identity if one is present.
        let user_identity = match encryption.request_user_identity(&me).await {
            Ok(Some(id)) => Some(id),
            Ok(None) => encryption
                .get_user_identity(&me)
                .await
                .map_err(|e| ErrorData::internal_error(format!("get_user_identity: {e}"), None))?,
            Err(e) => {
                warn!(error = %e, "request_user_identity failed; trying cached");
                encryption.get_user_identity(&me).await.map_err(|e| {
                    ErrorData::internal_error(format!("get_user_identity: {e}"), None)
                })?
            }
        };
        let user_has_master_key = user_identity.is_some();

        let device_id = client.device_id().map(ToOwned::to_owned);
        let cross_signed = if let Some(did) = &device_id {
            let device = encryption
                .get_device(&me, did)
                .await
                .map_err(|e| ErrorData::internal_error(format!("get_device: {e}"), None))?;
            device.is_some_and(|d| d.is_cross_signed_by_owner())
        } else {
            false
        };

        let message = if !user_has_master_key {
            "No cross-signing identity found. Set up cross-signing in Element X first.".to_owned()
        } else if cross_signed {
            "matrix-mcp device is cross-signed; E2EE rooms are accessible.".to_owned()
        } else {
            "matrix-mcp device exists but is not yet cross-signed. Open Element X → \
             Settings → Sessions and verify the matrix-mcp device via SAS (emoji compare)."
                .to_owned()
        };

        structured_result(&VerifyStatusResult {
            cross_signed,
            user_has_master_key,
            message,
        })
    }
}

#[tool_handler(router = self.tool_router)]
impl ServerHandler for MatrixMcpService {
    fn get_info(&self) -> ServerInfo {
        ServerInfo::new(ServerCapabilities::builder().enable_tools().build()).with_instructions(
            "Matrix MCP server for example.com. Reads, sends, and \
             (where cross-signing allows) decrypts E2EE messages on \
             behalf of the authenticated user. Call `verify_status` if \
             E2EE rooms appear to be missing or undecryptable.",
        )
    }
}

// ---------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------

impl MatrixMcpService {
    /// Resolve the per-user matrix-sdk `Client` for the request.
    /// First call for a given user takes seconds (build + restore +
    /// spawn sync); subsequent calls are immediate.
    async fn client_for(
        &self,
        ctx: &RequestContext<RoleServer>,
    ) -> Result<Arc<matrix_sdk::Client>, ErrorData> {
        let id = identity_from_ctx(ctx).ok_or_else(missing_identity_err)?;
        let token = token_from_ctx(ctx).ok_or_else(missing_token_err)?;
        self.clients
            .for_user(&id, &token.0)
            .await
            .map_err(|e| ErrorData::internal_error(format!("build matrix client: {e:#}"), None))
    }
}

fn summarize_room(room: &Room) -> JoinedRoom {
    let display_name = room.cached_display_name().map(|n| n.to_string());
    JoinedRoom {
        room_id: room.room_id().to_string(),
        display_name,
        topic: room.topic(),
        encrypted: room.encryption_state().is_encrypted(),
    }
}

pub fn identity_from_ctx(ctx: &RequestContext<RoleServer>) -> Option<AuthenticatedIdentity> {
    let parts = ctx.extensions.get::<http::request::Parts>()?;
    parts.extensions.get::<AuthenticatedIdentity>().cloned()
}

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

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn default_message_limit_is_sensible() {
        let n = default_message_limit();
        assert!((10..=100).contains(&n), "limit was {n}");
    }
}
