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
use std::time::Instant;

use rmcp::handler::server::router::tool::ToolRouter;
use rmcp::handler::server::wrapper::Parameters;
use rmcp::model::{ServerCapabilities, ServerInfo};
use rmcp::service::{RequestContext, RoleServer};
use rmcp::{ErrorData, ServerHandler, schemars, tool, tool_handler, tool_router};
use serde::{Deserialize, Serialize};
use tracing::warn;

use crate::audit::{self, outcome};
use crate::auth::AccessToken;
use crate::mas::AuthenticatedIdentity;
use crate::matrix_client::MatrixClientCache;
use crate::rate_limit::{Category, Limiter};

/// The MCP service. Per-session state is a reference to the shared
/// `MatrixClientCache`. The per-request identity + token come from
/// `RequestContext.extensions` (which rmcp populates with the original
/// HTTP `Parts`).
#[derive(Clone)]
pub struct MatrixMcpService {
    clients: MatrixClientCache,
    rate_limiter: Arc<Limiter>,
    tool_router: ToolRouter<Self>,
}

impl std::fmt::Debug for MatrixMcpService {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MatrixMcpService").finish()
    }
}

impl MatrixMcpService {
    pub fn new(clients: MatrixClientCache, rate_limiter: Arc<Limiter>) -> Self {
        Self {
            clients,
            rate_limiter,
            tool_router: Self::tool_router(),
        }
    }

    /// Check the rate-limit buckets for the caller. On denial, returns
    /// an `ErrorData` with the stable `RATE_LIMITED_CODE` so callers +
    /// audit + metrics all see the same shape.
    fn rate_limit_check(
        &self,
        ctx: &RequestContext<RoleServer>,
        category: Category,
    ) -> Result<(), ErrorData> {
        let token = token_from_ctx(ctx).ok_or_else(missing_token_err)?;
        let id = identity_from_ctx(ctx).ok_or_else(missing_identity_err)?;
        let bearer_hash = audit::token_hash(&token.0);
        let sub = id.sub.as_deref();
        self.rate_limiter
            .check(&bearer_hash, sub, category)
            .map_err(|_| {
                ErrorData::new(
                    rmcp::model::ErrorCode(audit::RATE_LIMITED_CODE),
                    "rate limit exceeded — try again in a minute".to_owned(),
                    None,
                )
            })
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

/// Hard cap on the number of events `read_recent_messages` may request
/// from the homeserver. Prevents authenticated callers from triggering
/// large upstream fetches and unbounded response buffering.
const MAX_MESSAGE_LIMIT: u32 = 50;

/// Hard cap on the byte length of a `send_text_message` body. Prevents
/// authenticated callers from forcing large allocations and outbound
/// uploads.
const MAX_TEXT_MESSAGE_BODY_BYTES: usize = 64 * 1024;

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct ReadRecentMessagesParams {
    /// Matrix room id, e.g. `!abc:example.com`.
    pub room_id: String,
    /// Maximum number of events to return. Defaults to 20 if omitted.
    /// Values above 50 are clamped to 50 to bound upstream work.
    #[serde(default = "default_message_limit")]
    pub limit: u32,
}

const fn default_message_limit() -> u32 {
    20
}

/// Clamp a caller-supplied message limit to [`MAX_MESSAGE_LIMIT`].
const fn capped_message_limit(limit: u32) -> u32 {
    if limit > MAX_MESSAGE_LIMIT {
        MAX_MESSAGE_LIMIT
    } else {
        limit
    }
}

/// Reject message bodies that exceed [`MAX_TEXT_MESSAGE_BODY_BYTES`].
fn validate_text_message_body(body: &str) -> Result<(), ErrorData> {
    let len = body.len();
    if len > MAX_TEXT_MESSAGE_BODY_BYTES {
        return Err(ErrorData::invalid_params(
            format!("message body is {len} bytes; maximum is {MAX_TEXT_MESSAGE_BODY_BYTES} bytes"),
            None,
        ));
    }
    Ok(())
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
    /// Bodies larger than 64 KiB are rejected.
    pub body: String,
}

#[derive(Debug, Serialize, schemars::JsonSchema)]
pub struct SendTextMessageResult {
    pub event_id: String,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct RoomInfoParams {
    /// Matrix room id, e.g. `!abc:example.com`.
    pub room_id: String,
}

#[derive(Debug, Serialize, schemars::JsonSchema)]
pub struct RoomInfoResult {
    /// Canonical room id.
    pub room_id: String,
    /// SDK-computed display name (falls back to heroes for unnamed
    /// rooms). May be `null` if the room state hasn't loaded yet.
    pub display_name: Option<String>,
    /// Canonical `m.room.name` if one is set; otherwise `null`.
    pub name: Option<String>,
    /// `m.room.topic` if one is set.
    pub topic: Option<String>,
    /// True if the room has `m.room.encryption` enabled.
    pub encrypted: bool,
    /// Count of members in `join` state. Cheap — read from cached state.
    pub joined_members_count: u64,
    /// Joined + invited. `joined_members_count <= active_members_count`.
    pub active_members_count: u64,
    /// The caller's power level in this room (0–100 for typical
    /// configurations; `null` if the room's power-level state event
    /// hasn't loaded yet, or if the caller is a v12-or-later room
    /// creator — see `is_room_creator`).
    pub my_power_level: Option<i64>,
    /// True if the caller is a room creator in a Matrix room version
    /// that grants creators infinite power level (room v12+). In that
    /// case `my_power_level` is `null`.
    pub is_room_creator: bool,
}

/// Hard cap on the number of members returned by `room_members`.
/// The SDK's `members_no_sync` loads the full cached list before any
/// truncation, so keeping this limit small caps both response size and
/// the serialization cost of the returned slice.
const MAX_MEMBER_LIMIT: u32 = 1000;

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct RoomMembersParams {
    /// Matrix room id, e.g. `!abc:example.com`.
    pub room_id: String,
    /// Maximum number of members to return. Defaults to 200.
    /// Values above 1000 are clamped to 1000.
    /// Bridged rooms (Telegram, `WhatsApp` channels, etc.) can have
    /// thousands of joined members; cap so we don't return a 5 MB
    /// JSON blob.
    #[serde(default = "default_member_limit")]
    pub limit: u32,
}

const fn default_member_limit() -> u32 {
    200
}

#[derive(Debug, Serialize, schemars::JsonSchema)]
pub struct RoomMemberInfo {
    pub mxid: String,
    /// The member's chosen display name, or `null` if they haven't set
    /// one (in which case the localpart of the mxid is a reasonable
    /// fallback for UIs).
    pub display_name: Option<String>,
    /// Avatar as an `mxc://server/mediaid` URI, or `null` if unset.
    pub avatar_url: Option<String>,
    /// Power level normalized to 0–100 against the highest power level
    /// in the room (so the room creator typically reads as 100,
    /// regardless of whether they raised the cap above 100). Negative
    /// values are passed through verbatim.
    pub power_level: i64,
}

#[derive(Debug, Serialize, schemars::JsonSchema)]
pub struct RoomMembersResult {
    pub members: Vec<RoomMemberInfo>,
    /// Total number of joined members in the room. If
    /// `members.len() < total`, the response was truncated by the
    /// `limit` parameter.
    pub total: u64,
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

// NOTE: an earlier draft (v0.0.10) exposed a `recover_with_key` MCP
// tool that took the user's recovery key as a tool argument. That
// path was deliberately removed in favour of the browser-based
// /setup flow (`setup.rs`), because passing the recovery key as a
// tool argument leaves it in claude.ai's chat history forever. The
// /setup flow takes it over HTTPS, processes it server-side, and
// never persists the key itself.

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
        let started = Instant::now();
        let mxid_for_audit = identity_from_ctx(&ctx).map_or_else(String::new, |i| i.mxid);
        let result = (|| {
            self.rate_limit_check(&ctx, Category::Read)?;
            let id = identity_from_ctx(&ctx).ok_or_else(missing_identity_err)?;
            structured_result(&WhoamiResult {
                mxid: id.mxid,
                device_id: id.device_id,
            })
        })();
        emit_tool_audit("whoami", &mxid_for_audit, None, started, None, &result);
        result
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
        let started = Instant::now();
        let mxid_for_audit = identity_from_ctx(&ctx).map_or_else(String::new, |i| i.mxid);
        let (result, room_count) = async {
            self.rate_limit_check(&ctx, Category::Read)?;
            let client = self.client_for(&ctx).await?;
            let rooms: Vec<JoinedRoom> = client.joined_rooms().iter().map(summarize_room).collect();
            let count = rooms.len();
            let res = structured_result(&JoinedRoomsResult { rooms });
            Ok::<_, ErrorData>((res, count))
        }
        .await
        .map_or_else(|e| (Err(e), 0), |(r, c)| (r, c));
        emit_tool_audit(
            "list_joined_rooms",
            &mxid_for_audit,
            None,
            started,
            Some(room_count),
            &result,
        );
        result
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
        let started = Instant::now();
        let mxid_for_audit = identity_from_ctx(&ctx).map_or_else(String::new, |i| i.mxid);
        let room_id_for_audit = params.room_id.clone();
        let (result, event_count) = async {
            self.rate_limit_check(&ctx, Category::Read)?;
            let client = self.client_for(&ctx).await?;
            let room_id: OwnedRoomId = params.room_id.parse().map_err(|e| {
                ErrorData::invalid_params(format!("invalid room_id {}: {e}", params.room_id), None)
            })?;
            let room = client.get_room(&room_id).ok_or_else(|| {
                ErrorData::invalid_params(format!("not joined to {room_id}"), None)
            })?;

            let mut opts = MessagesOptions::new(Direction::Backward);
            opts.limit = capped_message_limit(params.limit).into();
            let messages = room
                .messages(opts)
                .await
                .map_err(|e| ErrorData::internal_error(format!("fetch /messages: {e}"), None))?;

            let events: Vec<ReadEvent> = messages
                .chunk
                .into_iter()
                .map(|tle| {
                    let raw = tle.raw();
                    let value: serde_json::Value =
                        raw.deserialize_as().unwrap_or(serde_json::Value::Null);
                    let (status, body) = match &tle.kind {
                        matrix_sdk::deserialized_responses::TimelineEventKind::PlainText {
                            ..
                        } => ("plaintext", Some(value.clone())),
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
            let count = events.len();
            let res = structured_result(&ReadRecentMessagesResult { events });
            Ok::<_, ErrorData>((res, count))
        }
        .await
        .map_or_else(|e| (Err(e), 0), |(r, c)| (r, c));
        emit_tool_audit(
            "read_recent_messages",
            &mxid_for_audit,
            Some(&room_id_for_audit),
            started,
            Some(event_count),
            &result,
        );
        result
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
        let started = Instant::now();
        let mxid_for_audit = identity_from_ctx(&ctx).map_or_else(String::new, |i| i.mxid);
        let room_id_for_audit = params.room_id.clone();
        let result = async {
            self.rate_limit_check(&ctx, Category::Write)?;
            validate_text_message_body(&params.body)?;
            let client = self.client_for(&ctx).await?;
            let room_id: OwnedRoomId = params.room_id.parse().map_err(|e| {
                ErrorData::invalid_params(format!("invalid room_id {}: {e}", params.room_id), None)
            })?;
            let room = client.get_room(&room_id).ok_or_else(|| {
                ErrorData::invalid_params(format!("not joined to {room_id}"), None)
            })?;

            let content = RoomMessageEventContent::text_markdown(&params.body);
            let response = room
                .send(content)
                .await
                .map_err(|e| ErrorData::internal_error(format!("room.send: {e}"), None))?;
            structured_result(&SendTextMessageResult {
                event_id: response.response.event_id.to_string(),
            })
        }
        .await;
        emit_tool_audit(
            "send_text_message",
            &mxid_for_audit,
            Some(&room_id_for_audit),
            started,
            None,
            &result,
        );
        result
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
        let started = Instant::now();
        let mxid_for_audit = identity_from_ctx(&ctx).map_or_else(String::new, |i| i.mxid);
        let result = async {
            self.rate_limit_check(&ctx, Category::Read)?;
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
                Ok(None) => encryption.get_user_identity(&me).await.map_err(|e| {
                    ErrorData::internal_error(format!("get_user_identity: {e}"), None)
                })?,
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
                "No cross-signing identity found on the homeserver. Set up cross-signing in \
                 Element X first (Settings → Encryption → Set up secure backup), then visit \
                 https://matrix-mcp.example.com/setup to import the keys here."
                    .to_owned()
            } else if cross_signed {
                "matrix-mcp device is cross-signed; E2EE rooms are accessible.".to_owned()
            } else {
                "matrix-mcp device exists but isn't yet signed by your master key. Visit \
                 https://matrix-mcp.example.com/setup, sign in, and paste your Matrix \
                 Secret Storage recovery key — matrix-mcp will self-sign the device. No \
                 chat history, no emoji-compare with another device."
                    .to_owned()
            };

            structured_result(&VerifyStatusResult {
                cross_signed,
                user_has_master_key,
                message,
            })
        }
        .await;
        emit_tool_audit(
            "verify_status",
            &mxid_for_audit,
            None,
            started,
            None,
            &result,
        );
        result
    }

    /// Return metadata about a joined Matrix room: display name, topic,
    /// encryption state, and member counts. Only succeeds for rooms the
    /// caller is currently joined to — invited, left, knocked, and
    /// banned rooms are rejected. Read-only.
    #[tool(
        description = "Return metadata about a joined Matrix room (name, topic, encryption, members, power level)."
    )]
    #[allow(clippy::needless_pass_by_value)]
    async fn room_info(
        &self,
        ctx: RequestContext<RoleServer>,
        Parameters(params): Parameters<RoomInfoParams>,
    ) -> Result<rmcp::model::CallToolResult, ErrorData> {
        let started = Instant::now();
        let mxid_for_audit = identity_from_ctx(&ctx).map_or_else(String::new, |i| i.mxid);
        let room_id_for_audit = params.room_id.clone();
        let result = async {
            self.rate_limit_check(&ctx, Category::Read)?;
            let client = self.client_for(&ctx).await?;
            let room_id: OwnedRoomId = params.room_id.parse().map_err(|e| {
                ErrorData::invalid_params(format!("invalid room_id {}: {e}", params.room_id), None)
            })?;
            let room = client.get_room(&room_id).ok_or_else(|| {
                ErrorData::invalid_params(format!("not joined to {room_id}"), None)
            })?;

            // Enforce joined-only access. `get_room` returns any room
            // known to the SDK cache (invited, left, knocked, banned).
            // Returning metadata for non-joined rooms widens MCP access
            // beyond the user's current membership boundary.
            if room.state() != matrix_sdk::RoomState::Joined {
                return Err(ErrorData::invalid_params(
                    format!(
                        "not currently joined to {room_id} (membership: {:?})",
                        room.state()
                    ),
                    None,
                ));
            }

            let me = client
                .user_id()
                .ok_or_else(|| ErrorData::internal_error("no user_id on client", None))?
                .to_owned();

            // `power_levels()` can fail if the room state hasn't synced
            // the `m.room.power_levels` event yet — return None rather
            // than failing the whole call, so callers can still see
            // name/topic/etc.
            // `UserPowerLevel` is `Int(n) | Infinite`; the Infinite
            // variant signals a v12+ room creator with implicit
            // unbounded power. Surface that as a separate bool rather
            // than picking a sentinel integer.
            let (my_power_level, is_room_creator): (Option<i64>, bool) =
                match room.power_levels().await {
                    Ok(pl) => match pl.for_user(&me) {
                        matrix_sdk::ruma::events::room::power_levels::UserPowerLevel::Int(n) => {
                            (Some(i64::from(n)), false)
                        }
                        matrix_sdk::ruma::events::room::power_levels::UserPowerLevel::Infinite => {
                            (None, true)
                        }
                        // `UserPowerLevel` is marked non_exhaustive by ruma so we
                        // need a wildcard arm — but every variant we know about
                        // is handled above. If ruma adds a third state, treat it
                        // as "unknown integer level" rather than crash.
                        _ => (None, false),
                    },
                    Err(e) => {
                        warn!(error = %e, "power_levels() failed; reporting null");
                        (None, false)
                    }
                };

            structured_result(&RoomInfoResult {
                room_id: room.room_id().to_string(),
                display_name: room.cached_display_name().map(|n| n.to_string()),
                name: room.name(),
                topic: room.topic(),
                encrypted: room.encryption_state().is_encrypted(),
                joined_members_count: room.joined_members_count(),
                active_members_count: room.active_members_count(),
                my_power_level,
                is_room_creator,
            })
        }
        .await;
        emit_tool_audit(
            "room_info",
            &mxid_for_audit,
            Some(&room_id_for_audit),
            started,
            None,
            &result,
        );
        result
    }

    /// List joined members of a Matrix room with display name, avatar,
    /// and normalized power level. Capped at `limit` (default 200,
    /// maximum 1000). `total` reports the room's true joined-member
    /// count so callers can detect truncation.
    #[tool(
        description = "List joined members of a Matrix room (mxid, display name, avatar, power level)."
    )]
    #[allow(clippy::needless_pass_by_value)]
    async fn room_members(
        &self,
        ctx: RequestContext<RoleServer>,
        Parameters(params): Parameters<RoomMembersParams>,
    ) -> Result<rmcp::model::CallToolResult, ErrorData> {
        let started = Instant::now();
        let mxid_for_audit = identity_from_ctx(&ctx).map_or_else(String::new, |i| i.mxid);
        let room_id_for_audit = params.room_id.clone();
        let (result, member_count) = async {
            self.rate_limit_check(&ctx, Category::Read)?;
            let client = self.client_for(&ctx).await?;
            let room_id: OwnedRoomId = params.room_id.parse().map_err(|e| {
                ErrorData::invalid_params(format!("invalid room_id {}: {e}", params.room_id), None)
            })?;
            let room = client.get_room(&room_id).ok_or_else(|| {
                ErrorData::invalid_params(format!("not joined to {room_id}"), None)
            })?;

            // Clamp the caller-supplied limit to MAX_MEMBER_LIMIT before
            // doing any work. Note: `members_no_sync` loads the full
            // cached member list from the SDK store regardless — the SDK
            // provides no paginated variant. The clamp bounds the size of
            // the slice we serialize and return.
            let effective_limit =
                usize::try_from(params.limit.min(MAX_MEMBER_LIMIT)).unwrap_or(usize::MAX);

            // `members_no_sync` reads the cached member list rather
            // than firing /joined_members. The background sync keeps
            // this fresh; the trade-off is "freshness up to last sync"
            // vs "an extra round-trip per call". Take the cached read
            // — the same trade-off `list_joined_rooms` makes.
            let mut members = room
                .members_no_sync(matrix_sdk::RoomMemberships::JOIN)
                .await
                .map_err(|e| ErrorData::internal_error(format!("members_no_sync: {e}"), None))?;
            let total = u64::try_from(members.len()).unwrap_or(u64::MAX);
            members.truncate(effective_limit);

            let members: Vec<RoomMemberInfo> = members
                .iter()
                .map(|m| RoomMemberInfo {
                    mxid: m.user_id().to_string(),
                    display_name: m.display_name().map(ToOwned::to_owned),
                    avatar_url: m.avatar_url().map(ToString::to_string),
                    // `normalized_power_level` returns the same
                    // `UserPowerLevel` enum as `for_user`. Map Int(n)
                    // to n, Infinite (v12+ creator) to i64::MAX as a
                    // sentinel — the per-member API doesn't have a
                    // sibling bool for creator-ness, and this scales
                    // the data the way clients expect ("very high").
                    power_level: match m.normalized_power_level() {
                        matrix_sdk::ruma::events::room::power_levels::UserPowerLevel::Int(n) => {
                            i64::from(n)
                        }
                        matrix_sdk::ruma::events::room::power_levels::UserPowerLevel::Infinite => {
                            i64::MAX
                        }
                        _ => 0,
                    },
                })
                .collect();
            let count = members.len();
            let res = structured_result(&RoomMembersResult { members, total });
            Ok::<_, ErrorData>((res, count))
        }
        .await
        .map_or_else(|e| (Err(e), 0), |(r, c)| (r, c));
        emit_tool_audit(
            "room_members",
            &mxid_for_audit,
            Some(&room_id_for_audit),
            started,
            Some(member_count),
            &result,
        );
        result
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

/// Audit-log a finished tool call. Looks at the result to decide the
/// outcome class and pulls the JSON-RPC error code into a stable
/// `error_class` string. Keeps audit emission DRY across every tool.
fn emit_tool_audit(
    tool: &'static str,
    mxid: &str,
    room_id: Option<&str>,
    started: Instant,
    event_count: Option<usize>,
    result: &Result<rmcp::model::CallToolResult, ErrorData>,
) {
    let (outcome, err_class) = match result {
        Ok(_) => (outcome::OK, None),
        Err(e) => {
            let class = audit::error_class(e);
            // Map the in-band rate-limit error to the matching outcome
            // so dashboards can distinguish "429-ish" from real errors.
            let outcome_str = if e.code.0 == audit::RATE_LIMITED_CODE {
                outcome::RATE_LIMITED
            } else {
                outcome::ERROR
            };
            (outcome_str, Some(class))
        }
    };
    audit::tool_call(
        tool,
        mxid,
        room_id,
        outcome,
        started,
        event_count,
        err_class,
    );
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
        assert!((10..=MAX_MESSAGE_LIMIT).contains(&n), "limit was {n}");
    }

    #[test]
    fn message_limit_is_capped() {
        assert_eq!(capped_message_limit(1), 1);
        assert_eq!(capped_message_limit(MAX_MESSAGE_LIMIT), MAX_MESSAGE_LIMIT);
        assert_eq!(capped_message_limit(u32::MAX), MAX_MESSAGE_LIMIT);
    }

    #[test]
    fn oversized_text_message_body_is_rejected() {
        let at_limit = "a".repeat(MAX_TEXT_MESSAGE_BODY_BYTES);
        assert!(validate_text_message_body(&at_limit).is_ok());

        let oversized = "a".repeat(MAX_TEXT_MESSAGE_BODY_BYTES + 1);
        assert!(validate_text_message_body(&oversized).is_err());
    }

    #[test]
    fn member_limit_is_capped() {
        // Values below the cap pass through unchanged.
        assert_eq!(200_u32.min(MAX_MEMBER_LIMIT), 200);
        // Values at or above the cap are clamped to MAX_MEMBER_LIMIT.
        // Use a value that is definitively larger than MAX_MEMBER_LIMIT
        // rather than u32::MAX to avoid the unnecessary_min_or_max lint.
        let over = MAX_MEMBER_LIMIT + 1;
        assert_eq!(over.min(MAX_MEMBER_LIMIT), MAX_MEMBER_LIMIT);
    }
}
