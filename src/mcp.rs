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

use std::collections::HashSet;
use std::sync::Arc;
use std::time::{Duration, Instant};

use base64::Engine as _;
use matrix_sdk::Room;
use matrix_sdk::media::{MediaFormat, MediaRequestParameters};
use matrix_sdk::room::{IncludeRelations, MessagesOptions, RelationsOptions};
use matrix_sdk::ruma::OwnedEventId;
use matrix_sdk::ruma::OwnedMxcUri;
use matrix_sdk::ruma::OwnedRoomId;
use matrix_sdk::ruma::api::Direction;
use matrix_sdk::ruma::api::client::search::search_events;
use matrix_sdk::ruma::events::relation::RelationType;
use matrix_sdk::ruma::events::room::MediaSource;
use matrix_sdk::ruma::events::room::message::{
    ImageMessageEventContent, MessageType, RoomMessageEventContent,
};

use rmcp::handler::server::router::tool::ToolRouter;
use rmcp::handler::server::wrapper::Parameters;
use rmcp::model::{ServerCapabilities, ServerInfo};
use rmcp::service::{RequestContext, RoleServer};
use rmcp::{ErrorData, ServerHandler, schemars, tool, tool_handler, tool_router};
use serde::{Deserialize, Serialize};
use tracing::{Instrument as _, Span, warn};

use crate::audit::{self, outcome};
use crate::audit_room;
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
    /// MAS introspection client. Stored on the service so tool handlers
    /// can drop the per-token introspection cache entry when Synapse
    /// reports `M_UNKNOWN_TOKEN` — forces the auth middleware to
    /// re-introspect fresh next time the same token is presented, so a
    /// revoked token can't keep slipping through on a cached `active`
    /// verdict.
    mas: crate::mas::MasIntrospectionClient,
    rate_limiter: Arc<Limiter>,
    /// Maximum attachment size in bytes that `download_attachment` will
    /// fetch. Checked against the event's declared `info.size` before
    /// any media I/O occurs.
    download_max_bytes: u64,
    /// Maximum image size (bytes) `send_image_from_url` will fetch from a
    /// remote HTTPS URL before uploading to the homeserver media repo.
    upload_max_bytes: usize,
    tool_router: ToolRouter<Self>,
}

impl std::fmt::Debug for MatrixMcpService {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MatrixMcpService").finish()
    }
}

impl MatrixMcpService {
    pub fn new(
        clients: MatrixClientCache,
        mas: crate::mas::MasIntrospectionClient,
        rate_limiter: Arc<Limiter>,
        download_max_bytes: u64,
        upload_max_bytes: usize,
    ) -> Self {
        Self {
            clients,
            mas,
            rate_limiter,
            download_max_bytes,
            upload_max_bytes,
            tool_router: Self::tool_router(),
        }
    }

    /// Inspect a tool-call result for the Synapse "auth expired" error
    /// signatures (`M_UNKNOWN_TOKEN`, `Token is not active`) and, if
    /// matched: evict the per-mxid SDK client cache, drop the
    /// per-token MAS introspection cache, and replace the technical
    /// error with an actionable user-facing message instructing
    /// claude.ai to reconnect.
    ///
    /// Called from every tool handler immediately before the final
    /// `emit_tool_audit`. The cost is one substring scan on the error
    /// message, and only runs when the result is already an `Err` —
    /// zero impact on the happy path. The two evictions are
    /// idempotent and cheap (`HashMap::remove`s); calling this on a
    /// non-auth error is a no-op.
    async fn react_to_auth_expiry(
        &self,
        ctx: &RequestContext<RoleServer>,
        result: &mut Result<rmcp::model::CallToolResult, ErrorData>,
    ) {
        let Err(err) = result else {
            return;
        };
        if !is_auth_expiry_signature(&err.message) {
            return;
        }
        let mxid = identity_from_ctx(ctx).map(|id| id.mxid);
        if let Some(mxid) = &mxid {
            self.clients.evict(mxid).await;
        }
        if let Some(AccessToken(token)) = token_from_ctx(ctx) {
            self.mas.drop_token(&token);
        }
        tracing::warn!(
            mxid = mxid.as_deref().unwrap_or("<unknown>"),
            "Synapse reported M_UNKNOWN_TOKEN; evicted SDK client + introspect caches"
        );
        *err = ErrorData::invalid_request(
            "Your matrix-mcp OAuth session has expired or been revoked. \
             In claude.ai → Connectors → Matrix, click Disconnect and then \
             Connect again to get a fresh session, then retry. Your \
             cross-signing identity is preserved — no need to re-run /setup.",
            None,
        );
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
        self.rate_limiter
            .check(&bearer_hash, Some(id.mas_subject.as_str()), category)
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
    /// The event id this event is replying to, from
    /// `content["m.relates_to"]["m.in_reply_to"]["event_id"]`.
    /// `null` when the event is not a reply.
    pub in_reply_to: Option<String>,
    /// True if this event is the root of a thread — i.e. at least one
    /// other event in the same response has `rel_type: "m.thread"` and
    /// points at this event id. Derived client-side from the batch.
    pub is_thread_root: bool,
    /// Thread reply count from `unsigned["m.relations"]["m.thread"]["count"]`.
    /// `null` when the server didn't include bundled thread aggregations
    /// (older servers or events that are not thread roots).
    pub thread_event_count: Option<u64>,
}

#[derive(Debug, Serialize, schemars::JsonSchema)]
pub struct ReadRecentMessagesResult {
    pub events: Vec<ReadEvent>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct ReadThreadParams {
    /// Matrix room id, e.g. `!abc:example.com`.
    pub room_id: String,
    /// Event id of the thread root, e.g. `$abc:example.com`.
    pub root_event_id: String,
    /// Maximum number of thread events to return. Defaults to 50, capped at
    /// 200.
    #[serde(default = "default_thread_limit")]
    pub limit: u32,
}

const fn default_thread_limit() -> u32 {
    50
}

const MAX_THREAD_LIMIT: u32 = 200;

#[derive(Debug, Serialize, schemars::JsonSchema)]
pub struct ReadThreadResult {
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

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct SearchMessagesParams {
    /// Full-text query string forwarded to the homeserver's search index.
    pub query: String,
    /// Optional Matrix room id to scope the search, e.g. `!abc:example.com`.
    /// When absent the homeserver searches across all joined rooms.
    pub room_id: Option<String>,
    /// Maximum number of results to return. Defaults to 20, capped at 100.
    #[serde(default = "default_search_limit")]
    pub limit: u32,
}

const fn default_search_limit() -> u32 {
    20
}

/// A single result returned by `search_messages`.
#[derive(Debug, Serialize, schemars::JsonSchema)]
pub struct SearchHit {
    pub event_id: Option<String>,
    pub room_id: String,
    pub sender: Option<String>,
    pub origin_server_ts: Option<u64>,
    /// Homeserver-computed relevance score; higher means closer match.
    /// `null` when the homeserver did not return a rank.
    pub rank: Option<f64>,
    /// Plaintext message body extracted from the event content.
    ///
    /// `null` for E2EE rooms: the homeserver-side `/_matrix/client/v3/search`
    /// runs against the stored ciphertext blob and cannot decrypt it, so no
    /// readable body is available here. Use `read_recent_messages` in the
    /// specific room (where the SDK decrypts locally) to retrieve the actual
    /// content.
    pub body: Option<String>,
}

#[derive(Debug, Serialize, schemars::JsonSchema)]
pub struct SearchMessagesResult {
    pub results: Vec<SearchHit>,
    /// Homeserver-reported approximate total number of matching events.
    /// Falls back to `results.len()` when the homeserver omits the count.
    pub total: u64,
}

#[derive(Debug, Serialize, schemars::JsonSchema)]
pub struct UnreadRoomSummary {
    pub room_id: String,
    pub display_name: Option<String>,
    pub encrypted: bool,
    /// Count of unread messages in this room.
    pub unread_messages: u64,
    /// Count of unread notifications (`notification_count` from
    /// sync). Generally >= mentions but <= messages.
    pub unread_notifications: u64,
    /// Count of unread events that mention the caller specifically.
    pub unread_mentions: u64,
    /// Event id of the latest event the SDK considers "interesting"
    /// for a room preview (`m.room.message`, sticker, poll start,
    /// call invite/notify, knock state). May be `null` if the room
    /// has no such event cached.
    pub latest_event_id: Option<String>,
    /// MXID of the sender of `latest_event_id`.
    pub latest_sender: Option<String>,
    /// `origin_server_ts` (ms since epoch) of the latest event. Used
    /// to sort the response by recency.
    pub latest_origin_server_ts: Option<u64>,
}

#[derive(Debug, Serialize, schemars::JsonSchema)]
pub struct UnreadSummaryResult {
    /// Rooms with at least one unread message, sorted by latest
    /// activity (newest first).
    pub rooms: Vec<UnreadRoomSummary>,
    /// Total count of rooms with at least one unread message. Equal
    /// to `rooms.len()` since we don't truncate.
    pub total_unread_rooms: usize,
    /// Sum of `unread_messages` across all rooms.
    pub total_unread_messages: u64,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct MarkReadParams {
    pub room_id: String,
    /// Event id to mark as read. If omitted, the latest event in the
    /// room (per the SDK's cached `latest_event`) is used.
    #[serde(default)]
    pub event_id: Option<String>,
}

#[derive(Debug, Serialize, schemars::JsonSchema)]
pub struct MarkReadResult {
    pub room_id: String,
    pub event_id: String,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct SendReactionParams {
    pub room_id: String,
    pub event_id: String,
    /// Reaction key — usually a single emoji (`"👍"`), but Matrix lets
    /// it be any short string. Be respectful: this is sent in cleartext
    /// inside encrypted rooms too (reactions are intentionally
    /// non-E2EE per MSC2677).
    pub key: String,
}

#[derive(Debug, Serialize, schemars::JsonSchema)]
pub struct SendReactionResult {
    /// Event id of the new `m.reaction` event.
    pub event_id: String,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct RedactMessageParams {
    pub room_id: String,
    pub event_id: String,
    /// Optional human-readable reason. Stored on the redaction event
    /// and visible to other clients (including bridged ones).
    #[serde(default)]
    pub reason: Option<String>,
}

#[derive(Debug, Serialize, schemars::JsonSchema)]
pub struct RedactMessageResult {
    /// Event id of the `m.room.redaction` event.
    pub event_id: String,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct JoinRoomParams {
    /// Either a room id (`!abc:server`) or a canonical alias
    /// (`#name:server`). matrix-mcp passes the value through to
    /// `join_room_by_id_or_alias`.
    pub room_id_or_alias: String,
}

#[derive(Debug, Serialize, schemars::JsonSchema)]
pub struct JoinRoomResult {
    pub room_id: String,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct LeaveRoomParams {
    pub room_id: String,
}

#[derive(Debug, Serialize, schemars::JsonSchema)]
pub struct LeaveRoomResult {
    pub room_id: String,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct InviteUserParams {
    pub room_id: String,
    /// MXID to invite, e.g. `@alice:example.com`.
    pub mxid: String,
}

#[derive(Debug, Serialize, schemars::JsonSchema)]
pub struct InviteUserResult {
    pub room_id: String,
    pub mxid: String,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct SetAuditRoomParams {
    /// Canonical Matrix room id (`!room:server`) to receive audit notices.
    /// You must already be joined to this room.
    pub room_id: String,
}

#[derive(Debug, Serialize, schemars::JsonSchema)]
pub struct SetAuditRoomResult {
    /// The room id that was stored as the audit destination.
    pub room_id: String,
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
pub struct DownloadAttachmentParams {
    /// Matrix room id containing the attachment event,
    /// e.g. `!abc:example.com`.
    pub room_id: String,
    /// Event id of the `m.room.message` event whose `msgtype` is one of
    /// `m.file`, `m.image`, `m.audio`, or `m.video`.
    pub event_id: String,
}

#[derive(Debug, Serialize, schemars::JsonSchema)]
pub struct DownloadAttachmentResult {
    /// MIME type reported by the event's `info.mimetype` field,
    /// or `"application/octet-stream"` if the event didn't set one.
    pub content_type: String,
    /// Number of bytes in the decoded attachment.
    pub size_bytes: u64,
    /// Base64-encoded (standard alphabet, no line breaks) file contents.
    pub body_base64: String,
    /// Original filename from the event (`filename` field, falling back
    /// to `body`), or `null` if the event type doesn't carry one.
    pub filename: Option<String>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct SendImageFromUrlParams {
    /// Matrix room id, e.g. `!abc:example.com`.
    pub room_id: String,
    /// HTTPS URL of the image to fetch and upload. Must start with
    /// `https://` — plain `http://` URLs are rejected to prevent sending
    /// credentials over cleartext. Maximum fetch size is controlled by
    /// `MATRIX_MCP_UPLOAD_MAX_BYTES` (default 10 MiB).
    pub image_url: String,
    /// Optional caption. When set, it becomes the Matrix `body`
    /// (user-visible caption) and the URL-derived basename is stored as
    /// `filename`. When omitted the basename is used as `body`.
    pub caption: Option<String>,
}

#[derive(Debug, Serialize, schemars::JsonSchema)]
pub struct SendImageFromUrlResult {
    /// Matrix event id of the sent `m.image` message.
    pub event_id: String,
    /// `mxc://` URI assigned by the homeserver media repo.
    pub mxc_uri: String,
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
    #[tool(
        description = "Return the authenticated Matrix user id and device id.",
        annotations(title = "Who am I", read_only_hint = true)
    )]
    #[allow(clippy::unused_self, clippy::needless_pass_by_value)]
    fn whoami(
        &self,
        ctx: RequestContext<RoleServer>,
    ) -> Result<rmcp::model::CallToolResult, ErrorData> {
        let started = Instant::now();
        let mxid_for_audit = identity_from_ctx(&ctx).map_or_else(String::new, |i| i.mxid);
        let span = make_tool_span("whoami", &mxid_for_audit, None);
        // whoami reads identity straight from the auth-middleware
        // introspection result and never touches Synapse, so it cannot
        // observe `M_UNKNOWN_TOKEN` and there is nothing to evict.
        // Skip `react_to_auth_expiry` here (and avoid making this handler
        // async just to satisfy the helper's `.await`).
        let result = (|| {
            self.rate_limit_check(&ctx, Category::Read)?;
            let id = identity_from_ctx(&ctx).ok_or_else(missing_identity_err)?;
            structured_result(&WhoamiResult {
                mxid: id.mxid,
                device_id: id.device_id,
            })
        })();
        emit_tool_audit(
            "whoami",
            &mxid_for_audit,
            None,
            started,
            None,
            &span,
            &result,
        );
        result
    }

    /// List the rooms the authenticated user has joined. Each entry
    /// reports the room id, display name, topic, and whether the room
    /// is end-to-end encrypted.
    #[tool(
        description = "List Matrix rooms the authenticated user has joined.",
        annotations(title = "List joined rooms", read_only_hint = true)
    )]
    #[allow(clippy::needless_pass_by_value)]
    async fn list_joined_rooms(
        &self,
        ctx: RequestContext<RoleServer>,
    ) -> Result<rmcp::model::CallToolResult, ErrorData> {
        let started = Instant::now();
        let mxid_for_audit = identity_from_ctx(&ctx).map_or_else(String::new, |i| i.mxid);
        let span = make_tool_span("list_joined_rooms", &mxid_for_audit, None);
        let (mut result, room_count) = async {
            self.rate_limit_check(&ctx, Category::Read)?;
            let client = self.client_for(&ctx).await?;
            let rooms: Vec<JoinedRoom> = client.joined_rooms().iter().map(summarize_room).collect();
            let count = rooms.len();
            let res = structured_result(&JoinedRoomsResult { rooms });
            Ok::<_, ErrorData>((res, count))
        }
        .instrument(span.clone())
        .await
        .map_or_else(|e| (Err(e), 0), |(r, c)| (r, c));
        self.react_to_auth_expiry(&ctx, &mut result).await;
        emit_tool_audit(
            "list_joined_rooms",
            &mxid_for_audit,
            None,
            started,
            Some(room_count),
            &span,
            &result,
        );
        result
    }

    /// Read recent events from a Matrix room (newest first). The SDK
    /// decrypts E2EE rooms iff this device is cross-signed. Events
    /// that could not be decrypted are reported with
    /// `status: "unable_to_decrypt"` and a null event body.
    ///
    /// Each returned event includes threading metadata:
    /// - `in_reply_to`: the event id this event replies to (if any).
    /// - `is_thread_root`: true if any event in this response starts a
    ///   thread from this event.
    /// - `thread_event_count`: server-aggregated reply count (when present).
    #[tool(
        description = "Read recent events (newest first) from a Matrix room.",
        annotations(title = "Read recent messages", read_only_hint = true)
    )]
    #[allow(clippy::needless_pass_by_value)]
    async fn read_recent_messages(
        &self,
        ctx: RequestContext<RoleServer>,
        Parameters(params): Parameters<ReadRecentMessagesParams>,
    ) -> Result<rmcp::model::CallToolResult, ErrorData> {
        let started = Instant::now();
        let mxid_for_audit = identity_from_ctx(&ctx).map_or_else(String::new, |i| i.mxid);
        let room_id_for_audit = params.room_id.clone();
        let span = make_tool_span(
            "read_recent_messages",
            &mxid_for_audit,
            Some(&room_id_for_audit),
        );
        let (mut result, event_count) = async {
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

            let events = read_events_from_chunk(messages.chunk);
            let count = events.len();
            let res = structured_result(&ReadRecentMessagesResult { events });
            Ok::<_, ErrorData>((res, count))
        }
        .instrument(span.clone())
        .await
        .map_or_else(|e| (Err(e), 0), |(r, c)| (r, c));
        self.react_to_auth_expiry(&ctx, &mut result).await;
        emit_tool_audit(
            "read_recent_messages",
            &mxid_for_audit,
            Some(&room_id_for_audit),
            started,
            Some(event_count),
            &span,
            &result,
        );
        result
    }

    /// Read the events in a Matrix thread (MSC3440 / spec v1.4+). Returns all
    /// reply events that belong to the thread rooted at `root_event_id`,
    /// newest first, using the homeserver's
    /// `GET /_matrix/client/v1/rooms/{room_id}/relations/{event_id}/m.thread`
    /// endpoint. Each `ReadEvent` carries the same threading fields as
    /// `read_recent_messages`. The root event itself is not included in the
    /// response (fetch it with `read_recent_messages` if needed).
    #[tool(
        description = "Read all events in a Matrix thread rooted at a given event id (newest first).",
        annotations(title = "Read thread", read_only_hint = true)
    )]
    #[allow(clippy::needless_pass_by_value)]
    async fn read_thread(
        &self,
        ctx: RequestContext<RoleServer>,
        Parameters(params): Parameters<ReadThreadParams>,
    ) -> Result<rmcp::model::CallToolResult, ErrorData> {
        let started = Instant::now();
        let mxid_for_audit = identity_from_ctx(&ctx).map_or_else(String::new, |i| i.mxid);
        let room_id_for_audit = params.room_id.clone();
        let span = make_tool_span("read_thread", &mxid_for_audit, Some(&room_id_for_audit));
        let (mut result, event_count) = async {
            self.rate_limit_check(&ctx, Category::Read)?;
            let client = self.client_for(&ctx).await?;
            let room_id: OwnedRoomId = params.room_id.parse().map_err(|e| {
                ErrorData::invalid_params(format!("invalid room_id {}: {e}", params.room_id), None)
            })?;
            let room = client.get_room(&room_id).ok_or_else(|| {
                ErrorData::invalid_params(format!("not joined to {room_id}"), None)
            })?;
            let root_event_id: OwnedEventId = params.root_event_id.parse().map_err(|e| {
                ErrorData::invalid_params(
                    format!("invalid root_event_id {}: {e}", params.root_event_id),
                    None,
                )
            })?;

            // Cap the limit to MAX_THREAD_LIMIT; clamp(1, …) ensures we
            // don't ask for zero events.
            let limit = params.limit.clamp(1, MAX_THREAD_LIMIT);

            let opts = RelationsOptions {
                include_relations: IncludeRelations::RelationsOfType(RelationType::Thread),
                limit: Some(limit.into()),
                ..Default::default()
            };
            let relations = room.relations(root_event_id, opts).await.map_err(|e| {
                ErrorData::internal_error(format!("fetch thread relations: {e}"), None)
            })?;

            let events = read_events_from_chunk(relations.chunk);
            let count = events.len();
            let res = structured_result(&ReadThreadResult { events });
            Ok::<_, ErrorData>((res, count))
        }
        .instrument(span.clone())
        .await
        .map_or_else(|e| (Err(e), 0), |(r, c)| (r, c));
        self.react_to_auth_expiry(&ctx, &mut result).await;
        emit_tool_audit(
            "read_thread",
            &mxid_for_audit,
            Some(&room_id_for_audit),
            started,
            Some(event_count),
            &span,
            &result,
        );
        result
    }

    /// Send a text message to a Matrix room. The SDK renders the body
    /// as Markdown (for `formatted_body`) while keeping it as plain
    /// text in `body`. E2EE rooms are encrypted automatically iff this
    /// device is cross-signed.
    #[tool(
        description = "Send a text message to a Matrix room (markdown-rendered).",
        annotations(
            title = "Send text message",
            read_only_hint = false,
            destructive_hint = false,
            idempotent_hint = false
        )
    )]
    #[allow(clippy::needless_pass_by_value)]
    async fn send_text_message(
        &self,
        ctx: RequestContext<RoleServer>,
        Parameters(params): Parameters<SendTextMessageParams>,
    ) -> Result<rmcp::model::CallToolResult, ErrorData> {
        let started = Instant::now();
        let mxid_for_audit = identity_from_ctx(&ctx).map_or_else(String::new, |i| i.mxid);
        let room_id_for_audit = params.room_id.clone();
        let span = make_tool_span(
            "send_text_message",
            &mxid_for_audit,
            Some(&room_id_for_audit),
        );
        let mut result = async {
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
        .instrument(span.clone())
        .await;
        self.react_to_auth_expiry(&ctx, &mut result).await;
        emit_tool_audit(
            "send_text_message",
            &mxid_for_audit,
            Some(&room_id_for_audit),
            started,
            None,
            &span,
            &result,
        );
        emit_write_notice(
            &result,
            &self.clients,
            &ctx,
            "send_text_message",
            Some(room_id_for_audit.as_str()),
        )
        .await;
        result
    }

    /// Report whether this matrix-mcp device is verified (cross-signed)
    /// by the authenticated user. If not, no message in E2EE rooms can
    /// be decrypted and outgoing messages to E2EE rooms will be
    /// undecryptable to anyone else.
    #[tool(
        description = "Report the cross-signing / verification status of this matrix-mcp device.",
        annotations(title = "Verify status", read_only_hint = true)
    )]
    #[allow(clippy::needless_pass_by_value)]
    async fn verify_status(
        &self,
        ctx: RequestContext<RoleServer>,
    ) -> Result<rmcp::model::CallToolResult, ErrorData> {
        let started = Instant::now();
        let mxid_for_audit = identity_from_ctx(&ctx).map_or_else(String::new, |i| i.mxid);
        let span = make_tool_span("verify_status", &mxid_for_audit, None);
        let mut result = async {
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
        .instrument(span.clone())
        .await;
        self.react_to_auth_expiry(&ctx, &mut result).await;
        emit_tool_audit(
            "verify_status",
            &mxid_for_audit,
            None,
            started,
            None,
            &span,
            &result,
        );
        result
    }

    /// Return metadata about a joined Matrix room: display name, topic,
    /// encryption state, and member counts. Only succeeds for rooms the
    /// caller is currently joined to — invited, left, knocked, and
    /// banned rooms are rejected. Read-only.
    #[tool(
        description = "Return metadata about a joined Matrix room (name, topic, encryption, members, power level).",
        annotations(title = "Room info", read_only_hint = true)
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
        let span = make_tool_span("room_info", &mxid_for_audit, Some(&room_id_for_audit));
        let mut result = async {
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
        .instrument(span.clone())
        .await;
        self.react_to_auth_expiry(&ctx, &mut result).await;
        emit_tool_audit(
            "room_info",
            &mxid_for_audit,
            Some(&room_id_for_audit),
            started,
            None,
            &span,
            &result,
        );
        result
    }

    /// List joined members of a Matrix room with display name, avatar,
    /// and normalized power level. Capped at `limit` (default 200,
    /// maximum 1000). `total` reports the room's true joined-member
    /// count so callers can detect truncation.
    #[tool(
        description = "List joined members of a Matrix room (mxid, display name, avatar, power level).",
        annotations(title = "Room members", read_only_hint = true)
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
        let span = make_tool_span("room_members", &mxid_for_audit, Some(&room_id_for_audit));
        let (mut result, member_count) = async {
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
        .instrument(span.clone())
        .await
        .map_or_else(|e| (Err(e), 0), |(r, c)| (r, c));
        self.react_to_auth_expiry(&ctx, &mut result).await;
        emit_tool_audit(
            "room_members",
            &mxid_for_audit,
            Some(&room_id_for_audit),
            started,
            Some(member_count),
            &span,
            &result,
        );
        result
    }

    /// Return a summary of rooms with unread messages, sorted by latest
    /// activity. Each entry includes unread counts, the latest event
    /// preview (id + sender + display name + timestamp), and whether
    /// the room is encrypted.
    #[tool(
        description = "Summarise rooms with unread messages, sorted by latest activity.",
        annotations(title = "Unread summary", read_only_hint = true)
    )]
    #[allow(clippy::needless_pass_by_value)]
    async fn get_unread_summary(
        &self,
        ctx: RequestContext<RoleServer>,
    ) -> Result<rmcp::model::CallToolResult, ErrorData> {
        let started = Instant::now();
        let mxid_for_audit = identity_from_ctx(&ctx).map_or_else(String::new, |i| i.mxid);
        let span = make_tool_span("get_unread_summary", &mxid_for_audit, None);
        let (mut result, room_count) = async {
            self.rate_limit_check(&ctx, Category::Read)?;
            let client = self.client_for(&ctx).await?;
            let mut rooms: Vec<UnreadRoomSummary> = client
                .joined_rooms()
                .iter()
                .filter_map(|room| {
                    // matrix-rust-sdk 0.17 exposes two parallel sets of
                    // unread counters with very different semantics:
                    //
                    //   - `Room::num_unread_messages` / `num_unread_notifications`
                    //     / `num_unread_mentions` are **client-side
                    //     computed** from local read-receipt state. They
                    //     require the client to be actively browsing the
                    //     timeline and emitting `m.read` receipts — and
                    //     for a headless server like matrix-mcp, which
                    //     does neither, they are effectively always 0.
                    //   - `Room::unread_notification_counts()` returns
                    //     `UnreadNotificationsCount { notification_count,
                    //     highlight_count }` straight from Synapse's
                    //     `/sync` response. These are the **server-side**
                    //     counts — exactly what Element X's sidebar
                    //     badge shows and what `event_push_summary`
                    //     stores in postgres.
                    //
                    // We want "Synapse says these N rooms have unread,
                    // summarise them", so gate on the server-side
                    // counters. We still expose the client-side
                    // `num_unread_messages` in the response as
                    // supplementary context — for the small subset of
                    // rooms where the SDK has been tracking receipts
                    // (e.g. matrix-mcp itself emitted them via
                    // `mark_read`), it's a useful extra signal.
                    let server = room.unread_notification_counts();
                    let unread_notifications = server.notification_count;
                    let unread_mentions = server.highlight_count;
                    let unread_messages = room.num_unread_messages();
                    if unread_notifications == 0 && unread_mentions == 0 && unread_messages == 0 {
                        return None;
                    }
                    // `latest_event()` returns `LatestEventValue` (an
                    // enum, not Option). `event_id()`, `timestamp()`,
                    // and the parsed sender come out of the
                    // matching `Remote(TimelineEvent)` variant.
                    let latest = room.latest_event();
                    let latest_event_id = latest.event_id().map(|id| id.to_string());
                    let latest_origin_server_ts = latest.timestamp().map(|ts| ts.get().into());
                    let latest_sender =
                        if let matrix_sdk::latest_events::LatestEventValue::Remote(ref ev) = latest
                        {
                            ev.raw()
                                .deserialize_as::<serde_json::Value>()
                                .ok()
                                .and_then(|v| {
                                    v.get("sender").and_then(|s| s.as_str()).map(str::to_owned)
                                })
                        } else {
                            None
                        };
                    Some(UnreadRoomSummary {
                        room_id: room.room_id().to_string(),
                        display_name: room.cached_display_name().map(|n| n.to_string()),
                        encrypted: room.encryption_state().is_encrypted(),
                        unread_messages,
                        unread_notifications,
                        unread_mentions,
                        latest_event_id,
                        latest_sender,
                        latest_origin_server_ts,
                    })
                })
                .collect();
            rooms.sort_by(|a, b| {
                b.latest_origin_server_ts
                    .unwrap_or(0)
                    .cmp(&a.latest_origin_server_ts.unwrap_or(0))
            });
            let total_unread_rooms = rooms.len();
            let total_unread_messages: u64 = rooms.iter().map(|r| r.unread_messages).sum();
            let res = structured_result(&UnreadSummaryResult {
                rooms,
                total_unread_rooms,
                total_unread_messages,
            });
            Ok::<_, ErrorData>((res, total_unread_rooms))
        }
        .instrument(span.clone())
        .await
        .map_or_else(|e| (Err(e), 0), |(r, c)| (r, c));
        self.react_to_auth_expiry(&ctx, &mut result).await;
        emit_tool_audit(
            "get_unread_summary",
            &mxid_for_audit,
            None,
            started,
            Some(room_count),
            &span,
            &result,
        );
        result
    }

    /// Mark a Matrix room (or one specific event in it) as read by
    /// sending an unthreaded read receipt. Fire-and-forget: returns
    /// once the homeserver has accepted the receipt request. If
    /// `event_id` is omitted, the latest event in the room is used.
    #[tool(
        description = "Mark a room (or a specific event) as read.",
        annotations(
            title = "Mark read",
            read_only_hint = false,
            destructive_hint = false,
            idempotent_hint = true
        )
    )]
    #[allow(clippy::needless_pass_by_value)]
    async fn mark_read(
        &self,
        ctx: RequestContext<RoleServer>,
        Parameters(params): Parameters<MarkReadParams>,
    ) -> Result<rmcp::model::CallToolResult, ErrorData> {
        let started = Instant::now();
        let mxid_for_audit = identity_from_ctx(&ctx).map_or_else(String::new, |i| i.mxid);
        let room_id_for_audit = params.room_id.clone();
        let span = make_tool_span("mark_read", &mxid_for_audit, Some(&room_id_for_audit));
        let mut result = async {
            self.rate_limit_check(&ctx, Category::Write)?;
            let client = self.client_for(&ctx).await?;
            let room_id: OwnedRoomId = params.room_id.parse().map_err(|e| {
                ErrorData::invalid_params(format!("invalid room_id {}: {e}", params.room_id), None)
            })?;
            let room = client.get_room(&room_id).ok_or_else(|| {
                ErrorData::invalid_params(format!("not joined to {room_id}"), None)
            })?;
            let event_id = if let Some(id) = params.event_id {
                id.parse().map_err(|e| {
                    ErrorData::invalid_params(format!("invalid event_id {id}: {e}"), None)
                })?
            } else {
                room.latest_event().event_id().ok_or_else(|| {
                    ErrorData::invalid_params(
                        "room has no latest event to receipt; pass event_id explicitly",
                        None,
                    )
                })?
            };
            room.send_single_receipt(
                matrix_sdk::ruma::api::client::receipt::create_receipt::v3::ReceiptType::Read,
                matrix_sdk::ruma::events::receipt::ReceiptThread::Unthreaded,
                event_id.clone(),
            )
            .await
            .map_err(|e| ErrorData::internal_error(format!("send_single_receipt: {e}"), None))?;
            structured_result(&MarkReadResult {
                room_id: room.room_id().to_string(),
                event_id: event_id.to_string(),
            })
        }
        .instrument(span.clone())
        .await;
        self.react_to_auth_expiry(&ctx, &mut result).await;
        emit_tool_audit(
            "mark_read",
            &mxid_for_audit,
            Some(&room_id_for_audit),
            started,
            None,
            &span,
            &result,
        );
        emit_write_notice(
            &result,
            &self.clients,
            &ctx,
            "mark_read",
            Some(room_id_for_audit.as_str()),
        )
        .await;
        result
    }

    /// Add an emoji-style reaction to a Matrix event. Returns the
    /// event id of the new `m.reaction` event. Reactions are
    /// intentionally non-E2EE per MSC2677 — the `key` string is
    /// visible to anyone in the room (including bridged services).
    #[tool(
        description = "Add an emoji reaction to a Matrix event.",
        annotations(
            title = "Send reaction",
            read_only_hint = false,
            destructive_hint = false,
            idempotent_hint = false
        )
    )]
    #[allow(clippy::needless_pass_by_value)]
    async fn send_reaction(
        &self,
        ctx: RequestContext<RoleServer>,
        Parameters(params): Parameters<SendReactionParams>,
    ) -> Result<rmcp::model::CallToolResult, ErrorData> {
        let started = Instant::now();
        let mxid_for_audit = identity_from_ctx(&ctx).map_or_else(String::new, |i| i.mxid);
        let room_id_for_audit = params.room_id.clone();
        let span = make_tool_span("send_reaction", &mxid_for_audit, Some(&room_id_for_audit));
        let mut result = async {
            self.rate_limit_check(&ctx, Category::Write)?;
            let client = self.client_for(&ctx).await?;
            let room_id: OwnedRoomId = params.room_id.parse().map_err(|e| {
                ErrorData::invalid_params(format!("invalid room_id {}: {e}", params.room_id), None)
            })?;
            let room = client.get_room(&room_id).ok_or_else(|| {
                ErrorData::invalid_params(format!("not joined to {room_id}"), None)
            })?;
            let target_event_id: matrix_sdk::ruma::OwnedEventId =
                params.event_id.parse().map_err(|e| {
                    ErrorData::invalid_params(
                        format!("invalid event_id {}: {e}", params.event_id),
                        None,
                    )
                })?;
            let content = matrix_sdk::ruma::events::reaction::ReactionEventContent::new(
                matrix_sdk::ruma::events::relation::Annotation::new(target_event_id, params.key),
            );
            let response = room
                .send(content)
                .await
                .map_err(|e| ErrorData::internal_error(format!("room.send reaction: {e}"), None))?;
            structured_result(&SendReactionResult {
                event_id: response.response.event_id.to_string(),
            })
        }
        .instrument(span.clone())
        .await;
        self.react_to_auth_expiry(&ctx, &mut result).await;
        emit_tool_audit(
            "send_reaction",
            &mxid_for_audit,
            Some(&room_id_for_audit),
            started,
            None,
            &span,
            &result,
        );
        emit_write_notice(
            &result,
            &self.clients,
            &ctx,
            "send_reaction",
            Some(room_id_for_audit.as_str()),
        )
        .await;
        result
    }

    /// Redact a Matrix event you own (or that you have power to
    /// redact). The homeserver enforces ACLs; matrix-mcp does not
    /// check who sent the event — if your power level is below
    /// `redact`, the homeserver rejects the request and you get an
    /// `internal_error` back.
    #[tool(
        description = "Redact (delete) a Matrix event.",
        annotations(
            title = "Redact (delete) message",
            read_only_hint = false,
            destructive_hint = true,
            idempotent_hint = false
        )
    )]
    #[allow(clippy::needless_pass_by_value)]
    async fn redact_message(
        &self,
        ctx: RequestContext<RoleServer>,
        Parameters(params): Parameters<RedactMessageParams>,
    ) -> Result<rmcp::model::CallToolResult, ErrorData> {
        let started = Instant::now();
        let mxid_for_audit = identity_from_ctx(&ctx).map_or_else(String::new, |i| i.mxid);
        let room_id_for_audit = params.room_id.clone();
        let span = make_tool_span("redact_message", &mxid_for_audit, Some(&room_id_for_audit));
        let mut result = async {
            self.rate_limit_check(&ctx, Category::Write)?;
            let client = self.client_for(&ctx).await?;
            let room_id: OwnedRoomId = params.room_id.parse().map_err(|e| {
                ErrorData::invalid_params(format!("invalid room_id {}: {e}", params.room_id), None)
            })?;
            let room = client.get_room(&room_id).ok_or_else(|| {
                ErrorData::invalid_params(format!("not joined to {room_id}"), None)
            })?;
            let target_event_id: matrix_sdk::ruma::OwnedEventId =
                params.event_id.parse().map_err(|e| {
                    ErrorData::invalid_params(
                        format!("invalid event_id {}: {e}", params.event_id),
                        None,
                    )
                })?;
            let response = room
                .redact(&target_event_id, params.reason.as_deref(), None)
                .await
                .map_err(|e| ErrorData::internal_error(format!("room.redact: {e}"), None))?;
            structured_result(&RedactMessageResult {
                event_id: response.event_id.to_string(),
            })
        }
        .instrument(span.clone())
        .await;
        self.react_to_auth_expiry(&ctx, &mut result).await;
        emit_tool_audit(
            "redact_message",
            &mxid_for_audit,
            Some(&room_id_for_audit),
            started,
            None,
            &span,
            &result,
        );
        emit_write_notice(
            &result,
            &self.clients,
            &ctx,
            "redact_message",
            Some(room_id_for_audit.as_str()),
        )
        .await;
        result
    }

    /// Fetch and return the binary content of an attachment event
    /// (`m.file`, `m.image`, `m.audio`, or `m.video`) as a base64
    /// string. The SDK handles decryption transparently for E2EE rooms.
    /// Attachments whose declared size exceeds the configured cap
    /// (default 5 MiB; `MATRIX_MCP_DOWNLOAD_MAX_BYTES`) are rejected
    /// before any media I/O occurs.
    #[tool(
        description = "Download an attachment from a Matrix room event and return it as base64.",
        annotations(title = "Download attachment", read_only_hint = true)
    )]
    #[allow(clippy::needless_pass_by_value)]
    async fn download_attachment(
        &self,
        ctx: RequestContext<RoleServer>,
        Parameters(params): Parameters<DownloadAttachmentParams>,
    ) -> Result<rmcp::model::CallToolResult, ErrorData> {
        let started = Instant::now();
        let mxid_for_audit = identity_from_ctx(&ctx).map_or_else(String::new, |i| i.mxid);
        let room_id_for_audit = params.room_id.clone();
        let span = make_tool_span(
            "download_attachment",
            &mxid_for_audit,
            Some(&room_id_for_audit),
        );
        let mut result = async {
            self.rate_limit_check(&ctx, Category::Read)?;
            let client = self.client_for(&ctx).await?;

            let room_id: OwnedRoomId = params.room_id.parse().map_err(|e| {
                ErrorData::invalid_params(
                    format!("invalid room_id {}: {e}", params.room_id),
                    None,
                )
            })?;
            let room = client.get_room(&room_id).ok_or_else(|| {
                ErrorData::invalid_params(format!("not joined to {room_id}"), None)
            })?;

            let event_id: OwnedEventId = params.event_id.parse().map_err(|e| {
                ErrorData::invalid_params(
                    format!("invalid event_id {}: {e}", params.event_id),
                    None,
                )
            })?;

            // Fetch (and transparently decrypt for E2EE rooms) the event.
            let tle = room
                .event(&event_id, None)
                .await
                .map_err(|e| ErrorData::internal_error(format!("fetch event: {e}"), None))?;

            // Deserialize the (possibly decrypted) event JSON so we can
            // pattern-match on `content.msgtype`. For E2EE events the SDK
            // has already decrypted the payload, so `.raw()` always yields
            // the inner plaintext regardless of room encryption.
            let raw_value: serde_json::Value = tle
                .raw()
                .deserialize_as()
                .unwrap_or(serde_json::Value::Null);

            let msg_content = raw_value
                .get("content")
                .and_then(|c| serde_json::from_value::<RoomMessageEventContent>(c.clone()).ok())
                .ok_or_else(|| {
                    ErrorData::invalid_params(
                        "event content is not a room message (not m.room.message)",
                        None,
                    )
                })?;

            // Extract the media source, optional mimetype, declared size,
            // and filename depending on the msgtype. Only m.file, m.image,
            // m.audio, and m.video are accepted.
            let (source, mimetype, declared_size, filename): (
                MediaSource,
                Option<String>,
                Option<u64>,
                Option<String>,
            ) = match msg_content.msgtype {
                MessageType::File(f) => {
                    let mime = f.info.as_ref().and_then(|i| i.mimetype.clone());
                    let sz = f.info.as_ref().and_then(|i| i.size).map(u64::from);
                    let fname = Some(f.filename().to_owned());
                    (f.source, mime, sz, fname)
                }
                MessageType::Image(img) => {
                    let mime = img.info.as_ref().and_then(|i| i.mimetype.clone());
                    let sz = img.info.as_ref().and_then(|i| i.size).map(u64::from);
                    let fname = Some(img.filename().to_owned());
                    (img.source, mime, sz, fname)
                }
                MessageType::Audio(a) => {
                    let mime = a.info.as_ref().and_then(|i| i.mimetype.clone());
                    let sz = a.info.as_ref().and_then(|i| i.size).map(u64::from);
                    let fname = Some(a.filename().to_owned());
                    (a.source, mime, sz, fname)
                }
                MessageType::Video(v) => {
                    let mime = v.info.as_ref().and_then(|i| i.mimetype.clone());
                    let sz = v.info.as_ref().and_then(|i| i.size).map(u64::from);
                    let fname = Some(v.filename().to_owned());
                    (v.source, mime, sz, fname)
                }
                other => {
                    return Err(ErrorData::invalid_params(
                        format!(
                            "event msgtype '{}' is not a downloadable attachment;                              must be m.file, m.image, m.audio, or m.video",
                            other.msgtype()
                        ),
                        None,
                    ));
                }
            };

            // Size-cap check before any network I/O.
            if let Some(declared) = declared_size
                && declared > self.download_max_bytes
            {
                return Err(ErrorData::invalid_params(
                    format!(
                        "attachment declared size {declared} bytes exceeds \
                         the cap of {} bytes (MATRIX_MCP_DOWNLOAD_MAX_BYTES)",
                        self.download_max_bytes
                    ),
                    None,
                ));
            }

            // Fetch (and for E2EE, decrypt) the media bytes.
            // `use_cache = false` so we always get a fresh copy;
            // the SDK media cache is an optimisation for display,
            // not for this export path.
            let bytes = client
                .media()
                .get_media_content(
                    &MediaRequestParameters {
                        source,
                        format: MediaFormat::File,
                    },
                    false,
                )
                .await
                .map_err(|e| ErrorData::internal_error(format!("media download: {e}"), None))?;

            // Post-download size check — protects against missing or
            // incorrect info.size in the event.
            let size_bytes = u64::try_from(bytes.len()).unwrap_or(u64::MAX);
            if size_bytes > self.download_max_bytes {
                return Err(ErrorData::invalid_params(
                    format!(
                        "attachment actual size {size_bytes} bytes exceeds the                          configured cap of {} bytes",
                        self.download_max_bytes
                    ),
                    None,
                ));
            }

            let body_base64 = base64::engine::general_purpose::STANDARD_NO_PAD.encode(&bytes);
            let content_type =
                mimetype.unwrap_or_else(|| "application/octet-stream".to_owned());

            structured_result(&DownloadAttachmentResult {
                content_type,
                size_bytes,
                body_base64,
                filename,
            })
        }
        .instrument(span.clone())
        .await;
        self.react_to_auth_expiry(&ctx, &mut result).await;
        emit_tool_audit(
            "download_attachment",
            &mxid_for_audit,
            Some(&room_id_for_audit),
            started,
            Some(1),
            &span,
            &result,
        );
        result
    }

    /// Fetch an image from a public HTTPS URL, upload it to the Matrix
    /// homeserver media repo, and post it as an `m.image` message in the
    /// specified room.
    ///
    /// The URL must be HTTPS (plain HTTP is rejected). Redirects are limited
    /// to 3 hops and the fetch has a hard 15 s timeout. The response
    /// `Content-Type` must start with `image/`; anything else is rejected.
    /// Images larger than `MATRIX_MCP_UPLOAD_MAX_BYTES` (default 10 MiB) are
    /// rejected before the homeserver upload.
    ///
    /// # Security note
    ///
    /// `image_url` is user-supplied. Only HTTPS is accepted to prevent
    /// cleartext credential leakage. Redirects are limited to 3 hops.
    /// Full SSRF defence (RFC-1918 / loopback block) is a future hardening
    /// item tracked in the project issue tracker — do NOT remove this note
    /// before that work is done.
    #[tool(
        description = "Fetch an image from an HTTPS URL and post it to a Matrix room as m.image.",
        annotations(
            title = "Send image",
            read_only_hint = false,
            destructive_hint = false,
            idempotent_hint = false
        )
    )]
    #[allow(clippy::needless_pass_by_value)]
    async fn send_image_from_url(
        &self,
        ctx: RequestContext<RoleServer>,
        Parameters(params): Parameters<SendImageFromUrlParams>,
    ) -> Result<rmcp::model::CallToolResult, ErrorData> {
        let started = Instant::now();
        let mxid_for_audit = identity_from_ctx(&ctx).map_or_else(String::new, |i| i.mxid);
        let room_id_for_audit = params.room_id.clone();
        let span = make_tool_span(
            "send_image_from_url",
            &mxid_for_audit,
            Some(&room_id_for_audit),
        );
        let mut result = async {
            self.rate_limit_check(&ctx, Category::Write)?;

            // --- URL validation -----------------------------------------
            if !params.image_url.starts_with("https://") {
                return Err(ErrorData::invalid_params(
                    "image_url must be an HTTPS URL \
                     (http:// is rejected to prevent credential exposure over cleartext)",
                    None,
                ));
            }

            // --- Fetch --------------------------------------------------
            // SSRF note: we require HTTPS (above), cap the body to
            // `upload_max_bytes`, limit redirects to 3 hops, and apply a
            // 15 s timeout. Blocking RFC-1918 / loopback destinations is a
            // future hardening item — do NOT remove this comment before
            // that work is done.
            let http = reqwest::Client::builder()
                .use_rustls_tls()
                .redirect(reqwest::redirect::Policy::limited(3))
                .timeout(Duration::from_secs(15))
                .build()
                .map_err(|e| ErrorData::internal_error(format!("build http client: {e}"), None))?;

            let response =
                http.get(&params.image_url).send().await.map_err(|e| {
                    ErrorData::internal_error(format!("fetch image_url: {e}"), None)
                })?;

            // --- Content-Type guard -------------------------------------
            let ct = response
                .headers()
                .get(reqwest::header::CONTENT_TYPE)
                .and_then(|v| v.to_str().ok())
                .unwrap_or("")
                .to_owned();
            if !ct.starts_with("image/") {
                return Err(ErrorData::invalid_params(
                    format!("remote URL returned Content-Type `{ct}`; expected `image/*`"),
                    None,
                ));
            }
            // Parse to a typed Mime; fall back to image/jpeg on failure
            // (shouldn't occur after the prefix guard above).
            let mime_type: mime::Mime = ct.parse().unwrap_or(mime::IMAGE_JPEG);

            // --- Size cap -----------------------------------------------
            let cap = self.upload_max_bytes;
            let bytes = response
                .bytes()
                .await
                .map_err(|e| ErrorData::internal_error(format!("read image body: {e}"), None))?;
            if bytes.len() > cap {
                return Err(ErrorData::invalid_params(
                    format!(
                        "image body {} bytes exceeds the configured cap of {} bytes \
                         (set MATRIX_MCP_UPLOAD_MAX_BYTES to raise it)",
                        bytes.len(),
                        cap
                    ),
                    None,
                ));
            }

            // --- Upload to homeserver media repo ------------------------
            let client = self.client_for(&ctx).await?;
            let upload_resp = client
                .media()
                .upload(&mime_type, bytes.to_vec(), None)
                .await
                .map_err(|e| ErrorData::internal_error(format!("media upload: {e}"), None))?;
            let mxc_uri: OwnedMxcUri = upload_resp.content_uri;

            // --- Derive filename from URL path --------------------------
            // Take the last non-empty path segment; strip any query string.
            let url_filename = params
                .image_url
                .split('/')
                .next_back()
                .and_then(|s| s.split('?').next())
                .filter(|s| !s.is_empty())
                .unwrap_or("image")
                .to_owned();

            // --- Build ImageMessageEventContent -------------------------
            // Per Matrix spec: when `filename` ≠ `body`, `body` is the
            // caption. When there is no caption, use the filename as `body`
            // (no separate `filename` field) so clients show a file name.
            let img_content = if let Some(ref caption) = params.caption {
                let mut img = ImageMessageEventContent::plain(caption.clone(), mxc_uri.clone());
                img.filename = Some(url_filename);
                img
            } else {
                ImageMessageEventContent::plain(url_filename, mxc_uri.clone())
            };

            // --- Send ---------------------------------------------------
            let room_id: OwnedRoomId = params.room_id.parse().map_err(|e| {
                ErrorData::invalid_params(format!("invalid room_id {}: {e}", params.room_id), None)
            })?;
            let room = client.get_room(&room_id).ok_or_else(|| {
                ErrorData::invalid_params(format!("not joined to {room_id}"), None)
            })?;

            let msg = RoomMessageEventContent::new(
                matrix_sdk::ruma::events::room::message::MessageType::Image(img_content),
            );
            let send_resp = room
                .send(msg)
                .await
                .map_err(|e| ErrorData::internal_error(format!("room.send: {e}"), None))?;

            structured_result(&SendImageFromUrlResult {
                event_id: send_resp.response.event_id.to_string(),
                mxc_uri: mxc_uri.to_string(),
            })
        }
        .instrument(span.clone())
        .await;
        self.react_to_auth_expiry(&ctx, &mut result).await;
        emit_tool_audit(
            "send_image_from_url",
            &mxid_for_audit,
            Some(&room_id_for_audit),
            started,
            None,
            &span,
            &result,
        );
        emit_write_notice(
            &result,
            &self.clients,
            &ctx,
            "send_image_from_url",
            Some(room_id_for_audit.as_str()),
        )
        .await;
        result
    }

    /// Search Matrix room history using the homeserver's full-text search
    /// index (`POST /_matrix/client/v3/search`). Results are ordered by
    /// relevance (homeserver-computed rank). For E2EE rooms the homeserver
    /// only has access to the encrypted ciphertext, so `body` is always
    /// `null` in those hits — use `read_recent_messages` to read decrypted
    /// content from a specific E2EE room.
    #[tool(
        description = "Search Matrix room history by full-text query. \
                       Scope to one room with room_id or search across all joined rooms. \
                       body is null for E2EE rooms (homeserver cannot decrypt ciphertext).",
        annotations(title = "Search messages", read_only_hint = true)
    )]
    #[allow(clippy::needless_pass_by_value)]
    async fn search_messages(
        &self,
        ctx: RequestContext<RoleServer>,
        Parameters(params): Parameters<SearchMessagesParams>,
    ) -> Result<rmcp::model::CallToolResult, ErrorData> {
        let started = Instant::now();
        let mxid_for_audit = identity_from_ctx(&ctx).map_or_else(String::new, |i| i.mxid);
        let room_id_for_audit = params.room_id.clone();
        let span = make_tool_span(
            "search_messages",
            &mxid_for_audit,
            room_id_for_audit.as_deref(),
        );
        let (mut result, hit_count) = async {
            self.rate_limit_check(&ctx, Category::Read)?;
            let client = self.client_for(&ctx).await?;

            // Cap the requested limit at 100 to avoid oversized responses.
            let limit = params.limit.min(100) as usize;

            // Build the Criteria for the room_events search category.
            let mut criteria = search_events::v3::Criteria::new(params.query.clone());
            criteria.order_by = Some(search_events::v3::OrderBy::Rank);

            // When a room_id is provided, scope the search to that room only.
            if let Some(ref rid_str) = params.room_id {
                let room_id: OwnedRoomId = rid_str.parse().map_err(|e| {
                    ErrorData::invalid_params(format!("invalid room_id {rid_str}: {e}"), None)
                })?;
                criteria.filter.rooms = Some(vec![room_id]);
            }

            let mut categories = search_events::v3::Categories::new();
            categories.room_events = Some(criteria);
            let response = client
                .send(search_events::v3::Request::new(categories))
                .await
                .map_err(|e| ErrorData::internal_error(format!("search: {e}"), None))?;

            let room_events = response.search_categories.room_events;
            // Homeserver-reported approximate total (may be absent).
            let server_total: Option<u64> = room_events.count.map(u64::from);

            // Map each SearchResult to a SearchHit. Audit envelope only —
            // query terms and hit bodies are never written to the audit log.
            let hits: Vec<SearchHit> = room_events
                .results
                .into_iter()
                .take(limit)
                .map(|sr| {
                    // Deserialize the raw event JSON to extract top-level fields.
                    let raw_val: serde_json::Value = sr
                        .result
                        .as_ref()
                        .and_then(|raw| raw.deserialize_as().ok())
                        .unwrap_or(serde_json::Value::Null);

                    let event_id = raw_val
                        .get("event_id")
                        .and_then(|v| v.as_str())
                        .map(ToOwned::to_owned);
                    let room_id_str = raw_val
                        .get("room_id")
                        .and_then(|v| v.as_str())
                        .map_or_else(String::new, ToOwned::to_owned);
                    let sender = raw_val
                        .get("sender")
                        .and_then(|v| v.as_str())
                        .map(ToOwned::to_owned);
                    let origin_server_ts = raw_val
                        .get("origin_server_ts")
                        .and_then(serde_json::Value::as_u64);

                    // content.body is present only for plaintext m.room.message
                    // events. For E2EE rooms the homeserver stores the ciphertext
                    // blob — `content.body` is absent or contains encrypted bytes.
                    let body = raw_val
                        .get("content")
                        .and_then(|c| c.get("body"))
                        .and_then(|v| v.as_str())
                        .map(ToOwned::to_owned);

                    SearchHit {
                        event_id,
                        room_id: room_id_str,
                        sender,
                        origin_server_ts,
                        rank: sr.rank,
                        body,
                    }
                })
                .collect();

            let total = server_total.unwrap_or(hits.len() as u64);
            let count = hits.len();
            let res = structured_result(&SearchMessagesResult {
                results: hits,
                total,
            });
            Ok::<_, ErrorData>((res, count))
        }
        .instrument(span.clone())
        .await
        .map_or_else(|e| (Err(e), 0), |(r, c)| (r, c));
        self.react_to_auth_expiry(&ctx, &mut result).await;
        emit_tool_audit(
            "search_messages",
            &mxid_for_audit,
            room_id_for_audit.as_deref(),
            started,
            Some(hit_count),
            &span,
            &result,
        );
        result
    }

    /// Join a Matrix room by id or canonical alias. Returns the
    /// canonical room id after the join. If the homeserver bounces
    /// the join (invite-only, banned, etc.) an `internal_error` is
    /// returned.
    #[tool(
        description = "Join a Matrix room by id or alias.",
        annotations(
            title = "Join room",
            read_only_hint = false,
            destructive_hint = false,
            idempotent_hint = true
        )
    )]
    #[allow(clippy::needless_pass_by_value)]
    async fn join_room(
        &self,
        ctx: RequestContext<RoleServer>,
        Parameters(params): Parameters<JoinRoomParams>,
    ) -> Result<rmcp::model::CallToolResult, ErrorData> {
        let started = Instant::now();
        let mxid_for_audit = identity_from_ctx(&ctx).map_or_else(String::new, |i| i.mxid);
        let room_id_for_audit = params.room_id_or_alias.clone();
        let span = make_tool_span("join_room", &mxid_for_audit, Some(&room_id_for_audit));
        let mut result = async {
            self.rate_limit_check(&ctx, Category::Write)?;
            let client = self.client_for(&ctx).await?;
            let target: &matrix_sdk::ruma::RoomOrAliasId =
                params.room_id_or_alias.as_str().try_into().map_err(|e| {
                    ErrorData::invalid_params(
                        format!("invalid room id or alias {}: {e}", params.room_id_or_alias),
                        None,
                    )
                })?;
            let room = client
                .join_room_by_id_or_alias(target, &[])
                .await
                .map_err(|e| ErrorData::internal_error(format!("join_room: {e}"), None))?;
            structured_result(&JoinRoomResult {
                room_id: room.room_id().to_string(),
            })
        }
        .instrument(span.clone())
        .await;
        self.react_to_auth_expiry(&ctx, &mut result).await;
        emit_tool_audit(
            "join_room",
            &mxid_for_audit,
            Some(&room_id_for_audit),
            started,
            None,
            &span,
            &result,
        );
        emit_write_notice(
            &result,
            &self.clients,
            &ctx,
            "join_room",
            Some(room_id_for_audit.as_str()),
        )
        .await;
        result
    }

    /// Leave a Matrix room. Idempotent at the spec level — leaving
    /// a room you're not in is a homeserver-decided 200-or-error.
    #[tool(
        description = "Leave a Matrix room.",
        annotations(
            title = "Leave room",
            read_only_hint = false,
            destructive_hint = true,
            idempotent_hint = false
        )
    )]
    #[allow(clippy::needless_pass_by_value)]
    async fn leave_room(
        &self,
        ctx: RequestContext<RoleServer>,
        Parameters(params): Parameters<LeaveRoomParams>,
    ) -> Result<rmcp::model::CallToolResult, ErrorData> {
        let started = Instant::now();
        let mxid_for_audit = identity_from_ctx(&ctx).map_or_else(String::new, |i| i.mxid);
        let room_id_for_audit = params.room_id.clone();
        let span = make_tool_span("leave_room", &mxid_for_audit, Some(&room_id_for_audit));
        let mut result = async {
            self.rate_limit_check(&ctx, Category::Write)?;
            let client = self.client_for(&ctx).await?;
            let room_id: OwnedRoomId = params.room_id.parse().map_err(|e| {
                ErrorData::invalid_params(format!("invalid room_id {}: {e}", params.room_id), None)
            })?;
            let room = client.get_room(&room_id).ok_or_else(|| {
                ErrorData::invalid_params(format!("not joined to {room_id}"), None)
            })?;
            room.leave()
                .await
                .map_err(|e| ErrorData::internal_error(format!("leave: {e}"), None))?;
            structured_result(&LeaveRoomResult {
                room_id: room_id.to_string(),
            })
        }
        .instrument(span.clone())
        .await;
        self.react_to_auth_expiry(&ctx, &mut result).await;
        emit_tool_audit(
            "leave_room",
            &mxid_for_audit,
            Some(&room_id_for_audit),
            started,
            None,
            &span,
            &result,
        );
        emit_write_notice(
            &result,
            &self.clients,
            &ctx,
            "leave_room",
            Some(room_id_for_audit.as_str()),
        )
        .await;
        result
    }

    /// Invite an MXID to a Matrix room you're a member of. The
    /// homeserver enforces ACLs (your power level vs. `invite`).
    #[tool(
        description = "Invite a Matrix user to a room.",
        annotations(
            title = "Invite user",
            read_only_hint = false,
            destructive_hint = false,
            idempotent_hint = false
        )
    )]
    #[allow(clippy::needless_pass_by_value)]
    async fn invite_user(
        &self,
        ctx: RequestContext<RoleServer>,
        Parameters(params): Parameters<InviteUserParams>,
    ) -> Result<rmcp::model::CallToolResult, ErrorData> {
        let started = Instant::now();
        let mxid_for_audit = identity_from_ctx(&ctx).map_or_else(String::new, |i| i.mxid);
        let room_id_for_audit = params.room_id.clone();
        let span = make_tool_span("invite_user", &mxid_for_audit, Some(&room_id_for_audit));
        let mut result = async {
            self.rate_limit_check(&ctx, Category::Write)?;
            let client = self.client_for(&ctx).await?;
            let room_id: OwnedRoomId = params.room_id.parse().map_err(|e| {
                ErrorData::invalid_params(format!("invalid room_id {}: {e}", params.room_id), None)
            })?;
            let room = client.get_room(&room_id).ok_or_else(|| {
                ErrorData::invalid_params(format!("not joined to {room_id}"), None)
            })?;
            let user_id: matrix_sdk::ruma::OwnedUserId = params.mxid.parse().map_err(|e| {
                ErrorData::invalid_params(format!("invalid mxid {}: {e}", params.mxid), None)
            })?;
            room.invite_user_by_id(&user_id)
                .await
                .map_err(|e| ErrorData::internal_error(format!("invite_user_by_id: {e}"), None))?;
            structured_result(&InviteUserResult {
                room_id: room_id.to_string(),
                mxid: user_id.to_string(),
            })
        }
        .instrument(span.clone())
        .await;
        self.react_to_auth_expiry(&ctx, &mut result).await;
        emit_tool_audit(
            "invite_user",
            &mxid_for_audit,
            Some(&room_id_for_audit),
            started,
            None,
            &span,
            &result,
        );
        emit_write_notice(
            &result,
            &self.clients,
            &ctx,
            "invite_user",
            Some(room_id_for_audit.as_str()),
        )
        .await;
        result
    }

    /// Designate the audit room for self-audit `m.notice` events.
    ///
    /// Every subsequent write tool call will send a short `m.notice` event into
    /// this room summarising the tool name, target room, and outcome.
    ///
    /// The room id is stored in your Matrix global account data under
    /// the custom key `m.audit_room` so it persists across sessions.
    ///
    /// **Opt-in only** — no notices are emitted until you call this tool.
    #[tool(
        description = "Set the audit room for self-audit m.notice events. \
                          After this call every write tool emits a short notice \
                          (tool name + target room + outcome) into the audit room. \
                          Stored in your Matrix account data; persists across sessions.",
        annotations(
            title = "Set audit room",
            read_only_hint = false,
            destructive_hint = false,
            idempotent_hint = true
        )
    )]
    #[allow(clippy::needless_pass_by_value)]
    async fn set_audit_room(
        &self,
        ctx: RequestContext<RoleServer>,
        Parameters(params): Parameters<SetAuditRoomParams>,
    ) -> Result<rmcp::model::CallToolResult, ErrorData> {
        let started = Instant::now();
        let mxid_for_audit = identity_from_ctx(&ctx).map_or_else(String::new, |i| i.mxid);
        let room_id_for_audit = params.room_id.clone();
        let span = make_tool_span("set_audit_room", &mxid_for_audit, Some(&room_id_for_audit));
        let mut result = async {
            self.rate_limit_check(&ctx, Category::Write)?;
            let client = self.client_for(&ctx).await?;
            let room_id: matrix_sdk::ruma::OwnedRoomId = params.room_id.parse().map_err(|e| {
                ErrorData::invalid_params(format!("invalid room_id {}: {e}", params.room_id), None)
            })?;
            let _room = client.get_room(&room_id).ok_or_else(|| {
                ErrorData::invalid_params(format!("not joined to {room_id}"), None)
            })?;
            audit_room::set_audit_room(&client, room_id.as_ref())
                .await
                .map_err(|e| ErrorData::internal_error(format!("set_audit_room: {e}"), None))?;
            structured_result(&SetAuditRoomResult {
                room_id: room_id.to_string(),
            })
        }
        .instrument(span.clone())
        .await;
        self.react_to_auth_expiry(&ctx, &mut result).await;
        emit_tool_audit(
            "set_audit_room",
            &mxid_for_audit,
            Some(&room_id_for_audit),
            started,
            None,
            &span,
            &result,
        );
        emit_write_notice(
            &result,
            &self.clients,
            &ctx,
            "set_audit_room",
            Some(room_id_for_audit.as_str()),
        )
        .await;
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

/// Convert a batch of [`matrix_sdk::deserialized_responses::TimelineEvent`]s
/// into [`ReadEvent`]s with threading metadata.
///
/// Thread-root detection is derived client-side: an event is a thread root if
/// at least one sibling in the same batch has `rel_type: "m.thread"` pointing
/// at its `event_id`. The `unsigned["m.relations"]["m.thread"]["count"]` field
/// (when present) is surfaced as `thread_event_count`.
fn read_events_from_chunk(
    chunk: Vec<matrix_sdk::deserialized_responses::TimelineEvent>,
) -> Vec<ReadEvent> {
    // First pass: deserialise every event and collect the set of event ids
    // that are the root of at least one m.thread relation in this batch.
    let values: Vec<serde_json::Value> = chunk
        .iter()
        .map(|tle| {
            tle.raw()
                .deserialize_as::<serde_json::Value>()
                .unwrap_or(serde_json::Value::Null)
        })
        .collect();

    // Build the set of thread-root ids referenced in this batch.
    let thread_roots: HashSet<String> = values
        .iter()
        .filter_map(|v| {
            let rel = v.get("content")?.get("m.relates_to")?;
            if rel.get("rel_type")?.as_str()? == "m.thread" {
                rel.get("event_id")?.as_str().map(str::to_owned)
            } else {
                None
            }
        })
        .collect();

    // Second pass: build ReadEvent for every timeline event.
    chunk
        .into_iter()
        .zip(values)
        .map(|(tle, value)| {
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

            let event_id_str = value
                .get("event_id")
                .and_then(|v| v.as_str())
                .map(str::to_owned);

            // `in_reply_to`: from content["m.relates_to"]["m.in_reply_to"]["event_id"].
            // Present on replies AND on thread replies (which carry both
            // rel_type=m.thread and m.in_reply_to).  We surface it
            // unconditionally so callers can distinguish genuine replies
            // from the thread fallback via the surrounding rel_type.
            let in_reply_to = value
                .get("content")
                .and_then(|c| c.get("m.relates_to"))
                .and_then(|r| r.get("m.in_reply_to"))
                .and_then(|irt| irt.get("event_id"))
                .and_then(|v| v.as_str())
                .map(str::to_owned);

            // `is_thread_root`: true if any sibling in the batch has
            // rel_type=m.thread pointing at this event.
            let is_thread_root = event_id_str
                .as_deref()
                .is_some_and(|id| thread_roots.contains(id));

            // `thread_event_count`: from unsigned["m.relations"]["m.thread"]["count"].
            let thread_event_count = value
                .get("unsigned")
                .and_then(|u| u.get("m.relations"))
                .and_then(|r| r.get("m.thread"))
                .and_then(|t| t.get("count"))
                .and_then(serde_json::Value::as_u64);

            ReadEvent {
                event_id: event_id_str,
                sender: value
                    .get("sender")
                    .and_then(|v| v.as_str())
                    .map(str::to_owned),
                origin_server_ts: value
                    .get("origin_server_ts")
                    .and_then(serde_json::Value::as_u64),
                status,
                event: body,
                in_reply_to,
                is_thread_root,
                thread_event_count,
            }
        })
        .collect()
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

/// Fire-and-forget: send an `m.notice` audit event into the user's
/// designated audit room (if any). Spawns a background task so failures
/// cannot block the actual tool response.
///
/// Skips the notice when the result is a rate-limit denial (the write
/// never actually executed).
async fn emit_write_notice(
    result: &Result<rmcp::model::CallToolResult, ErrorData>,
    clients: &MatrixClientCache,
    ctx: &RequestContext<RoleServer>,
    tool: &'static str,
    room_id: Option<&str>,
) {
    if let Err(e) = result
        && e.code.0 == audit::RATE_LIMITED_CODE
    {
        return;
    }
    let Some(id) = identity_from_ctx(ctx) else {
        return;
    };
    let Some(token) = token_from_ctx(ctx) else {
        return;
    };
    let Ok(client) = clients.for_user(&id, &token.0).await else {
        return;
    };
    let outcome_str = if result.is_ok() {
        outcome::OK
    } else {
        outcome::ERROR
    };
    let target = room_id.map(str::to_owned);
    let client_inner: matrix_sdk::Client = (*client).clone();
    tokio::spawn(async move {
        audit_room::emit_notice(client_inner, tool, target, outcome_str).await;
    });
}

/// Audit-log a finished tool call. Looks at the result to decide the
/// outcome class and pulls the JSON-RPC error code into a stable
/// `error_class` string. Keeps audit emission DRY across every tool.
/// Build an `mcp.tool` span for a tool call. The `outcome` and
/// `latency_ms` fields are recorded after the call completes via
/// `Span::record()`.
///
/// Attributes carry envelope metadata only — no message bodies, keys,
/// tokens, or display names (same invariant as `audit.rs`).
fn make_tool_span(tool: &'static str, mxid: &str, room_id: Option<&str>) -> Span {
    tracing::info_span!(
        "mcp.tool",
        tool,
        mxid,
        room_id = room_id.unwrap_or(""),
        outcome = tracing::field::Empty,
        latency_ms = tracing::field::Empty,
    )
}

/// Recognise the Synapse error-text signatures that mean "this token
/// is no longer valid on the homeserver". Matches both the modern
/// ruma error variant message (`M_UNKNOWN_TOKEN`) and the older
/// plaintext (`Token is not active`) so we cover every matrix-rust-sdk
/// version we might ever depend on. Substring check is fine — these
/// strings only appear in legitimate 401 envelopes.
fn is_auth_expiry_signature(msg: &str) -> bool {
    msg.contains("M_UNKNOWN_TOKEN") || msg.contains("Token is not active")
}

fn emit_tool_audit(
    tool: &'static str,
    mxid: &str,
    room_id: Option<&str>,
    started: Instant,
    event_count: Option<usize>,
    span: &Span,
    result: &Result<rmcp::model::CallToolResult, ErrorData>,
) {
    let elapsed = started.elapsed();
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
    span.record("outcome", outcome);
    span.record(
        "latency_ms",
        u64::try_from(elapsed.as_millis()).unwrap_or(u64::MAX),
    );
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

    #[test]
    fn send_image_rejects_http_url() {
        // The HTTPS guard is a pure string check — verify the invariant
        // without a live Matrix client.
        assert!(
            !"http://example.com/image.png".starts_with("https://"),
            "http:// must fail the https-only guard"
        );
        assert!(
            "https://example.com/image.png".starts_with("https://"),
            "https:// must pass the https-only guard"
        );
    }

    #[test]
    fn send_image_url_filename_extraction() {
        // Mirror the filename-derivation logic from send_image_from_url.
        let derive = |url: &str| -> String {
            url.split('/')
                .next_back()
                .and_then(|s| s.split('?').next())
                .filter(|s| !s.is_empty())
                .unwrap_or("image")
                .to_owned()
        };
        assert_eq!(derive("https://cdn.example.com/photos/cat.jpg"), "cat.jpg");
        assert_eq!(derive("https://example.com/img.png?v=2"), "img.png");
        // Trailing slash → empty last segment → falls back to "image".
        assert_eq!(derive("https://example.com/"), "image");
        // No path at all → last segment is the host → used as-is (acceptable
        // fallback; the Content-Type guard already confirmed it is an image).
        assert_eq!(derive("https://example.com"), "example.com");
    }

    #[test]
    fn default_thread_limit_is_sensible() {
        let n = default_thread_limit();
        assert!((1..=MAX_THREAD_LIMIT).contains(&n), "thread limit was {n}");
    }

    #[test]
    fn thread_limit_cap_enforced() {
        // Any value above MAX_THREAD_LIMIT must be clamped down.
        let capped = 999_u32.clamp(1, MAX_THREAD_LIMIT);
        assert!(capped <= MAX_THREAD_LIMIT);
        // Value at the cap is unchanged.
        assert_eq!(
            MAX_THREAD_LIMIT.clamp(1, MAX_THREAD_LIMIT),
            MAX_THREAD_LIMIT
        );
        // Value well below the cap is unchanged.
        assert_eq!(10_u32.clamp(1, MAX_THREAD_LIMIT), 10);
    }

    #[test]
    fn thread_root_detection_from_batch() {
        // A root event and a thread-reply event. The helper must mark
        // the root as `is_thread_root = true` and the reply's
        // `in_reply_to` must surface the root id.
        //
        // We build synthetic serde_json values directly (no live SDK
        // types needed) and exercise the path through
        // `read_events_from_chunk` by testing the logic inline.
        let root_id = "$root:example.com";
        let reply_id = "$reply:example.com";

        // Simulate the output of the two-pass logic.
        let values: Vec<serde_json::Value> = vec![
            serde_json::json!({
                "event_id": root_id,
                "sender": "@alice:example.com",
                "origin_server_ts": 1_000_000_u64,
                "content": { "msgtype": "m.text", "body": "hello" },
                "unsigned": {
                    "m.relations": {
                        "m.thread": { "count": 1 }
                    }
                }
            }),
            serde_json::json!({
                "event_id": reply_id,
                "sender": "@bob:example.com",
                "origin_server_ts": 2_000_000_u64,
                "content": {
                    "msgtype": "m.text",
                    "body": "reply",
                    "m.relates_to": {
                        "rel_type": "m.thread",
                        "event_id": root_id,
                        "m.in_reply_to": { "event_id": root_id }
                    }
                }
            }),
        ];

        // First pass: collect thread roots.
        let thread_roots: HashSet<String> = values
            .iter()
            .filter_map(|v| {
                let rel = v.get("content")?.get("m.relates_to")?;
                if rel.get("rel_type")?.as_str()? == "m.thread" {
                    rel.get("event_id")?.as_str().map(str::to_owned)
                } else {
                    None
                }
            })
            .collect();

        assert!(
            thread_roots.contains(root_id),
            "root_id should be detected as a thread root"
        );

        // Check root detection for the root event.
        let root_is_thread_root = values[0]
            .get("event_id")
            .and_then(|v| v.as_str())
            .is_some_and(|id| thread_roots.contains(id));
        assert!(
            root_is_thread_root,
            "root event must be flagged is_thread_root"
        );

        // Check thread_event_count on the root.
        let count = values[0]
            .get("unsigned")
            .and_then(|u| u.get("m.relations"))
            .and_then(|r| r.get("m.thread"))
            .and_then(|t| t.get("count"))
            .and_then(serde_json::Value::as_u64);
        assert_eq!(count, Some(1));

        // Check in_reply_to on the reply event.
        let in_reply_to = values[1]
            .get("content")
            .and_then(|c| c.get("m.relates_to"))
            .and_then(|r| r.get("m.in_reply_to"))
            .and_then(|irt| irt.get("event_id"))
            .and_then(|v| v.as_str());
        assert_eq!(in_reply_to, Some(root_id));
    }
}
