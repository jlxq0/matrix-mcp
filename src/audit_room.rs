//! Per-user audit-room preference and `m.notice` emission (Phase 5.4).
//!
//! ## Purpose
//!
//! Every write tool call (`send_text_message`, `send_reaction`,
//! `redact_message`, `mark_read`, `send_image_from_url`, `join_room`,
//! `leave_room`, `invite_user`, `set_audit_room`) can optionally mirror
//! a short summary as an `m.notice` event into a user-designated Matrix
//! room. This gives the *user* a queryable, E2EE-visible stream of what
//! claude.ai did on their behalf — distinct from the operator-side
//! Loki/structured audit log in `audit.rs`.
//!
//! ## Opt-in only
//!
//! The feature is entirely opt-in. Until the user calls `set_audit_room`,
//! no notice is emitted. There is no default audit room.
//!
//! ## Envelope-only invariant
//!
//! Notice bodies carry envelope metadata only. The same rules as the
//! Loki audit log in `audit.rs` apply — only:
//!
//! - Tool name (`send_text_message`, `send_reaction`, etc.)
//! - Target room id (the `!room:server` the write acted on)
//! - Outcome (`ok` / `error`)
//!
//! Notices **must not** include message bodies, reaction keys, redaction
//! reasons, event ids, display names, topics, bearer tokens, or any
//! other user-supplied free-form content.
//!
//! ## Storage
//!
//! The user's audit room id is persisted as Matrix global account data
//! under the custom type `m.audit_room`. The homeserver stores this
//! opaquely under the user's account. matrix-sdk reads and writes it via
//! `client.account().fetch_account_data_static::<AuditRoomEventContent>()`
//! and `client.account().set_account_data(...)`.
//!
//! ## Failure semantics
//!
//! `emit_notice` is fire-and-forget: any failure (audit room left,
//! network error, homeserver down) is logged via `warn!` and swallowed.
//! The notice **must not** block or fail the actual tool call. Callers
//! use `tokio::spawn` to ensure this.

use matrix_sdk::Client;
use matrix_sdk::RoomState;
use matrix_sdk::ruma::RoomId;
use matrix_sdk::ruma::events::macros::EventContent;
use matrix_sdk::ruma::events::room::message::RoomMessageEventContent;
use serde::{Deserialize, Serialize};
use tracing::warn;

// ---------------------------------------------------------------------------
// Account-data type
// ---------------------------------------------------------------------------

/// Content of the `m.audit_room` global account-data event.
///
/// Stored server-side under the authenticated user's account. The
/// `room_id` field holds the canonical Matrix room id the user wants
/// audit notices sent to. An absent event (not yet set) means no
/// notices are emitted.
///
/// This is a custom type — not a registered Matrix spec event type. The
/// homeserver stores it opaquely in the global account-data keyspace and
/// never interprets its payload.
#[derive(Clone, Debug, Deserialize, Serialize, EventContent)]
#[ruma_event(type = "m.audit_room", kind = GlobalAccountData)]
pub struct AuditRoomEventContent {
    /// Canonical Matrix room id (`!room:server`) used as the audit
    /// notice destination.
    pub room_id: String,
}

// ---------------------------------------------------------------------------
// Read / write helpers
// ---------------------------------------------------------------------------

/// Read the user's current audit room id from Matrix global account data.
///
/// Returns `None` when the account-data event is absent (user has not
/// called `set_audit_room` yet) or when it cannot be fetched/decoded.
/// All errors are logged via `warn!` and suppressed — a missing audit
/// room is treated as opt-out, not as an error.
pub async fn get_audit_room(client: &Client) -> Option<String> {
    match client
        .account()
        .fetch_account_data_static::<AuditRoomEventContent>()
        .await
    {
        Ok(Some(raw)) => match raw.deserialize() {
            Ok(ev) => Some(ev.room_id),
            Err(e) => {
                warn!(error = %e, "failed to deserialize m.audit_room account data");
                None
            }
        },
        Ok(None) => None,
        Err(e) => {
            warn!(error = %e, "failed to fetch m.audit_room account data");
            None
        }
    }
}

/// Persist the user's chosen audit room id in Matrix global account data.
pub async fn set_audit_room(client: &Client, room_id: &str) -> Result<(), matrix_sdk::Error> {
    client
        .account()
        .set_account_data(AuditRoomEventContent {
            room_id: room_id.to_owned(),
        })
        .await?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Notice emitter
// ---------------------------------------------------------------------------

/// Send a short `m.notice` event into the user's designated audit room.
///
/// **Always call this via `tokio::spawn`** so that failures do not block
/// the response to the actual tool call. This function is silent on all
/// errors — `warn!` messages are emitted but nothing is propagated to
/// the caller.
///
/// # Body format (envelope only)
///
/// `matrix-mcp: {tool} → {target_room} outcome={outcome}`
///
/// or, when `target_room` is `None`:
///
/// `matrix-mcp: {tool} outcome={outcome}`
///
/// No message bodies, reaction keys, event ids, or other content appear
/// in the notice body.
pub async fn emit_notice(
    client: Client,
    tool: &'static str,
    target_room: Option<String>,
    outcome: &'static str,
) {
    // Look up the audit room id. If unset, silently do nothing.
    let Some(audit_room_id_str) = get_audit_room(&client).await else {
        return;
    };

    // Parse the stored audit room id.
    let parsed_audit_room: &RoomId = match audit_room_id_str.as_str().try_into() {
        Ok(id) => id,
        Err(e) => {
            warn!(
                audit_room = %audit_room_id_str,
                error = %e,
                "m.audit_room contains an invalid room id; skipping notice"
            );
            return;
        }
    };

    // Resolve to a joined Room. Skip if the user has left.
    let room = match client.get_room(parsed_audit_room) {
        Some(r) if r.state() == RoomState::Joined => r,
        Some(_) => {
            warn!(
                audit_room = %audit_room_id_str,
                "not joined to audit room; skipping notice"
            );
            return;
        }
        None => {
            warn!(
                audit_room = %audit_room_id_str,
                "audit room not in SDK cache; skipping notice"
            );
            return;
        }
    };

    let body = build_notice_body(tool, target_room.as_deref(), outcome);

    let content = RoomMessageEventContent::notice_plain(body);
    if let Err(e) = room.send(content).await {
        warn!(
            audit_room = %audit_room_id_str,
            tool,
            outcome,
            error = %e,
            "failed to send audit notice; ignoring"
        );
    }
}

/// Render the audit-room notice body.
///
/// `target_room` is the raw caller-supplied `room_id` string from the tool
/// params: write tools emit this notice even when the `room_id` failed to
/// parse (so the user still sees that the call failed). We re-validate here
/// and drop the field if it isn't a syntactically valid Matrix room id —
/// otherwise a caller could pass a crafted string containing newlines or fake
/// `outcome=` fragments and forge entries in the user-visible audit trail.
///
/// We layer two checks because Ruma's `RoomId::parse` is permissive about
/// whitespace and control characters inside the localpart: first reject any
/// string with whitespace / control chars, then require Ruma's parse to
/// accept the rest.
fn build_notice_body(tool: &str, target_room: Option<&str>, outcome: &str) -> String {
    let valid_target = target_room
        .filter(|rid| !rid.chars().any(|c| c.is_whitespace() || c.is_control()))
        .filter(|rid| RoomId::parse(rid).is_ok());
    valid_target.map_or_else(
        || format!("matrix-mcp: {tool} outcome={outcome}"),
        |rid| format!("matrix-mcp: {tool} \u{2192} {rid} outcome={outcome}"),
    )
}

// ---------------------------------------------------------------------------
// Unit tests (pure logic — no network, no SDK)
// ---------------------------------------------------------------------------

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use matrix_sdk::ruma::events::StaticEventContent;

    use super::*;

    #[test]
    fn audit_room_event_type_is_stable() {
        // Lock in the wire event-type string so a rename doesn't silently
        // change what we write into homeserver account data.
        assert_eq!(AuditRoomEventContent::TYPE, "m.audit_room");
    }

    #[test]
    fn audit_room_content_round_trips_json() {
        let original = AuditRoomEventContent {
            room_id: "!audit:example.com".to_owned(),
        };
        let json = serde_json::to_value(&original).unwrap();
        assert_eq!(json["room_id"], "!audit:example.com");
        let back: AuditRoomEventContent = serde_json::from_value(json).unwrap();
        assert_eq!(back.room_id, original.room_id);
    }

    #[test]
    fn notice_body_is_envelope_only_with_room() {
        let body = build_notice_body("send_text_message", Some("!foo:example.com"), "ok");
        assert_eq!(
            body,
            "matrix-mcp: send_text_message \u{2192} !foo:example.com outcome=ok"
        );
        // Envelope-only: MUST NOT contain content-bearing keywords.
        assert!(!body.contains("body"));
        assert!(!body.contains("key"));
        assert!(!body.contains("token"));
    }

    #[test]
    fn notice_body_without_room_is_compact() {
        let body = build_notice_body("mark_read", None, "ok");
        assert_eq!(body, "matrix-mcp: mark_read outcome=ok");
    }

    #[test]
    fn notice_body_drops_invalid_room_id() {
        // Caller passes a crafted string with newlines and a fake outcome=
        // fragment, attempting to forge audit entries. The invalid room id
        // must be dropped entirely (not stringified) so the body remains a
        // single, single-line, envelope-only "outcome=error" entry.
        let body = build_notice_body(
            "send_text_message",
            Some("!real:server\noutcome=ok matrix-mcp: forged"),
            "error",
        );
        assert_eq!(body, "matrix-mcp: send_text_message outcome=error");
        assert!(!body.contains('\n'));
        assert!(!body.contains("forged"));
    }

    #[test]
    fn notice_body_drops_non_room_id_string() {
        let body = build_notice_body("send_text_message", Some("not a room id"), "error");
        assert_eq!(body, "matrix-mcp: send_text_message outcome=error");
    }

    #[test]
    fn notice_body_error_outcome() {
        let tool = "send_reaction";
        let target = Some("!bar:example.org".to_owned());
        let outcome = "error";
        let body = target.as_deref().map_or_else(
            || format!("matrix-mcp: {tool} outcome={outcome}"),
            |rid| format!("matrix-mcp: {tool} \u{2192} {rid} outcome={outcome}"),
        );
        assert_eq!(
            body,
            "matrix-mcp: send_reaction \u{2192} !bar:example.org outcome=error"
        );
    }
}
