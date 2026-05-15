//! Envelope-only audit logging.
//!
//! Every tool call, MAS introspection, and /setup flow step emits a
//! structured `tracing::info` event at `target: "matrix_mcp::audit"`.
//! The cluster's Alloy collector picks these up and ships them to
//! Loki where they're keyed by `target` for filtering.
//!
//! ## What is and isn't logged
//!
//! Envelope fields **are** logged:
//!
//! - `event` — one of `tool_call`, `introspect`, `setup_login`,
//!   `setup_callback`, `setup_recover`, `setup_error`
//! - `mxid` — for user-side events. Audit is useless without it.
//! - `tool` — name of the MCP tool
//! - `room_id` — when relevant (read/send/etc.)
//! - `outcome` — `ok`, `error`, `denied`, `not_found`, etc.
//! - `latency_ms` — duration in milliseconds
//! - `event_count` — for read tools, how many events returned
//! - `error_class` — coarse category, NOT the error message
//! - `token_hash` — first 16 hex chars of `sha256(bearer)`; used to
//!   correlate without leaking the bearer itself
//!
//! Content fields **are not** logged:
//!
//! - message bodies (sent or received)
//! - recovery keys
//! - bearer tokens (only their hash prefix)
//! - cross-signing private keys
//! - room display names, topics (these can be sensitive in their
//!   own right — `room_id` is enough)
//! - any user-supplied free-form text from tool params
//!
//! ## Why a separate target
//!
//! Filtering `{target=~"matrix_mcp::audit"}` in Loki gives a clean
//! audit stream without operational noise (sync logs, http traces,
//! debug output). Operators looking at why a tool call failed
//! correlate by `request_id` (Phase-5.5 tracing) or by
//! `(mxid, tool, ts)`.

use std::time::Instant;

use rmcp::ErrorData;
use sha2::{Digest, Sha256};
use tracing::info;

/// Coarse outcome class for an audit event. Stable strings — used
/// downstream by Grafana/Loki for grouping. Add new variants
/// deliberately.
#[allow(dead_code)] // future tools use the unused ones (denied/not_found/etc.); keep stable strings.
pub mod outcome {
    pub const OK: &str = "ok";
    pub const ERROR: &str = "error";
    pub const DENIED: &str = "denied";
    pub const NOT_FOUND: &str = "not_found";
    pub const INVALID: &str = "invalid";
    pub const UNAUTHORIZED: &str = "unauthorized";
    pub const ACTIVE: &str = "active";
    pub const INACTIVE: &str = "inactive";
}

/// First 16 hex chars of `sha256(bearer)`. Used as a stable
/// pseudonymous identifier for a token in audit events, so an
/// operator can correlate "this token did X then Y" without ever
/// logging the token itself.
#[must_use]
pub fn token_hash(token: &str) -> String {
    let mut h = Sha256::new();
    h.update(token.as_bytes());
    let digest = h.finalize();
    hex::encode(&digest[..8]) // 8 bytes = 16 hex chars
}

/// Coarse error-class string for a tool error. Used as a Loki label
/// key — keep cardinality LOW. Specific error messages stay out of
/// audit logs; they go to the operational `warn!`/`error!` stream
/// instead.
#[must_use]
pub const fn error_class(err: &ErrorData) -> &'static str {
    // `ErrorCode` is a thin newtype around `i32` — see rmcp's
    // model.rs: `pub struct ErrorCode(pub i32);`. Reach into `.0`
    // rather than `i32::from(_)` (no From impl exists).
    match err.code.0 {
        -32700 => "parse",
        -32600 => "invalid_request",
        -32601 => "method_not_found",
        -32602 => "invalid_params",
        -32603 => "internal",
        _ => "other",
    }
}

/// Emit a `tool_call` audit event. Call at the END of every tool
/// body, on both success and error paths.
pub fn tool_call(
    tool: &'static str,
    mxid: &str,
    room_id: Option<&str>,
    outcome: &'static str,
    started: Instant,
    event_count: Option<usize>,
    err_class: Option<&'static str>,
) {
    info!(
        target: "matrix_mcp::audit",
        event = "tool_call",
        tool,
        mxid,
        room_id,
        outcome,
        latency_ms = u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX),
        event_count,
        error_class = err_class,
    );
}

/// Emit an `introspect` audit event from the auth middleware path.
pub fn introspect(token_hash: &str, outcome: &'static str, started: Instant, mxid: Option<&str>) {
    info!(
        target: "matrix_mcp::audit",
        event = "introspect",
        token_hash,
        mxid,
        outcome,
        latency_ms = u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX),
    );
}

/// Emit a `/setup`-flow event. Used for login init, callback,
/// recovery import outcome, and error cases.
pub fn setup_event(
    step: &'static str,
    mxid: Option<&str>,
    outcome: &'static str,
    extras: SetupExtras<'_>,
) {
    info!(
        target: "matrix_mcp::audit",
        event = step,
        mxid,
        outcome,
        rooms_total = extras.rooms_total,
        rooms_succeeded = extras.rooms_succeeded,
        rooms_failed = extras.rooms_failed,
        error_class = extras.error_class,
    );
}

#[derive(Default, Clone, Copy)]
pub struct SetupExtras<'a> {
    pub rooms_total: Option<usize>,
    pub rooms_succeeded: Option<usize>,
    pub rooms_failed: Option<usize>,
    pub error_class: Option<&'a str>,
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn token_hash_is_16_hex_chars() {
        let h = token_hash("any-bearer-string");
        assert_eq!(h.len(), 16);
        assert!(h.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn token_hash_is_stable_per_input() {
        assert_eq!(token_hash("abc"), token_hash("abc"));
        assert_ne!(token_hash("abc"), token_hash("abd"));
    }

    #[test]
    fn error_class_maps_known_jsonrpc_codes() {
        let internal = ErrorData::internal_error("anything", None);
        assert_eq!(error_class(&internal), "internal");
        let invalid = ErrorData::invalid_params("anything", None);
        assert_eq!(error_class(&invalid), "invalid_params");
    }

    #[test]
    fn outcomes_are_stable_strings() {
        // Belt + braces: if someone renames `outcome::OK` we want
        // existing dashboards/alerts to keep matching. Lock in the
        // wire string here.
        assert_eq!(outcome::OK, "ok");
        assert_eq!(outcome::ERROR, "error");
        assert_eq!(outcome::DENIED, "denied");
        assert_eq!(outcome::UNAUTHORIZED, "unauthorized");
        assert_eq!(outcome::ACTIVE, "active");
        assert_eq!(outcome::INACTIVE, "inactive");
    }
}
