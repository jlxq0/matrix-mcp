//! Per-bearer last-used tracking.
//!
//! Records, for each accepted bearer hash, the timestamp and (when
//! available) the caller's IP at the moment of the most recent
//! successful introspection. Exposed via [`crate::token_introspect`]
//! so a user can audit live state for their own bearer without
//! scraping operator-side logs.
//!
//! ## Storage
//!
//! In-memory only. A new pod starts with an empty map. Bounded to
//! [`MAX_ENTRIES`] distinct bearer hashes; when the cap is hit on a
//! fresh insert, the oldest entry is evicted (linear scan — fine at
//! this cardinality). Cardinality of distinct active bearers in
//! production is expected to be small (a few users, occasional
//! rotation), so the cap is generous and the eviction is rare.
//!
//! ## Why a separate module from `audit.rs`
//!
//! `audit.rs` writes structured events to stdout for Loki consumption,
//! never holds state, and intentionally never sees client IPs (audit
//! events ship to a shared log indexer; we don't want PII in there).
//! This module holds *per-user* state that only the bearer's owner
//! can read back via the introspect endpoint, so caller IP is fine
//! to retain in memory.
//!
//! ## Bearer hash key
//!
//! We key on the same short hex digest as [`crate::audit::token_hash`]
//! (`sha256(token)[..8]` → 16 hex chars). Collision probability at our
//! scale is negligible and it keeps the audit-log key and the
//! last-used key cross-referenceable.

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::{Arc, RwLock};
use std::time::{SystemTime, UNIX_EPOCH};

use serde::Serialize;

/// Maximum number of distinct bearer hashes we hold last-used data
/// for. When exceeded on a fresh insert, the oldest entry is evicted.
const MAX_ENTRIES: usize = 1024;

/// A single bearer's last-used record. `at` is serialised as a Unix
/// epoch second integer for stability across timezone / formatting
/// dependencies.
#[derive(Debug, Clone, Serialize)]
pub struct LastUsedRecord {
    /// When the bearer was last presented and accepted by MAS.
    /// Serialised as `at_unix` (seconds since the Unix epoch).
    #[serde(rename = "at_unix", serialize_with = "ser_unix_secs")]
    pub at: SystemTime,
    /// Caller IP parsed from the `X-Forwarded-For` header (leftmost
    /// value). `None` when the header was absent or unparseable.
    pub ip: Option<IpAddr>,
}

fn ser_unix_secs<S: serde::Serializer>(t: &SystemTime, ser: S) -> Result<S::Ok, S::Error> {
    let secs: i64 = t
        .duration_since(UNIX_EPOCH)
        .ok()
        .and_then(|d| i64::try_from(d.as_secs()).ok())
        .unwrap_or(0);
    ser.serialize_i64(secs)
}

/// In-memory `bearer-hash → last-used-record` map. Cheap to clone via
/// the inner `Arc` — see [`new`](LastUsedTracker::new).
#[derive(Debug, Default)]
pub struct LastUsedTracker {
    inner: RwLock<HashMap<String, LastUsedRecord>>,
}

impl LastUsedTracker {
    /// Construct a fresh tracker wrapped in [`Arc`] so it can be
    /// shared between the auth middleware (which writes) and the
    /// `/token/introspect` handler (which reads).
    pub fn new() -> Arc<Self> {
        Arc::new(Self::default())
    }

    /// Record / refresh the entry for this bearer hash. When the map
    /// is at capacity and the key is new, drop the oldest entry
    /// first. Lock poisoning is recovered from in-place — a panic
    /// elsewhere should not cripple the introspect endpoint.
    pub fn record(&self, token_hash: &str, ip: Option<IpAddr>) {
        let now = SystemTime::now();
        let mut map = self
            .inner
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if map.len() >= MAX_ENTRIES
            && !map.contains_key(token_hash)
            && let Some(oldest_key) = map.iter().min_by_key(|(_, r)| r.at).map(|(k, _)| k.clone())
        {
            map.remove(&oldest_key);
        }
        map.insert(token_hash.to_owned(), LastUsedRecord { at: now, ip });
    }

    /// Look up the most recent record for this bearer hash.
    pub fn get(&self, token_hash: &str) -> Option<LastUsedRecord> {
        let map = self
            .inner
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        map.get(token_hash).cloned()
    }
}

/// Best-effort parser for the client IP from an `X-Forwarded-For`
/// header value. Traefik appends each hop's IP comma-separated; the
/// **leftmost** value is the original client, the rightmost values
/// are proxies closer to us. Returns `None` if the header is absent
/// or contains no parseable IP.
#[must_use]
pub fn parse_client_ip(xff: Option<&str>) -> Option<IpAddr> {
    xff.and_then(|h| h.split(',').next())
        .map(str::trim)
        .and_then(|s| s.parse::<IpAddr>().ok())
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use std::net::Ipv4Addr;
    use std::thread::sleep;
    use std::time::Duration;

    use super::*;

    #[test]
    fn record_then_get_round_trip() {
        let t = LastUsedTracker::new();
        t.record("abc", Some(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1))));
        let r = t.get("abc").unwrap();
        assert_eq!(r.ip, Some(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1))));
    }

    #[test]
    fn record_overwrites_previous_entry_for_same_key() {
        let t = LastUsedTracker::new();
        t.record("k", None);
        sleep(Duration::from_millis(10));
        t.record("k", Some(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))));
        assert_eq!(
            t.get("k").unwrap().ip,
            Some(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)))
        );
    }

    #[test]
    fn get_returns_none_for_unknown_hash() {
        let t = LastUsedTracker::new();
        assert!(t.get("nope").is_none());
    }

    #[test]
    fn at_field_serialises_as_unix_seconds() {
        let t = LastUsedTracker::new();
        t.record("a", None);
        let r = t.get("a").unwrap();
        let json = serde_json::to_value(&r).unwrap();
        assert!(
            json.get("at_unix")
                .and_then(serde_json::Value::as_i64)
                .is_some(),
            "expected at_unix integer field, got: {json}"
        );
        // `ip` should be present and null.
        assert_eq!(json.get("ip").unwrap(), &serde_json::Value::Null);
    }

    #[test]
    fn parse_client_ip_handles_typical_xff_values() {
        assert_eq!(
            parse_client_ip(Some("203.0.113.5")),
            Some(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 5)))
        );
        // Traefik adds the next-hop IP to the right; leftmost is the
        // original client.
        assert_eq!(
            parse_client_ip(Some("203.0.113.5, 10.0.0.1, 10.0.0.2")),
            Some(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 5)))
        );
        // Surrounding whitespace.
        assert_eq!(
            parse_client_ip(Some("  198.51.100.7  ,  10.0.0.1")),
            Some(IpAddr::V4(Ipv4Addr::new(198, 51, 100, 7)))
        );
    }

    #[test]
    fn parse_client_ip_returns_none_for_garbage() {
        assert_eq!(parse_client_ip(None), None);
        assert_eq!(parse_client_ip(Some("")), None);
        assert_eq!(parse_client_ip(Some("not an ip")), None);
        assert_eq!(parse_client_ip(Some(", , ,")), None);
    }
}
