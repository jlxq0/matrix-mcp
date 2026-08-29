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
use std::sync::atomic::{AtomicUsize, Ordering};
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
    ///
    /// **`token_hash` identifies a credential, not a caller, and a row here
    /// pairs it with one address.** Every session mounting these servers
    /// presents the same bearer: measured on a sibling as nine requests
    /// resolving to one hash and one account. So the address is whichever
    /// caller was most recent, the hash cannot separate two of them, and
    /// **neither is wrong in a way that shows** — during an incident somebody
    /// pairs the two fields and believes they have distinguished two callers.
    ///
    /// **Do not repair this by reaching for a better identifier here.** The
    /// obvious substitutions pass review and are not fixes; separating
    /// callers needs a per-request correlation id, or the count folded into
    /// the audit event, which is a different change from this map.
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
/// header value.
///
/// `X-Forwarded-For` is the comma-separated chain of IPs each proxy
/// has *appended* on the way in. The leftmost entry is **claimed** by
/// the original client (and is therefore attacker-controllable on a
/// public service — any HTTP client can set the header to whatever it
/// wants before talking to us). Reading the leftmost entry produces
/// audit signals that an attacker holding a stolen bearer can trivially
/// spoof.
///
/// Instead, count `trusted_proxy_hops` entries in from the right. Each
/// trusted proxy on the path is expected to *append* the IP it saw
/// when the request arrived at it; the rightmost N entries are
/// therefore the ones we trust. The default of 1 trusted proxy assumes
/// a typical "ingress (Traefik / nginx / etc.) in front of the matrix-mcp
/// pod" deployment; override via `MATRIX_MCP_TRUSTED_PROXY_HOPS`.
///
/// Returns `None` when the header is absent, has fewer entries than
/// the trusted-hops count, or contains no parseable IP at the trusted
/// position.
/// The entries of an `X-Forwarded-For`, trimmed, with empties discarded.
///
/// **One definition of "entry", used by the counter and the parser both.**
/// They disagreed at first: a trailing comma made the observer count two and
/// the parser count three, so the log line said the chain matched the
/// configured hops while the parser selected one position too far right and
/// recorded the edge as the caller. A reporter that counts differently from
/// the thing it reports on is worse than no reporter, because it agrees with
/// the configuration exactly when the parser has gone wrong.
///
/// Empties are discarded rather than kept: `a, b,` is two hops with a stray
/// comma, and RFC 9110 lets a recipient ignore empty list elements.
fn xff_entries(raw: &str) -> Vec<&str> {
    raw.split(',')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .collect()
}

/// How many proxies this chain says are in front of us.
///
/// Named rather than inlined into [`observe_ingress_chain`] because that
/// function's only observable is a log line, so a test cannot reach it: a
/// mutation that made the counter split differently from the parser left the
/// suite green. The agreement between this and [`parse_client_ip`] is the
/// property worth pinning, and it needs a name on both sides of it.
fn ingress_chain_len(raw: &str) -> usize {
    xff_entries(raw).len()
}

/// The chain length last reported, so the count is logged on change rather
/// than once per request.
static LAST_REPORTED_CHAIN: AtomicUsize = AtomicUsize::new(usize::MAX);

/// Log how many `X-Forwarded-For` entries arrived, beside how many this
/// process trusts.
///
/// **The count, never the entries.** Those are addresses and one of them is a
/// caller's; a log line is the wrong place for either.
///
/// The number of hops to trust is a claim about the topology in front of this
/// pod, and nothing in the process can check it. This line is what makes the
/// claim falsifiable from outside: a chain length that does not match the
/// configured count means the deployment moved and the constant did not.
/// Reported on change rather than per request, so a topology change is one
/// line and steady state is silent after the first.
pub fn observe_ingress_chain(xff: Option<&str>, trusted_proxy_hops: usize) {
    let Some(raw) = xff else {
        return;
    };
    let entries = ingress_chain_len(raw);
    if LAST_REPORTED_CHAIN.swap(entries, Ordering::Relaxed) != entries {
        tracing::info!(
            xff_entries = entries,
            trusted_proxy_hops,
            "ingress chain length"
        );
    }
}

#[must_use]
pub fn parse_client_ip(xff: Option<&str>, trusted_proxy_hops: usize) -> Option<IpAddr> {
    let raw = xff?;
    let parts = xff_entries(raw);
    let len = parts.len();
    if trusted_proxy_hops == 0 || len < trusted_proxy_hops {
        return None;
    }
    // The entry immediately upstream of the last `trusted_proxy_hops`
    // proxies is the real client IP — i.e., index `len - trusted_proxy_hops`.
    let idx = len - trusted_proxy_hops;
    parts.get(idx)?.parse::<IpAddr>().ok()
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
    fn a_trailing_comma_does_not_shift_which_entry_is_the_caller() {
        // Found by a cross-engine review of the hop-count change. The
        // observer filtered empty entries and the parser did not, so
        // `"caller, edge,"` was counted as two and parsed as three: the log
        // line said the chain matched the configured hops while the parser
        // selected one position too far right and recorded the edge.
        let caller = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 5));
        for chain in [
            "203.0.113.5, 10.0.0.1",
            "203.0.113.5, 10.0.0.1,",
            "203.0.113.5, 10.0.0.1, ",
            "203.0.113.5,, 10.0.0.1",
        ] {
            assert_eq!(
                parse_client_ip(Some(chain), 2),
                Some(caller),
                "a stray comma moved the caller: {chain:?}"
            );
        }
    }

    #[test]
    fn the_counter_and_the_parser_agree_about_what_an_entry_is() {
        // The property rather than the spelling. A reporter that counts
        // differently from the thing it reports on agrees with the
        // configuration exactly when the parser has gone wrong.
        for chain in [
            "203.0.113.5, 10.0.0.1",
            "203.0.113.5, 10.0.0.1,",
            " , 203.0.113.5 , 10.0.0.1 , ",
            "2001:db8::1, 10.0.0.1",
        ] {
            let counted = ingress_chain_len(chain);
            // The parser's guard fires at exactly one more than it holds.
            assert!(parse_client_ip(Some(chain), counted).is_some(), "{chain:?}");
            assert_eq!(parse_client_ip(Some(chain), counted + 1), None, "{chain:?}");
        }
    }

    #[test]
    fn parse_client_ip_with_one_trusted_hop_takes_rightmost() {
        // Single-entry XFF with one trusted hop → that's the IP Traefik saw.
        assert_eq!(
            parse_client_ip(Some("203.0.113.5"), 1),
            Some(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 5)))
        );
        // The leftmost entry is the **claimed** client IP and may be
        // spoofed; with one trusted proxy in front, the rightmost is
        // the real one (Traefik appends what it saw).
        assert_eq!(
            parse_client_ip(Some("1.2.3.4, 10.0.0.1, 198.51.100.7"), 1),
            Some(IpAddr::V4(Ipv4Addr::new(198, 51, 100, 7)))
        );
        // Surrounding whitespace.
        assert_eq!(
            parse_client_ip(Some("  198.51.100.7  ,  10.0.0.1  "), 1),
            Some(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)))
        );
    }

    #[test]
    fn parse_client_ip_with_two_trusted_hops_takes_third_from_right() {
        // Clean chain (no spoof): client → trustedA → trustedB → us
        // produces exactly 2 entries, and the leftmost is the real
        // client IP (because trustedA appended what it saw of the
        // client, trustedB appended trustedA's IP, and we never put
        // ourselves into XFF).
        assert_eq!(
            parse_client_ip(Some("198.51.100.7, 10.0.0.1"), 2),
            Some(IpAddr::V4(Ipv4Addr::new(198, 51, 100, 7)))
        );
        // Spoofed: the client put `1.2.3.4` in XFF themselves. Now we
        // see 3 entries; the trusted ones are the last 2, so the real
        // client IP is the one at position `len - 2 = 1`.
        assert_eq!(
            parse_client_ip(Some("1.2.3.4, 198.51.100.7, 10.0.0.1"), 2),
            Some(IpAddr::V4(Ipv4Addr::new(198, 51, 100, 7)))
        );
    }

    #[test]
    fn parse_client_ip_returns_none_when_chain_shorter_than_trust() {
        // We expect 2 trusted hops but only got 1 entry: refuse to trust.
        assert_eq!(parse_client_ip(Some("198.51.100.7"), 2), None);
    }

    #[test]
    fn parse_client_ip_returns_none_when_no_proxies_trusted() {
        // Defence-in-depth: trust_hops=0 means "don't read XFF at all".
        assert_eq!(parse_client_ip(Some("198.51.100.7"), 0), None);
    }

    #[test]
    fn parse_client_ip_returns_none_for_garbage() {
        assert_eq!(parse_client_ip(None, 1), None);
        assert_eq!(parse_client_ip(Some(""), 1), None);
        assert_eq!(parse_client_ip(Some("not an ip"), 1), None);
        assert_eq!(parse_client_ip(Some(", , ,"), 1), None);
    }
}
