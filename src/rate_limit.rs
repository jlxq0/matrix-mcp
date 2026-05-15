//! Per-identity rate limiting (Phase 6.1).
//!
//! ## Why two keys
//!
//! Each tool call is checked against two independent token buckets:
//!
//! 1. `sha256(bearer)[..16]` — protects the homeserver/MAS from a leaked
//!    token: even if the same `sub` has multiple active tokens, a
//!    compromised one can only burn its own bucket before being denied.
//! 2. MAS `sub` (ULID) — protects against the same user spinning up many
//!    tokens (e.g. claude.ai issuing a fresh one per session) and using
//!    the union of their per-token allowances to flood Synapse.
//!
//! Either bucket exceeded → request denied. Both must allow.
//!
//! When `sub` is unavailable (the `/setup` browser flow doesn't go
//! through MAS introspection), only the bearer-hash bucket applies.
//!
//! ## Why two quotas
//!
//! Reads (`list_joined_rooms`, `read_recent_messages`, `whoami`,
//! `verify_status`) are cheap and idempotent — high default quota.
//! Writes (`send_text_message` + future write tools) are more expensive
//! and side-effectful; tighter default.
//!
//! ## Memory bound
//!
//! Buckets are retained for the lifetime of the process; map growth is
//! bounded by the number of distinct bearer hashes + MAS subjects, which
//! is small for matrix-mcp's threat model (single tenant today, dozens
//! long-term). Token rotation may churn a handful of extra entries, but
//! each bucket is only a few hundred bytes — no eviction needed.
//!
//! ## Quota knobs
//!
//! Configured at startup; no per-request override. Read from env in
//! `config.rs`:
//!
//! - `MATRIX_MCP_RATE_LIMIT_READS_PER_MIN` (default 60)
//! - `MATRIX_MCP_RATE_LIMIT_WRITES_PER_MIN` (default 30)

use std::collections::HashMap;
use std::num::NonZeroU32;
use std::sync::{Arc, RwLock};

use governor::clock::DefaultClock;
use governor::state::{InMemoryState, NotKeyed};
use governor::{Quota, RateLimiter};

/// Limiter type alias — `governor`'s direct (non-keyed) variant; we
/// build one per identity and hand it out keyed by bearer-hash or sub.
type Bucket = RateLimiter<NotKeyed, InMemoryState, DefaultClock>;

/// What kind of MCP tool this call is. Drives which quota applies.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Category {
    Read,
    Write,
}

/// Returned when a request would exceed the configured quota.
#[derive(Debug, Clone, Copy)]
pub struct RateLimited;

#[derive(Debug)]
pub struct Limiter {
    reads_per_min: NonZeroU32,
    writes_per_min: NonZeroU32,
    bearer_read: RwLock<HashMap<String, Arc<Bucket>>>,
    bearer_write: RwLock<HashMap<String, Arc<Bucket>>>,
    sub_read: RwLock<HashMap<String, Arc<Bucket>>>,
    sub_write: RwLock<HashMap<String, Arc<Bucket>>>,
}

impl Limiter {
    /// New limiter with the given per-minute quotas. `0` quotas are
    /// rejected (`None`) — use a large quota to "effectively disable",
    /// don't pass `0`.
    #[must_use]
    pub fn new(reads_per_min: u32, writes_per_min: u32) -> Option<Self> {
        Some(Self {
            reads_per_min: NonZeroU32::new(reads_per_min)?,
            writes_per_min: NonZeroU32::new(writes_per_min)?,
            bearer_read: RwLock::new(HashMap::new()),
            bearer_write: RwLock::new(HashMap::new()),
            sub_read: RwLock::new(HashMap::new()),
            sub_write: RwLock::new(HashMap::new()),
        })
    }

    /// Check both per-bearer-hash and per-sub buckets. Returns `Ok(())`
    /// if both allow, `Err(RateLimited)` if either denies.
    pub fn check(
        &self,
        bearer_hash: &str,
        sub: Option<&str>,
        category: Category,
    ) -> Result<(), RateLimited> {
        let (bearer_map, sub_map, quota) = match category {
            Category::Read => (&self.bearer_read, &self.sub_read, self.reads_per_min),
            Category::Write => (&self.bearer_write, &self.sub_write, self.writes_per_min),
        };
        let bearer_bucket = get_or_insert(bearer_map, bearer_hash, quota);
        if bearer_bucket.check().is_err() {
            return Err(RateLimited);
        }
        if let Some(s) = sub {
            let sub_bucket = get_or_insert(sub_map, s, quota);
            if sub_bucket.check().is_err() {
                return Err(RateLimited);
            }
        }
        Ok(())
    }
}

fn get_or_insert(
    map: &RwLock<HashMap<String, Arc<Bucket>>>,
    key: &str,
    quota: NonZeroU32,
) -> Arc<Bucket> {
    if let Ok(guard) = map.read()
        && let Some(b) = guard.get(key)
    {
        return Arc::clone(b);
    }
    // Slow path: re-check under write lock to avoid double-insert under
    // contention. `governor::Quota::per_minute(n)` translates to one
    // token every (60/n) seconds with a burst of `n`.
    let mut guard = match map.write() {
        Ok(g) => g,
        // RwLock poisoning is unrecoverable here. A poisoned lock means a
        // panic happened while holding the lock — the safe thing is to
        // fall through to "no rate-limiting for this caller right now"
        // rather than panic again and tear down the server. Logged
        // upstream via tracing in the call site if it ever fires.
        Err(p) => p.into_inner(),
    };
    Arc::clone(
        guard
            .entry(key.to_owned())
            .or_insert_with(|| Arc::new(RateLimiter::direct(Quota::per_minute(quota)))),
    )
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn zero_quota_rejected() {
        assert!(Limiter::new(0, 1).is_none());
        assert!(Limiter::new(1, 0).is_none());
    }

    #[test]
    fn reads_and_writes_have_independent_buckets() {
        let l = Limiter::new(2, 2).unwrap();
        // Burn the read bucket.
        l.check("h", Some("s"), Category::Read).unwrap();
        l.check("h", Some("s"), Category::Read).unwrap();
        assert!(l.check("h", Some("s"), Category::Read).is_err());
        // Writes are unaffected.
        l.check("h", Some("s"), Category::Write).unwrap();
        l.check("h", Some("s"), Category::Write).unwrap();
        assert!(l.check("h", Some("s"), Category::Write).is_err());
    }

    #[test]
    fn distinct_bearers_dont_share_a_bucket() {
        let l = Limiter::new(1, 1).unwrap();
        l.check("h1", None, Category::Read).unwrap();
        // Same identity at the bearer-hash level → denied.
        assert!(l.check("h1", None, Category::Read).is_err());
        // Different bearer → fresh bucket.
        l.check("h2", None, Category::Read).unwrap();
    }

    #[test]
    fn sub_bucket_denies_across_bearers_for_same_user() {
        let l = Limiter::new(1, 1).unwrap();
        l.check("h1", Some("user-A"), Category::Read).unwrap();
        // Different bearer, same sub → sub bucket exhausted.
        assert!(l.check("h2", Some("user-A"), Category::Read).is_err());
    }

    #[test]
    fn no_sub_means_bearer_only() {
        let l = Limiter::new(1, 1).unwrap();
        // Without sub, the sub bucket is skipped; only bearer-hash
        // applies.
        l.check("h1", None, Category::Read).unwrap();
        assert!(l.check("h1", None, Category::Read).is_err());
        l.check("h2", None, Category::Read).unwrap();
    }
}
