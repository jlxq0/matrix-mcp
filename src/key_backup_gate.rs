//! Concurrency + cooldown gate for Matrix room-key backup pulls.
//!
//! The matrix-sdk `Client::encryption().backups().download_room_keys_for_room(...)`
//! call hits Synapse's `/room_keys` endpoint, decrypts each backed-up
//! Megolm session, and persists it to the SDK store. The work is
//! linear in the number of backed-up sessions for that room — big
//! rooms with long history can produce minutes-long downloads and
//! megabytes of `SQLite` writes per call.
//!
//! Two independent secscan findings (#de85922e on the MCP tool side,
//! #e4797214 on the /setup/recover side) flagged the same primitive
//! as an authenticated availability risk: every code path that calls
//! it spawned a detached `tokio::task` with no per-room cooldown, no
//! concurrency limit, and no timeout. An authenticated caller — or a
//! prompt-injection-driven Claude — could repeatedly trigger pulls
//! for many large rooms in parallel and exhaust the runtime's
//! crypto-store contention budget, Synapse's per-user rate limit,
//! and the pod's network/CPU.
//!
//! `KeyBackupGate` is the single shared limiter every call site goes
//! through:
//!
//! * **Per-room cooldown** — a pull for room R completed less than
//!   [`COOLDOWN`] ago short-circuits to `None`. Self-healing reads
//!   (`spawn_key_backup_pull_if_needed`) get this for free; the
//!   explicit `request_room_keys` tool surfaces the rejection so the
//!   caller knows to wait.
//! * **Global concurrency cap** — at most [`MAX_CONCURRENT`] pulls
//!   running across all rooms. Pulls beyond the cap wait for a
//!   permit; the explicit tool returns rate-limited rather than
//!   queueing.
//! * **Per-pull timeout** — the actual download is wrapped in
//!   [`PER_PULL_TIMEOUT`] inside the helper so a wedged Synapse can't
//!   pin a permit forever.

use std::collections::HashMap;
use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant};

use matrix_sdk::ruma::{OwnedRoomId, RoomId};
use tokio::sync::Semaphore;

/// Maximum number of room-key backup pulls allowed to run at the same
/// time across the whole process. The number is generous compared to
/// a normal user's working set (one or two pulls when a long-thread
/// read hits undecryptable events) but small relative to the pod's
/// available crypto-store contention budget.
pub const MAX_CONCURRENT: usize = 4;

/// How long after a successful pull we refuse to re-pull the same
/// room. Five minutes is more than enough to absorb a Claude session
/// that revisits a thread several times; long-running incident
/// recovery should use `/setup/recover` (which has its own per-room
/// loop bounded by total joined-room count).
#[allow(clippy::duration_suboptimal_units)]
pub const COOLDOWN: Duration = Duration::from_secs(5 * 60);

/// Hard timeout on a single `download_room_keys_for_room` call.
/// Empirically a backup pull for a moderate-size room finishes in
/// under a second; ~30s leaves room for slow networks and heavy
/// homeservers without letting one wedged call pin a permit.
pub const PER_PULL_TIMEOUT: Duration = Duration::from_secs(30);

/// The bookkeeping state. Cheap to clone — the inner data lives in
/// `Arc`s, this is just a handle.
#[derive(Clone)]
pub struct KeyBackupGate {
    inner: Arc<Inner>,
}

struct Inner {
    /// Maximum concurrent in-flight pulls across all rooms / users.
    /// The cap is process-global rather than per-user because the
    /// resource it protects (matrix-sdk crypto-store contention,
    /// Synapse `/room_keys` request budget) is shared.
    semaphore: Arc<Semaphore>,
    /// Last successful pull time per (caller, room). The key
    /// includes the caller's stable identifier (typically the MAS
    /// subject, sometimes the MXID for `/setup/recover`) so that
    /// one user's successful pull does not silently suppress
    /// another user's recovery for the same shared encrypted room.
    /// Bounded by number of distinct (user, room) pairs — small
    /// for normal usage; no eviction needed.
    last_pull: RwLock<HashMap<CooldownKey, Instant>>,
}

/// Cooldown-map key. The caller is identified by an opaque string
/// (MAS subject in normal MCP requests, MXID in `/setup/recover`).
/// Either is stable per-user; using the opaque string lets the call
/// site pick whichever identifier it already has.
type CooldownKey = (String, OwnedRoomId);

/// Permit returned by [`KeyBackupGate::try_acquire`]. Holding it
/// reserves one of the [`MAX_CONCURRENT`] slots; dropping it (after
/// `done`) releases the slot for the next caller.
pub struct PullPermit {
    _semaphore_permit: tokio::sync::OwnedSemaphorePermit,
    gate: KeyBackupGate,
    caller: String,
    room_id: OwnedRoomId,
}

impl PullPermit {
    /// Mark the pull as completed successfully so the per-(caller, room)
    /// cooldown applies to subsequent calls. On failure, don't call
    /// this — the caller may legitimately want to retry sooner.
    pub fn record_success(&self) {
        if let Ok(mut map) = self.gate.inner.last_pull.write() {
            map.insert((self.caller.clone(), self.room_id.clone()), Instant::now());
        }
    }
}

impl KeyBackupGate {
    #[must_use]
    pub fn new() -> Self {
        Self {
            inner: Arc::new(Inner {
                semaphore: Arc::new(Semaphore::new(MAX_CONCURRENT)),
                last_pull: RwLock::new(HashMap::new()),
            }),
        }
    }

    /// Non-blocking permit attempt. Returns:
    /// * `Ok(Some(permit))` — proceed with the pull.
    /// * `Ok(None)` — silent skip (cooldown still active for this
    ///   `(caller, room)`). Use this branch in detached helpers like
    ///   `spawn_key_backup_pull_if_needed`.
    /// * `Err(reason)` — global concurrency cap reached. Surface to
    ///   the caller in explicit tool invocations.
    ///
    /// `caller` is the caller's stable identifier (MAS subject in
    /// normal MCP requests, MXID in `/setup/recover`). The cooldown
    /// is scoped to `(caller, room)` so user A's pull doesn't block
    /// user B's recovery for a shared encrypted room.
    pub fn try_acquire(
        &self,
        caller: &str,
        room_id: &RoomId,
    ) -> Result<Option<PullPermit>, GateBusy> {
        if self.in_cooldown(caller, room_id) {
            return Ok(None);
        }
        self.inner
            .semaphore
            .clone()
            .try_acquire_owned()
            .map_or(Err(GateBusy), |p| {
                Ok(Some(PullPermit {
                    _semaphore_permit: p,
                    gate: self.clone(),
                    caller: caller.to_owned(),
                    room_id: room_id.to_owned(),
                }))
            })
    }

    /// True when a successful pull for `(caller, room_id)` happened
    /// less than [`COOLDOWN`] ago.
    fn in_cooldown(&self, caller: &str, room_id: &RoomId) -> bool {
        let Ok(map) = self.inner.last_pull.read() else {
            return false;
        };
        map.get(&(caller.to_owned(), room_id.to_owned()))
            .is_some_and(|t| t.elapsed() < COOLDOWN)
    }
}

impl Default for KeyBackupGate {
    fn default() -> Self {
        Self::new()
    }
}

impl std::fmt::Debug for KeyBackupGate {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let available = self.inner.semaphore.available_permits();
        let tracked = self.inner.last_pull.read().map_or(0, |m| m.len());
        f.debug_struct("KeyBackupGate")
            .field("available_permits", &available)
            .field("rooms_tracked", &tracked)
            .finish()
    }
}

/// Returned when the global concurrency cap is full.
#[derive(Debug, Clone, Copy)]
pub struct GateBusy;

impl std::fmt::Display for GateBusy {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "key-backup gate at concurrency cap ({MAX_CONCURRENT}); try again shortly"
        )
    }
}

impl std::error::Error for GateBusy {}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::significant_drop_tightening,
    clippy::needless_collect
)]
mod tests {
    use super::*;

    fn rid(s: &str) -> OwnedRoomId {
        s.parse().unwrap()
    }

    const ALICE: &str = "01JABCDEFGHJKMNPQRSTVWXY01"; // MAS subject ULID shape
    const BOB: &str = "01JABCDEFGHJKMNPQRSTVWXY02";

    #[test]
    fn first_acquire_succeeds() {
        let g = KeyBackupGate::new();
        let p = g.try_acquire(ALICE, &rid("!a:example.test")).unwrap();
        assert!(p.is_some());
    }

    #[test]
    fn cooldown_short_circuits_until_recorded_success_ages_out() {
        let g = KeyBackupGate::new();
        let r = rid("!a:example.test");
        let p = g.try_acquire(ALICE, &r).unwrap().unwrap();
        p.record_success();
        drop(p);
        // Second attempt by the same caller for the same room →
        // cooldown skip.
        assert!(g.try_acquire(ALICE, &r).unwrap().is_none());
    }

    #[test]
    fn cooldown_is_per_caller_not_global() {
        // Regression: a successful pull by user A for room R must
        // NOT block user B from pulling the same room. The previous
        // implementation keyed cooldown by room only, which silently
        // suppressed cross-user E2EE recovery for shared rooms.
        let g = KeyBackupGate::new();
        let r = rid("!shared:example.test");
        let a = g.try_acquire(ALICE, &r).unwrap().unwrap();
        a.record_success();
        drop(a);
        // Bob, different caller, same room → must get a permit.
        let b = g.try_acquire(BOB, &r).unwrap();
        assert!(
            b.is_some(),
            "user B was blocked by user A's cooldown for shared room"
        );
    }

    #[test]
    fn concurrency_cap_blocks_when_full() {
        let g = KeyBackupGate::new();
        let rooms: Vec<_> = (0..MAX_CONCURRENT)
            .map(|i| rid(&format!("!{i}:example.test")))
            .collect();
        let permits: Vec<_> = rooms
            .iter()
            .map(|r| g.try_acquire(ALICE, r).unwrap().unwrap())
            .collect();
        // One more slot → GateBusy (process-global, deliberately —
        // protects the shared crypto-store / Synapse budget).
        let extra = rid("!extra:example.test");
        assert!(matches!(g.try_acquire(ALICE, &extra), Err(GateBusy)));
        // Drop one permit → next attempt for a fresh room succeeds.
        drop(permits.into_iter().next().unwrap());
        assert!(g.try_acquire(ALICE, &extra).unwrap().is_some());
    }

    #[test]
    fn permit_without_record_success_does_not_set_cooldown() {
        let g = KeyBackupGate::new();
        let r = rid("!a:example.test");
        let p = g.try_acquire(ALICE, &r).unwrap().unwrap();
        // Don't call record_success — simulates a failed pull.
        drop(p);
        // Cooldown should NOT be active; caller can retry immediately.
        assert!(g.try_acquire(ALICE, &r).unwrap().is_some());
    }
}
