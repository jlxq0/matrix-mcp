# Architecture Decision Records

---

## ADR-01: MAS subject as store ownership key

**Status:** Accepted  
**Date:** 2026-05-15

### Context

matrix-mcp needs a stable, non-reusable per-user key for the SQLite
store directory and the HKDF salt. Matrix MXIDs are mutable – a user
can rename their localpart, and the old name can be reassigned.

### Decision

Use the MAS `sub` claim (a stable, opaque ULID) as the ownership key,
combined with the device_id. The store path is
`sha256(mas_subject + device_id)[..32]`. The MXID is used only for
Matrix API calls, not for store ownership.

### Consequences

- A localpart rename does not open a new user's store.
- A post-rename user gets a fresh store on their first reconnect and
  must re-run /setup. This is correct – a renamed user is effectively
  a new identity from the store's perspective.
- Implemented in: `src/matrix_client.rs`, `src/mas.rs`.

---

## ADR-02: No Postgres backend

**Status:** Accepted  
**Date:** 2026-05-15

### Context

matrix-rust-sdk's state and crypto stores require per-user SQLite files
(its SqliteStateStore / SqliteCryptoStore). Using Postgres as the
backing store for the SDK is not supported upstream.

### Decision

Use SQLite files on a PVC. Each user gets their own directory under
`MATRIX_MCP_STORE_DIR`. Longhorn backs the PVC on Gruyere.

### Consequences

- Simple: no separate DB to provision or migrate.
- Single-replica only (see ADR-04).
- PVC is ephemeral by design (see `gruyere_state_lives_in_r2_or_postgres`
  memory note) – if the PVC is lost, users re-run /setup. Acceptable
  because key backup can restore history.

---

## ADR-03: Accept tokens without `aud` claim

**Status:** Accepted  
**Date:** 2026-05-15

### Context

RFC 8707 resource indicators require that a token issued for a specific
resource carry an `aud` claim matching that resource URL. claude.ai's
MCP connector (as of 2026-05) does not pass the `resource=` parameter
to MAS's token endpoint, so MAS issues tokens with no `aud` claim.

### Decision

Accept tokens where `aud` is absent, emit a WARN log, and rely on two
compensating controls:

1. **Matrix C-S API scope check**: the token must carry a
   `urn:matrix:client:api:*` (or MSC2967 unstable) scope token. A
   random bearer token from an unrelated service would not have this.
2. **Synapse re-validation**: every `/_matrix/client/v3/*` call hits
   Synapse, which re-validates the scope via its own MAS introspection.
   A token without Matrix scopes gets 401 from Synapse regardless.

### Consequences

- claude.ai works. Without this change it was completely broken.
- Residual risk: a token issued for a *different* Matrix-aware service
   on the same MAS could theoretically be replayed here. The Matrix
   scope check and Synapse re-validation mitigate but do not eliminate
   this. Formally correct `aud` handling remains the goal; this is a
   workaround for client behaviour we don't control.

---

## ADR-04: Single replica only

**Status:** Accepted  
**Date:** 2026-05-15

### Context

matrix-rust-sdk's SQLite crypto store uses Olm sessions that require
exclusive write access. Running two replicas against the same store
directory would corrupt the Olm state.

### Decision

`replicas: 1`. Multi-replica support requires matrix-sdk's
`CrossProcessLockConfig` at minimum, and likely separate per-replica
store directories with shared distributed state. Deferred.

### Consequences

- Zero-downtime deploys are not possible without draining the single pod.
  The `PodDisruptionBudget minAvailable: 1` limits but does not eliminate
  disruption during node maintenance.
- In practice, a rolling restart takes ~10 s and claude.ai's retry
  handles it transparently.

---

## ADR-05: Parse device_id from scope

**Status:** Accepted  
**Date:** 2026-05-15

### Context

MAS's `device_id` field in the introspection response is documented but
was not populated in the live MAS deployment even with the
`X-MAS-Supports-Device-Id: 1` header. The device id was embedded in the
scope string as `urn:matrix:client:device:<id>` instead.

### Decision

Parse `device_id` from the scope string as a fallback when the
`device_id` field is absent. Accept both the stable
(`urn:matrix:client:device:`) and unstable MSC2967
(`urn:matrix:org.matrix.msc2967.client:device:`) prefixes. Stable wins
if both are present.

### Consequences

- Works with current MAS behaviour and will continue to work if MAS
  starts populating the field properly (stable prefix preferred).
- Tested in `mas.rs` unit tests against a wiremock server.

---

## ADR-06: HKDF pepper model for store-cipher keys

**Status:** Accepted  
**Date:** 2026-05-15

### Context

matrix-sdk's SqliteStateStore and SqliteCryptoStore require a
passphrase to encrypt the SQLite files. We need per-user passphrases
without storing them anywhere except in derivation.

### Decision

Use a single deployment-wide pepper (`MATRIX_MCP_STORE_PEPPER`) as HKDF
input key material. Derive per-user passphrases as:

```
HKDF-SHA256(
  salt = cache_key (sha256(mas_subject + device_id)[..32]),
  ikm  = pepper,
  info = "matrix-mcp-store-cipher v1",
  len  = 32 bytes
) → hex string
```

The pepper lives in 1Password, flows to the pod via ExternalSecret.
It is never written to disk.

### Consequences

- Rotating the pepper invalidates all stores (see operations.md).
- An attacker needs both the pepper and the stores to decrypt anything.
- Losing the pepper means losing all user stores – treat it like an
  encryption master key.

---

## ADR-07: No SAS verification path

**Status:** Accepted  
**Date:** 2026-05-15

### Context

The standard Matrix cross-signing flow involves SAS (Short Authentication
String) verification – comparing emoji on two devices. This requires
interactive back-and-forth between two active Matrix sessions.

### Decision

Do not implement SAS verification in the MCP tool surface. Instead,
use the browser-based `/setup` flow to import cross-signing keys directly
from Matrix Secret Storage.

### Consequences

- No emoji comparison needed. Users paste their recovery key once.
- The recovery key is transmitted over HTTPS and not stored – the
  derived cross-signing private keys are stored, encrypted.
- The original `recover_with_key` MCP tool (which took the recovery key
  as a tool argument) was removed because it exposed the key in
  claude.ai's chat history.

---

## ADR-08: Remove `recover_with_key` MCP tool

**Status:** Accepted (supersedes the tool added in v0.0.10)  
**Date:** 2026-05-15

### Context

An early iteration exposed a `recover_with_key(key)` MCP tool that let
users pass their Matrix Secret Storage recovery key as a tool argument
from within claude.ai. This meant the recovery key appeared in
claude.ai's chat history permanently.

### Decision

Remove the tool. Replace with the browser-based `/setup` flow that takes
the key via a standard HTTPS form, processes it server-side, and never
persists the key.

### Consequences

- Recovery keys no longer appear in chat history.
- Users must visit a URL in a browser once.

---

## ADR-09: Rate-limit janitor removal

**Status:** Accepted  
**Date:** 2026-05-15

### Context

An early rate-limit implementation included a background "janitor" task
that periodically swept and reset exhausted quotas. The logic was
inverted: it reset buckets that had run dry, which effectively gave users
a free refill as soon as they hit the limit.

### Decision

Drop the janitor entirely (audit finding #10). The token-bucket
implementation from the `governor` crate refills on its own schedule
based on the configured rate. No external reset is needed or wanted.

### Consequences

- Rate limiting now works correctly.
- Exhausted users wait for the bucket to refill at the configured rate
  (default: 60 reads/min, 30 writes/min).

---

## ADR-10: Drop protobuf feature (RUSTSEC-2024-0437)

**Status:** Accepted  
**Date:** 2026-05-15

### Context

matrix-rust-sdk's `protobuf` feature pulled in `protobuf` crate v2.28,
which has a known memory safety advisory (RUSTSEC-2024-0437).
matrix-mcp doesn't use any protobuf serialisation.

### Decision

Remove `features = ["protobuf"]` from the matrix-sdk dependency. The
affected code path (backup import/export) uses the native JSON backup
format instead, which is what MAS/Synapse actually serve.

### Consequences

- Advisory cleared.
- Backup functionality unaffected – key backup uses JSON, not protobuf.
