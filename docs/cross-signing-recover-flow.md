# Cross-signing & /setup recovery flow

This document is the operational reference for matrix-mcp's E2EE
bootstrap and recovery: how cross-signing is set up the first time,
why /setup must be hit in a specific order, what auto-rotates and
what doesn't, and how to verify cryptographically that the device is
actually trusted from outside the SDK's own opinion of itself.

If the connector "works in claude.ai" but other clients (Element X
on iPhone, Element for macOS) treat matrix-mcp's device as
*Unverified*, this is the document.

## The three keys that have to agree

For a Matrix client (e.g. Element on Julian's Mac) to trust
matrix-mcp's device and share megolm room keys with it on request,
**three** things must be true on Synapse simultaneously:

1. The user has cross-signing **public** keys published — master,
   self-signing, user-signing — at `/_matrix/client/v3/keys/query`.
   These ed25519 pubkeys are derived from **private** keys held
   client-side; the user typically wrote them once when first
   enabling Secure Backup in Element.
2. matrix-mcp's **device** is registered on Synapse with a specific
   ed25519 + curve25519 keypair, under the device id matrix-mcp
   advertises in its protected-resource metadata.
3. matrix-mcp's device record carries a **cross-signing signature**
   from the user's self-signing key — a signature whose payload is
   the canonical-JSON of the device's keys, and whose ed25519 must
   verify against the published self-signing pubkey.

If signature #3 fails to verify against pubkey #1, peers refuse to
trust the device. They don't share keys. Decryption of historical
E2EE messages fails for any session the device wasn't an in-room
recipient of. This is the failure mode that turned into a multi-hour
debugging saga before the auto-rotating-device-id fix landed.

You can verify all three independently against the live Synapse
database — see *Verifying cryptographically* near the end.

## The order-of-operations rule

> **/setup must be hit *after* claude.ai has built the matrix-sdk client.**
> Hitting /setup first will produce a cryptographically valid
> signature attached to a device that doesn't exist on Synapse.
> Code-enforced since the device-id-rotation work: /setup refuses
> with HTTP 428 if the per-user SDK cache is empty.

### Why this rule exists

`/setup` and `/mcp` use **different OAuth tokens**:

| Surface | OAuth flow | Token's device binding |
| --- | --- | --- |
| `/mcp` (claude.ai's connector) | claude.ai requests scope `device:<id>` per matrix-mcp's well-known doc | bound to the advertised device id |
| `/setup` (browser) | own OAuth flow, requests `openid` + `api:*` only | **deviceless** |

Both tokens introspect to the same MXID, so both resolve to the
**same** matrix-sdk client in matrix-mcp's per-mxid cache. The
client built **first wins** — its access token is the one all
subsequent Matrix API calls use, regardless of which surface
triggers them.

If `/setup` builds the client first:
- The cached client uses /setup's deviceless token.
- `recover()` imports cross-signing private keys from Secret Storage.
- `recover()` calls `/keys/signatures/upload` (which Synapse accepts
  even from a deviceless token) — landing a valid-looking signature.
- The SDK's background sync calls `/keys/upload` to register the
  device's ed25519 keys — Synapse rejects with **400 "must pass
  device_id when authenticating"**.
- Net result: Synapse has a cross-signing signature naming an
  ed25519 it never received, attached to a device record that
  doesn't exist. From peers' perspective: an unsigned ghost.

If `/mcp` (any real Matrix tool) builds the client first:
- The cached client uses claude.ai's device-bound token.
- Background sync's `/keys/upload` succeeds — device is registered.
- `/setup`'s `recover()` hits the cache, uses the device-bound client.
- `/keys/signatures/upload` lands on a real device. Math works.

### The recipe (happy path, first time on a fresh PVC)

1. **Connect** the Matrix MCP connector in claude.ai. Step through
   MAS consent.
2. **In claude.ai**, send a message that uses any *real* matrix-mcp
   tool — for example: *"Use matrix-mcp list_joined_rooms."*
   - This step builds the matrix-sdk client server-side with
     claude.ai's properly device-bound token.
   - `whoami` does **not** count — it only reads the OAuth
     introspection result, never touches the matrix-sdk client.
     Tools that do count: `list_joined_rooms`, `read_recent_messages`,
     `verify_status`, anything that actually queries Matrix state.
3. **Browser → `https://matrix-mcp.example.com/setup`** → sign in
   → paste your Secret Storage recovery key → submit.
4. Page reads ✓ Unlocked. Done.

If step 3 returns HTTP 428 ("matrix-mcp's Matrix client isn't built
yet for your account"), go do step 2 first.

## Auto-rotating device id

matrix-mcp picks its Matrix device id at startup from
`<MATRIX_MCP_STORE_DIR>/.device-id` (the PVC root). The resolution
order is:

1. **File exists** → use the value verbatim.
2. **File missing**, env `MATRIX_MCP_DEVICE_ID_BOOTSTRAP=<id>` set →
   write `<id>` to the file, use it. *One-shot migration aid.*
3. **File missing**, no env override → generate `MATRIXMCP-XXXXXXXX`
   (8 random Crockford-base32-ish chars), write it, use it.

After step 2 or 3, subsequent boots take path 1 and the id is
stable. The well-known doc advertises whatever id was resolved.

### Why this design

The old design hard-coded the id as a compile-time constant. The
sharp edge: PVC wipe → SDK regenerates ed25519 → Synapse still
remembers the old ed25519 under the same device id → every new
`/keys/upload` fails with `M_FORBIDDEN / SigningKeyChanged`, and
the only recovery was to ship a code change rotating the constant.

Persisting the id on the PVC means PVC and device id share a
lifetime. A PVC wipe (intentional or accidental — Longhorn
incident, `kubectl delete pvc`, snapshot restore mishap) **rotates
the device id automatically** to a fresh value that Synapse has
never seen. `/keys/upload` succeeds the first time, the saga
doesn't repeat.

### Operational consequence: PVC loss is now self-healing

When the PVC is wiped:
- New pod boots, sees no `.device-id`, generates a new one (e.g.
  `MATRIXMCP-7K3PXQ8N`), writes it to the fresh PVC.
- Well-known doc now advertises `device:MATRIXMCP-7K3PXQ8N`.
- claude.ai's existing connector token is bound to the **old**
  device id and no longer matches our advertised scope. Tool
  calls start failing at introspection (`device_id` mismatch).
- User notices the connector is broken → in claude.ai, **disconnect
  and reconnect** the Matrix MCP connector. claude.ai re-fetches the
  well-known doc, requests the new scope, MAS issues a fresh
  device-bound token.
- User follows the recipe from *step 2* above.
- Total operator action: zero `kubectl`, zero database surgery,
  zero code changes. Just a reconnect.

Old device ids accumulate as zombie records in MAS sessions and
Synapse `e2e_device_keys_json`. They're cosmetic — Element will
ignore unverified zombie devices on /keys/query. Remove them from
the MAS sessions page when you feel like it; no rush.

## Verifying cryptographically (without trusting the SDK)

When in doubt, ignore `verify_status` and check the chain
directly against `postgres-rescue` (the Synapse DB). Three SELECTs
plus a tiny ed25519 verification script.

```bash
# 1. Pull device's published keys + inline signatures.
kubectl -n postgres exec postgres-rescue-1 -c postgres -- psql -U postgres -d synapse -tA -c "
  SELECT key_json
  FROM e2e_device_keys_json
  WHERE user_id='@<user>:<server>' AND device_id='<DEVICE_ID>';
"

# 2. Pull user's cross-signing pubkeys (master + self_signing + user_signing).
kubectl -n postgres exec postgres-rescue-1 -c postgres -- psql -U postgres -d synapse -tA -c "
  SELECT keytype, keydata
  FROM e2e_cross_signing_keys
  WHERE user_id='@<user>:<server>'
  ORDER BY stream_id DESC LIMIT 6;
"

# 3. (Optional, older signature storage path) Pull from the legacy
#    signatures table — signatures uploaded *after* the device
#    existed inline often go here instead of into key_json.
kubectl -n postgres exec postgres-rescue-1 -c postgres -- psql -U postgres -d synapse -tA -c "
  SELECT key_id, signature
  FROM e2e_cross_signing_signatures
  WHERE target_user_id='@<user>:<server>' AND target_device_id='<DEVICE_ID>';
"
```

The verification: canonical-JSON-encode the `key_json` from query 1
*after stripping the `signatures` field*, then `ed25519.verify`
that canonical-bytes against the published self-signing pubkey
from query 2.

A worked example lives at `scripts/verify-device-signature.py`
(adapted from the in-incident verifier — uses `PyNaCl` and
`canonicaljson`). Three outcomes:

| Step 1 (master → self_signing) | Step 2 (self_signing → device) | Diagnosis |
| --- | --- | --- |
| ✓ | ✓ | Device is properly cross-signed. If peers still don't trust it, their `/keys/query` cache is stale; restart the peer client. |
| ✓ | ✗ | The signature on Synapse was made with a different private key than the published self-signing pubkey's pair. Most likely cause: `/setup` ran before claude.ai built the SDK client (pre-428-precondition). Recovery: rotate device id (delete PVC, or set `MATRIX_MCP_DEVICE_ID_BOOTSTRAP` to a new value), follow the recipe. |
| ✗ | * | Master and self-signing keys on Synapse are inconsistent with each other — Secret Storage / Synapse drift from a prior partial reset. This is a user-account issue, not a matrix-mcp issue; the user needs to reset cross-signing identity from a verified primary client. |

## Migration: existing PVCs with hard-coded device ids

If you're upgrading from a build where the device id was
`MATRIXMCP2` (or anything else hard-coded) and the PVC has matrix-sdk
state tied to that id:

1. Set `MATRIX_MCP_DEVICE_ID_BOOTSTRAP=<the-current-id>` in the
   deployment env.
2. Roll the pod. On first boot, the env value is written to
   `.device-id` and used — the SDK store on disk continues to match
   what the world sees.
3. After the pod is healthy and `verify_status` reports
   `cross_signed: true`, remove the env var from the deployment
   manifest. Subsequent boots read `.device-id` from disk and the
   env is no longer consulted.

Failure to set the bootstrap env on an existing PVC means the new
boot rotates to a random id while the SDK state on disk is bound
to the old id — same failure mode as a fresh PVC except now with
the added confusion of having historical Matrix state for a
device that no longer matches what we advertise. Recoverable
(reconnect claude.ai, re-do /setup), but disruptive; the env var
is the cheap insurance.
