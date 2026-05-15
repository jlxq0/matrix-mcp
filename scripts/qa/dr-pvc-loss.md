# DR procedure: PVC loss recovery

**Phase 10.3** — disaster-recovery runbook for loss of the matrix-mcp
store PVC (the on-disk SQLite E2EE key stores).

---

## What lives on the PVC?

The PVC at `/data/stores` holds one SQLite database per authenticated user,
named by the hex-encoded SHA-256 of the user's Matrix ID. Each database
contains:

- Vodozemac OLM account keys (one per device)
- MegOLM inbound/outbound session state for E2EE rooms
- The matrix-sdk device store (device lists, cross-signing keys)

**What does NOT live on the PVC:**
- User messages and room history (on the homeserver)
- OAuth bearer tokens (issued by MAS, never persisted by matrix-mcp)
- Server config, secrets (ExternalSecret / 1Password)

---

## Impact of PVC loss

If the PVC is lost (node eviction, storage driver bug, accidental `kubectl
delete pvc`):

1. All per-user E2EE key stores are gone.
2. On the next authenticated tool call, matrix-sdk creates a new OLM account
   and device for the user.
3. The new device is **unverified** by other users and by the user themselves.
4. Previously encrypted room history that was encrypted to the old device
   is inaccessible (undecryptable) from the new device. This is a fundamental
   property of E2EE — keys rotate on device change.
5. New messages in E2EE rooms work normally once the user re-verifies their
   new device.

There is no way to recover the old E2EE keys after PVC loss. The recovery
procedure focuses on restoring service availability, not on recovering
historical key material.

---

## Recovery procedure

### 1. Confirm PVC loss

```bash
kubectl -n matrix-mcp get pvc
# STATUS should be "Bound". If it is "Lost" or missing, PVC loss is confirmed.

kubectl -n matrix-mcp describe pvc matrix-mcp-stores
# Look for "Phase: Lost" or storage driver errors.
```

### 2. Delete the lost PVC and re-create it

```bash
# Delete (if it exists in Lost state)
kubectl -n matrix-mcp delete pvc matrix-mcp-stores --ignore-not-found

# The PVC is defined in the ArgoCD-managed manifest. Force ArgoCD to re-create it:
argocd app sync matrix-mcp --force
# ArgoCD will re-create the PVC from the manifest. The new PVC starts empty.
```

### 3. Restart the deployment

```bash
kubectl -n matrix-mcp rollout restart deployment/matrix-mcp
kubectl -n matrix-mcp rollout status  deployment/matrix-mcp
```

### 4. Verify service is up

```bash
curl -sf https://matrix-mcp.example.com/health | jq .
```

### 5. Notify affected users

Users who had active sessions before the PVC loss will encounter E2EE
decryption failures on historical messages and will need to re-verify their
matrix-mcp device in their Matrix client.

Suggested notification (post to the matrix-mcp support room):

> The matrix-mcp server had a storage incident on [date]. Your E2EE session
> has been reset. If you see "Unable to decrypt" for messages sent before
> [date], this is expected — the old encryption keys are gone. New messages
> will work normally. You may need to re-verify the matrix-mcp device in your
> Matrix client's session settings.

---

## Prevention

- The PVC uses Longhorn storage (replicated across nodes). A single-node
  failure does not lose the PVC.
- However, Gruyere's design rule is: **durable state lives in R2 or Postgres,
  not PVCs**. The E2EE key store is a deliberate exception because the
  matrix-sdk SQLite format is not trivially exportable to Postgres, and the
  data is intrinsically user-device-bound.
- A future improvement is to periodically back up the stores directory to R2
  (encrypted). This is not implemented as of Phase 10.

---

## See also

- `scripts/qa/dr-pepper-rotation.md` — pepper rotation
- `docs/architecture.md` — storage design rationale
- `docs/security.md` — E2EE key lifecycle
