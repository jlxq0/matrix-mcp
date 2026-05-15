# DR procedure: bearer-token pepper rotation

**Phase 10.3** — disaster-recovery runbook for rotating the store-cipher pepper.

---

## What is the pepper?

Every user's SQLite store directory is derived from an HKDF computation:

```
store_cipher_key = HKDF(ikm=PEPPER, salt=mxid, info="matrix-mcp-store-cipher v1")
```

The pepper is a shared secret stored in the `matrix-mcp` ExternalSecret
(sourced from 1Password). Rotating it invalidates all existing per-user
store directories — every user's in-process SDK state is effectively wiped.

**When to rotate:**
- The pepper has been leaked (e.g. a 1Password incident or an accidental log dump).
- A security audit mandates periodic rotation (optional; the pepper is not a
  high-value secret — it only protects the on-disk E2EE key store from local
  filesystem reads, not from a compromised API server).

**What is lost on rotation:**
- All cached E2EE key store data for every user.
- Users will need to re-complete the E2EE login flow on their next tool call.
- No messages or room history is lost — that lives on the homeserver.

---

## Rotation procedure

### 1. Generate a new pepper

```bash
# Generate 32 bytes of cryptographic randomness, base64-encoded.
openssl rand -base64 32
```

### 2. Update 1Password

Log into 1Password and update the `STORE_PEPPER` field in the
`matrix-mcp-www` (or `matrix-mcp-beta`) item under the
"Gruyere k8s Cluster" vault.

### 3. Trigger ExternalSecret sync

The ExternalSecret controller polls on a 1-minute interval. Either wait, or
force an immediate re-sync:

```bash
kubectl -n matrix-mcp annotate externalsecret matrix-mcp \
  force-sync="$(date +%s)" --overwrite
```

Verify the Secret was updated:

```bash
kubectl -n matrix-mcp get secret matrix-mcp-secret -o jsonpath='{.data.STORE_PEPPER}' \
  | base64 -d | sha256sum
# The hash should differ from the previous value.
```

### 4. Purge existing store directories

The old store directories on the PVC are keyed by the old pepper. They must be
removed so the server creates fresh ones with the new pepper:

```bash
# Exec into the pod and remove all per-user store directories.
# WARNING: this drops all cached E2EE keys. Users re-bootstrap on next login.
kubectl -n matrix-mcp exec deploy/matrix-mcp -- \
  sh -c 'rm -rf /data/stores/*'
```

### 5. Roll the deployment

Force a pod restart to pick up the new Secret value:

```bash
kubectl -n matrix-mcp rollout restart deployment/matrix-mcp
kubectl -n matrix-mcp rollout status  deployment/matrix-mcp
```

### 6. Verify

```bash
# Health check
curl -sf https://matrix-mcp.example.com/health | jq .

# Issue a test tool call with a valid bearer token and confirm it returns 200.
curl -sf -X POST https://matrix-mcp.example.com/mcp \
  -H "Authorization: Bearer $TEST_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"whoami"}}' \
  | jq .
```

---

## Rollback

If the new pepper causes unexpected errors (e.g. a bad base64 encoding),
restore the old pepper value in 1Password, re-sync the ExternalSecret, and
restart the deployment. The old store directories are already gone at this
point; a rollback only restores the known-good pepper, not the old stores.

---

## Frequency recommendation

Rotate the pepper only when there is a concrete reason to (leak, audit
requirement). There is no operational benefit to routine rotation.
