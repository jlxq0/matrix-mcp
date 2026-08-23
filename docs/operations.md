# Operations

Debug recipes, rotation procedures, and env var reference for a
matrix-mcp deployment.

---

## Environment variables

| Variable | Required | Default | Notes |
|---|---|---|---|
| `MATRIX_MCP_RESOURCE_URL` | yes | – | Public URL of this server, e.g. `https://matrix-mcp.example.com`. No trailing slash. |
| `MATRIX_MCP_AUTHORIZATION_SERVER` | yes | – | MAS **issuer identifier**, copied byte-for-byte from the AS metadata document's `issuer` field (MAS publishes it *with* a trailing slash: `https://matrixauthservice.example.com/`). Clients compare it exactly per RFC 8414 §3.3 and refuse the metadata on a mismatch. Endpoint URLs are built from it with any trailing slash removed. |
| `MATRIX_MCP_HOMESERVER_URL` | yes | – | Synapse base URL, e.g. `https://matrix.example.com`. No trailing slash. |
| `MATRIX_MCP_SERVER_NAME` | yes | – | Matrix server name (right side of MXIDs), e.g. `example.com`. Not a URL. |
| `MATRIX_MCP_INTROSPECTION_CLIENT_ID` | yes | – | OAuth client id for MAS introspection endpoint. |
| `MATRIX_MCP_INTROSPECTION_CLIENT_SECRET` | yes | – | OAuth client secret paired with the id above. |
| `MATRIX_MCP_STORE_DIR` | yes | – | Root directory for per-user SQLite stores. In production: PVC mount at `/var/lib/matrix-mcp`. |
| `MATRIX_MCP_STORE_PEPPER` | yes | – | ≥32-byte high-entropy string. HKDF input for store-cipher key derivation. See pepper section below. |
| `MATRIX_MCP_BIND_ADDR` | no | `0.0.0.0:3000` | TCP bind for the public API. |
| `MATRIX_MCP_METRICS_BIND_ADDR` | no | `{POD_IP}:9090` | TCP bind for Prometheus metrics. Never `0.0.0.0` by default. |
| `POD_IP` | no (k8s injects) | – | Pod IP from downward API. Used to derive the metrics bind address. |
| `MATRIX_MCP_RATE_LIMIT_READS_PER_MIN` | no | `60` | Per-identity read quota. |
| `MATRIX_MCP_RATE_LIMIT_WRITES_PER_MIN` | no | `30` | Per-identity write quota. |
| `MATRIX_MCP_DOWNLOAD_MAX_BYTES` | no | `5242880` (5 MiB) | Max attachment size for `download_attachment`. |
| `MATRIX_MCP_UPLOAD_MAX_BYTES` | no | `10485760` (10 MiB) | Max streamed fetch size for URL media uploads and TTS responses. |
| `MATRIX_MCP_ALLOWED_ORIGINS` | no | – (disabled) | Comma-separated browser origins accepted on `/mcp`, e.g. `https://claude.ai`. Each entry needs a scheme; `null` matches `Origin: null`. Empty disables `Origin` validation — see below. |

### `Origin` validation

The MCP Streamable HTTP spec says servers MUST validate `Origin`. It is off by
default here, deliberately: the attack it defends against is DNS rebinding
against a server bound to localhost, and non-browser MCP clients (Claude
Desktop, VS Code, Cursor, CLI tools) either omit `Origin` or send an
app-private value that no allow-list can enumerate in advance — so a default
allow-list would lock out desktop clients without improving the security of a
public, bearer-authenticated deployment. `Host` is validated unconditionally.

Set `MATRIX_MCP_ALLOWED_ORIGINS` when the only clients are browser-based.
Requests with no `Origin` header still pass; only a present-and-unlisted
`Origin` is rejected (403).

### Durable MCP sessions

Session state is persisted under `{MATRIX_MCP_STORE_DIR}/mcp-sessions/` — one
small JSON file per session, named `sha256(session_id)`, holding the client's
`initialize` parameters (no tokens, no identity). A restart, a rollout, or an
idle eviction therefore does not invalidate a client's `Mcp-Session-Id`: the
next request carrying it is restored transparently instead of getting a `404`
that would force a fresh handshake.

Entries expire seven days after their last write and the directory is capped at
4096 sessions. To wipe them (clients will simply re-handshake):

```
kubectl exec -n matrix-mcp deploy/matrix-mcp -- rm -rf /var/lib/matrix-mcp/mcp-sessions
```

---

## Debug recipes

### "Cannot find libsqlite3.so" at container startup

matrix-sdk bundles SQLite statically – this should never happen with the
current Dockerfile. If it does, the base image changed.

```
# check what's in the container
docker run --rm --entrypoint sh matrix-mcp:dev -c 'ldd /app/matrix-mcp'
```

The binary should have no SQLite dependency in the dynamic linker output.
If it does, the `features = ["bundled"]` on `rusqlite` was dropped. Add
it back in `Cargo.toml`.

### "/setup/callback: Unknown or expired state"

PKCE state tokens have a 5-minute TTL. Either the user took too long to
authorize in the browser, or the state map hit its 256-entry cap (unlikely
unless the endpoint is being probed). Have the user click "Sign in" again
immediately.

### "MAS returned active token without aud claim; accepting" in logs

Normal behaviour when claude.ai's MCP connector omits the `resource=`
parameter in the token request. The log is a WARN but the token is still
accepted – compensating controls (Matrix scope check, Synapse re-validation)
remain in place. Not actionable unless it disappears entirely (would mean
all tokens suddenly have `aud`, indicating a MAS behaviour change).

### "parse device_id from scope" or device_id missing

MAS sometimes omits `device_id` from the introspection response even with
`X-MAS-Supports-Device-Id: 1`. matrix-mcp falls back to parsing it from
the scope string (`urn:matrix:client:device:<id>`). If both are missing,
`device_id` is `null` in `whoami` – verify_status will still work because
Synapse assigns the device on first use.

Check the raw introspection response by temporarily adding a debug log,
or by calling the MAS introspect endpoint directly:

```bash
curl -su 'CLIENT_ID:CLIENT_SECRET' \
  https://matrixauthservice.example.com/oauth2/introspect \
  -d "token=<bearer>" | jq .
```

### verify_status returns cross_signed: false after /setup

Wait ~30 s for the sync task to pick up the updated key state. If it's
still false after a minute:

1. Check the pod logs for `request_user_identity` errors.
2. Try `verify_status` again – a transient /keys/query failure will
   resolve on retry.
3. If the device doesn't appear in Element X's verified devices list at
   all, the recovery key may have been wrong. Run `/setup` again.

### MCP session expired / auth loop

claude.ai holds its own refresh token. When the access token expires,
claude.ai refreshes via MAS. If the loop restarts entirely (new DCR
registration), it's because MAS revoked the claude.ai client. This can
happen after a MAS restart with ephemeral client storage. Re-adding the
connector in claude.ai settings reregisters the client.

### "rate limit exceeded" on every call

Check if the rate limit env vars were set to very low values. Defaults
are 60 reads/min and 30 writes/min per identity. If a single claude.ai
session is hitting this under normal use, raise the limits:

```yaml
# in deployment.yaml env section
- name: MATRIX_MCP_RATE_LIMIT_READS_PER_MIN
  value: "120"
```

---

## Pepper rotation (destructive)

**This destroys every user's encrypted store. All users must re-run /setup.**

1. Generate a new pepper:
   ```bash
   openssl rand -hex 32
   ```
2. Update the `STORE_PEPPER` field in the `matrix-mcp-www` 1Password item.
3. Delete the PVC contents (or the PVC itself and recreate it):
   ```bash
   kubectl -n matrix-mcp-www exec deploy/matrix-mcp-www -- \
     sh -c 'rm -rf /var/lib/matrix-mcp/*'
   ```
4. Restart the pod. It will start fresh – no user stores, no sync state.
5. Notify users: each must visit `/setup` again to re-import their recovery
   key and re-enable E2EE.

The old stores are unreadable with the new pepper and can be deleted.
Element X will prompt users to verify the new matrix-mcp device.

---

## OAuth client_secret rotation

Rotates the MAS introspection credentials. Non-destructive – existing
user sessions continue after rotation.

1. Generate a new secret:
   ```bash
   openssl rand -hex 32
   ```
2. Update the `INTROSPECTION_CLIENT_SECRET` field in the `matrix-mcp-www`
   1Password item.
3. Update the matching secret in the `Matrix Authentication Service`
   1Password item (`matrix-mcp-client-secret` field).
4. Apply the updated ExternalSecret (or wait for the refresh interval):
   ```bash
   kubectl -n matrix-mcp-www annotate externalsecret matrix-mcp-www \
     force-sync=$(date +%s) --overwrite
   ```
5. Restart the pod to pick up the new secret from env.
6. Verify: `curl -i https://matrix-mcp.example.com/health` should return
   200. If MCP calls start returning 401 immediately after restart, the
   MAS-side secret wasn't updated – double-check step 3.

---

## Recovery key change (user-initiated)

If a user changes their Matrix Secret Storage recovery key in Element X,
the old key imported via `/setup` is no longer valid for future key
backups. The existing cross-signing state is not affected – the user
is already verified.

To update: user visits `/setup` again and pastes the new recovery key.
The `recover()` call replaces the old secret storage credentials.
No data is lost; the existing store remains valid.


## Recovery for accounts with no human

`/setup` is how a cross-signing identity gets into this deployment, and it is a
browser flow: sign in at MAS, paste the recovery key Element produced. That
assumes somebody can sign in.

A **bot account has nobody**. Its identity would therefore live in exactly one
place — this deployment's encrypted store. Lose the volume, move the
deployment, or rebuild the store, and the identity is stranded: the homeserver
still holds a master key, so `bootstrap_cross_signing` correctly refuses to
mint a second one, and the account is left permanently unverifiable.

**Nothing needs configuring.** When `bootstrap_cross_signing` creates an
identity, it also writes it to Secret Storage under a passphrase derived from
the pepper and the MXID:

```text
passphrase = HKDF-SHA256(salt = mxid, ikm = pepper,
                         info = "matrix-mcp-recovery v1")
```

the same construction [`derive_store_passphrase`] already uses for the store
cipher, with a different `info` string. When a client is built for that account
later — on another pod, after a volume loss, in a fresh deployment — the
identity is imported back automatically.

This was first built as an operator-maintained map of per-account passphrases.
That was the wrong shape: this server accepts any active token, so anyone can
connect any number of accounts, and a feature that needs the operator to add a
line before each one works is not really available to them.

### What this does and does not grant

It grants nobody anything new. The pepper already decrypts every per-user
store, and those stores already contain the same cross-signing private keys.
Anyone holding the pepper could read them before this existed.

It never touches a human's identity. The passphrase is only ever *written* by
`bootstrap_cross_signing`, which refuses to run on an account that already has
a cross-signing identity — so it only ever applies to accounts this deployment
set up itself. Reading is a `recover()` attempt that simply fails for every
human user, whose Secret Storage is locked with their own key and is left
untouched. `/setup` remains the route for those.

Pepper rotation is already documented as destructive to the stores. It is
equally destructive here: rotate it and previously created identities can no
longer be recovered.

### One matrix-sdk client per device

Related, and learned the hard way: **never point two matrix-sdk clients at the
same access token.** Both build a crypto store and generate identity keys for
the same device id, only one set can be advertised, and the loser can decrypt
nothing while looking perfectly healthy. Reissuing the token does not fix it —
the device id, and its keys, survive. Recovery cannot fix it either: it
restores an identity, not a device. Give each consumer its own account.
