# Multi-user

matrix-mcp is multi-tenant by construction. Every authenticated user
gets their own per-mxid state. This page documents the isolation
guarantees and how to verify them in the code.

## State that is per-user

| Thing | Where it lives | Keyed by |
|---|---|---|
| matrix-sdk client | `MatrixClientCache` (in-memory) | mxid |
| Encrypted SQLite store | `<store_root>/<sha256(mxid)[..32]>/` | mxid (via 32-char hash) |
| Store encryption key | `HKDF-SHA256(salt = mxid, ikm = pepper, info = "matrix-mcp-store-cipher v1")` | mxid + global pepper |
| Audit room id | Matrix `account_data` event `app.matrix-mcp.audit_room` | the user's own account |
| Rate-limit bucket | In-memory token bucket map | mxid |
| Recovery-key prompt cookie | `__Secure-` cookie, `Path=/setup`, `SameSite=Lax` | per browser session |

Two users connecting from claude.ai share **none** of the above. The
only thing they share is the deployment-wide pepper, which is never
exposed to either user.

## The mxid cannot be spoofed

The mxid for an incoming request is derived inside MAS introspection
(`src/mas.rs`), not taken from anywhere the client controls:

```
identity.mxid = "@" + introspection.username + ":" + config.server_name
```

`username` comes from MAS's response to `POST /oauth2/introspect`,
which is authenticated with matrix-mcp's pre-registered client secret
over TLS. `server_name` is a static deployment config value. The
client never gets to influence either.

A malicious user can't even race the resolution: introspection
happens before tool dispatch, in the same async task, and the result
is moved by value into the tool handler. There is no in-between
moment where another mxid could be substituted.

## The store path cannot collide

`mxid_dir_name(mxid)` returns the first 16 bytes of `sha256(mxid)` as
32 hex characters. SHA-256 collision resistance is the security
boundary; two different mxids producing the same 16-byte prefix is
not a realistic event.

Tests in `src/matrix_client.rs`:

- `mxid_dir_name_is_stable` – same input → same output.
- `mxid_dir_name_differs_per_user` – different mxids → different
  paths.

## The audit room is per-user by protocol

`set_audit_room(room_id)` calls `client.account().set_account_data(...)`
with a `app.matrix-mcp.audit_room` event. Matrix `account_data` is
scoped to the calling user account – Synapse refuses cross-user reads
and writes at the API level. A user setting an audit room only
affects their own audit timeline.

When matrix-mcp emits a notice, it does so via that user's matrix-sdk
client, posting as that user. Another user's matrix-sdk client never
touches the room.

## What is **not** isolated

- The deployment-wide pepper. If it leaks while on-disk stores still
  exist, every user's store decrypts. Rotation is destructive –
  every user re-runs `/setup`. See
  [`docs/operations.md`](operations.md) for the procedure.
- The matrix-mcp operator. Whoever runs the binary has unfettered
  access to every connected user's decrypted content. See
  [`THREAT_MODEL.md`](../THREAT_MODEL.md).
- Synapse and MAS. Both are upstream of the isolation boundary – a
  compromise there compromises everyone.

## How to verify

1. Connect two test users from two browsers.
2. `ls <store_root>` – two directories, both 32-char hex, neither
   matching either mxid in plaintext.
3. Have user A call `set_audit_room` for a room user A controls.
4. Have user B make a write call. Confirm the notice does **not**
   appear in user A's audit room.
5. Tail the audit-log stream and confirm each tool call carries the
   correct `mxid` envelope.
