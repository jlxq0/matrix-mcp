# Multi-user

matrix-mcp can serve multiple Matrix users from a single deployment.
Each authenticated user gets their own per-MXID state — own
matrix-sdk client, own encrypted SQLite store, own rate-limit bucket,
own audit room. This page documents the isolation guarantees, **and
the conditions under which they hold**.

> **Read this section first.** matrix-mcp's per-user isolation is
> keyed by MXID. That is safe when MXIDs are non-reassignable on
> your homeserver, which is the default on Synapse + MAS — once a
> localpart has been used, it cannot be re-bound to a different
> identity. If your homeserver / MAS configuration allows localpart
> reassignment (renames followed by re-registration, manual admin
> reassignment, custom userdb), see [MXID collision risk](#mxid-collision-risk)
> below for the threat model. For the upstream production deployment
> matrix-mcp was originally written for, this is a single-MAS-subject
> single-MXID-per-user environment in which the issue does not arise.

## State that is per-user

| Thing | Where it lives | Keyed by |
|---|---|---|
| matrix-sdk client | `MatrixClientCache` (in-memory) | MXID |
| Encrypted SQLite store | `<store_root>/<sha256(MXID)[..32]>/` | MXID (via 32-char hash) |
| Store encryption key | `HKDF-SHA256(salt = MXID, ikm = pepper, info = "matrix-mcp-store-cipher v1")` | MXID + global pepper |
| Audit room id | Matrix `account_data` event `app.matrix-mcp.audit_room` | the user's own account |
| Rate-limit bucket | In-memory token bucket map | MXID + MAS subject |
| Recovery-key prompt cookie | `__Secure-` cookie, `Path=/setup`, `SameSite=Lax` | per browser session |

Two users connecting from claude.ai with distinct, non-collidable
MXIDs share **none** of the above. The only thing they share is the
deployment-wide pepper, which is never exposed to either user.

## MXID cannot be spoofed

The MXID for an incoming request is derived inside MAS introspection
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
moment where another MXID could be substituted.

## Store-path collisions are not realistic

`mxid_dir_name(mxid)` returns the first 16 bytes of `sha256(mxid)` as
32 hex characters. SHA-256 collision resistance is the security
boundary; two **distinct** MXIDs producing the same 16-byte prefix is
not a realistic event.

Tests in `src/matrix_client.rs`:

- `mxid_dir_name_is_stable` – same input → same output.
- `mxid_dir_name_differs_per_user` – different MXIDs → different
  paths.

The next section covers what happens when the same MXID is reused by
a different MAS subject — a non-collision-resistant scenario.

## MXID collision risk

> What if homeserver+MAS *does* let a localpart be reassigned?

`MatrixClientCache::for_user`, `build_cached`, and `/setup/recover`
all key on `identity.mxid` rather than the stable MAS `sub`. The
in-code comments call this out:

> *Single-tenant kampong.social deployment the original mxid-only
> tradeoff predates the multi-user docs. If localparts are ever
> reassigned on this homeserver, this needs to be re-keyed by
> MAS subject + device id.*

If a previously-used localpart can be assigned to a new MAS subject
later (e.g. user A renames away, user B registers `@alice:server`),
matrix-mcp's cache lookup for `@alice:server` will return user A's
old cached client if it is still in memory. After a process restart
where only the on-disk store remains, the new user B's
`/setup/recover` flow would open the same SQLite store path with the
same HKDF-derived passphrase — A's encrypted E2EE keys would be
readable by B's matrix-mcp session.

This is **accepted** as an operational tradeoff for the single-MAS
deployment matrix-mcp was originally written for. If you intend to
deploy matrix-mcp against a homeserver/MAS that does support
localpart reassignment, the cache + store + passphrase key derivation
need to be re-keyed by `(MAS subject, device id)` before going live.
See [`src/matrix_client.rs`](../src/matrix_client.rs) `for_user` and
`build_cached` for the call sites to change.

## Audit room is per-user by protocol

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
- Process-global resource limits. The session pool (`MAX_SESSIONS =
  256`), the global key-backup concurrency cap (`MAX_CONCURRENT = 4`),
  and the upload/download byte caps apply across all users in
  aggregate. The per-bearer + per-MAS-subject rate limits then ensure
  no single user can monopolise the shared budget.

## How to verify

1. Connect two test users from two browsers.
2. `ls <store_root>` – two directories, both 32-char hex, neither
   matching either MXID in plaintext.
3. Have user A call `set_audit_room` for a room user A controls.
4. Have user B make a write call. Confirm the notice does **not**
   appear in user A's audit room.
5. Tail the audit-log stream and confirm each tool call carries the
   correct `mxid` envelope.
