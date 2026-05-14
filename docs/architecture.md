# Architecture

Last updated 2026-05-14. Phase 0 — to be expanded in subsequent phases.

## High-level shape

```
                              ┌─────────────────────────┐
                              │       claude.ai         │
                              │  (custom connector UI)  │
                              └────────────┬────────────┘
                                           │ HTTPS / Streamable HTTP
                                           │ Bearer <MAS access token>
                                           ▼
        Traefik ──── IP allowlist (160.79.104.0/21) ────► matrix-mcp
                                                                │
                              token introspection ┌─────────────┤
                                                  │             │
                                                  ▼             │
                                            MAS (OIDC)          │
                                       matrixauthservice.       │
                                          kampong.social        │
                                                                ▼
                                          Synapse (matrix.kampong.social)
                                          /_matrix/client/v3/*
```

The MCP server is a slim adapter:
- **MCP protocol** on the claude.ai side: Streamable HTTP at `/mcp`,
  OAuth 2.1 resource server semantics (RFC 9728 metadata, RFC 8707
  resource indicators, PKCE-mandated, DCR-supported).
- **Matrix client** on the Synapse side: one `matrix_sdk::Client` per
  authenticated user, kept warm in process, persisting state to a
  per-user SQLite file.
- **Authorisation** flows end-to-end: the OAuth bearer claude.ai presents
  to us is the *same* token we forward to Synapse. No token exchange.
  Synapse introspects the token via MAS and recognises the bound device.

## Auth sequence (Phase 1+)

```
claude.ai ─(1)── GET /mcp                                                                     ──► matrix-mcp
matrix-mcp ─(2)── 401 + WWW-Authenticate: resource_metadata=https://matrix-mcp.kampong.social/.well-known/oauth-protected-resource ──► claude.ai
claude.ai ─(3)── GET /.well-known/oauth-protected-resource                                    ──► matrix-mcp
matrix-mcp ─(4)── {authorization_servers: ["https://matrixauthservice.kampong.social"]}      ──► claude.ai
claude.ai ─(5)── GET https://matrixauthservice.kampong.social/.well-known/oauth-authorization-server ──► MAS
claude.ai ─(6)── POST /oauth2/registration  (DCR with client_uri: https://claude.ai/)         ──► MAS
MAS ──── {client_id, client_secret}                                                          ──► claude.ai
claude.ai ─(7)── opens browser → MAS consent → callback to https://claude.ai/api/mcp/auth_callback with code + PKCE verifier
claude.ai ─(8)── POST /oauth2/token  (code, verifier, resource=https://matrix-mcp.kampong.social) ──► MAS
MAS ──── {access_token, refresh_token, scope: "openid urn:matrix:... device:matrix-mcp-XXXX"} ──► claude.ai
claude.ai ─(9)── POST /mcp + Bearer <token>                                                   ──► matrix-mcp
matrix-mcp ─(10)─ POST /oauth2/introspect                                                    ──► MAS
MAS ──── {active: true, sub: @julian:kampong.social, scope: ..., device_id: matrix-mcp-XXXX, aud: https://matrix-mcp.kampong.social} ──► matrix-mcp
matrix-mcp ─(11)─ load (or create) Client(user=@julian, device=matrix-mcp-XXXX), forward bearer to /_matrix/client/v3/*  ──► Synapse
matrix-mcp ─(12)─ tool result                                                                 ──► claude.ai
```

Key facts:

- Step (10): MAS introspection caches in matrix-mcp for **60 s** to bound
  load on MAS. Cache invalidation on 401 from Synapse.
- Step (11): the bearer token is the **same** token. We do not re-sign,
  do not exchange. Synapse trusts MAS, MAS issued the token, the loop
  closes.

## Storage layout

```
/var/lib/matrix-mcp/
├── julian@kampong.social/
│   ├── state.sqlite3            # rooms, members, timelines (sync state)
│   ├── crypto.sqlite3           # Olm sessions, Megolm inbound, identity keys
│   └── event-cache.sqlite3      # recent timeline events for fast reads
├── alice@kampong.social/
│   └── ...
```

- One **PersistentVolumeClaim** mounted at `/var/lib/matrix-mcp`.
- One subdir per Matrix user ID (sanitised).
- Each SQLite file is encrypted by `matrix-sdk`'s `StoreCipher` with a
  passphrase derived as `HKDF(pepper, mxid)`.
- The pepper lives in an env var sourced from a Kubernetes Secret backed
  by an ExternalSecret (1Password). The pepper is **never written to
  disk**.

Failure modes:

- **Pod compromise (read-only):** attacker has env (pepper) + disk (the
  encrypted stores). Game over — they can derive every passphrase, open
  every store, read every room key. Mitigated by: short pod lifecycle,
  rotated devices, audit logging.
- **Disk leak alone:** stores are encrypted at rest; pepper not on disk.
  No data exposure.
- **Env leak alone:** attacker has the pepper but not the stores. Useful
  only if combined with a disk leak.

## MCP transport details

- Endpoint: `POST /mcp` with `Content-Type: application/json` and
  optional `text/event-stream` upgrade for streaming responses.
- JSON-RPC 2.0 framing.
- Server-initiated SSE is OPTIONAL in spec; v0 won't use it.

## Tool surface (target v1)

| Tool | Inputs | Output |
|---|---|---|
| `whoami` | none | `{mxid, device_id}` |
| `list_rooms` | none | `[{room_id, alias, name, last_activity, unread_count}]` |
| `list_unread` | none | `[{room_id, name, unread_count}]` |
| `read_room` | `room_id`, `limit=50`, `before=None` | `[{sender, ts, body, event_id, in_reply_to}]` |
| `search_room` | `room_id`, `query`, `limit=20` | search results |
| `send_message` | `room_id`, `body`, `msgtype="m.text"` | `{event_id}` |

Out of scope for v1:

- Server-pushed notifications (no MCP transport channel for it)
- Room creation / membership management
- Media uploads / downloads
- VOIP / call signalling
