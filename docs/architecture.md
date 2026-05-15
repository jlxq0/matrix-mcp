# Architecture

Last updated: 2026-05-15, v0.1.0.

## Overview

matrix-mcp is a slim adapter between claude.ai (MCP client) and a
Matrix homeserver. It is an OAuth 2.1 resource server on one side and
a Matrix client on the other. There is no token exchange – the bearer
token claude.ai presents is the same token forwarded to Synapse.

```
claude.ai ──HTTPS/MCP── [Traefik IP-allowlist] ──► matrix-mcp ──► MAS (introspection)
                                                         │
                                                         └──────────► Synapse (Matrix C-S API)
```

Traefik restricts `/mcp` to Anthropic's published egress range
(`160.79.104.0/21`) before the request reaches the process.

---

## OAuth dance (first connection)

```mermaid
sequenceDiagram
    participant C as claude.ai
    participant M as matrix-mcp
    participant MAS as MAS (OIDC)

    C->>M: GET /mcp (no token)
    M-->>C: 401 WWW-Authenticate: resource_metadata=…/.well-known/oauth-protected-resource
    C->>M: GET /.well-known/oauth-protected-resource
    M-->>C: {authorization_servers: ["https://matrixauthservice.example.com"]}
    C->>MAS: GET /.well-known/oauth-authorization-server
    MAS-->>C: endpoints
    C->>MAS: POST /oauth2/registration (DCR, client_uri: https://claude.ai/)
    MAS-->>C: {client_id, client_secret}
    C->>MAS: browser → /authorize?scope=openid+urn:matrix:…+device:…&code_challenge=…
    Note over MAS: user approves
    MAS-->>C: redirect to claude.ai/api/mcp/auth_callback?code=…
    C->>MAS: POST /oauth2/token (code + PKCE verifier + resource=https://matrix-mcp.…)
    MAS-->>C: {access_token, refresh_token, scope: "openid urn:matrix:… device:XXXX"}
    C->>M: POST /mcp Bearer <access_token>
    M->>MAS: POST /oauth2/introspect (Basic auth + X-MAS-Supports-Device-Id: 1)
    MAS-->>M: {active: true, sub: <MAS-ULID>, username: julian, device_id: XXXX, scope: …}
    M->>M: load or create Client(@alice:example.com, device=XXXX)
    M-->>C: tool result
```

Key points:

- MAS's `authorization_endpoint` is at `/authorize`, not `/oauth2/authorize`
  – an exception to its `/oauth2/*` convention.
- Introspection response is cached for min(60 s, token TTL). Cache
  invalidates on a 401 from Synapse downstream.
- Tokens without an `aud` claim are accepted (claude.ai omits `resource=`),
  but must carry a Matrix C-S API scope token as a compensating control.

---

## /setup flow (E2EE unlock)

The `/setup` flow takes the recovery key via browser HTTPS so it never
appears in claude.ai's chat history.

```mermaid
sequenceDiagram
    participant U as User (browser)
    participant S as matrix-mcp /setup
    participant MAS as MAS

    U->>S: GET /setup/login
    S->>S: generate PKCE verifier + state token (map TTL 5 min, cap 256)
    S-->>U: 302 → MAS /authorize
    Note over MAS: user authenticates
    U->>S: GET /setup/callback?code=…&state=…
    S->>MAS: POST /oauth2/token + introspect
    MAS-->>S: {sub, mxid, device_id}
    S->>S: create setup session (map TTL 30 min, cap 64), set __Secure- cookie
    S-->>U: 302 → /setup/form
    U->>S: POST /setup/recover (recovery_key + CSRF token)
    S->>S: CSRF check (constant-time)
    S->>S: client.encryption().recovery().recover(key)
    S->>S: spawn: download megolm key backup (≤200 rooms, 15 s/room)
    S-->>U: success page
```

`verify_status` reports `cross_signed: true` within ~30 s after success.

---

## MCP request lifecycle

```mermaid
sequenceDiagram
    participant C as claude.ai
    participant A as auth middleware
    participant R as rate limiter
    participant T as tool handler
    participant K as MatrixClientCache
    participant Sy as Synapse

    C->>A: POST /mcp Bearer <token>
    A->>A: hash token → cache lookup (60 s TTL)
    Note over A: on miss: POST /oauth2/introspect + validate scope
    A-->>T: inject AuthenticatedIdentity + AccessToken
    T->>R: rate_limit_check(sha256(bearer) + mas_subject, Read|Write)
    R-->>T: ok or RATE_LIMITED
    T->>K: for_user(identity, token)
    K-->>T: Arc<Client> (cached or newly built)
    T->>Sy: /_matrix/client/v3/… Bearer <same token>
    Sy-->>T: response (SDK decrypts E2EE)
    T-->>C: tool result
    T->>T: emit audit log (envelope only)
```

---

## Sync loop

Each `matrix_sdk::Client` runs a background sync task after construction.
The Phase 6.3 watchdog wraps it with exponential backoff.

```
MatrixClientCache::for_user()
  └── build Client (SqliteStateStore + SqliteCryptoStore, HKDF passphrase)
  └── restore_session(MatrixSession)
  └── spawn tokio task:
        loop {
          sync_once().await
            → ok  : reset backoff
            → err : exponential backoff, warn log
        }
```

The sync task is aborted via `JoinHandle::abort()` when `CachedClient` drops.

---

## Per-user state model

| Concept | Value |
|---|---|
| Cache key | `sha256(mas_subject + device_id)[..32]` |
| Store dir | `{STORE_DIR}/{cache_key}/` |
| Store cipher passphrase | `HKDF-SHA256(salt=cache_key, ikm=pepper, info="matrix-mcp-store-cipher v1", len=32) → hex` |
| Sync task | `JoinHandle<()>`, aborted on eviction |

### Store files

```
{STORE_DIR}/
  {cache_key}/
    matrix-sdk-state.sqlite3    — room state, timelines, members
    matrix-sdk-crypto.sqlite3   — Olm/Megolm sessions, cross-signing keys
```

Both files are encrypted by matrix-sdk's `StoreCipher`. The pepper
lives exclusively in the pod environment (Kubernetes Secret from
1Password) and is never written to disk.

---

## HTTP endpoints

| Path | Auth | Purpose |
|---|---|---|
| `GET /health` | none | Liveness / readiness probe |
| `GET /.well-known/oauth-protected-resource` | none | RFC 9728 resource metadata |
| `POST /mcp` | Bearer (MAS) | MCP Streamable HTTP transport |
| `GET /setup` | none | Landing page |
| `GET /setup/login` | none | Initiates PKCE flow |
| `GET /setup/callback` | PKCE state cookie | OAuth callback |
| `GET /setup/form` | Session cookie | Recovery key form |
| `POST /setup/recover` | Session cookie + CSRF | Import recovery key |
| `GET /metrics` | internal (pod IP:9090) | Prometheus metrics |
