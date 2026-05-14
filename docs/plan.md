# matrix-mcp – Phased build plan

Last updated 2026-05-14.

## Premise

Build a remote MCP server, written in Rust, that exposes a Matrix
homeserver (kampong.social via Synapse + MAS) to claude.ai as a custom
connector. Single binary, self-hosted on Gruyere at
`matrix-mcp.kampong.social`. OAuth via MAS (no new user system).
Per-user E2EE-capable.

## Stack (locked-in)

| Layer | Choice |
|---|---|
| Language | Rust 1.85+ (edition 2024) |
| Async runtime | `tokio` |
| HTTP server | `axum` 0.7 |
| MCP framework | `rmcp` (preferred) or hand-rolled axum + serde_json |
| Matrix SDK | `matrix-sdk` 0.17+ with `e2e-encryption` + `sqlite` features |
| Storage | SQLite per user via matrix-sdk's `SqliteStateStore` + `SqliteCryptoStore` |
| Crypto store passphrase | `HKDF(pepper, mxid)`; pepper from 1Password env var (Option A, decided 2026-05-14) |
| Auth | MAS opaque-token introspection, cached 60 s |
| Client registration | Dynamic (RFC 7591 / DCR); confirmed working against MAS 2026-05-14 |
| Container | Multi-stage Rust 1.85 → distroless `cc-debian12:nonroot` |
| Logging | `tracing` + `tracing-subscriber` JSON formatter |

## Threat model (locked-in)

The MCP server is a Matrix client on behalf of the user, with the same
E2EE blast radius as any other Matrix client. Pod compromise →
all room keys for all logged-in users.

Mitigations baked in:

1. PSS restricted, non-root, `readOnlyRootFilesystem`
2. NetworkPolicy: ingress from Traefik only; egress to MAS + Synapse +
   DNS
3. IP allowlist at Traefik for Anthropic's documented egress
   `160.79.104.0/21`
4. Per-user `StoreCipher` passphrase = `HKDF(pepper, mxid)`; pepper from
   1Password / ExternalSecret, never on disk
5. Audit log every tool call to Loki
6. Token introspection validates `resource=https://matrix-mcp.kampong.social`
   (RFC 8707)

Mitigations deferred:

- Passphrase-per-session via MCP elicitation (if claude.ai is confirmed
  to support it)
- 90-day per-user device rotation

## Phased plan

### Phase 0 — Skeleton + design lock-in **(in progress)**

**Goal:** Repo exists, plan committed, "hello world" axum boots, CI green.

**Deliverables:**

- `github.com/jlxq0/matrix-mcp` created (private, AGPL-3.0)
- `README.md` – elevator pitch + status + dev setup
- `docs/plan.md` – this document
- `docs/architecture.md` – sequence diagrams + storage layout
- `docs/security.md` – threat model + mitigations
- `Cargo.toml` – pinned deps for Phase 0 only (tokio, axum, tracing,
  serde, anyhow, thiserror)
- `src/main.rs` – axum boots on `:3000` with `/healthz`
- `.github/workflows/ci.yml` – fmt, clippy, test, audit, deny, docker
- `Dockerfile` – multi-stage, distroless
- `deny.toml`, `rustfmt.toml`, `.gitignore`

**Gate to Phase 1:** repo green on CI, `docker run` produces a working
`/healthz`.

### Phase 1 — Auth + MCP transport, no Matrix

**Goal:** claude.ai can complete the OAuth handshake against the server
and call a stub tool that returns the authenticated MXID. No Matrix yet.

**Deliverables:**

- `/.well-known/oauth-protected-resource` endpoint (RFC 9728)
- 401 + `WWW-Authenticate` header on unauthenticated `/mcp`
- MAS introspection client (validates `aud`/`resource`, caches 60 s)
- IP allowlist middleware
- MCP `/mcp` endpoint with Streamable HTTP transport (rmcp or
  hand-rolled)
- Tools: `whoami` (returns MXID from introspection)
- Structured audit log (JSON to stdout)

**Test plan:**

- Local: scripted OAuth flow + curl against `whoami`
- Real: add `https://matrix-mcp.kampong.social` to claude.ai → OAuth
  dance completes → `whoami` returns my MXID

**Gate to Phase 2:** OAuth dance works end-to-end against real MAS.

### Phase 2 — Matrix integration, plaintext rooms only

**Goal:** read and write to unencrypted rooms via persistent per-user
client.

**Deliverables:**

- Per-user `matrix_sdk::Client` instances kept warm in a
  `DashMap<UserId, Client>`
- Sliding sync subscription (MSC4186) per user
- SQLite state store per user under `/var/lib/matrix-mcp/<mxid>/state.sqlite3`
- Tools: `list_rooms`, `read_room` (plaintext only), `send_message`,
  `list_unread`

**Test plan:**

- Plaintext test room on kampong.social, send messages from Element,
  `read_room` returns them
- Restart pod, verify state persistence
- `send_message` writes a message visible in Element

**Gate to Phase 3:** state persistence works, sliding sync is healthy.

### Phase 3 — E2EE

**Goal:** decrypt encrypted rooms.

**Deliverables:**

- Crypto store per user under `/var/lib/matrix-mcp/<mxid>/crypto.sqlite3`
- `StoreCipher` derived from `HKDF(pepper, mxid)`; pepper from env
- Device id pinned via OAuth scope
  `urn:matrix:org.matrix.msc2967.client:device:matrix-mcp-<random>`
- Cross-signing flow + key-backup retrieval for historical messages
- Surface "verify this device in Element" instruction until verified

**Test plan:**

- Encrypted DM → first call says verify, verify in Element, subsequent
  calls decrypt
- Pod restart preserves decryption
- Document historical-message retrieval behaviour

**Gate to Phase 4:** stable E2EE decryption in steady state.

### Phase 4 — Production deploy on Gruyere

**Goal:** live at `matrix-mcp.kampong.social`.

**Deliverables (in the `argocd` repo under
`clusters/gruyere/apps/matrix-mcp/`):**

- `namespace.yaml` (PSS restricted)
- `deployment.yaml` (single replica, PVC mount, probes)
- `service.yaml`
- `pvc.yaml` (Longhorn, 10 GiB)
- `external-secret.yaml` (MAS introspection creds + StoreCipher pepper)
- `certificate.yaml`
- `httproute.yaml` (Traefik, IP allowlist, security headers)
- `networkpolicy.yaml`
- Grafana alerts: tool errors, OAuth failures, crypto failures

**Test plan:**

- Deploy, add to claude.ai, read encrypted room end-to-end
- Pod restart with no manual intervention
- Audit log entries in Loki

**Gate to Phase 5:** stable for 1 week, no Grafana alerts.

### Phase 5 — Polish

- `search_room`, `search_all_rooms`
- `mark_read`
- Tool result size optimisation
- 90-day device rotation cron
- Litestream R2 backup of SQLite
- Passphrase-per-session via MCP elicitation (if supported)
- Family/friend onboarding

## Test discipline

Per the operator's standing instruction: **always test**.

- **CI on every commit:** fmt, clippy (`-D warnings`), test, audit, deny.
- **Unit tests:** at every level. Crypto-adjacent code requires
  proportionally more.
- **Integration tests:** mock MAS introspection in Phase 1; real Matrix
  client against `@matrix-mcp-dev:kampong.social` (test account, to be
  created) in Phase 2+.
- **E2EE tests:** manual "before / after" steps documented per PR;
  manual sign-off required before merge.
- **End-to-end:** Phase 4 PR includes a runbook entry that can be
  re-executed in 5 minutes to validate a working deploy.
