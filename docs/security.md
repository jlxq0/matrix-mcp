# Security

Last updated: 2026-05-17, v0.3.0.

## What matrix-mcp is, security-wise

matrix-mcp is a Matrix client running on a server. It holds per-user
E2EE device keys and can decrypt messages on behalf of users. From a
threat-model perspective it is **part of the user's TCB** for E2EE –
equivalent to Element X on a laptop or a mautrix bridge in the cluster.

Any operator deploying this server should treat its pod like a
cross-signing device: compromise of the pod means compromise of every
room key for every user who has used that pod.

---

## Attacker model

We consider the following adversaries:

1. **External network attacker** – can observe traffic from outside the cluster.
2. **Rogue claude.ai client** – a claude.ai session (or bearer token
   holder) calling tools with malicious intent.
3. **Leaked bearer token** – a valid MAS access token extracted from
   network traffic or session data.
4. **Pod compromise** – attacker has code execution inside the container.
5. **Disk-only access** – attacker exfiltrates the PVC without the pod env.
6. **Pepper compromise** – attacker reads `MATRIX_MCP_STORE_PEPPER` only.
7. **MAS compromise** – attacker can mint tokens that pass introspection.
8. **Synapse compromise** – attacker controls the homeserver.

---

## What each compromise gives an attacker

| Attacker | Gets | Doesn't get | Primary defence |
|---|---|---|---|
| External network | Nothing – TLS at Traefik | Plaintext requests | TLS + Traefik IP allowlist |
| Rogue claude.ai client | Tool calls as that user | Other users' data | Per-user isolation, rate limits, audit log |
| Leaked bearer token | Same as rogue client for that user | Persistent access (tokens expire) | Token TTL, 60 s introspection cache max |
| Pod compromise (read) | Pepper + disk → all user key stores | Audit logs (in Loki) | PSS restricted, read-only root FS |
| Pod compromise (exec) | Full control of all active sessions | Keys for users not yet synced | Single replica, no root, no privilege escalation |
| Disk-only (PVC exfil) | Encrypted SQLite blobs | Plaintext keys (no pepper) | HKDF key derivation; pepper lives only in env |
| Pepper-only | Derivation formula | Nothing without the stores | Pepper and disk must both be compromised |
| MAS compromise | Mint passing tokens → pod-level access | Historical keys (users not connected since) | Token expiry, Synapse scope re-validation |
| Synapse compromise | All Matrix data | Nothing new beyond Synapse compromise | Out of scope – Synapse compromise is terminal |

### Headline risk

**Full pod compromise reveals all room keys for all users who have
connected to this pod.** This is inherent to server-side E2EE – a
server holding device keys must be treated as a trusted device.

Mitigating factors: single-replica (blast radius bounded to one pod),
PSS-restricted namespace, read-only root filesystem, audit logging to Loki.

---

## Mitigations in place

### Storage encryption

- SQLite stores encrypted by `matrix-sdk`'s `StoreCipher`.
- Per-user passphrase = `HKDF-SHA256(salt=owner_key, ikm=pepper,
  info="matrix-mcp-store-cipher v1")`.
- Owner key = `sha256(mas_subject + device_id)[..32]` – stable across
  token refreshes, resistant to MXID localpart renames.
- Pepper is a Kubernetes Secret sourced from 1Password via ExternalSecret.
  **Never written to disk.**

### Pod hardening (PSS restricted)

- `runAsNonRoot: true`, `runAsUser: 1000`
- `readOnlyRootFilesystem: true`
- `allowPrivilegeEscalation: false`
- `capabilities.drop: ["ALL"]`
- `seccompProfile.type: RuntimeDefault`

### Network boundary

- Ingress: from Traefik namespace only (NetworkPolicy).
- Egress: allowlisted to MAS, Synapse, and cluster DNS.
- External IP allowlist at Traefik: Anthropic egress `160.79.104.0/21`.

### Authentication

- MAS opaque-token introspection on every request.
- Tokens **must** carry a Matrix C-S API scope token
  (`urn:matrix:client:api:*` or MSC2967 unstable equivalent).
- `aud` validated against our resource URL when present; missing `aud`
  accepted with a WARN log (claude.ai behaviour – see ADR-03).
- Introspection cached 60 s or token TTL, whichever is shorter.
- Cache invalidates on a 401 from Synapse.
- MAS `sub` (stable ULID) used as store ownership key – mutable MXID
  localpart cannot hijack another user's store (ADR-01).

### /setup hardening

- PKCE state map capped at 256 entries; sessions at 64. Both TTL-pruned.
- CSRF token on `POST /setup/recover`, validated in constant time.
- Session cookie: `__Secure-` prefix, `Path=/setup`, `HttpOnly`,
  `SameSite=Lax`, session-only (no Max-Age).
- Setup sessions are isolated from the `/mcp` auth path.

### Rate limiting

- Per-identity token-bucket: `sha256(bearer)[..16]` + MAS subject ULID.
- Defaults: 60 reads/min, 30 writes/min. Configurable via env.

### Audit logging

- Every tool call: timestamp, MXID, tool name, room_id, token hash,
  outcome, latency, error class.
- **Never logged:** message bodies, recovery keys, bearer tokens, room content.
- Shipped to Loki via stdout JSON + Alloy.

### Input caps

- `read_recent_messages`: limit capped at 50.
- `send_text_message`: body capped at 64 KiB.
- `room_members`: capped at 1000.
- `search_messages`: capped at 100 results.
- `download_attachment`: declared + actual size checked against cap (default 5 MiB).
- `send_image_from_url`: HTTPS only, 3 redirects, 15 s timeout, cap 10 MiB.

### Supply chain

- CI `cargo audit` + `cargo deny` on every PR.
- Container base images digest-pinned in Dockerfile.
- GitHub Actions pinned to full commit SHAs.
- Renovate watches both for updates.
- `#![forbid(unsafe_code)]` at the crate root.

---

## Residual risk

| Risk | Status |
|---|---|
| Pod compromise leaks all active user key stores | **Accepted** – inherent to server-side E2EE. Mitigated by pod hardening + audit log. |
| SSRF via `send_image_from_url` to RFC-1918 addresses | **Known gap** – HTTPS + redirect cap in place; loopback/RFC-1918 blocking is a future item. |
| MCP prompt injection via Matrix room content | **Known** – see `matrix_mcp_prompt_injection_pattern` in MEMORY.md. Not a server-side concern. |
| vodozemac X25519 contributory-check issue (Feb 2026) | **Monitor** – will bump matrix-sdk when the fix lands upstream. |
| Anthropic egress range change | **Monitor** – auth failure alerts would catch an unannounced change. |

---

## Things we explicitly do NOT do

- **No persistent refresh-token storage.** Refresh tokens flow claude.ai → MAS → claude.ai.
- **No unsafe Rust.** `#![forbid(unsafe_code)]` enforced.
- **No rate-limit bypass paths.** All tool calls share the same middleware.
- **No SAS verification path.** Cross-signing uses `/setup` only.
- **No recovery key in chat.** The `recover_with_key` MCP tool was removed;
  the key flows only via the browser `/setup` form.
