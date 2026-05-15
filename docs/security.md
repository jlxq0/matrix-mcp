# Security

Last updated 2026-05-14. Phase 0 — pre-implementation. Revised as the
code lands.

## What this server is, security-wise

`matrix-mcp` is a Matrix client running on a server, holding **per-user
E2EE device keys** so it can decrypt messages on behalf of the user. It
is *not* a "neutral" middleware. From a threat-model perspective it is
**part of the user's TCB** for E2EE, same as Element on your laptop or
mautrix-signal in our cluster.

## Threat model

### What an attacker gains from each compromise

| Compromise | Gains |
|---|---|
| Read access to PVC disk only | Encrypted SQLite blobs. **No plaintext keys without the pepper.** |
| Read access to a pod env var (without disk) | The pepper. Useful only when combined with disk access. |
| Full pod compromise (root in container) | Disk + env + memory. All room keys for all logged-in users — past, future. Audit logs leak only if Loki/Alloy compromised separately. |
| Compromise of MAS (the issuer) | Ability to mint tokens that pass introspection. Equivalent to full pod compromise for users whose tokens were minted. |
| Compromise of Synapse | All Matrix data + ability to manipulate cross-signing. Not new — Synapse compromise is already terminal. |
| Compromise of claude.ai (client) | Claude can call tools as the user. Limited to the tools we expose; logged in our audit trail. |
| Network-tier MITM | TLS termination at Traefik makes this hard from outside. Inside cluster, NetworkPolicy + Kyverno prevent same-namespace pod-to-pod sniffing. |

The headline threat is **pod compromise reveals all room keys for all
logged-in users**. This is fundamental to the design — server-side E2EE
*by definition* requires the server to hold keys.

### Mitigations

#### Confidentiality of stored data
- SQLite files encrypted with `matrix-sdk`'s `StoreCipher`
- Per-user passphrase = `HKDF-SHA256(pepper, mxid)` — pepper is the
  only secret; `mxid` is the salt
- Pepper lives in a Kubernetes Secret backed by an ExternalSecret
  (1Password); **never written to disk**

#### Pod hardening
- PSS `restricted` namespace label
- `runAsNonRoot: true`, `runAsUser: 1000`
- `readOnlyRootFilesystem: true`
- `allowPrivilegeEscalation: false`, `capabilities.drop: ["ALL"]`
- `seccompProfile.type: RuntimeDefault`
- Single writable mount: the `/var/lib/matrix-mcp` PVC

#### Network boundary
- **Ingress:** from Traefik namespace only (existing pattern)
- **Egress:** allowlisted to MAS, Synapse, and cluster DNS. R2 added
  when/if we proxy media.
- **External IP allowlist** at Traefik for Anthropic's documented egress
  range `160.79.104.0/21`. Defence in depth against scanners.

#### Authentication
- MAS opaque-token introspection on every request
- Resource indicator (`resource=https://matrix-mcp.kampong.social`)
  validated against the introspection response
- Introspection cached for **60 s max**; cache invalidates on a 401
  from Synapse downstream

#### Audit
- Every tool invocation logged: timestamp, user MXID, tool name, room
  id (if relevant), arg-hash, result-size, latency, success/error
- Shipped to Loki via stdout JSON + Alloy (existing pattern)
- Grafana alert proposals (Phase 4):
  - Tool error rate > 5 % over 10 m
  - OAuth introspection failures > 1/s
  - Decryption failures > 0 (any failure is interesting)

#### Operational
- Pod is **single replica** in Phase 4 (state is per-pod). Multi-replica
  needs `CrossProcessLockConfig` in matrix-rust-sdk — deferred.
- Container base images are digest-pinned in the Dockerfile (`rust:1.93-bookworm` and
  `gcr.io/distroless/cc-debian12:nonroot`). Third-party GitHub Actions in `ci.yml` are
  pinned to full commit SHAs. Renovate watches both for updates.
- CI action SHAs and image digests were resolved 2026-05-15; update when Renovate bumps them.

### Mitigations deferred

- **MCP elicitation for per-session passphrase**: if claude.ai supports
  elicitation in custom connectors (unverified as of 2026-05-14), we
  flip from "pepper-always-in-env" to "user types passphrase per
  session". Threat model improves to: pod compromise *while the user is
  actively connected* leaks current session keys only.
- **90-day device rotation**: caps historical-decryption blast radius
  if a key store is later exfiltrated.
- **Per-tool authorisation policy** beyond "user authenticated → all
  tools": narrowing send permissions to specific rooms via an explicit
  user-configured policy.

## Specific external risks to watch

- **vodozemac contributory-check issue (Feb 2026)**. Two issues
  disclosed by Soatok: non-contributory X25519 acceptance + v2 → v1
  downgrade. Matrix.org committed to a defence-in-depth fix; no
  version pinned as of 2026-05-14. We're shipping with current
  `matrix-sdk` and will bump when the fix lands.
- **Anthropic egress range change**. Documented as stable but we should
  page on auth failures so an unannounced change is caught quickly.
- **MAS DCR policy regressions**. Our MAS policy currently enforces
  `client_uri` host match (good). If that policy ever loosens or
  introspection-bypass appears, our auth would silently accept tokens
  it shouldn't. Audit cadence: review MAS policy on every MAS upgrade.

## Things we explicitly do NOT do

- **No persistent refresh token storage on server.** Refresh tokens
  flow client (claude.ai) → MAS → claude.ai. The MCP server only ever
  holds short-lived access tokens in memory, refreshed by claude.ai out
  of band.
- **No user-supplied URLs or recovery keys.** Phase 0–3 don't accept
  any user-controlled secret that could be a phishing vector.
- **No HTTP-side ratelimit-bypass paths.** All tool calls go through
  the same rate-limit middleware.
- **No `unsafe` Rust code** (`#![forbid(unsafe_code)]` at the crate
  root).
