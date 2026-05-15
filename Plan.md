# matrix-mcp roadmap

Post-Phase-4 work, after the basic OAuth/E2EE/recovery flow shipped
(v0.0.1 → v0.0.13). Each item is a small PR. Mark done with
`- [x]` + a trailing `<!-- completed YYYY-MM-DD -->` per the project's
Plan.md convention.

**Sequencing rule:** finish Phase 5 before any work that needs to
prove it didn't break something. Phase 6 before Phase 7 so we don't
ship features into a not-yet-hardened system.

**Out of scope (deliberately):** horizontal multi-replica. The Olm
single-writer constraint makes that a protocol-level problem, not a
store-backend problem; staying single-replica with Longhorn
underneath is correct.

---

## Phase 5 — observability foundation

- [x] 5.1 Tool-call audit log: envelope-only structured JSON to stdout.
      Fields: ts, request_id, mxid, tool, room_id, outcome, latency_ms,
      error_class. **Never** message body, recovery key, bearer, room
      content. Alloy ships to Loki. <!-- completed 2026-05-15 -->
- [ ] 5.2 Prometheus `/metrics` endpoint on a separate port; never
      label by mxid/room_id/token. Counters: tool_calls_total{tool,
      outcome}; histograms: tool_latency_seconds{tool},
      mas_introspect_latency_seconds. ServiceMonitor manifest in
      argocd.
- [ ] 5.3 Grafana dashboard JSON in `clusters/gruyere/platform/grafana-dashboards/`:
      tool-call rate, error rate, p50/p95/p99 latency per tool, MAS
      introspect latency, sync state, /setup attempts/successes.
- [ ] 5.4 Optional self-audit `m.notice` for write tools to a
      user-designated audit room (env var `MATRIX_MCP_AUDIT_ROOM` per
      user via a `set_audit_room` tool, or auto-create one on first
      /setup). E2EE; user owns it; no Loki involvement.
- [ ] 5.5 OpenTelemetry tracing spans for tool calls + introspection
      + setup flow steps, via `tracing-opentelemetry` → Alloy → Tempo.
      Span attributes envelope-only.

## Phase 6 — hardening + multi-tenancy correctness

- [ ] 6.1 Rate limiting middleware using `governor`. Two buckets:
      `sha256(bearer)[..16]` and `sub` (MAS ULID, requires
      introspection result). Defaults: 60/min reads, 30/min writes.
      Configurable via env.
- [ ] 6.2 CSRF token on `POST /setup/recover`. Cookie path tightened
      from `/` to `/setup`.
- [ ] 6.3 Background sync watchdog: wrap `client.sync()` in a
      retry-with-exponential-backoff loop in `matrix_client.rs` so a
      transient homeserver error doesn't leave the OlmMachine idle.
- [ ] 6.4 NetworkPolicy in `clusters/gruyere/apps/matrix-mcp-www/`:
      egress allow-list (MAS, Synapse, GHCR registry, R2 if/when we
      use it), deny everything else.
- [ ] 6.5 PodDisruptionBudget `minAvailable: 1` so a node drain
      doesn't kill the only pod mid-request. PVC fill alert at 80%
      via Grafana-alerting.
- [ ] 6.6 Weekly cron in `.github/workflows/audit.yml`:
      `cargo audit` + `cargo deny check`. Open issue on failure.
- [ ] 6.7 Per-user device id: derive from `sub` (MAS ULID).
      `MM<sha256(sub)[..12]>` so multi-user smoke shows distinct
      devices in each user's Element X. Update
      `oauth_metadata.rs` to generate per-request device scope —
      this changes the metadata document from static to
      bearer-aware. Migration note: existing single-user device
      `MATRIXMCPCONNECTOR` retired or kept as alias.
- [ ] 6.8 Two-user smoke test: invite a second kampong.social user
      to /setup + run tool calls in parallel from two claude.ai
      accounts. Verify no cross-leakage in audit log, devices, key
      backup.

## Phase 7 — feature expansion (11 new tools)

- [ ] 7.1 `send_reaction(room_id, event_id, key)` — adds an emoji
      reaction to an event.
- [ ] 7.2 `redact_message(room_id, event_id, reason?)` — deletes
      one of your own messages.
- [ ] 7.3 `room_info(room_id)` — name, topic, encryption state,
      member count, power-level of caller, my-membership state.
- [ ] 7.4 `room_members(room_id, limit?)` — list of mxids with
      display names and avatars.
- [ ] 7.5 `get_unread_summary()` — across all joined rooms: count,
      last-sender, last-message-ts. Sorted by recency.
- [ ] 7.6 `mark_read(room_id, event_id?)` — fire-and-forget receipt.
      Default to latest event in room.
- [ ] 7.7 `download_attachment(event_id, room_id)` — return file as
      base64 + content-type + size. Size-cap configurable; default
      5 MiB.
- [ ] 7.8 `send_image_from_url(room_id, image_url, caption?)` —
      fetch URL, upload to homeserver media, send `m.image`.
- [ ] 7.9 `search_messages(query, room_id?)` — wraps
      `/_matrix/client/v3/search`. Returns events with context.
- [ ] 7.10 `join_room(alias_or_id)` / `leave_room(room_id)` /
       `invite_user(room_id, mxid)`. Three small tools.
- [ ] 7.11 Threading in `read_recent_messages`: per-event
      `in_reply_to`, `is_thread_root`, `thread_event_count`. Add
      `read_thread(room_id, root_event_id)` tool.

## Phase 9 — documentation

- [ ] 9.1 Rewrite `README.md` (≤100 lines top-level, links out for
      detail).
- [ ] 9.2 Rewrite `docs/architecture.md` with Mermaid diagrams:
      OAuth dance, /setup flow, MCP request lifecycle, sync loop,
      key backup pull.
- [ ] 9.3 Rewrite `docs/security.md` as a real threat model:
      attacker model, trust boundaries, what each compromise (pod,
      bearer, pepper, recovery key, mxid, master key) gets the
      attacker, defenses in place, residual risk.
- [ ] 9.4 New `docs/operations.md`: debug recipes for the failure
      modes already encountered (libsqlite3, MAS quirks, scope
      issues, device_id absence), pepper rotation procedure, OAuth
      client_secret rotation, recovery key change.
- [ ] 9.5 New `docs/onboarding.md`: how a new user is set up
      (visits /setup, pastes recovery key, optional self-audit
      room).
- [ ] 9.6 New `docs/installation.md`: how a new operator deploys
      matrix-mcp against their own MAS+Synapse from scratch.
      Different deployment surfaces: Gruyere (ours), generic k8s,
      docker-compose for local hacking.
- [ ] 9.7 New `docs/decisions.md` (ADR format): no Postgres backend,
      single-replica, accept missing-aud tokens, parse device_id
      from scope, single device-id (now per-user), HKDF pepper
      model, no SAS verification path.
- [ ] 9.8 New `docs/api-reference.md`: every tool, params, return
      shape, example.
- [ ] 9.9 New `CHANGELOG.md`: v0.0.1 → current.
- [ ] 9.10 Update `clusters/gruyere/apps/matrix-mcp-www/RUNBOOK.md`
       to reflect the current state (post deploy, not pre).

## Phase 10 — battle-proofing

- [ ] 10.1 Integration tests with testcontainers: spin up Synapse +
       MAS + Postgres in containers. Run the full claude.ai-shaped
       flow (DCR, authorize, token, introspect, mcp/init,
       tools/call) end-to-end. Behind `--features=integration`.
- [ ] 10.2 Load test: 100 tool calls/min sustained for 10 min,
       record p50/p95/p99, observed memory + CPU footprint.
- [ ] 10.3 Disaster recovery dry-run: rotate pepper (destructive
       for users; document procedure), rotate
       `MAS_MATRIX_MCP_CLIENT_SECRET`, simulate PVC loss.
- [ ] 10.4 Performance baseline doc in `docs/operations.md`:
       memory-per-active-user, sync rate, key-download time.
- [ ] 10.5 Chaos test: pod kill mid-request, MAS down for 30s,
       Synapse 500s for 30s. Verify graceful degradation, no
       corrupted state.
