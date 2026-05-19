# Changelog

All notable changes to matrix-mcp. Format: [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

---

## [Unreleased]

### Added (PR-C: state events + ignored users)
- `get_room_state(room_id, event_type, state_key?)` tool. Fetch
  state events of a given type (`m.room.name`, `m.room.topic`,
  `m.room.member`, `m.room.power_levels`, `m.room.pinned_events`,
  etc.). Optional `state_key` narrows to one event. Returns raw
  state-event JSON for type-flexibility. Tool count 46 → 47.
- `set_room_name(room_id, value)` tool. Sets the `m.room.name`
  state event. Requires power to send that state event (default 50).
  Tool count 47 → 48.
- `set_room_topic(room_id, value)` tool. Same pattern for
  `m.room.topic`. Tool count 48 → 49.
- `ignore_user(user_id)` tool. Adds a user to the caller's
  `m.ignored_user_list`. Tool count 49 → 50.
- `unignore_user(user_id)` tool. Inverse. Tool count 50 → 51.
- `list_ignored_users()` tool. Returns the caller's current
  ignore-list MXIDs. Tool count 51 → 52.

### Added (latest-event differentiation)
- `latest_event_type` field on `RecentActivityRoom` (`list_recent_activity`)
  and `UnreadRoomSummary` (`get_unread_summary`). The Matrix event type
  of the room's "latest interesting" event, e.g. `m.room.message`,
  `m.sticker`, `m.room.encrypted`, `m.poll.start`, `m.call.invite`.
  Lets the caller tell real chat apart from poll/call/encrypted-unknown
  noise without an extra read.
- `message_events_only: bool` parameter on both tools (default `false`
  for back-compat). When `true`, rooms whose latest event is not in
  `{m.room.message, m.sticker, m.room.encrypted}` are dropped from
  the response. Filters out call invites and poll lifecycle, the
  most common non-chat-but-still-"latest" events. Encrypted events
  are preserved because we can't tell their decrypted type without
  decrypting — being permissive is safer than hiding rooms where the
  caller might have a real message they can't see.

### Added (PR-B: receipts + threads)
- `get_user_receipts(room_id, user_ids?)` tool. Returns each named
  user's most recent public read receipt in a room (default:
  caller). The "ball in my court" primitive: combine the room's
  `latest_event_id` from `list_recent_activity` with the caller's
  own receipt to detect "I read this but never replied". Tool
  count 43 → 44.
- `get_event_receipts(room_id, event_id)` tool. Inverse of the
  above: returns every public read receipt pointing at a specific
  event. Use to confirm whether a specific recipient has read a
  specific message. Tool count 44 → 45.
- `list_threads_in_room(room_id, limit?, only_participated?)`
  tool. Wraps the MSC3856 `/threads` endpoint and returns thread
  roots newest-first, with the same envelope-only metadata and
  `untrusted_body` sandbox wrap as `read_recent_messages`. Each
  entry's `root_event_id` feeds straight into `read_thread` to
  fetch the actual reply chain. Tool count 45 → 46.

### Added
- `list_recent_activity` tool. Returns every joined room sorted by
  `latest_origin_server_ts` descending, with optional `since_unix_ms`
  filter and `encrypted_only` flag. Companion to `get_unread_summary`
  (which only returns the unread slice) — solves the "find rooms
  where I read the message and forgot to reply" use case without
  walking every joined room one at a time. Tool count 41 → 42.
- `request_room_keys` tool. Asks the homeserver's encrypted key
  backup for missing megolm session keys for a specific room. Used
  on demand when a read tool returns `unable_to_decrypt` events.
  Tool count 42 → 43.
- Read tools (`read_recent_messages`, `read_thread`) now
  automatically fire a background `download_room_keys_for_room` for
  any room that returned at least one `unable_to_decrypt` event.
  Best-effort: sessions in backup self-heal on the next read;
  sessions never backed up stay opaque.

### Fixed
- `/setup/recover` no longer panics the pod when claude.ai's connector
  has already built the matrix-sdk client for the user (which the
  `/setup` precondition demands). Previously, recover went through
  `MatrixClientCache::for_user` with `/setup`'s own unbound OAuth
  access token; the fast path then called `restore_session` to swap
  that token onto the already-initialised cached client, which
  matrix-sdk 0.17 rejects with `AlreadyInitializedError`, taking the
  pod down. Setup now uses a new `get_if_cached(&mxid)` accessor that
  returns the cached client untouched. The recovery operation runs
  against Synapse using claude.ai's already-installed device-bound
  bearer, which is what we want (the unbound `/setup` token has no
  device scope). Verified 2026-05-18 during device-binding recovery
  on v0.3.3.

### Added
- `GET /token/introspect` endpoint. Bearer-authenticated; returns
  `{mxid, device_id, scope, exp, token_hash, last_used:{at_unix, ip}}`
  for the calling bearer. `last_used` is recorded by the auth
  middleware on every successful introspect, keyed on the bearer's
  short SHA-256 (same identifier as the operator audit log). `ip`
  comes from `X-Forwarded-For` (leftmost). Bounded in-memory cache
  (1024 distinct bearers, evict-oldest on overflow) — survives only
  pod-lifetime, intentional. See `src/last_used.rs` and
  `src/token_introspect.rs`.
- Read-path content sandboxing. `read_recent_messages`, `read_thread`,
  and `search_messages` now return two additional fields per event:
  `untrusted_body` (the body wrapped in a
  `<matrix:message trust="external">…</matrix:message>` delimiter with
  common prompt-injection tokens — `<system>`, `[INST]`, `<|im_start|>`,
  etc. — escaped to entity references) and `suspicious` (a heuristic
  flag for instruction-override phrasing and role-control markers).
  The existing `event` / `body` fields are unchanged. Tool descriptions
  document the new contract. See `src/content_sandbox.rs`.
- `SECURITY.md`, `THREAT_MODEL.md` and a tightened `README.md` for the
  public release.
- `docs/multi-user.md` documenting the per-mxid isolation guarantees.
- `send_text_message` gained an optional `reply_to_event_id` so the
  caller can reply or continue a thread; the reply is auto-promoted
  into the original event's thread when the target is threaded.
- `message_edit` tool – replace a previously-sent message via
  `m.replace`. Matrix enforces sender ownership.
- `message_forward` tool – forward the text body of a message into
  another room. Text only; media is not re-uploaded.
- `me_set_displayname` tool – set or clear this user's display name.
- `me_set_avatar` tool – set or clear this user's avatar from an
  HTTPS URL (re-uploaded to the homeserver media repo).
- `users_get_profile` tool – fetch another user's public display
  name + avatar.
- `send_file`, `send_video`, `send_audio` tools – mirror
  `send_image_from_url` for the other media `MessageType`s. The
  underlying upload pipeline (HTTPS-only, redirect-limited, timeouted,
  size-capped) is now shared via `MatrixMcpService::upload_from_url`.
- `send_voice_note` deliberately omitted: it would require the
  `unstable-msc3245-v1-compat` feature on `matrix-sdk` + `ruma`, and
  without that marker it'd be an exact duplicate of `send_audio`.
- `room_create` tool – create a new Matrix room. Defaults to private
  + encrypted. Accepts name, topic, invite list, public/private,
  is_direct, alias.
- `room_create_dm` tool – convenience wrapper for 1:1 encrypted DMs.
- `invites_list` tool – return pending invites.
- `invites_accept` / `invites_reject` tools.
- `room_kick` / `room_ban` / `room_unban` – membership-state changes
  on a single user with an optional reason.
- `admin_get_power_levels` / `admin_set_power_level` – inspect and
  edit power-level assignments. The set tool flips one user's
  level at a time; pass the default (`0`) to remove the explicit
  entry.
- `room_pin_message` / `room_unpin_message` – append to / remove
  from `m.room.pinned_events`.
- `send_bulk` tool – send the same body to up to 20 rooms in one
  call. Per-room outcomes returned individually.
- `send_broadcast` tool – send to every joined room. Refuses
  without `confirm: true`, refuses if joined > 50 rooms, skips
  rooms above `max_room_members` (default 10) so the blast radius
  stays DM / small-group shaped.
- `send_at` deliberately omitted: a durable scheduled-send needs a
  persistent queue (survive pod restarts, replay on cold start),
  which is more storage-layer work than belongs in this PR. An
  in-memory `tokio::time::sleep + spawn` would silently drop sends
  on the next pod rotation – worse than not shipping at all.
- `examples/docker-compose.yml` + `examples/Caddyfile` – a
  single-host setup with Let's Encrypt for users who don't want to
  set up Talos and ArgoCD.
- CI badge on the README.
- `Plan.md` and `docs/plan.md` are now gitignored (internal notes,
  not part of the public docs surface).

### Fixed
- In-place token refresh on the cached matrix-sdk client. When
  claude.ai presents a fresh OAuth bearer (typically every ~hour),
  matrix-mcp now swaps it into the cached session via
  `restore_session` instead of using the stale token until Synapse
  returns `M_UNKNOWN_TOKEN`. Eliminates the "session expired
  mid-call → retry succeeds" UX for cron-style usage.
- `get_unread_summary` now returns populated `latest_event_id`,
  `latest_sender`, and `latest_origin_server_ts` for E2EE rooms.
  matrix-sdk's `/sync` handler only feeds the LatestEvents subsystem
  when `Client::event_cache().subscribe()` has been called. Without
  that call `Room::latest_event()` returned `LatestEventValue::None`
  for every encrypted room. Same subscription Element X's
  `RoomListService` performs at startup.

---

## [v0.2.2.1] – 2026-05-16

### Fixed
- CI `cargo audit` job grants itself `checks: write` so tag pushes
  stop emailing "build failed".

---

## [v0.2.2] – 2026-05-16

### Fixed
- `get_unread_summary` now uses `Room::unread_notification_counts()`
  (server-side, from `/sync`) instead of `Room::num_unread_*` (which
  are receipt-based and always 0 for a headless server). Matches the
  Element badge.

---

## [v0.2.1] – 2026-05-16

### Fixed
- Cache eviction on Synapse `M_UNKNOWN_TOKEN`: when a tool call hits
  an expired token, the per-mxid matrix-sdk client and MAS
  introspection entry are dropped so the next reconnect rebuilds
  cleanly. No more pod restarts on token rotation.
- `get_unread_summary` first attempt at a wider filter (superseded by
  v0.2.2, which fixed the real bug – wrong method entirely).

---

## [v0.2.0] – 2026-05-15

### Added
- Auto-rotating per-PVC device id. `<store_root>/.device-id` is
  written on first start (random) or seeded from
  `MATRIX_MCP_DEVICE_ID_BOOTSTRAP`. PVC wipes self-heal: a fresh id
  is generated and the next `/setup` cross-signs it. Sidesteps
  Synapse's `SigningKeyChanged` permanently-rejected device state.
- `/setup` precondition (HTTP 428) refuses if the matrix-sdk cache
  is cold for the calling mxid – forces the user through the proper
  order (connect MCP first, then recovery key).
- MCP tool annotations on all 19 tools: `title`, `read_only_hint`,
  and (where applicable) `destructive_hint`, `idempotent_hint`. Per
  the MCP spec, `destructive_hint` and `idempotent_hint` are only
  meaningful when `read_only_hint = false`.
- `docs/cross-signing-recover-flow.md` and
  `scripts/verify-device-signature.py` for end-to-end verification
  of the cross-signing chain without trusting matrix-rust-sdk's own
  opinion.

---

## [v0.1.0] – 2026-05-15

### Added
- `send_reaction(room_id, event_id, key)` – add an emoji reaction to an event.
- `redact_message(room_id, event_id, reason?)` – delete an event.
- `room_info(room_id)` – name, topic, encryption, member counts, power level.
- `room_members(room_id, limit?)` – list joined members with display names and avatars.
- `get_unread_summary()` – rooms with unread messages sorted by latest activity.
- `mark_read(room_id, event_id?)` – send an unthreaded read receipt.
- `download_attachment(room_id, event_id)` – return file as base64 + content-type. Size-capped.
- `send_image_from_url(room_id, image_url, caption?)` – fetch URL, upload to media repo, send m.image.
- `search_messages(query, room_id?)` – wrap `/_matrix/client/v3/search`. Body null for E2EE rooms.
- `join_room(room_id_or_alias)`, `leave_room(room_id)`, `invite_user(room_id, mxid)`.
- `read_recent_messages`: per-event `in_reply_to`, `is_thread_root`, `thread_event_count` fields.
- `read_thread(room_id, root_event_id, limit?)` – fetch a thread by its root event id.
- Per-identity token-bucket rate limiting. Defaults: 60 reads/min, 30 writes/min.
- CSRF token on `POST /setup/recover`; session cookie path tightened to `/setup`.
- Sync watchdog: exponential backoff on homeserver errors in the background sync loop.
- Prometheus `/metrics` on pod IP:9090. Counters and histograms per tool.
- Tool-call audit log (envelope only, no message bodies) to stdout JSON.

### Fixed
- Key Matrix clients by stable MAS `sub` (ULID) instead of mutable MXID (audit #1).
- Enforce Matrix C-S API scope on every active token (audit #2, #7).
- CI GHCR write permission scoped to tag-only pushes (audit #3).
- PKCE and session maps are now bounded (256 and 64 entries) with TTL pruning (audit #4, #12).
- Cap tool inputs: message limit, body size, member list size, search result count (audit #5, #6, #14).
- Serialize first-use `MatrixClientCache` construction; abort sync task on drop (audit #9).
- Drop broken rate-limit janitor that reset exhausted quotas (audit #10).
- Bind metrics listener to pod IP, not `0.0.0.0` (audit #11).
- Tighter MCP session TTL and global session cap (audit #13).
- `room_info` now only returns data for joined rooms (not invited/left/banned).
- CI actions and Docker images pinned to digest SHAs (audit #8).
- Metrics listener defaults to `127.0.0.1:9090` in dev, `{POD_IP}:9090` in k8s.

### Removed
- `recover_with_key` MCP tool (key now flows via browser `/setup` only).

---

## [v0.0.15] – 2026-05-15

### Added
- Prometheus `/metrics` endpoint on a separate cluster-internal port (9090).
  ServiceMonitor manifest in argocd.

---

## [v0.0.14] – 2026-05-15

### Added
- Structured audit log for every tool call (stdout JSON, shipped to Loki via Alloy).
- `Plan.md` roadmap document.

---

## [v0.0.13] – 2026-05-14

### Added
- Pull megolm key backup after `recovery().recover()` so E2EE history decrypts.
  Background task: up to 200 rooms, 15 s timeout per room.

---

## [v0.0.12] – 2026-05-14

### Fixed
- Use `/authorize` (not `/oauth2/authorize`) for the setup PKCE flow –
  MAS endpoint quirk discovered on live deployment.

---

## [v0.0.11] – 2026-05-14

### Changed
- `recover_with_key` MCP tool replaced with browser-based `/setup` flow.
  Recovery key now taken via HTTPS form, never stored, never in chat history.

---

## [v0.0.10] – 2026-05-13

### Added
- `recover_with_key` MCP tool for cross-signing via secret storage.
  *(Removed in v0.1.0 – key flowed through chat history.)*

---

## [v0.0.9] – 2026-05-13

### Fixed
- Force `/keys/query` before reading user identity in `verify_status`
  so OAuth-restored sessions see up-to-date cross-signing state.

---

## [v0.0.8] – 2026-05-13

### Fixed
- Parse `device_id` from the `scope` string when MAS omits the
  `device_id` field even with `X-MAS-Supports-Device-Id: 1`.

---

## [v0.0.7] – 2026-05-13

### Fixed
- Send `X-MAS-Supports-Device-Id: 1` on introspect requests to opt into
  MAS's dedicated `device_id` field.

---

## [v0.0.6] – 2026-05-13

### Fixed
- Advertise the device-binding scope in the protected-resource metadata
  so claude.ai requests it and MAS binds the token to the matrix-mcp device.

---

## [v0.0.5] – 2026-05-12

### Fixed
- Build MXID from MAS `username` field + configured `server_name`, not
  from `sub` (which is an opaque MAS ULID, not a Matrix localpart).

---

## [v0.0.4] – 2026-05-12

### Fixed
- Accept introspection tokens without an `aud` claim (claude.ai omits
  `resource=` in token requests; MAS therefore omits `aud`).

---

## [v0.0.3] – 2026-05-12

### Changed
- Rename `/healthz` → `/health` to match cluster convention.

---

## [v0.0.2] – 2026-05-12

### Fixed
- Bundle SQLite statically into the binary via `rusqlite`'s `bundled`
  feature so the distroless container doesn't need `libsqlite3.so`.

---

## [v0.0.1] – 2026-05-10

### Added
- Axum HTTP server on `:3000`.
- MAS introspection client with 60 s token cache.
- Streamable HTTP MCP transport (`/mcp` endpoint) via `rmcp`.
- OAuth 2.1 resource server: `/.well-known/oauth-protected-resource`,
  `WWW-Authenticate` on 401.
- `whoami` tool – first E2EE-aware tool.
- `list_joined_rooms`, `read_recent_messages`, `send_text_message` tools
  backed by `matrix-rust-sdk` (phase 2 + 3).
- `verify_status` tool for checking cross-signing state.
- `/setup` browser flow for recovery-key import.
- Per-user encrypted SQLite stores (phase 3 E2EE).
- `GET /health` endpoint.
- Multi-stage Dockerfile: Rust builder → distroless `cc-debian12:nonroot`.
- CI: fmt, clippy, test, cargo audit, cargo deny, docker build.
- AGPL-3.0-or-later license.
- Production deploy on Gruyere (`matrix-mcp.example.com`).

[Unreleased]: https://github.com/jlxq0/matrix-mcp/compare/v0.2.2.1...HEAD
[v0.2.2.1]: https://github.com/jlxq0/matrix-mcp/compare/v0.2.2...v0.2.2.1
[v0.2.2]: https://github.com/jlxq0/matrix-mcp/compare/v0.2.1...v0.2.2
[v0.2.1]: https://github.com/jlxq0/matrix-mcp/compare/v0.2.0...v0.2.1
[v0.2.0]: https://github.com/jlxq0/matrix-mcp/compare/v0.1.0...v0.2.0
[v0.1.0]: https://github.com/jlxq0/matrix-mcp/compare/v0.0.15...v0.1.0
[v0.0.15]: https://github.com/jlxq0/matrix-mcp/compare/v0.0.14...v0.0.15
[v0.0.14]: https://github.com/jlxq0/matrix-mcp/compare/v0.0.13...v0.0.14
[v0.0.13]: https://github.com/jlxq0/matrix-mcp/compare/v0.0.12...v0.0.13
[v0.0.12]: https://github.com/jlxq0/matrix-mcp/compare/v0.0.11...v0.0.12
[v0.0.11]: https://github.com/jlxq0/matrix-mcp/compare/v0.0.10...v0.0.11
[v0.0.10]: https://github.com/jlxq0/matrix-mcp/compare/v0.0.9...v0.0.10
[v0.0.9]: https://github.com/jlxq0/matrix-mcp/compare/v0.0.8...v0.0.9
[v0.0.8]: https://github.com/jlxq0/matrix-mcp/compare/v0.0.7...v0.0.8
[v0.0.7]: https://github.com/jlxq0/matrix-mcp/compare/v0.0.6...v0.0.7
[v0.0.6]: https://github.com/jlxq0/matrix-mcp/compare/v0.0.5...v0.0.6
[v0.0.5]: https://github.com/jlxq0/matrix-mcp/compare/v0.0.4...v0.0.5
[v0.0.4]: https://github.com/jlxq0/matrix-mcp/compare/v0.0.3...v0.0.4
[v0.0.3]: https://github.com/jlxq0/matrix-mcp/compare/v0.0.2...v0.0.3
[v0.0.2]: https://github.com/jlxq0/matrix-mcp/compare/v0.0.1...v0.0.2
[v0.0.1]: https://github.com/jlxq0/matrix-mcp/releases/tag/v0.0.1
