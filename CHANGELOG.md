# Changelog

All notable changes to matrix-mcp. Format: [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

---

## [Unreleased]

### Added
- `send_voice_message` MCP tool: posts `m.audio` with the MSC3245
  voice flag + MSC1767 audio block (duration + waveform) so Element
  renders the event as a voice-memo bubble instead of a generic audio
  attachment. Accepts an optional caller-supplied waveform (0..=1024
  samples, cap 200 entries); without one, clients still treat the
  event as a voice message but show a flat bar. Audio is not decoded
  server-side. Enables `ruma`'s `unstable-msc3245-v1-compat` feature.
- `send_tts_voice_message` MCP tool: POSTs caller text to a
  configured OpenAI-compatible TTS endpoint
  (`{base}/audio/speech`, e.g. Chatterbox), parses the returned
  WAV for duration, uploads to the homeserver media repo, and
  sends the result as a voice message (same MSC3245 + MSC1767
  envelope as `send_voice_message`). New env vars
  `MATRIX_MCP_TTS_BASE_URL` and `MATRIX_MCP_TTS_BEARER_TOKEN` —
  both must be set together, or both unset (the tool then
  returns `invalid_params`). Input capped at 4096 chars; response
  capped at the existing `MATRIX_MCP_UPLOAD_MAX_BYTES`. Token
  is never logged.

### Security (secscan Group D: rescan follow-ups)
- `CappedSessionManager::create_session` now takes a `tokio::sync::Mutex`
  gate before reading the session count and inserting. Previously the
  check + insert could race under concurrent initialize load and
  overshoot `MAX_SESSIONS`. Closes secscan #c3579fdc.
- `react_to_auth_expiry` only fires on `internal_error` (JSON-RPC
  -32603); previously any error containing `M_UNKNOWN_TOKEN` or
  `Token is not active` (including `invalid_params` errors formatted
  with caller-controlled fields) triggered cache eviction, a
  trivially authenticated cache-thrash DoS. Closes secscan #795787a2.
- `room_kick`/`room_ban`/`room_unban` reasons now share the 64 KiB
  cap Group A added on `redact_message.reason`. Closes secscan
  #7d95f605.
- `invites_accept` requires `RoomState::Invited`. Previously a
  generic join (any room id). Same shape as Group A's `invites_reject`
  fix. Closes secscan #3596b649.
- `audit::tool_call` sanitises `room_id` before emitting to the
  structured Loki audit stream — replaces anything that isn't a
  syntactically valid Matrix `RoomId` with `<invalid>`. Group A
  fixed the user-visible audit-room equivalent; this is the
  operational-audit twin. Closes secscan #01174866.
- `KeyBackupGate` cooldown caller-id is now consistent across paths:
  `/setup/recover` switched from `mxid` to `mas_subject` to match
  the MCP `request_room_keys` / auto-pull paths. Mixing the two
  identifiers used to let the same user bypass cooldown by hopping
  between setup and MCP. Closes secscan #96461937.
- `content_sandbox::escape_injection_markers` escapes the `</matrix:message`
  opening prefix (without trailing `>`) in addition to the canonical
  full close tag, so whitespace / self-close / tab variants of the
  end-tag (`</matrix:message >`, `</matrix:message/>`) can no longer
  bypass the wrap. The `is_suspicious` heuristic was broadened the
  same way. Closes secscan #305700b8.
- `bearer_auth` skips the `last_used.record(...)` call when the
  request path is `/token/introspect`. Previously the act of calling
  the audit endpoint overwrote the record it returned, hiding any
  prior (potentially attacker-driven) use the owner was trying to
  detect. The endpoint now returns `last_used: null` when no other
  real use has been recorded. Closes secscan #845de87c.

### Changed
- `docs/multi-user.md` rewritten to accurately describe the
  MXID-keyed cache + store + passphrase derivation as a single-MAS
  deployment tradeoff. Adds an explicit "MXID collision risk"
  section spelling out what happens under localpart-reassignment
  scenarios, and what would need to change in `for_user` /
  `build_cached` for true multi-tenant safety. No code change.
  Closes secscan #eafe9ef7.

- Relicensed from AGPL-3.0-or-later to **MIT**. matrix-mcp was a
  single-author personal project from the start; MIT matches the
  "here's the source, do what you want with it" posture more
  honestly than the network-copyleft AGPL. `deny.toml` updated to
  drop AGPL from the allow-list (the strong-copyleft viral effect
  was the whole reason it was there).
- README rewritten to be generic — tool list updated from "19 tools"
  (accurate around v0.1.x) to the current ~58, with a forward-facing
  pointer to the canonical Forgejo repo and the GitHub push-mirror.
- `docs/api-reference.md` header honest about coverage: it documents
  a subset; `tools/list` against the running server is the source of
  truth for the complete current set.
- `docs/installation.md` and `docs/decisions.md` generalized — the
  reference Kubernetes deployment is described in platform-agnostic
  terms; the operator's specific choices (ExternalSecrets +
  1Password Connect + Traefik Gateway API + Longhorn) are mentioned
  as one working example rather than the prescription.

### Security (secscan Group C: rescan follow-ups)
- `set_account_data` rejects reserved global account-data event types
  (`m.audit_room`, `m.ignored_user_list`, `m.push_rules`, `m.direct`,
  `m.secret_storage.default_key`, `m.secret_storage.key.*`,
  `m.cross_signing.{master,self_signing,user_signing}`,
  `m.megolm_backup.v1`). The generic writer previously let a caller
  overwrite `m.audit_room` with malformed content to silently disable
  audit notices, or corrupt Matrix-managed E2EE recovery state.
  Custom `org.<...>` namespaces remain writable. Closes #8c54c9f0.
- `set_account_data` also caps serialized content at 32 KiB
  (`MAX_ACCOUNT_DATA_CONTENT_BYTES`).
- `get_room_state` caps returned events at `MAX_STATE_EVENTS = 500`
  with a new `truncated: bool` field, and refuses
  `event_type=m.room.member` when `state_key` is omitted (public
  rooms can have tens of thousands of member events; use
  `room_members` for bounded listing or pass a concrete MXID as
  `state_key`). Closes #ea339918.
- `KeyBackupGate` cooldown is now keyed by `(caller, room_id)` rather
  than `room_id` alone. The previous process-global key meant one
  user's pull for a shared encrypted room blocked another user's
  recovery for the same room for 5 minutes — a cross-user E2EE
  availability issue introduced by Group B's gate. The global
  semaphore (resource cap) remains process-wide on purpose.
  Closes #baa1ab07.
- `MatrixClientCache::for_user` checks the cached client's
  `sync_task.is_finished()` and evicts + rebuilds when the background
  sync watchdog has exited (which the Group B watchdog fix introduced
  for permanent auth failures). Without this, room/state freshness
  silently degraded after token revocation. Closes #cef36421.

### Security (secscan Group B: rate-limit / SSRF / availability)
- Per-identity initialize rate-limit: a new middleware on `/mcp` charges
  one bucket-token per fresh-session POST keyed by bearer-hash AND MAS
  subject. Refill period matches `session::SESSION_KEEP_ALIVE` (30 min)
  so an attacker who has filled their slots can only open new ones at
  the rate their existing ones idle out. Burst = 8 covers legitimate
  Claude reconnect bursts. Closes secscan #83350ed0.
- `send_bulk` + `send_broadcast` charge the write rate-limit per actual
  room send (not once per call). Burst-rate is now identical to N
  discrete `send_text_message` calls. Mid-loop denials appear as
  per-room `rate_limited` outcomes. Closes secscan #885d2ecc.
- SSRF defence (`src/url_safety.rs`): every URL-fetch tool
  (`send_image_from_url`, `send_file`/`_audio`/`_video`, `me_set_avatar`,
  `upload_media_from_url`) now resolves the host and refuses if any
  resolved IP is non-publicly-routable (RFC1918, loopback, link-local
  incl. 169.254.169.254, ULA, CGNAT, multicast, unspecified, IPv4-mapped
  IPv6 of the above). reqwest's auto-redirect handling is disabled and
  each `Location` is re-validated against the same denylist before
  follow. Closes secscan #38b3701b, #bc9b30b0, #9ed16733.
- `download_attachment` wraps the SDK `get_media_content` call in a
  60-second timeout to bound the OOM blast-radius when event-supplied
  `info.size` is missing or under-reports. The proper fix requires
  upstream streaming media-download in matrix-sdk; this is the best
  mitigation without forking the SDK. Closes secscan #6244d14c.
- Room-key backup pulls go through a shared `KeyBackupGate`
  (`src/key_backup_gate.rs`): per-room cooldown (5 min), global
  concurrency cap (4), per-pull timeout (30 s). Applies to the
  `request_room_keys` tool, the auto-pull helper, and the
  `/setup/recover` loop. The explicit tool surfaces cooldown +
  gate-busy as user-visible errors; the auto-pull helper silent-skips.
  Closes secscan #de85922e, #e4797214.
- `sync_watchdog` exits cleanly when matrix-sdk's background sync
  reports `M_UNKNOWN_TOKEN` or `Token is not active` — no more
  indefinite retry of permanent auth failures hammering Synapse.
  Closes secscan #8141aba3.
- `search_messages` pushes the result limit upstream via
  `Criteria.filter.limit` so Synapse paginates at the cap instead of
  paginating at its default and letting us truncate locally.
  Closes secscan #8741a8de.
- `/token/introspect` last_used.ip reads the trusted XFF position
  instead of the spoofable leftmost. New env
  `MATRIX_MCP_TRUSTED_PROXY_HOPS` (default 1, matches Traefik in front
  in production). Closes secscan #37478d02.
- `react_to_auth_expiry` tags rewritten errors with a stable
  `AUTH_EXPIRED_CODE = -32028`; `emit_write_notice` now skips the
  `for_user` round-trip for that code so a write-tool path can't
  re-cache the just-evicted client with the same (still-expired)
  bearer. Closes secscan #353a2b4e.
- `MatrixClientCache` switches to per-MXID `tokio::sync::OnceCell`:
  the global `RwLock` is held only for the `HashMap` lookup, the SDK
  build runs **off-lock** inside each cell. A first build for MXID A
  no longer blocks unrelated calls for MXID B. Closes secscan #65c9b8f0.

### Changed
- New env `MATRIX_MCP_TRUSTED_PROXY_HOPS` (default `1`): number of
  trusted proxies in front of matrix-mcp. Used to pick the real client
  IP out of `X-Forwarded-For`. Set to `0` in dev / direct-hosted
  setups; raise to `2`+ behind multiple trusted hops.

### Security (secscan Group A: validation/clamp fixes)
- `audit_room::emit_notice` drops the `target_room` field from the
  user-visible audit-room notice body when the raw `room_id` string
  fails Matrix-id validation (whitespace/control-char free + Ruma
  `RoomId::parse`). Previously a crafted `room_id` containing newlines
  and a forged `outcome=ok` fragment could poison the audit trail.
  Closes secscan #071b456a.
- `invites_reject` requires `RoomState::Invited`. Previously
  `room.leave()` was called unconditionally, so the tool — advertised
  as non-destructive — could silently leave a Joined room. Returns
  `invalid_params` with a pointer to `leave_room` otherwise.
  Closes secscan #8aac2b50.
- `read_thread` requires `RoomState::Joined` (matching `room_info`).
  Previously any room in the SDK cache (invited/left/knocked/banned)
  would yield thread replies. Closes secscan #f43552ff.
- `send_reaction` rejects keys longer than 1 KiB; `redact_message`
  rejects reasons longer than 64 KiB. Brings these write tools in
  line with the existing `send_text_message` body cap.
  Closes secscan #162d4cf5.
- `get_user_receipts` caps `user_ids` at 100 entries; `get_event_receipts`
  truncates the returned readers list at 1000 and surfaces a
  `truncated: bool` field. Closes secscan #603a9b23.
- `message_edit` refuses to send an `m.replace` whose target was
  authored by a different user. Spec-compliant clients ignore forged
  edits, but buggy clients / bridges / downstream consumers may not.
  Closes secscan #d412f0c4.

### Changed
- Install snippets (README + examples/docker-compose.yml) pin the
  image tag to `v0.3.14` rather than the mutable `:latest`. The
  Kubernetes guide in `docs/installation.md` was already pinned.
  Closes secscan #dca0974a.

### Fixed
- `set_account_data` no longer rejects content from MCP clients that
  JSON-encode the `content` argument as a string. claude.ai sends
  e.g. `"{\"version\":\"v0.3.13\"}"` rather than the structured
  object, which would reach Synapse as a JSON string literal and
  trip `M_BAD_JSON: Content must be a JSON object`. The handler now
  detects `Value::String`, parses it as JSON, and uses the result;
  falls back to the literal string only if parsing fails. Non-object
  content now returns a clear early-rejection error rather than
  letting Synapse respond with the less-informative `M_BAD_JSON`.
  Found during v0.3.13 smoke test on 2026-05-19.

### Added (PR-D: account data + presence + media + spaces)
- `get_account_data(event_type)` / `set_account_data(event_type, content)`
  tools. Generic read/write for arbitrary global account-data event
  types. Prefer dedicated tools (`set_audit_room`, `ignore_user`)
  where they exist; use these for custom or non-standard types.
  Tool count 52 → 54.
- `upload_media_from_url(url)` tool. Fetches HTTPS media, uploads to
  the homeserver media repo, returns the `mxc://` URI **without
  sending to a room**. Stages media for downstream consumers
  (avatars, custom payloads). Same fetch policy as
  `send_image_from_url`. Tool count 54 → 55.
- `get_presence(user_id?)` / `set_presence(presence, status_msg?)`
  tools. Wraps the spec's `/presence/{userId}/status` endpoints.
  Synapse often disables presence reporting — expect `offline`
  from federated users. Tool count 55 → 57.
- `get_space_hierarchy(room_id, limit?, max_depth?, suggested_only?)`
  tool. MSC1772-aware `/hierarchy` wrapper: lists rooms inside a
  Matrix space. Returns one paginated page; `next_batch_token`
  is surfaced but pagination input isn't exposed yet. Tool count
  57 → 58.

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
