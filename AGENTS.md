## Known Pitfalls

- Do not enforce remote fetch size caps with `response.bytes().await` followed
  by a length check. That buffers the full attacker-controlled body first.
  Stream response chunks and reject before appending beyond the configured cap.
- Do not let authenticated outbound requests follow redirects automatically
  when a bearer token is attached. Disable redirects or validate every hop
  before sending credentials to the next URL.
- Do not iterate UTF-8 text by raw bytes when mutating user-visible strings.
  Use `chars()` or another Unicode-aware path so non-ASCII input is preserved.
- `room_members` cannot rely on truncating after `members_no_sync`; the SDK has
  already loaded the full cached member list. Check the cheap member count
  before enumeration.
- The RFC 9728 `resource` we publish and the audience we accept in a token are
  the same identifier. Changing one without the other silently breaks every
  spec-conformant client (they send `resource=<published value>`, the AS mints
  that `aud`, and introspection rejects it). Keep them derived from one place.
- OAuth issuer identifiers are compared byte-for-byte (RFC 8414 §3.3). Do not
  normalise `MATRIX_MCP_AUTHORIZATION_SERVER` — a stripped trailing slash makes
  strict clients refuse the AS metadata. Trim only when concatenating an
  endpoint path.
- A 401/429/404 on the MCP transport is not a transport detail: it lands on the
  user's first tool call. Rate limits guarding the handshake need refill
  periods measured against how often clients legitimately reconnect, not
  against the session TTL.
- Matrix SDK store keying is intentionally MXID-based for device-key
  continuity. Re-keying by MAS subject/device id must account for Synapse
  device-key continuity or it can regenerate keys for the same device id.
- `download_attachment` returns plaintext for an E2EE event only because the
  `e2e-encryption` feature is on. `matrix_sdk::Media::get_media_content`
  decrypts a `MediaSource::Encrypted` inside `#[cfg(feature =
  "e2e-encryption")]`; with the feature off that block compiles out and the
  same call returns the ciphertext, which the tool then base64-encodes and
  reports as the file. Nothing errors, and a test that only asserts a
  non-empty body passes. Verified against matrix-sdk 0.17 `src/media.rs:450`
  on 2026-08-25. Do not trim that feature to slim the image.
- **The tree builds on rustc 1.93 and lints only on clippy 1.98, and those are
  two different floors.** `Cargo.toml`'s `rust-version = "1.93"` and the
  digest-pinned `rust:1.93-bookworm` builder are correct, and the builder makes
  that a gate rather than a comment: `cargo check --all-features --locked`
  passes on 1.93.0, and anything needing past 1.93 fails the release build.
  `cargo clippy -D warnings` is the other floor, and the reason is not the
  code. `#[allow]` attributes across `src/` name lints that did not exist yet,
  and an `#[allow]` naming a lint the running clippy does not have is itself an
  error under `-D warnings`.

  Counted by clippy rather than by grep, because
  `#[allow(clippy::unwrap_used, clippy::duration_suboptimal_units)]` in
  `rate_limit.rs` is one line and two suppressions. Measured 2026-08-25 on
  `cargo clippy --all-targets --all-features --locked -- -D warnings`:

  | clippy | before this change | after |
  |---|---|---|
  | 1.93.0 | 13 `unknown lint` | 12 |
  | 1.96.0 | 2 | 1 |
  | 1.97.1 | — | 1 |
  | 1.98.0 | 0 | 0 |

  The 12 remaining are 11 `duration_suboptimal_units` and one
  `unused_async_trait_impl`. 1.98.0 is the *first* clean toolchain, not a
  promise that later ones stay clean — a clippy release adds lints, and each
  one fires on code nobody touched. That is why `ci.yml` names `1.98.0` rather
  than `stable` or a range. Classify a red clippy with `cargo clippy --version`
  before reading the diff.
- **Do not delete a `duration_suboptimal_units` or `unused_async_trait_impl`
  allow to lower that floor.** All eleven of the first suppress a suggestion to
  use `Duration::from_mins`/`from_days`, which are still unstable on 1.98
  (`E0658: duration_constructors`) — taking clippy's advice does not compile.
  The second fires on code `#[tool_handler]` generates, so there is nothing to
  rewrite. A thirteenth attribute, `chunks_exact_to_as_chunks`, *was* removable
  and was removed: its comment claimed `as_chunks::<2>()` postdated the MSRV,
  and it compiles on 1.93.0. Check that claim before trusting the next one.
- **This crate needs two different base64 alphabets and the wrong one fails
  silently on half its inputs.** PKCE in `setup.rs` requires `URL_SAFE_NO_PAD`
  — RFC 7636 specifies unpadded — while `download_attachment`'s `body_base64`
  requires padded `STANDARD`, because Python's `b64decode`, Rust's `STANDARD`
  and Go's `StdEncoding` all reject unpadded input while Node's `Buffer.from`
  and `atob` accept it. It shipped as `STANDARD_NO_PAD` and reached production
  in `v0.10.3`; the other fields came back correct, so the first caller to hit
  it read a decoder error as a corrupt or still-encrypted file. Encoding is
  `encode_attachment`, in one place, with the reason on it.

  A payload whose length is a multiple of three encodes identically with and
  without padding, so any fixture of that length is blind to this. Test 3n+1
  and 3n+2 and decode strictly.
- A byte-slicing cap is not proven safe by a fixture built from one repeated
  multi-byte character. `"ü".repeat(n)` puts a character boundary at every even
  offset and `"→".repeat(n)` at every multiple of three, so if the cap is such
  an offset — and `PROMPT_DESCRIPTION_MAX`, `PROMPT_PREVIEW_MAX` and
  `MAX_PUSH_BYTES` all are — a `clip` that never walks to a boundary passes the
  test and panics in production. Offset the fixture by one ASCII byte.
- Permission relay hands a tool approval to whoever can reply through the
  channel. Two orderings carry that: the allowlist gate runs before the verdict
  branch, and the fallback prompt room is recorded only after that same gate.
  Recording the room first lets a stranger who DMs the bot redirect every later
  approval prompt into a room he controls. Neither ordering is visible in a
  diff, so both live in named functions (`classify_inbound`, `remember_room`)
  with the gate as an argument rather than as preceding statements.
- **When a bug report's acceptance criterion is a count this server already
  logs, read the log before writing the fix.** Every channel push logs `live`
  and `written`:

      kubectl logs -n matrix-mcp <pod> | grep '"channel: pushed"'

  so "is `notify` fanning out to stale peers?" is answerable in one command.
  #120 reported one event delivered three times and named peer accumulation as
  the cause, reasoning correctly about code that really does write once per live
  peer. Every push in the pod's life read `live=1 written=1`, the event appeared
  once, and there had never been a second peer — the duplication was in the
  client's transcript, byte-identical copies of the original tag with no server
  write behind two of the three.

  The cost of skipping the check was not the wasted work. The recommended fix,
  de-duplicating on event id per mxid at the send, would have broken two
  sessions authenticated as one identity — a supported shape — while suppressing
  nothing, because there was no second call to suppress. A cause that explains
  the symptom and fits the code is still a hypothesis.
- **`git tag -a` silently eats any line of the annotation that begins with
  `#`, and an annotation is exactly where issue numbers belong.** The default
  is `--cleanup=strip`, which removes commentary lines, so whether a reference
  survives depends on where the paragraph happened to wrap. `v0.10.5` shipped
  without `#113 trap. And the live_peers(mxid) == 0 early return dropped
  verdicts for`: the release note breaks mid-clause and two of the four fixes
  it describes are unnamed in it. `#107` survived in the same annotation only
  because it sits mid-line. Nothing in git's output says a line was dropped,
  and the tag was on the remote before anyone read it back.

  Measured with a control on a throwaway tag at the same sha, since the flag
  is the whole difference: identical message, line kept under
  `--cleanup=verbatim`, gone under the default. Reflow so no line starts with
  `#` — that survives the next person writing the tag command without the
  flag, which is the failure that will actually happen. Read the annotation
  back out of the tag object before pushing it.
- The rule that anyone who can reply through the channel can approve tool use
  extends to any new inbound surface, and a reaction is one: an `m.reaction`
  from anyone in the room reaches `/relations`, so once an emoji means
  "approve this tool call", approval is available to whoever is standing in
  the room. The allowlist gate belongs in the read path and in the push, not
  in the consumer, or the next consumer omits it. See #124.
- A relation-carrying event delivered by its **fallback body** reads as
  ordinary input, because the fallback is designed to be indistinguishable
  from one. An `m.replace` is an `m.room.message` whose `content.body` is
  `* <the correction>`, so before #125 a corrected message reached a session
  as a second, near-identical instruction: nothing absent, nothing malformed,
  no error anywhere, and a reader that acts twice on something its sender sent
  once. The `* ` fallback exists for clients that cannot render an edit and a
  session is not one. Deliver `m.new_content` and mark the event with the id
  it replaces, on both the live and the replay path, and have replay send only
  the newest version — the mark is what lets a session that already acted on
  the original say which of its instructions was withdrawn.

  The same shape is waiting in every other relation: whatever the channel
  drops is invisible rather than degraded, so nothing looks wrong. #124.
- **A shape check that guesses what a parser will accept turns deliverable
  input into dropped input.** `carried_of` picked `m.new_content` over the
  outer content whenever both `msgtype` and `body` were *present*, which
  `{"msgtype": 7}` satisfies — and then the classifier rejected it and the
  whole event was dropped, where the old code had delivered the outer content.
  Ask the parser instead: `get(..).and_then(classify).or_else(|| classify(outer))`
  cannot disagree with the classifier because it is the classifier. Found by
  cross-engine review, not by the suite, and the suite stayed green through it.
- **When two membership checks can both match one event, their order decides
  whether it vanishes.** In the edit supersession pass a self-replacing event,
  or two events replacing each other, is in the winner set *and* the
  superseded set. Asking "superseded?" first drops every one of them and the
  correction disappears; asking "is it the newest edit?" first keeps exactly
  one version. Malformed relations are the normal case for this, so decide the
  order deliberately and test the cycle.
