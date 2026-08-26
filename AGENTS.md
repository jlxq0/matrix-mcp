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
- **Most of the eleven `duration_suboptimal_units` allows are removable, and
  this file said the opposite until 2026-08-26.** The claim was that they all
  suppress a suggestion to use `Duration::from_mins`/`from_days`, "which are
  still unstable on 1.98". Probed one constructor per file, in const context:

    | | 1.93.0 | 1.98.0 |
    |---|---|---|
    | `from_mins` | const-stable | const-stable |
    | `from_hours` | const-stable | const-stable |
    | `from_days` | `E0658` | `E0658` |

  Only `from_days` is unstable, and pinning forward does not retire it. The
  original probe put both constructors in one file, got one `E0658`, and
  attributed it to both — an error message read as being about more than it was
  about. Caught by the `hevy-mcp` lead, which found the same false sentence in
  its own tree and deleted both of its allows after compiling the replacement on
  1.93.0.

  So: `session_store.rs`'s `from_secs(7 * 24 * 60 * 60)` genuinely needs its
  allow, because `from_days(7)` does not compile. The ones over `from_secs(60)`,
  `from_secs(5 * 60)`, `from_secs(15 * 60)`, `from_secs(30 * 60)`,
  `from_secs(300)`, `from_secs(1800)` and `from_secs(120)` are suppressing
  advice that compiles on the MSRV. Each one removed is one less thing this file
  has to promise. Verify by compiling, not by reading this bullet.

- **`unused_async_trait_impl` does need its allow.** It fires on code
  `#[tool_handler]` generates, so there is nothing to rewrite, and it is what
  puts the lint floor at 1.98.

  A thirteenth attribute, `chunks_exact_to_as_chunks`, was removable and was
  removed: its comment claimed `as_chunks::<2>()` postdated the MSRV, and it
  compiles on 1.93.0. That is now twice in one file that a suppression carried a
  false reason for existing, both found by compiling the thing the comment said
  would not compile. **Check the claim before trusting the next one** — and this
  bullet has itself been wrong once, which is the point.
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
