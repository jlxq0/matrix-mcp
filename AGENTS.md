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
- **A field that only means something under a relation must be read only when
  that relation is present**, or a sender can attach it as a decoy. Reading
  `m.new_content` on any event carrying the key let an `m.location` — which
  the channel does not carry — be classified from an `m.text` decoy and
  delivered with the outer body. Replay only, because the live path reads a
  typed `Relation` and has no such key, so it was also the two paths
  disagreeing about one event: the #107 shape, for the third time in this
  file. When adding a field to one path, ask what the other path reads instead
  of it.
- **A quotation is untrusted content arriving by a second route, so it must be
  escaped by the same functions as the body it quotes**, not by an escaper
  written beside it. `quote_excerpt` calls `escape_injection_markers` and
  `is_suspicious` rather than reimplementing them, and the test compares its
  output against what `content_sandbox::evaluate` produces for the same input,
  so the two cannot drift. A hand-written expected string would agree with
  whichever implementation it was copied from.
- **A lookup keyed on something the sender controls needs a collision policy,
  and "the map keeps one" is not one.** Two events claiming one event id made
  a `HashMap` answer for the wrong one, so a reply could quote one message's
  words under another's name. Neither is quotable now. The same reasoning
  covers a response fetched *by* id: compare what came back against what was
  asked for, because keeping the requested id as the label while taking the
  sender and the body from the response attributes words to a message that
  never contained them.
- **Trust does not follow the content, it follows the route it came in by.**
  The sender allowlist gates who may push into a session; a reply quoting
  somebody else carries their words in regardless, since the batch a quotation
  is drawn from is fetched before any allowlist filter. Refusing to quote
  would make replies to our own messages unresolvable, which is the case the
  feature exists for, so the excerpt travels and says who wrote it:
  `in_reply_to_untrusted_sender`. Any new inbound surface has this question
  and it does not answer itself.
- **A guard can be load-bearing and pinned by nothing, and the way you find
  out is that deleting it leaves the suite green.** `reactions_from_chunk`
  refuses anything whose `rel_type` is not `m.annotation`; deleting that check
  broke no test, because every fixture in the control set was *also* refused
  by the missing `key` field. `m.relates_to` is sender-controlled and accepts
  arbitrary fields, so a thread relation carrying a `key` is one message to
  write and would have been read as a reaction — an approval, once an emoji
  means one. The fixture that pins a guard is the one that satisfies every
  *other* check and fails only this one; a control set where each entry fails
  for its own reason measures whichever check happens to run first.
- **A per-entry decoding failure that drops the entry turns "cannot tell"
  into "none".** `read_reactions` documented that an empty list means no
  reactions and a failure is an error, and then dropped undecryptable and
  malformed entries silently, so a chunk holding only an entry we could not
  read returned `reactions: []`. A caller polling for an authorisation reads
  that as "nobody has reacted" and either waits forever or concludes from it.
  Count what was declined and return the count: `unreadable > 0` beside an
  empty list is a third answer, and the request-level error is only the
  first two.
- **A single page is not the answer to "is it there".** `/relations` returns
  newest first, so a reaction older than one page is invisible to a single
  request and stays invisible however often a caller polls, since every poll
  starts at the same newest page. Follow the pagination token, cap the total,
  and **report having hit the cap** — otherwise a capped page is
  indistinguishable from the end of the list, which is the same absence fault
  one layer up.
- **A second route to the same content needs the first route's judgement, not
  just its escaping.** Reply quotations were escaped like a body and selected
  like nothing: `quotable_from` took `raw_body` off any event with an id and a
  sender, so an allowlisted person replying to a permission verdict, or to an
  event type the channel does not carry, pulled that body into the session by
  a route the delivery path refuses. `quotable_body` now applies
  `is_replayed_verdict` and `carried_of` exactly as delivery does, and quotes
  a caption rather than a filename for the same reason `replay_body` does.
  Third instance of two paths disagreeing about one event in this file, and it
  was introduced while the rule was in a doc comment on the function above.
- **A mutation that leaves the suite green on a path needing a live `Room` is
  telling you the judgement is in the wrong place, not that it is safe.**
  `resolve_reply`'s fetch fallback was unreachable, so making it quote
  `raw_body` changed nothing anybody could see. It is `reply_ref_from` now, a
  free function over a decoded event, which also pinned the requested-id check
  and the undecryptable check that had no tests either. Same move as
  `replay_deliverable` out of `replay_room` and `live_delivery` out of
  `push_message`; when a mutation stays green, ask what the function needs in
  order to run before assuming the test was weak.
- **Two correct features compose into a wrong one when they disagree about
  which field *is* the message.** `carried_of` classifies a replacement by
  `m.new_content`; `quotable_body` took `content.body`. Each was right on its
  own and together they quoted the `* `-prefixed fallback instead of the
  correction, measured the injection heuristic on the fallback so a hostile
  correction was quoted unflagged, and withheld an ordinary correction whose
  fallback happened to match the verdict pattern. Pick the body once, through
  `replay_body_source`, and run every later check against that. Neither
  feature's own tests could see this; it took a review scoped to the commit
  that introduced the second one.
- **Assembling a push's attributes inside a function that needs a live `Room`
  means no test sees what the push actually carries.** A mutation deleting the
  reaction attributes from the replay push left the suite green, because the
  test asserted the helper that produces them rather than the assembly that
  uses it. `replay_meta` and `live_reaction_meta` are free functions for that
  reason, and the test that matters compares the two paths' spelling of the
  same attribute rather than either one alone. Three separate faults in this
  file have been two paths disagreeing about one event.
- **A cap on the body is not a cap on the attributes.** `MAX_PUSH_BYTES` and
  `cap_wrapped` bound what a channel event says; they do not touch the meta,
  and `build_params` escapes meta values without bounding them. A reaction key
  is an arbitrary string the sender chooses, so a sixty-kilobyte key reached a
  model's context in full on both paths, past a cap that only ever looked at a
  body which is empty for a reaction. Anything sender-controlled that lands in
  attribute position needs its own limit, applied in one place so the paths
  cannot cap differently.
- **A new push path must apply every gate the existing one applies, in the
  same order, and the omission is invisible.** `push_reaction` shipped without
  the `RoomState::Joined` check and without the self-sender suppression that
  `push_message` has, so a reaction in a room this identity had left would
  have been delivered and an agent could have read its own emoji back as
  inbound context. Nothing about a missing guard shows up in a diff of the new
  function; read the old one beside it.
- **`main` is protected and requires `CI / cargo*`, deliberately not
  `CI / docker`.** The glob covers both event suffixes, since a branch push
  posts `CI / cargo (push)` and a pull-request head posts
  `CI / cargo (pull_request)`.

  `docker` is excluded because a skipped job still posts a status, and in this
  repository it posts **two different wrong answers** depending on why it
  skipped. Measured here, not inferred:

      c17aa805   cargo failed, docker skipped by `needs:`   docker status = pending
      a0a389d3   cargo failed, docker skipped by `needs:`   docker status = success
      3409c72    docker skipped by `if: != pull_request`    docker status = success

  So requiring it builds a gate that is **satisfied by a commit whose `cargo`
  failed and where nothing was built**, and that on other commits never
  resolves at all. `cargo` is the job that does the work on a pull request;
  `docker` cannot even run on one (`.forgejo/workflows/ci.yml`, `if:
  github.event_name != 'pull_request'`), so its green there is always a skip.

  **Do not add `CI / docker` to the required contexts.** The rule shows what is
  required and nothing in it says why this is absent, which is how it comes
  back.
- **`mergeable: true` from the pull-request API does not account for the status
  gate.** PR #94 read `mergeable=true` with `CI / cargo (pull_request)=failure`
  on its head at the moment `main` was armed. Read the head commit's statuses
  rather than the PR's own field before concluding that a change is ready, and
  before concluding that arming a rule stranded nothing.
- **`DEFAULT_TRUSTED_PROXY_HOPS` is 2, and it is a claim about the topology
  that nothing in this process can check.** The measured chain is
  `client -> Caddy edge -> Cilium gateway (Envoy appends) -> pod`, so two
  entries arrive and `parse_client_ip` counts in from the right. At 1 it
  selected the edge and recorded that as the caller's address on every
  authenticated request.

  **The number is correct only while the Caddy edge replaces the header rather
  than appending.** `oddie-apps/edge-config#40` at `880ea46` asserts that with
  93 tests; the two values have to be re-derived together and nothing outside
  these comments says so. **Too high does not fail safe**: behind a single
  *appending* proxy a caller's own header makes the chain two long, the
  `len < hops` guard never fires, and 2 returns whatever the caller typed.

  `observe_ingress_chain` logs `xff_entries` beside `trusted_proxy_hops`, on
  change rather than per request, which is what makes the claim falsifiable
  from outside. **The count, never the entries**: those are addresses and one
  of them is a caller's.
- **A test that passes a constant's value in as an argument is green at any
  value of that constant.** Every `parse_client_ip` test supplied its own hop
  count, so reverting the default broke nothing, in this repository and in
  three siblings. Construct through `Config::new` and assert the
  **consequence** — which address comes back — rather than the number, since
  `assert_eq!(hops, 2)` restates the constant and cannot fail for a reason
  worth knowing. Mutate in both directions: 1 and 3 must each go red, and here
  they redden two tests and one respectively.
- **A counter that reports on a parser must split its input the same way, or
  it agrees with the configuration exactly when the parser has gone wrong.**
  `observe_ingress_chain` filtered empty `X-Forwarded-For` entries and
  `parse_client_ip` did not, so a trailing comma made the log line say
  `xff_entries=2 trusted_proxy_hops=2` while the parser counted three and
  recorded the edge as the caller. One `xff_entries` helper now serves both.
  Found by cross-engine review; the suite was green.
- **A function whose only observable is a log line cannot be tested, so the
  judgement inside it has to come out.** A mutation making the counter split
  differently left the suite green until `ingress_chain_len` had a name a test
  could call. Fourth instance in this repository of a mutation surviving
  because the thing it broke was unreachable rather than because the code was
  right.
- **Backtick every CamelCase name from another system in a doc comment.**
  `clippy::doc_markdown` rejects bare `MetalLB`, `HTTPRoute`, `BGPAdvertisement`
  and the like with "item in documentation is missing backticks", and a
  comments-only change is exactly where those names appear, so run the full
  gate on a docs-only diff rather than only the suite.
- **The `platform` manifest is not a third source for what digest is running,
  for any `forge.oddie.app` image.** The fleet rule says pod `imageID`, the
  registry, and the manifest are three independent answers, and where a
  manifest reads `tag@sha256:...` that holds. Ours reads a bare tag:
  `platform`'s Renovate config turns `pinDigests` off for
  `/^forge\.oddie\.app\//` because a pin PR races the next CI push and turns
  an app deploy into a merge conflict. **So it corroborates the version and
  never the digest, and a tag can move.** Verifying a release here is two
  sources agreeing, the pod's `imageID` against what the tag build pushed, and
  saying it is two rather than counting the manifest as a third.
- **Nothing in a mount's name says which server it is.** Six sessions hold live
  mounts to this service and not one is called `matrix-mcp`: they are
  `channel`, `matrix-julian`, `matrix-penny`, `matrix-vryan`, all resolving to
  `https://matrix-mcp.kampong.social` at `/channel` and `/mcp`. A sweep for
  this repository's own name finds nothing, so **"nobody is connected" read off
  a name search is a statement about the search.** Read the URL, not the key.
