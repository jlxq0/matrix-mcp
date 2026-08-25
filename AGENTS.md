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
