# matrix-mcp

A remote MCP server that lets [claude.ai](https://claude.ai) (or any other
MCP client) read, search, and write in your [Matrix](https://matrix.org)
account – including in **end-to-end-encrypted rooms** – using your existing
cross-signing identity and Secret Storage recovery key.

It speaks [OAuth 2.1 / MCP / RFC 9728](https://modelcontextprotocol.io) on
one side and the Matrix Client-Server API on the other.
[matrix-rust-sdk](https://github.com/matrix-org/matrix-rust-sdk) handles
olm/megolm/cross-signing – encrypted history decrypts normally as long as
the device is cross-signed, which `/setup` arranges with your recovery key.

## What you get

Two mounts, sharing one deployment's auth, clients and encrypted stores:

| Mount | For | Shape |
|---|---|---|
| `/mcp` | claude.ai, Claude Code, any MCP client | ~61 tools. You ask, it answers |
| `/channel` | agents that must react while nobody is watching | Pushes inbound Matrix messages into a running [Claude Code](https://code.claude.com) session, plus a scoped seven-tool subset |

See [Push Matrix into a running agent](#push-matrix-into-a-running-agent) for
the second one.

Two surfaces, and ~61 tools carrying MCP annotations (`read_only_hint`,
`destructive_hint`, `idempotent_hint`) so client UIs can auto-approve reads
and warn before writes.

- **Reads**: `read_recent_messages`, `read_thread`, `search_messages`,
  `get_unread_summary`, `list_joined_rooms`, `list_recent_activity`,
  `room_info`, `room_members`, `list_threads_in_room`,
  `download_attachment`, `verify_status`, `whoami`, `users_get_profile`,
  `get_room_state`, `get_space_hierarchy`, `get_account_data`,
  `get_user_receipts`, `get_event_receipts`, `get_presence`,
  `list_ignored_users`, `invites_list`
- **Writes**: `send_text_message`, `send_image_from_url`, `send_file`,
  `send_audio`, `send_voice_message`, `send_tts_voice_message`,
  `send_video`, `send_reaction`, `send_bulk`,
  `send_broadcast`, `mark_read`, `message_edit`, `message_forward`,
  `redact_message`, `upload_media_from_url`, `set_account_data`,
  `set_presence`, `set_room_name`, `set_room_topic`,
  `me_set_displayname`, `me_set_avatar`, `ignore_user`, `unignore_user`,
  `request_room_keys`
- **Room management**: `room_create`, `room_create_dm`, `join_room`,
  `leave_room`, `invite_user`, `invites_accept`, `invites_reject`,
  `room_pin_message`, `room_unpin_message`
- **Moderation / admin**: `room_kick`, `room_ban`, `room_unban`,
  `admin_get_power_levels`, `admin_set_power_level` (constrained by
  the user's Matrix power level on the room)
- **Self-audit**: `set_audit_room` – designate a Matrix room where
  matrix-mcp posts an `m.notice` for every write it makes on your behalf

See [`docs/api-reference.md`](docs/api-reference.md) for arguments and
return shapes.

## Push Matrix into a running agent

A [Claude Code channel](https://code.claude.com/docs/en/channels) is an MCP
server that pushes events into a session that is already open, so the agent
reacts to things happening while you are away from the terminal. `/channel`
implements it for Matrix: message the account from your phone and it lands in
the session's context; the agent answers in the room.

Point a session at it — the token is any Matrix access token for the account,
so a bot registered however you like works:

```json
{ "mcpServers": { "matrix": {
    "type": "http",
    "url": "https://matrix-mcp.your-domain.example/channel",
    "headers": { "Authorization": "Bearer ${MATRIX_TOKEN}" } } } }
```

```sh
export MATRIX_TOKEN=...            # from your secret manager, not a file
claude --dangerously-load-development-channels server:matrix
```

The flag is not a testing step. During the channels research preview
`--channels` accepts only plugins on an Anthropic-maintained allowlist, and a
private marketplace does not qualify, so any self-hosted channel uses the
development flag permanently. It shows a full-screen confirmation at startup.
Channels also need Anthropic authentication (claude.ai or a Console key) and
are unavailable on Bedrock, Vertex and Foundry.

**Nothing is pushed until you say who may push.** The sender allowlist lives in
the account's own Matrix account data, so each account configures itself:

```jsonc
// event type: app.matrix_mcp.channel
{ "allowed_senders": ["@you:your-domain.example"] }
```

Absent or empty means nothing is delivered. An ungated channel is a
prompt-injection vector: message bodies reach a model holding live credentials
with no human turn in front of them. Gating is on the **sender**, never the
room, because those differ in a group. Bodies are wrapped and escaped by the
same content sandbox the read tools use, and anything tripping the injection
heuristic is tagged `suspicious="true"`.

Messages that arrive while no session is listening are replayed when one
attaches, watermarked by the account's own read receipt. The server never
writes that receipt itself — it cannot observe delivery — so the agent
acknowledges with `mark_read` and delivery is at-least-once.

### Accounts with no human

A bot cannot run the browser `/setup` flow, so `bootstrap_cross_signing`
creates its cross-signing identity directly and writes it to Secret Storage
under a passphrase derived from your pepper. Recovery therefore survives losing
the volume, with nothing to configure. It refuses to run where an identity
already exists, so it can never reset one.

**One matrix-sdk client per access token.** Two clients on one device id both
generate identity keys, only one set is advertised, and the loser decrypts
nothing while looking perfectly healthy. Reissuing the token does not fix it.
Give every consumer its own account.

## Prerequisites

- A Synapse homeserver (≥ 1.130) with
  [Matrix Authentication Service](https://github.com/element-hq/matrix-authentication-service)
  / MSC3861. Legacy password-only homeservers won't work.
- A Matrix account on that homeserver with cross-signing already set up
  (the standard Element "Set up secure backup" flow). You'll need the
  recovery key that flow produced.
- An MCP client that speaks the streamable-HTTP transport (claude.ai
  Custom Connectors, etc.).

## Quick start

```bash
docker run --rm -p 3000:3000 \
  -v matrix-mcp-store:/var/lib/matrix-mcp \
  -e MATRIX_MCP_RESOURCE_URL=https://matrix-mcp.your-domain.example \
  -e MATRIX_MCP_AUTHORIZATION_SERVER=https://your-mas.example \
  -e MATRIX_MCP_HOMESERVER_URL=https://matrix.your-domain.example \
  -e MATRIX_MCP_SERVER_NAME=your-domain.example \
  -e MATRIX_MCP_INTROSPECTION_CLIENT_ID=... \
  -e MATRIX_MCP_INTROSPECTION_CLIENT_SECRET=... \
  -e MATRIX_MCP_STORE_DIR=/var/lib/matrix-mcp \
  -e MATRIX_MCP_STORE_PEPPER="$(openssl rand -hex 32)" \
  forge.oddie.app/jlxq0/matrix-mcp:v0.9.0
```

The image is public — no registry account needed. Then point a public
hostname at it over HTTPS (claude.ai requires `https://`) and follow [`docs/onboarding.md`](docs/onboarding.md) to
connect. For a Kubernetes deployment with cert-manager, External
Secrets, and Traefik Gateway API, see
[`docs/installation.md`](docs/installation.md). For a single-host
homelab setup with Caddy or Traefik, see
[`examples/docker-compose.yml`](examples/docker-compose.yml).

## Multi-user

Every authenticated user gets their own encrypted SQLite store, their
own matrix-sdk client, their own audit room (held in their Matrix
`account_data`), and their own rate-limit bucket. Two users share zero
state. The MAS introspection middleware accepts any active token, so
by default every user on your homeserver can connect – same surface
as Element. Restrict with an upstream allowlist if you want fewer.

[`docs/multi-user.md`](docs/multi-user.md) walks through the isolation
guarantees.

## Security

matrix-mcp gives claude.ai access to your **decrypted** Matrix content
– that's the entire point. So:

1. You extend trust to claude.ai (and Anthropic). If that's not OK,
   don't connect.
2. You extend trust to whoever runs the matrix-mcp instance. Run your
   own.

[`SECURITY.md`](SECURITY.md) covers reporting; [`THREAT_MODEL.md`](THREAT_MODEL.md)
covers what's in and out of scope.

## Development

Rust 1.93+ with `edition = "2024"`.

```sh
cargo run                                           # build + run
curl http://127.0.0.1:3000/health                   # health check
cargo fmt --check
cargo clippy --all-targets --all-features -- -D warnings
cargo test --all-features --locked
```

PRs welcome. Run the three checks above before pushing; CI will reject
otherwise. Conventional Commits for messages.

## Documentation

| File | Contents |
|---|---|
| [`docs/onboarding.md`](docs/onboarding.md) | Connecting from claude.ai end-to-end |
| [`docs/installation.md`](docs/installation.md) | Deploy on a VPS or Kubernetes |
| [`docs/architecture.md`](docs/architecture.md) | Component diagrams, OAuth dance, sync loop, storage layout |
| [`docs/api-reference.md`](docs/api-reference.md) | Arguments + return shapes for the most-used tools (full set returned by `tools/list`) |
| [`docs/operations.md`](docs/operations.md) | Running in production, debug recipes, pepper rotation, recovery for accounts with no human |
| [`docs/security.md`](docs/security.md) | Implementation-level security notes |
| [`docs/multi-user.md`](docs/multi-user.md) | Multi-user isolation guarantees |
| [`docs/cross-signing-recover-flow.md`](docs/cross-signing-recover-flow.md) | E2EE bootstrap, recovery, auto-rotating device id |
| [`docs/decisions.md`](docs/decisions.md) | Architecture decision records |
| [`SECURITY.md`](SECURITY.md) | Reporting vulnerabilities |
| [`THREAT_MODEL.md`](THREAT_MODEL.md) | What this defends against |
| [`CHANGELOG.md`](CHANGELOG.md) | Version history |

## Licence

[MIT](LICENSE).

## Where this code lives

The canonical source repository is on Forgejo.
[`github.com/jlxq0/matrix-mcp`](https://github.com/jlxq0/matrix-mcp) is
a public push-mirror so the code is discoverable and forkable from
GitHub. PRs opened on either side are fine; merges happen on the
primary Forgejo remote and are mirrored.

