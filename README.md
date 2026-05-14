# matrix-mcp

A remote [MCP](https://modelcontextprotocol.io) server that exposes a
[Matrix](https://matrix.org) homeserver to [claude.ai](https://claude.ai)
as a custom connector.

**Status:** Phase 0 — repo skeleton. Not deployed. Not functional yet.
See [`docs/plan.md`](docs/plan.md) for the roadmap.

## What this is

Claude.ai supports custom MCP connectors over OAuth. This server is the
bridge between Claude and a self-hosted Matrix homeserver: Claude
authenticates via the homeserver's [OIDC issuer](https://matrix-org.github.io/matrix-authentication-service/),
the server holds a per-user Matrix client (with E2EE), and exposes a small
set of tools (`list_rooms`, `read_room`, `send_message`, …) that let an
LLM-driven workflow read and write chat on your behalf.

Designed for one homeserver at a time — initially `example.com`.

## Design choices

- **Language:** Rust
- **Matrix SDK:** [`matrix-rust-sdk`](https://github.com/matrix-org/matrix-rust-sdk)
  for native MSC4186 sliding sync, OAuth/MSC3861 client, and vodozemac
  crypto
- **MCP transport:** Streamable HTTP (`/mcp` endpoint)
- **Auth:** Bearer tokens issued by the homeserver's MAS, validated via
  introspection
- **Storage:** SQLite per user, encrypted at rest via `matrix-sdk`'s
  `StoreCipher`
- **Deployment target:** Kubernetes (Gruyere cluster), distroless
  container, PSS-restricted namespace

See [`docs/architecture.md`](docs/architecture.md) and
[`docs/security.md`](docs/security.md) for the full design.

## Local development

Requires Rust 1.85+ (`edition = "2024"`).

```sh
cargo run
```

Server boots on `http://0.0.0.0:3000`. Phase 0 only exposes `/healthz`.

```sh
curl http://127.0.0.1:3000/healthz
# ok
```

### Testing

```sh
cargo test
cargo clippy --all-targets --all-features -- -D warnings
cargo fmt --check
```

CI runs on every PR: `fmt`, `clippy`, `test`, `cargo audit` (CVE check),
`cargo deny` (license + advisory + ban check), and a `docker build`
dry-run.

### Container

```sh
docker build -t matrix-mcp:dev .
docker run --rm -p 3000:3000 matrix-mcp:dev
```

The image is multi-stage: Rust 1.85 builder → distroless `cc-debian12:nonroot`
runtime. Final size ≈ 25–35 MiB.

## License

[AGPL-3.0-or-later](LICENSE).

Matches Matrix ecosystem convention; ensures forks stay open.

## Not for general use yet

This is early-stage code. There is no public deployment. The repo is
private until the security posture has been reviewed and the threat
model is documented. See [`docs/security.md`](docs/security.md) for
what the threat model will say.
