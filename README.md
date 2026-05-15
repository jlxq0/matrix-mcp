# matrix-mcp

A remote [MCP](https://modelcontextprotocol.io) server that gives
[claude.ai](https://claude.ai) read/write access to a self-hosted
[Matrix](https://matrix.org) homeserver – including E2EE rooms.

**Status:** v0.1.0, deployed at `matrix-mcp.example.com` for `example.com` users.

## What it does

Claude authenticates via the homeserver's OIDC issuer
([MAS](https://matrix-org.github.io/matrix-authentication-service/)).
The server holds a per-user Matrix client (with full E2EE via
`matrix-rust-sdk`) and exposes 17 tools: list rooms, read messages,
send messages, search history, manage membership, download attachments,
and more.

Designed for a single homeserver at a time. Currently hardwired to
`example.com`.

## As a user

Visit `https://matrix-mcp.example.com/setup` once to unlock E2EE,
then add `https://matrix-mcp.example.com/mcp` as a custom connector
in claude.ai. See [docs/onboarding.md](docs/onboarding.md).

## As an operator

See [docs/installation.md](docs/installation.md) to deploy against your
own MAS + Synapse. Environment variables are in [docs/operations.md](docs/operations.md).

## Development

Requires Rust 1.85+ (`edition = "2024"`).

```sh
# start the server (all env vars optional in dev)
cargo run

# health check
curl http://127.0.0.1:3000/health
```

Minimum env for a real local run against a test MAS:

```sh
export MATRIX_MCP_RESOURCE_URL=http://localhost:3000
export MATRIX_MCP_AUTHORIZATION_SERVER=http://localhost:8080
export MATRIX_MCP_HOMESERVER_URL=http://localhost:8008
export MATRIX_MCP_SERVER_NAME=localhost
export MATRIX_MCP_INTROSPECTION_CLIENT_ID=matrix-mcp
export MATRIX_MCP_INTROSPECTION_CLIENT_SECRET=dev-secret
export MATRIX_MCP_STORE_DIR=/tmp/matrix-mcp-dev
export MATRIX_MCP_STORE_PEPPER=$(openssl rand -hex 32)
cargo run
```

### CI checks

```sh
cargo fmt --check
cargo clippy --all-targets --all-features -- -D warnings
cargo test
cargo audit
```

CI runs all of the above plus a `docker build` dry-run on every PR.

### Container

```sh
docker build -t matrix-mcp:dev .
docker run --rm -p 3000:3000 -e MATRIX_MCP_RESOURCE_URL=... matrix-mcp:dev
```

Multi-stage build: Rust builder → distroless `cc-debian12:nonroot`. Final image ~25–35 MiB.

## Docs

| File | Contents |
|---|---|
| [docs/architecture.md](docs/architecture.md) | Component diagrams, OAuth dance, sync loop, storage layout |
| [docs/security.md](docs/security.md) | Threat model, mitigations, residual risk |
| [docs/onboarding.md](docs/onboarding.md) | User setup walkthrough |
| [docs/installation.md](docs/installation.md) | Operator deployment guide (k8s, docker-compose) |
| [docs/operations.md](docs/operations.md) | Debug recipes, pepper rotation, secret rotation |
| [docs/api-reference.md](docs/api-reference.md) | All 17 MCP tools, params, return shapes |
| [docs/decisions.md](docs/decisions.md) | Architecture decision records |
| [CHANGELOG.md](CHANGELOG.md) | Version history |

## License

[AGPL-3.0-or-later](LICENSE). Matches Matrix ecosystem convention.
