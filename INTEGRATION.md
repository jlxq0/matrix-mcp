# Integration test bring-up

Manual procedure for running the full Phase 10.1 integration test stack
locally. This covers the same scenario as the `#[ignore]` tests in
`tests/integration.rs` and is the reference for anyone completing the
testcontainers wiring.

---

## Prerequisites

- Docker Desktop running (or Docker Engine on Linux).
- `cargo` 1.93 or newer.
- `curl` and `jq` for manual verification steps.
- Ports 5432 (Postgres), 8080 (MAS), 8008 (Synapse), and 3000 (matrix-mcp)
  available on localhost.

---

## Architecture

```
localhost:5432  ← Postgres (Docker)
   │
   ├── localhost:8080  ← MAS (Docker, MSC3861 auth)
   │        │
   └── localhost:8008  ← Synapse (Docker, delegates auth to MAS)
                │
            localhost:3000  ← matrix-mcp (cargo run, local build)
```

---

## Step 1 — Start Postgres

```bash
docker run --rm -d \
  --name matrix-mcp-pg \
  -e POSTGRES_DB=matrix_mcp_test \
  -e POSTGRES_USER=matrix_mcp_test \
  -e POSTGRES_PASSWORD=testpassword \
  -p 5432:5432 \
  postgres:16-alpine
```

Verify:
```bash
docker exec matrix-mcp-pg pg_isready -U matrix_mcp_test
```

---

## Step 2 — Start MAS

MAS requires a config file. Create a minimal `mas-config.yaml`:

```yaml
# Minimal MAS config for local integration testing.
# NOT for production use.

http:
  listeners:
    - name: web
      resources:
        - name: discovery
        - name: human
        - name: oauth
        - name: graphql
          playground: true
        - name: assets
        - name: compat
      binds:
        - address: "0.0.0.0:8080"

database:
  uri: postgres://matrix_mcp_test:testpassword@host.docker.internal:5432/matrix_mcp_test

matrix:
  homeserver: localhost
  secret: "local-test-secret-do-not-use-in-production"
  endpoint: http://host.docker.internal:8008

clients:
  - client_id: matrix-mcp-test
    client_auth_method: client_secret_basic
    client_secret: test-introspection-secret

secrets:
  encryption: "11111111111111111111111111111111"
  keys:
    - kid: "local"
      key: |
        -----BEGIN RSA PRIVATE KEY-----
        # TODO: generate a test RSA key with: openssl genrsa 2048
        -----END RSA PRIVATE KEY-----
```

```bash
docker run --rm -d \
  --name matrix-mcp-mas \
  -v "$(pwd)/mas-config.yaml:/config.yaml:ro" \
  -p 8080:8080 \
  ghcr.io/element-hq/matrix-authentication-service:v0.13.0 \
  server --config /config.yaml
```

Wait for MAS:
```bash
until curl -sf http://localhost:8080/health; do sleep 1; done
echo "MAS ready"
```

---

## Step 3 — Start Synapse

Create `synapse-homeserver.yaml`:

```yaml
server_name: "localhost"
public_baseurl: "http://localhost:8008/"
listeners:
  - port: 8008
    tls: false
    type: http
    x_forwarded: true
    resources:
      - names: [client, federation]

database:
  name: psycopg2
  args:
    user: matrix_mcp_test
    password: testpassword
    database: matrix_mcp_test
    host: host.docker.internal
    cp_min: 5
    cp_max: 10

log_config: /dev/null
media_store_path: /tmp/synapse-media
registration_shared_secret: "local-test-secret"

experimental_features:
  msc3861:
    enabled: true
    issuer: http://host.docker.internal:8080/
    client_id: synapse-mas-client
    client_secret: synapse-mas-secret
    admin_token: synapse-admin-token
    account_management_url: "http://localhost:8080/account"
```

```bash
docker run --rm -d \
  --name matrix-mcp-synapse \
  -v "$(pwd)/synapse-homeserver.yaml:/data/homeserver.yaml:ro" \
  -p 8008:8008 \
  docker.io/matrixdotorg/synapse:v1.129.0 \
  run --config-path /data/homeserver.yaml
```

Wait for Synapse:
```bash
until curl -sf http://localhost:8008/_matrix/client/versions; do sleep 2; done
echo "Synapse ready"
```

---

## Step 4 — Register a test user in MAS

MAS has an admin API. Register a user for the integration test:

```bash
# TODO: MAS v0.13 admin API path — check the MAS docs for the correct endpoint.
# Reference: https://element-hq.github.io/matrix-authentication-service/
curl -sf -X POST http://localhost:8080/api/admin/v1/users \
  -H 'Content-Type: application/json' \
  -d '{"username": "testuser", "skip_welcome_email": true}'
```

---

## Step 5 — Issue a bearer token for the test user

```bash
# Device Authorization Grant or Password Grant (depends on MAS config).
# Reference: https://element-hq.github.io/matrix-authentication-service/
TOKEN=$(curl -sf -X POST http://localhost:8080/oauth2/token \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  -u 'matrix-mcp-test:test-introspection-secret' \
  -d 'grant_type=password&username=testuser&password=testpass&scope=openid+urn:matrix:org.matrix.msc2967.client:api:*' \
  | jq -r '.access_token')
echo "Token: $TOKEN"
```

---

## Step 6 — Start matrix-mcp locally

```bash
# Copy .env.example to .env and fill in the local values:
cat > .env <<EOF
RESOURCE_URL=http://localhost:3000
AUTH_SERVER=http://localhost:8080
HOMESERVER_URL=http://localhost:8008
SERVER_NAME=localhost
INTROSPECTION_CLIENT_ID=matrix-mcp-test
INTROSPECTION_CLIENT_SECRET=test-introspection-secret
STORE_DIR=/tmp/matrix-mcp-test-stores
STORE_PEPPER=local-test-pepper-do-not-use-in-production
RUST_LOG=matrix_mcp=debug
EOF

cargo run
```

---

## Step 7 — Verify with a tool call

```bash
# Initialize MCP session
curl -sf -X POST http://localhost:3000/mcp \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"test","version":"0.1"}}}' \
  | jq .

# Call whoami
curl -sf -X POST http://localhost:3000/mcp \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"whoami"}}' \
  | jq .
```

Expected: `{ "result": { "mxid": "@testuser:localhost", ... } }`

---

## Step 8 — Run the integration tests

Once the stack is running:

```bash
# The tests marked #[ignore] require this env var to locate the stack.
export MATRIX_MCP_TEST_URL=http://localhost:3000
export MATRIX_MCP_TEST_TOKEN="$TOKEN"
export MATRIX_MCP_TEST_MAS_URL=http://localhost:8080
export MATRIX_MCP_TEST_SYNAPSE_URL=http://localhost:8008

# Run the full integration suite (starts its own containers for the smoke test)
cargo test --features=integration --test integration -- --nocapture

# Run only the smoke test (no MAS/Synapse needed)
cargo test --features=integration --test integration -- postgres_container_starts --nocapture

# Run the ignored tests once you have completed the wiring
cargo test --features=integration --test integration -- --include-ignored --nocapture
```

---

## Teardown

```bash
docker stop matrix-mcp-pg matrix-mcp-mas matrix-mcp-synapse 2>/dev/null || true
rm -rf /tmp/matrix-mcp-test-stores /tmp/synapse-media
```

---

## Next steps: wiring testcontainers

The `mas_container()` and `synapse_container()` helpers in `tests/integration.rs`
need real config file injection (not just env vars). Use testcontainers'
`.with_copy_to()` or `.with_mount()` to inject the YAML files shown in steps
2 and 3 above. See the testcontainers-rs docs:
<https://docs.rs/testcontainers/latest/testcontainers/core/struct.ContainerRequest.html>

The key fields to plumb through:
- `pg_port` → MAS `database.uri` host
- `mas_port` → Synapse `msc3861.issuer`, matrix-mcp `AUTH_SERVER`
- `syn_port` → matrix-mcp `HOMESERVER_URL`
- matrix-mcp start → in-process axum server bound to a random free port

Once wired, remove the `#[ignore]` attribute from `happy_path_whoami_and_list_rooms`
and `invalid_bearer_returns_401`.
