# Operations

Runbook for the matrix-mcp production deployment on Gruyere.

---

## Deployment

matrix-mcp runs as a single Deployment in the `matrix-mcp` namespace on Gruyere.
ArgoCD syncs the manifest; trigger a rollout by pushing a new image tag.

```bash
# Force a rollout of the current image (e.g. after a ConfigMap change)
kubectl -n matrix-mcp rollout restart deployment/matrix-mcp

# Watch rollout progress
kubectl -n matrix-mcp rollout status deployment/matrix-mcp
```

---

## Health checks

```bash
# Liveness / readiness probe endpoint
curl -sf https://matrix-mcp.example.com/health | jq .

# Prometheus metrics (cluster-internal only — pod IP port 9090)
kubectl -n matrix-mcp port-forward deploy/matrix-mcp 9090:9090 &
curl -s http://localhost:9090/metrics | grep matrix_mcp
```

---

## Logs

```bash
# Tail structured JSON logs (Loki also ingests these via Alloy)
kubectl -n matrix-mcp logs -f deploy/matrix-mcp | jq .

# Filter to a specific user's tool calls
kubectl -n matrix-mcp logs deploy/matrix-mcp \
  | jq 'select(.mxid == "@alice:example.com")'
```

---

## Rate-limit quota

Read and write quotas are configurable via environment variables.
Defaults at time of writing: 60 reads/min, 30 writes/min per identity.

```bash
# Check current env values
kubectl -n matrix-mcp get deployment matrix-mcp -o jsonpath=\
  '{.spec.template.spec.containers[0].env}' | jq .
```

---

## Bearer-token rotation

Client bearer tokens are issued by MAS and are short-lived (default 1 h).
No action is needed on the matrix-mcp side — the SDK library handles refresh.
If a user reports persistent 401 errors, check the MAS introspect endpoint
directly:

```bash
curl -s -X POST https://mas.example.com/oauth2/introspect \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  -d "token=<bearer>&client_id=<id>&client_secret=<secret>"
```

See `scripts/qa/dr-pepper-rotation.md` for the full manual rotation procedure.

---

## Performance baseline

> **Status: pending load test** — the numbers below are design estimates based
> on the component architecture. No production or synthetic load test has been
> run yet. Fill these in once `scripts/qa/load.sh` has been executed against a
> staging environment.

### What we expect (architecture estimates)

| Scenario | Expected p50 | Expected p99 | Basis |
|---|---|---|---|
| `whoami` (cache hit, no Synapse call) | < 5 ms | < 20 ms | In-process only, rate-limit check + token introspect cache |
| `list_joined_rooms` (warm Synapse session) | < 50 ms | < 200 ms | One Synapse HTTP call (GET /joined_rooms) over LAN |
| `read_recent_messages` (50 events, E2EE room) | < 200 ms | < 800 ms | Synapse timeline + Vodozemac decryption |
| `send_text_message` (E2EE room) | < 300 ms | < 1 s | Key upload check + Synapse PUT /send + to-device |
| Token introspection (MAS, uncached) | < 30 ms | < 100 ms | MAS HTTP call over LAN |
| Token introspection (in-process LRU cache hit) | < 1 ms | < 5 ms | HashMap lookup |

### Rate limits and concurrency

- The Governor token bucket enforces **60 reads/min** and **30 writes/min** per
  user identity. At these limits, sustained throughput is ~1 req/s reads, ~0.5
  req/s writes — well within Synapse's per-user federation budget.
- MCP sessions are bounded by `CappedSessionManager`. Current cap: **50
  concurrent sessions**. Each session holds an open HTTP/2 connection.
- matrix-sdk uses a per-user SQLite store (on-disk, `bundled-sqlite`).
  Concurrent writes from multiple tool calls in the same session are serialized
  by the SDK's internal mutex.

### Known bottlenecks (architecture analysis)

1. **MAS introspection** — every unauthenticated tool call pays a MAS HTTP
   round-trip (~30 ms on Gruyere LAN). An in-process LRU cache with a 5-minute
   TTL amortizes this across a session. Cache hit rate under typical claude.ai
   usage (one session, multiple tool calls) is expected to be > 95 %.

2. **E2EE key exchange on first message** — the first `send_text_message` to an
   E2EE room triggers an OLM key claim + to-device delivery, adding ~100–200 ms.
   Subsequent messages in the same session skip key negotiation.

3. **Store-cipher HKDF on session init** — computing the per-user store key
   adds ~1 ms on first login. This is a one-time cost per session, not per
   tool call.

### How to run the load test

```bash
# See scripts/qa/load.sh for the full procedure.
# Prerequisite: a staging environment (see INTEGRATION.md).
bash scripts/qa/load.sh --target https://matrix-mcp-staging.example.com \
  --users 10 --duration 60
```

Replace the estimates above with measured p50/p99 values once the test has run.

---

## Disaster recovery

### Pod loss (crashloop / OOMKill)

See `scripts/qa/dr-pvc-loss.md` for the procedure if the SQLite store PVC is
affected.

For a plain pod restart (no storage loss):

```bash
kubectl -n matrix-mcp delete pod -l app=matrix-mcp
# Pod is replaced by the Deployment controller within seconds.
# No state is lost — store is on PVC, config in ExternalSecret.
```

### Bearer-token pepper rotation

See `scripts/qa/dr-pepper-rotation.md`.

### Chaos / pod kill drill

See `scripts/qa/chaos-pod-kill.sh`.
