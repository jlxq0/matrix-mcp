# Installation

How to deploy matrix-mcp against your own MAS + Synapse.

---

## Requirements

- A running Synapse homeserver with MAS as the OIDC provider
  (MSC3861 / MSC2967).
- A pre-registered OAuth client in MAS for introspection.
- Rust 1.85+ (for building) or Docker/Podman (for containers).

---

## 1. Register an OAuth client in MAS

matrix-mcp needs a client it can use to authenticate against MAS's
introspection endpoint. This is a confidential client (has a secret).

In your MAS config (or via the MAS admin API), register a client with:

- `client_id`: any opaque string, e.g. `matrix-mcp`
- `client_secret`: `openssl rand -hex 32`
- `client_auth_method`: `client_secret_basic`
- No redirect URIs needed (introspection only).

Keep the client_id and client_secret – they become `MATRIX_MCP_INTROSPECTION_CLIENT_ID`
and `MATRIX_MCP_INTROSPECTION_CLIENT_SECRET`.

---

## 2. Generate the pepper

```bash
openssl rand -hex 32
```

This becomes `MATRIX_MCP_STORE_PEPPER`. Store it in your secret manager.
Do not lose it – losing the pepper destroys all user key stores.

---

## 3. Deployment: docker-compose (local hacking)

```yaml
# docker-compose.yml
services:
  matrix-mcp:
    image: ghcr.io/jlxq0/matrix-mcp:latest
    ports:
      - "3000:3000"
    volumes:
      - ./data:/var/lib/matrix-mcp
    environment:
      MATRIX_MCP_RESOURCE_URL: https://matrix-mcp.your-domain.example
      MATRIX_MCP_AUTHORIZATION_SERVER: https://your-mas.example
      MATRIX_MCP_HOMESERVER_URL: https://matrix.your-domain.example
      MATRIX_MCP_SERVER_NAME: example.com
      MATRIX_MCP_INTROSPECTION_CLIENT_ID: matrix-mcp
      MATRIX_MCP_INTROSPECTION_CLIENT_SECRET: your-secret-here
      MATRIX_MCP_STORE_DIR: /var/lib/matrix-mcp
      MATRIX_MCP_STORE_PEPPER: your-pepper-here
```

For local development with non-TLS MAS, use `http://` URLs – the config
validator accepts both schemes.

---

## 4. Deployment: generic Kubernetes

Minimum manifests. Adapt namespaces and image tags as needed.

### Namespace

```yaml
apiVersion: v1
kind: Namespace
metadata:
  name: matrix-mcp
  labels:
    pod-security.kubernetes.io/enforce: restricted
```

### Secret (inline; use ExternalSecret in production)

```yaml
apiVersion: v1
kind: Secret
metadata:
  name: matrix-mcp-secrets
  namespace: matrix-mcp
stringData:
  MATRIX_MCP_INTROSPECTION_CLIENT_SECRET: "your-secret"
  MATRIX_MCP_STORE_PEPPER: "your-pepper"
```

### PVC

```yaml
apiVersion: v1
kind: PersistentVolumeClaim
metadata:
  name: matrix-mcp-data
  namespace: matrix-mcp
spec:
  accessModes: [ReadWriteOnce]
  resources:
    requests:
      storage: 5Gi
```

### Deployment (minimal)

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: matrix-mcp
  namespace: matrix-mcp
spec:
  replicas: 1  # must be 1 – Olm single-writer constraint
  selector:
    matchLabels:
      app: matrix-mcp
  template:
    metadata:
      labels:
        app: matrix-mcp
    spec:
      securityContext:
        runAsNonRoot: true
        runAsUser: 1000
        seccompProfile:
          type: RuntimeDefault
      containers:
        - name: app
          image: ghcr.io/jlxq0/matrix-mcp:latest
          ports:
            - containerPort: 3000
          securityContext:
            allowPrivilegeEscalation: false
            readOnlyRootFilesystem: true
            capabilities:
              drop: ["ALL"]
          env:
            - name: MATRIX_MCP_RESOURCE_URL
              value: "https://matrix-mcp.your-domain.example"
            - name: MATRIX_MCP_AUTHORIZATION_SERVER
              value: "https://your-mas.example"
            - name: MATRIX_MCP_HOMESERVER_URL
              value: "https://matrix.your-domain.example"
            - name: MATRIX_MCP_SERVER_NAME
              value: "example.com"
            - name: MATRIX_MCP_INTROSPECTION_CLIENT_ID
              value: "matrix-mcp"
            - name: MATRIX_MCP_INTROSPECTION_CLIENT_SECRET
              valueFrom:
                secretKeyRef:
                  name: matrix-mcp-secrets
                  key: MATRIX_MCP_INTROSPECTION_CLIENT_SECRET
            - name: MATRIX_MCP_STORE_DIR
              value: "/var/lib/matrix-mcp"
            - name: MATRIX_MCP_STORE_PEPPER
              valueFrom:
                secretKeyRef:
                  name: matrix-mcp-secrets
                  key: MATRIX_MCP_STORE_PEPPER
            - name: POD_IP
              valueFrom:
                fieldRef:
                  fieldPath: status.podIP
          volumeMounts:
            - name: data
              mountPath: /var/lib/matrix-mcp
          livenessProbe:
            httpGet:
              path: /health
              port: 3000
          readinessProbe:
            httpGet:
              path: /health
              port: 3000
      volumes:
        - name: data
          persistentVolumeClaim:
            claimName: matrix-mcp-data
```

---

## 5. Deployment: Gruyere (our cluster)

The Gruyere manifests live in
`clusters/gruyere/apps/matrix-mcp-www/` in the argocd repo.
They use:

- ExternalSecret pulling from 1Password (`matrix-mcp-www` item in
  `Gruyere k8s Cluster` vault).
- Traefik HTTPRoute with IP allowlist middleware for the `/mcp` path.
- `PodDisruptionBudget minAvailable: 1`.
- Alloy sidecar for Prometheus metrics scraping (pod IP annotation).

For the initial deploy procedure (pre-existing), see
`clusters/gruyere/apps/matrix-mcp-www/RUNBOOK.md`.

---

## 6. DNS and TLS

The server's public URL (`MATRIX_MCP_RESOURCE_URL`) must match the
hostname in your TLS certificate and must be reachable by claude.ai.

For the Gruyere deployment, Bunny DNS + cert-manager handle this.
For a generic k8s deployment, configure an Ingress/HTTPRoute with
your own cert-manager issuer or static cert.

---

## 7. Smoke test

```bash
# health
curl -i https://matrix-mcp.your-domain.example/health
# expect: 200 ok

# resource metadata (RFC 9728)
curl -s https://matrix-mcp.your-domain.example/.well-known/oauth-protected-resource | jq .

# unauthenticated MCP call
curl -i -X POST https://matrix-mcp.your-domain.example/mcp
# expect: 401 with WWW-Authenticate pointing at /.well-known/...
```

Once the server responds correctly, add
`https://matrix-mcp.your-domain.example/mcp` as a custom connector in claude.ai
and follow the [onboarding guide](onboarding.md).
