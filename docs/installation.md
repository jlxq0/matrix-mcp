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
    image: forge.oddie.app/jlxq0/matrix-mcp:v0.6.0
    ports:
      - "3000:3000"
    volumes:
      - ./data:/var/lib/matrix-mcp
    environment:
      MATRIX_MCP_RESOURCE_URL: https://matrix-mcp.example.com
      MATRIX_MCP_AUTHORIZATION_SERVER: https://matrixauthservice.example.com
      MATRIX_MCP_HOMESERVER_URL: https://matrix.example.com
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
          image: forge.oddie.app/jlxq0/matrix-mcp:v0.6.0
          ports:
            - containerPort: 3000
          securityContext:
            allowPrivilegeEscalation: false
            readOnlyRootFilesystem: true
            capabilities:
              drop: ["ALL"]
          env:
            - name: MATRIX_MCP_RESOURCE_URL
              value: "https://matrix-mcp.example.com"
            - name: MATRIX_MCP_AUTHORIZATION_SERVER
              value: "https://matrixauthservice.example.com"
            - name: MATRIX_MCP_HOMESERVER_URL
              value: "https://matrix.example.com"
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

## 5. Deployment: reference k8s manifests

A reference Kubernetes deployment looks like:

- A `Deployment` with `replicas: 1`, the matrix-mcp container image,
  and a `PodDisruptionBudget minAvailable: 1`.
- A `Service` exposing port 3000 (not 9090 — metrics stays internal).
- An `Ingress` / Gateway-API `HTTPRoute` terminating TLS for your
  public matrix-mcp hostname, optionally with an IP-allowlist
  middleware on `/mcp`.
- A `PersistentVolumeClaim` backed by your block-storage class for
  the encrypted Matrix store.
- Secrets pulled in via your platform's secret manager (ExternalSecrets
  Operator + 1Password Connect / Vault / sealed-secrets / etc.) for
  `MATRIX_MCP_INTROSPECTION_CLIENT_SECRET` and
  `MATRIX_MCP_STORE_PEPPER`.

The author's production deployment uses ExternalSecrets +
1Password Connect + Traefik Gateway API + Longhorn-backed PVCs.
Substitute the equivalents for your platform.

---

## 6. DNS and TLS

The server's public URL (`MATRIX_MCP_RESOURCE_URL`) must match the
hostname in your TLS certificate and must be reachable by claude.ai.

Configure an Ingress / HTTPRoute with your own cert-manager issuer
or static cert.

---

## 7. Smoke test

```bash
# health
curl -i https://matrix-mcp.example.com/health
# expect: 200 {"status":"healthy"}

# resource metadata (RFC 9728)
curl -s https://matrix-mcp.example.com/.well-known/oauth-protected-resource | jq .

# unauthenticated MCP call
curl -i -X POST https://matrix-mcp.example.com/mcp
# expect: 401 with WWW-Authenticate pointing at /.well-known/...
```

Once the server responds correctly, add
`https://matrix-mcp.example.com/mcp` as a custom connector in claude.ai
and follow the [onboarding guide](onboarding.md).
