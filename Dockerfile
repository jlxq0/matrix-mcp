# syntax=docker/dockerfile:1.7

# Multi-stage build → distroless runtime.
# Final image ~25-35 MiB (Rust release binary + glibc-shared libraries).
# Compatible with our existing PSS-restricted namespace conventions.

ARG RUST_VERSION=1.93
# Digest pinned to rust:1.93-bookworm (OCI index). Update via Renovate or:
#   TOKEN=$(curl -s "https://auth.docker.io/token?service=registry.docker.io&scope=repository:library/rust:pull" | jq -r .token)
#   curl -sI -H "Accept: application/vnd.oci.image.index.v1+json" -H "Authorization: Bearer $TOKEN" \
#     "https://registry-1.docker.io/v2/library/rust/manifests/${RUST_VERSION}-bookworm" | grep docker-content-digest
FROM rust:${RUST_VERSION}-bookworm@sha256:7c4ae649a84014c467d79319bbf17ce2632ae8b8be123ac2fb2ea5be46823f31 AS builder

WORKDIR /build

# `opus` (via audiopus_sys) builds libopus from C source via CMake.
# The rust:1.93-bookworm image has gcc but not cmake; install it here
# so the build script can produce libopus.a for static linking. We
# don't need cmake at runtime — only during `cargo build`.
RUN apt-get update \
    && apt-get install -y --no-install-recommends cmake \
    && rm -rf /var/lib/apt/lists/*

# Force static linking of libopus so the distroless runtime image
# (which has no libopus.so) doesn't crash at startup. audiopus_sys's
# default on Linux/glibc is dynamic linking; OPUS_STATIC=1 flips it.
ENV OPUS_STATIC=1

# Cache dependencies separately from source: copy manifest first, build a
# stub, then copy real source. This means `cargo build` only re-runs the
# slow dependency compile if Cargo.toml / Cargo.lock change.
COPY Cargo.toml Cargo.lock* ./
RUN mkdir src && \
    echo 'fn main() { println!("dep stub"); }' > src/main.rs && \
    cargo build --release --locked && \
    rm -rf src target/release/deps/matrix_mcp* target/release/matrix-mcp*

# Now the real source.
COPY src ./src
RUN cargo build --release --locked

# Distroless runtime: no shell, no apt, no package manager. Smaller surface.
# `cc` variant includes glibc + ca-certs which we need for HTTPS to MAS / Synapse.
# Digest pinned to gcr.io/distroless/cc-debian12:nonroot (OCI index). Update via:
#   curl -sI -H "Accept: application/vnd.oci.image.index.v1+json" \
#     "https://gcr.io/v2/distroless/cc-debian12/manifests/nonroot" | grep docker-content-digest
FROM gcr.io/distroless/cc-debian12:nonroot@sha256:e2d29aec8061843706b7e484c444f78fafb05bfe47745505252b1769a05d14f1

# Standard OCI annotations. `image.source` is what makes a registry link the
# package back to its repository — without it the GHCR package page shows no
# code, no README and no licence, which is a poor front door for something
# people are meant to self-host.
LABEL org.opencontainers.image.source="https://github.com/jlxq0/matrix-mcp" \
      org.opencontainers.image.url="https://github.com/jlxq0/matrix-mcp" \
      org.opencontainers.image.documentation="https://github.com/jlxq0/matrix-mcp#readme" \
      org.opencontainers.image.title="matrix-mcp" \
      org.opencontainers.image.description="Remote MCP server exposing Matrix — including E2EE rooms — to AI clients, with a Claude Code channel surface" \
      org.opencontainers.image.licenses="MIT"

WORKDIR /app
COPY --from=builder /build/target/release/matrix-mcp /app/matrix-mcp

# Non-root by default (distroless `nonroot` user, UID 65532). Matches
# a typical PSS-restricted Kubernetes security context (no privilege
# escalation, drop ALL capabilities, read-only root filesystem).
USER nonroot:nonroot

EXPOSE 3000
ENTRYPOINT ["/app/matrix-mcp"]
