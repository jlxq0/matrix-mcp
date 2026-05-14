# syntax=docker/dockerfile:1.7

# Multi-stage build → distroless runtime.
# Final image ~25-35 MiB (Rust release binary + glibc-shared libraries).
# Compatible with our existing PSS-restricted namespace conventions.

ARG RUST_VERSION=1.90
FROM rust:${RUST_VERSION}-bookworm AS builder

WORKDIR /build

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
FROM gcr.io/distroless/cc-debian12:nonroot

WORKDIR /app
COPY --from=builder /build/target/release/matrix-mcp /app/matrix-mcp

# Non-root by default (distroless `nonroot` user, UID 65532). Matches the
# PSS-restricted security context we use everywhere else on Gruyere.
USER nonroot:nonroot

EXPOSE 3000
ENTRYPOINT ["/app/matrix-mcp"]
