# syntax=docker/dockerfile:1

# Server image. Clients are not bundled: /install and /install.ps1 fetch the
# matching release binary from GitHub Releases and verify its checksum.

FROM rust:bookworm AS builder
WORKDIR /app
COPY Cargo.toml Cargo.lock rust-toolchain.toml ./
COPY crates ./crates
# Installer scripts are embedded into the server at compile time.
COPY scripts ./scripts
RUN cargo build --release --locked -p nonla-tunnel-server \
    && cp target/release/nonla-tunnel-server /nonla-tunnel-server

FROM debian:bookworm-slim
LABEL org.opencontainers.image.source="https://github.com/devnonla/nonla-tunnel" \
      org.opencontainers.image.description="Nonla Tunnel server — self-hosted CLI tunnels behind Traefik" \
      org.opencontainers.image.licenses="MIT"
COPY --from=builder /nonla-tunnel-server /usr/local/bin/nonla-tunnel-server
RUN mkdir -p /etc/nonla-tunnel /etc/traefik/dynamic
ENV NONLA_CONFIG=/etc/nonla-tunnel/server.yaml \
    NONLA_TRAEFIK_ENABLED=true \
    NONLA_TRAEFIK_CONFIG_DIR=/etc/traefik/dynamic \
    NONLA_TRAEFIK_SERVICE_URL=http://127.0.0.1:6210 \
    RUST_LOG=info
EXPOSE 6200 6210
CMD ["nonla-tunnel-server", "start"]
