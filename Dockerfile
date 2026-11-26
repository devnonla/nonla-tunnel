# syntax=docker/dockerfile:1

FROM rust:bookworm AS builder
WORKDIR /app
COPY Cargo.toml Cargo.lock rust-toolchain.toml ./
COPY crates ./crates
COPY configs ./configs
RUN cargo build --release -p nonla-tunnel-server -p nonla-tunnel-client \
    && mkdir -p /out/clients \
    && cp target/release/nonla-tunnel-server /out/ \
    && ARCH="$(uname -m)" \
    && case "$ARCH" in \
         x86_64) LABEL=amd64 ;; \
         aarch64) LABEL=arm64 ;; \
         *) LABEL=amd64 ;; \
       esac \
    && cp target/release/nonla-tunnel /out/clients/nonla-tunnel-linux-${LABEL} \
    && tar -czf /out/clients/nonla-tunnel-src.tar.gz \
         Cargo.toml Cargo.lock rust-toolchain.toml crates configs \
    && cd /out/clients && sha256sum nonla-tunnel-* > SHA256SUMS

FROM debian:bookworm-slim
LABEL org.opencontainers.image.source="https://github.com/devnonla/nonla-tunnel" \
      org.opencontainers.image.description="Nonla Tunnel server — self-hosted CLI tunnels behind Traefik" \
      org.opencontainers.image.licenses="MIT"
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates curl \
    && rm -rf /var/lib/apt/lists/*
COPY --from=builder /out/nonla-tunnel-server /usr/local/bin/nonla-tunnel-server
COPY --from=builder /out/clients /var/lib/nonla-tunnel/clients
RUN mkdir -p /etc/nonla-tunnel /etc/traefik/dynamic
ENV NONLA_CONFIG=/etc/nonla-tunnel/server.yaml \
    NONLA_CLIENTS_DIR=/var/lib/nonla-tunnel/clients \
    NONLA_TRAEFIK_ENABLED=true \
    NONLA_TRAEFIK_CONFIG_DIR=/etc/traefik/dynamic \
    NONLA_TRAEFIK_SERVICE_URL=http://127.0.0.1:6210 \
    RUST_LOG=info
EXPOSE 6200 6210
CMD ["nonla-tunnel-server", "start"]
