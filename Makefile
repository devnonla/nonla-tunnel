.PHONY: build build-server build-client build-all clean test run-server dev-client-config run-client docker docker-up docker-down

# Local dev: plaintext on 127.0.0.1, no Traefik. Config lives in target/dev.
DEV_DIR   := target/dev
DEV_TOKEN := dev-token-0123456789abcdef

build: build-all

build-server:
	cargo build --release -p nonla-tunnel-server

build-client:
	cargo build --release -p nonla-tunnel-client

build-all:
	cargo build --release

test:
	cargo test --workspace

run-server:
	@mkdir -p $(DEV_DIR)
	@test -f $(DEV_DIR)/server.yaml || printf 'domain: localhost\nbind_addr: 127.0.0.1\nauth:\n  tokens: ["$(DEV_TOKEN)"]\ntraefik:\n  enabled: false\n' > $(DEV_DIR)/server.yaml
	RUST_LOG=info cargo run -p nonla-tunnel-server -- start --config $(DEV_DIR)/server.yaml

# Point the local client at the dev server (writes ~/.nonla-tunnel/config.yaml).
dev-client-config:
	cargo run -p nonla-tunnel-client -- config set --server 127.0.0.1:6200 --token $(DEV_TOKEN) --no-tls

# Then: curl -H 'Host: my-app.localhost' http://127.0.0.1:6210/
run-client:
	RUST_LOG=info cargo run -p nonla-tunnel-client -- http 3000 --name my-app

docker:
	docker compose build

docker-up:
	docker compose up -d --build

docker-down:
	docker compose down

clean:
	cargo clean

cross-linux-amd64:
	cross build --release --target x86_64-unknown-linux-gnu -p nonla-tunnel-client

cross-linux-arm64:
	cross build --release --target aarch64-unknown-linux-gnu -p nonla-tunnel-client

cross-macos-arm64:
	cross build --release --target aarch64-apple-darwin -p nonla-tunnel-client

cross-all: cross-linux-amd64 cross-linux-arm64
