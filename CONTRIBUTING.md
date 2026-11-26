# Contributing to Nonla Tunnel

Thank you for your interest in Nonla Tunnel! 🚀

## 🚀 Quick Start

### Prerequisites

- [Rust](https://rustup.rs/) stable (pinned via `rust-toolchain.toml`)
- Git

### Setup

```bash
# Fork the repo on GitHub, then clone it
git clone https://github.com/<your-username>/nonla-tunnel.git
cd nonla-tunnel

# Build
cargo build

# Run tests
cargo test --workspace

# Run clippy (linter)
cargo clippy --workspace -- -D warnings
```

### Local Dev

```bash
# Terminal 1 — server on 127.0.0.1:6200/6210, no Traefik (config in target/dev/)
make run-server

# Terminal 2 — point the client at it, then expose localhost:3000 as my-app
make dev-client-config
make run-client

# Terminal 3
curl -H 'Host: my-app.localhost' http://127.0.0.1:6210/
```

## 📝 Contribution Workflow

### 1. Create an Issue first

Before writing code, create or comment on a related issue:
- **Bug?** → Create a [Bug Report](https://github.com/devnonla/nonla-tunnel/issues/new?template=bug_report.md)
- **New feature?** → Create a [Feature Request](https://github.com/devnonla/nonla-tunnel/issues/new?template=feature_request.md)

### 2. Fork & Branch

```bash
git clone https://github.com/<your-username>/nonla-tunnel.git
git checkout -b fix/short-description
```

**Branch naming:**
- `fix/description` — bug fix
- `feat/description` — new feature
- `docs/description` — documentation
- `refactor/description` — code refactor

### 3. Code

- Follow Rust coding conventions
- Run `cargo fmt` before committing
- Run `cargo clippy --workspace -- -D warnings` — no warnings allowed
- Add tests for new code when possible

### 4. Commit

Use [Conventional Commits](https://www.conventionalcommits.org/):

```
feat: add per-credential name quota
fix: handle client disconnect during auth
docs: document invite flow
refactor: simplify claim store
test: add subdomain routing tests
```

### 5. Create a Pull Request

- Push your branch to your fork
- Create a PR targeting `main`
- Fill in the PR template
- Wait for CI to pass (tests + clippy)

## 🏗️ Project Structure

```
nonla-tunnel/
├── crates/
│   ├── nonla-tunnel-protocol/        # Wire protocol, name validation, self-update
│   ├── nonla-tunnel-server/          # nonla-tunnel-server
│   │   └── src/
│   │       ├── main.rs               # CLI: start, token, invite, clients, revoke, sessions, kick, release-name
│   │       ├── config.rs             # server.yaml + env overrides
│   │       ├── server.rs             # Control channel: auth, enrollment, yamux, revocation, housekeeping
│   │       ├── proxy.rs              # Public HTTP → tunnel (subdomain routing, limits)
│   │       ├── install.rs            # /install script + /download binaries
│   │       ├── admin.rs              # Local admin socket (sessions, kick, release-name)
│   │       ├── credentials.rs        # Invites + issued client credentials
│   │       ├── claims.rs             # Tunnel name ownership
│   │       ├── proxy_protocol.rs     # PROXY v1/v2 from Traefik
│   │       ├── traefik.rs            # Traefik dynamic YAML
│   │       ├── registry.rs           # Connected sessions
│   │       └── metrics.rs            # Metrics, rate limiter, auth throttle
│   └── nonla-tunnel-client/          # nonla-tunnel (enroll, config, http, status, stop, …)
├── configs/                          # Example YAML configs
├── deploy/traefik/                   # Example Traefik static config
├── scripts/                          # install.sh, pre-release.sh
└── .github/                          # CI, release, image build, templates
```

## 🧪 Testing

```bash
cargo test --workspace
./scripts/pre-release.sh   # fmt + clippy + test (before tagging a release)
```

## 📋 Coding Style

- **Formatter:** `cargo fmt` (rustfmt defaults)
- **Linter:** `cargo clippy -- -D warnings`
- **Error handling:** `anyhow::Result` + `.context("description")`
- **Logging:** `tracing::{info, debug, warn, error}`
- **Async:** All I/O must be async (tokio)

## ❓ Questions?

Create a [Discussion](https://github.com/devnonla/nonla-tunnel/discussions) or open an Issue.

Thank you for contributing! ❤️
