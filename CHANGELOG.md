# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- Prebuilt clients for **every major platform**: Linux x86_64/arm64 (static musl — runs on any distro incl. Alpine), macOS Apple Silicon/Intel, Windows x86_64/arm64
- Windows support in the client: background tunnels (`-d`), `status`, `stop`, `upgrade`, `uninstall`
- `install.ps1` for Windows; server serves it at `https://<domain>/install.ps1`
- **Claude Code plugin** (`/plugin marketplace add devnonla/nonla-tunnel`) with a skill to install, enroll and use `nonla-tunnel`
- `nonla-tunnel upgrade --version X.Y.Z`; installers accept `--version`, `--dir`, `--no-modify-path` and `NONLA_DOWNLOAD_BASE` (mirror)
- CI runs client tests on macOS and Windows

### Changed

- One installer for everything: `scripts/install.sh` (POSIX sh, works without bash/curl) is what the server serves at `/install`, with its version and address filled in. Binaries always come from GitHub Releases and are checksum-verified; no more build-from-source fallback
- Releases ship plain binaries (`nonla-tunnel-<os>-<arch>[.exe]`) + `SHA256SUMS.txt` instead of tarballs
- `upgrade`/`uninstall` no longer shell out to curl/tar/sudo; `uninstall` stops background tunnels and removes the installer's PATH entry
- The server image no longer bundles client binaries (`/download` and `NONLA_CLIENTS_DIR` removed)

## [0.1.0] - 2026-11-26

Initial release of **Nonla Tunnel**: self-hosted, CLI-only HTTP tunnels for agents, behind your own Traefik.

### Added

- **Tunnels:** `nonla-tunnel http <port> --name <name> [-d]` exposes a local HTTP port at `https://<name>.<domain>`; `-d` returns once the URL is live (exit codes suited to agents); `status`, `stop`, `upgrade`, `uninstall`
- **Server:** `nonla-tunnel-server start` (Docker image `ghcr.io/devnonla/nonla-tunnel`), writing Traefik file-provider routes per tunnel; `/install` script and `/download` client binaries on the apex domain
- **TLS control channel** on `connect.<domain>:443` via a Traefik TCP router; plaintext ports bind to `127.0.0.1` only. The client uses TLS by default
- **One-time enrollment invites:** `nonla-tunnel-server invite [--ttl 24h] [--label …]` creates a single-use, expiring `nti_…` code; `nonla-tunnel enroll` (or `curl -sSL https://<domain>/install | bash -s -- --invite …`) trades it for a per-client `ntc_…` credential — the only token the client stores
- **Credential management:** `clients` lists credentials and pending invites; `revoke <c_…|i_…>` revokes a credential (live tunnels drop within ~15s) or deletes an invite; `token` prints the shared admin token
- **Live sessions:** `sessions [--json]` lists connected tunnels (credential, label, real client IP, uptime, requests, bytes, health); `kick <name> [--ban 1m]` disconnects one; `release-name <name>` frees a name — all via a local `0600` admin socket
- **Tunnel name ownership:** each name is bound to a per-name client claim key, so clients cannot take over each other's URL; claims expire after 30 days unused
- Real client IPs on the control channel via PROXY protocol v2 from Traefik
- Hourly housekeeping removes routers of tunnels idle for 24h and expired claims
- Docker images on GitHub Container Registry, tagged per release (`0.1.0`, `0.1`, `latest`) and `main`; `IMAGE_TAG` selects the tag in `docker-compose.yml`

### Security

- Tunnel names and the domain are validated as DNS names before anything reaches Traefik YAML, rules or scripts
- Server refuses to start without an admin token (≥16 chars); tokens compared in constant time; only SHA-256 hashes of invites, credentials and claim keys are stored (`0600` files)
- Limits: 100 req/s and 128 concurrent requests per tunnel; 4 KB pre-auth messages; 256 pending auths (8 per IP); 5s auth timeout; wrong tokens delayed 1s; an IP is blocked 60s after 10 failures
- Unknown hosts never reveal which tunnels exist
- Install script, `scripts/install.sh` and `upgrade` verify SHA-256 checksums over HTTPS; upgrades unpack in a private random temp dir

[Unreleased]: https://github.com/devnonla/nonla-tunnel/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/devnonla/nonla-tunnel/releases/tag/v0.1.0
