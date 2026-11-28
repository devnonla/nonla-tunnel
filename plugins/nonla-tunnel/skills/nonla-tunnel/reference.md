# Nonla Tunnel — server operator reference

Use this only when the user runs the Nonla Tunnel **server** and asks to manage it. In Docker, prefix every command with `docker compose exec nonla-tunnel` (run from the directory with `docker-compose.yml`).

## Onboard an agent / machine

```bash
nonla-tunnel-server invite --label agent-1            # single use, expires in 24h
nonla-tunnel-server invite --label ci --ttl 1h        # 1m … 30d
nonla-tunnel-server invite --label x -q               # print only the code (for scripts)
```

It prints the `nti_…` code plus ready-made install commands (`curl … /install | sh -s -- --invite …` and the PowerShell variant). Hand the code to the agent through a private channel. It is single-use: a used or expired invite is worthless, so just create a new one.

## Credentials

```bash
nonla-tunnel-server clients               # issued credentials (c_…) + pending invites (i_…)
nonla-tunnel-server revoke c_1a2b3c4d     # revoke a credential; its live tunnels drop within ~15s
nonla-tunnel-server revoke i_04cf7bf6     # delete an unused invite
nonla-tunnel-server token                 # shared admin token (do not give it to agents)
```

## Live tunnels

```bash
nonla-tunnel-server sessions              # NAME, CLIENT (credential + label), PEER (real IP), UPTIME, REQS, IN, OUT, HEALTH
nonla-tunnel-server sessions --json       # same, machine-readable
nonla-tunnel-server kick my-app           # disconnect; reconnects refused for 1m, so the client exits
nonla-tunnel-server kick my-app --ban 0   # just reset the connection; the client reconnects
nonla-tunnel-server kick my-app --ban 1h  # keep the name off for an hour
nonla-tunnel-server release-name my-app   # free a name from its owner (after revoking the old client)
```

`kick` keeps the credential. To shut a client out for good, `revoke` it.

## Facts worth knowing

- Clients connect over TLS to `connect.<domain>:443` (Traefik terminates TLS); public traffic hits `https://<name>.<domain>`.
- Limits per tunnel: 100 req/s, 128 concurrent requests (`503 Tunnel busy` beyond).
- Name claims expire after 30 days unused; Traefik routers of tunnels idle for 24h are removed hourly.
- State files (all `0600`, next to `server.yaml`, i.e. `/etc/nonla-tunnel/` in Docker): `credentials.json`, `claims.json`, `admin.sock`.
- **Real client IPs** (`PEER` in `sessions`, the 10-failures/60s block) come from Traefik's PROXY protocol header, which the server only trusts from loopback. If Traefik runs elsewhere (Docker Swarm service, another host), every client looks like Traefik's IP, so one bad client blocks everyone and `PEER` is wrong, or the connection is rejected. Fix: set `trusted_proxies` in `server.yaml` to the narrowest CIDR holding only Traefik (e.g. `["10.0.1.0/24"]` for a Swarm overlay network; find it with `docker network inspect <net>`), then restart the server. Needs server ≥ 0.2.1. Never use a broad range or `0.0.0.0/0`: anything inside can spoof any client IP.
- Never print the admin token or credentials into chat unless the user explicitly asks for them.
