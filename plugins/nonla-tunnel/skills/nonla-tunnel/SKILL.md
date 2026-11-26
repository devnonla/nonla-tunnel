---
name: nonla-tunnel
description: Give a local HTTP app a public HTTPS URL with the nonla-tunnel CLI (self-hosted, ngrok-style) — install it, enroll with a one-time invite, open/stop tunnels, and fix tunnel errors. Use when the user wants to expose, share or preview a localhost port, test webhooks/OAuth callbacks against a public URL, or mentions nonla-tunnel, Nonla Tunnel, an `nti_…` invite or a `connect.<domain>` server.
---

# nonla-tunnel

`nonla-tunnel` exposes a local HTTP port at `https://<name>.<domain>` through the user's own Nonla Tunnel server. Every command is non-interactive and returns a clear exit code. Answer the user in their language.

## 1. Is it installed and enrolled?

```bash
nonla-tunnel --version || ~/.nonla-tunnel/bin/nonla-tunnel --version   # Windows: %USERPROFILE%\.nonla-tunnel\bin\nonla-tunnel.exe
nonla-tunnel status
```

- Not found → **Install** (step 2).
- `status` says `Not configured` → **Enroll** (step 3).
- Otherwise it prints `server:` and the running tunnels → go to step 4.

If `nonla-tunnel` is not on `PATH` in your shell (fresh install), call it by its full path: `~/.nonla-tunnel/bin/nonla-tunnel`.

## 2. Install (+ enroll in one go)

You need two things from the user. **Never guess them:**
- the server **domain** (e.g. `tunnel.example.com`), and
- a one-time **invite** (`nti_…`). The server operator creates it with `nonla-tunnel-server invite --label <name>`.

Linux / macOS:
```bash
curl -fsSL https://<domain>/install | sh -s -- --invite nti_...
```
Windows (PowerShell):
```powershell
$env:NONLA_INVITE='nti_...'; irm https://<domain>/install.ps1 | iex
```

The installer downloads the matching release binary from GitHub, verifies its SHA-256 and installs it to `~/.nonla-tunnel/bin`. It adds that directory to PATH and enrolls the client. Without an invite it only installs.

## 3. Enroll (if installed but not configured)

```bash
nonla-tunnel enroll --server connect.<domain> --invite nti_...
```

- Exit `0`, prints `Enrolled as c_…`. The client now holds its own credential in `~/.nonla-tunnel/config.yaml`.
- `Authentication failed: invalid or expired invite` (exit `1`) means the invite was already used, expired or deleted. **Do not retry the same code**: ask the user for a new invite.
- An invite is single-use. Never reuse one, and never put it in files, commits or logs.

## 4. Open a tunnel

Make sure the local app is running and listening first (e.g. `curl -sI http://localhost:3000`). Then open the tunnel in **detached mode**; foreground mode blocks until Ctrl+C.

```bash
nonla-tunnel http 3000 --name my-app -d
```

- On success (exit `0`) it prints a line starting with `Forwarding  `. Example: `Forwarding  https://my-app.tunnel.example.com -> http://localhost:3000`. That URL is the answer: give it to the user. Verify it with `curl -sI <url>` when useful.
- `<addr>` can be a port (`3000`) or `host:port` (`127.0.0.1:8080`).
- **Always pass `--name`** so the URL is stable and you can stop it later. A name is one lowercase DNS label: `a-z`, `0-9`, `-`, 1–63 chars, no leading or trailing `-`. Derive it from the project, e.g. `shop-api`. Reserved: `dashboard`, `connect`, `api`, `www`, `admin`, `install`, `download`.

**Before exposing, consider:** anything on that port becomes reachable from the internet. If the app has no auth and holds real data, or the user did not ask for a public URL, confirm with them first. Only expose the port they asked for.

## 5. Manage

```bash
nonla-tunnel status                 # config + background tunnels (name, pid)
nonla-tunnel stop my-app            # stop one; `nonla-tunnel stop` stops all
cat ~/.nonla-tunnel/tunnels/my-app.log   # log of a background tunnel (contains the Forwarding line)
nonla-tunnel upgrade                # latest release (checksum-verified)
nonla-tunnel uninstall --yes        # removes ~/.nonla-tunnel and the PATH entry
```

When you only opened a tunnel for a task (e.g. a one-off webhook test), stop it when the task is done unless the user wants it kept.

## Errors → what to do

| Output (exit 1 unless noted) | Meaning | Action |
|---|---|---|
| `Authentication failed: Invalid token` | Credential revoked or wrong server | Ask the user for a new invite, then re-run `enroll` |
| `tunnel name '<n>' is in use by another client` | Another machine owns that name | Pick a different `--name` |
| `tunnel '<n>' was disconnected by the operator; reconnect allowed in Ns` | Operator kicked it | Tell the user; retry only after N seconds if they want |
| `Tunnel '<n>' is already running in background` | Already up | Reuse it (URL is in its log) or `nonla-tunnel stop <n>` first |
| `invalid --name …` | Bad name | Use a valid DNS label (see step 4) |
| `Still connecting…` (exit 0) | Server unreachable for 15s; keeps retrying | Check `~/.nonla-tunnel/tunnels/<n>.log` and the network; `stop` to give up |
| Public URL returns `502 Tunnel not found or offline` | Tunnel down | `nonla-tunnel status`, restart it |
| Public URL returns `502`/connection refused from the app | Local app not listening | Start the app / check the port |
| `503 Tunnel busy` | >128 concurrent requests | Load issue on the app side |

## Rules

- Never print, echo or copy the credential (`token:` in `config.yaml`) or an invite into chat, files or commits. `status` shows only a masked token. That is enough.
- Do not edit `~/.nonla-tunnel/config.yaml` by hand. Use `enroll`, or `config set` only with a token the user explicitly provides.
- Do not run `nonla-tunnel http` in the foreground from a tool call. Use `-d`.
- If the user runs the **server** and asks to create invites, list sessions, kick or revoke clients, see [reference.md](reference.md).
