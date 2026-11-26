use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use std::fs::OpenOptions;
use std::io::{Read, Seek, SeekFrom};
use std::path::PathBuf;
use std::process::{Command as ProcCommand, Stdio};
use tokio::sync::watch;
use tokio_util::sync::CancellationToken;
use tracing_subscriber::EnvFilter;

mod client;
mod config;
mod platform;
mod update;

#[derive(Parser, Debug)]
#[command(
    name = "nonla-tunnel",
    about = "nonla-tunnel — expose a local HTTP port through your Nonla Tunnel server",
    version
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand, Debug)]
enum Command {
    /// Manage client configuration
    Config(ConfigCmd),
    /// Enroll with a one-time invite; saves the issued credential (not the invite)
    Enroll(EnrollArgs),
    /// Forward a local HTTP port (ngrok-style)
    Http(HttpArgs),
    /// Show config and running background tunnels
    Status,
    /// Stop a background tunnel (or all)
    Stop(StopArgs),
    /// Upgrade to the latest release (or --version X.Y.Z)
    Upgrade(UpgradeArgs),
    /// Uninstall nonla-tunnel
    Uninstall(UninstallArgs),
}

#[derive(Parser, Debug)]
struct ConfigCmd {
    #[command(subcommand)]
    action: ConfigAction,
}

#[derive(Subcommand, Debug)]
enum ConfigAction {
    /// Set server address and auth token
    Set(ConfigSetArgs),
    /// Print current config
    Show,
}

#[derive(Parser, Debug)]
struct ConfigSetArgs {
    /// Server control address, e.g. connect.tunnel.example.com[:443]
    #[arg(long)]
    server: String,
    #[arg(long)]
    token: String,
    /// Disable TLS (plaintext control channel; token sent in clear — localhost/dev only)
    #[arg(long)]
    no_tls: bool,
    /// Deprecated: TLS is on by default
    #[arg(long, hide = true)]
    tls: bool,
    #[arg(long, default_value = "")]
    tls_server_name: String,
    /// Accept any TLS certificate (insecure; testing only)
    #[arg(long)]
    tls_skip_verify: bool,
}

#[derive(Parser, Debug)]
struct EnrollArgs {
    /// Server control address, e.g. connect.tunnel.example.com[:443]
    #[arg(long)]
    server: String,
    /// One-time invite code (nti_…) from `nonla-tunnel-server invite`
    #[arg(long, env = "NONLA_INVITE")]
    invite: String,
    /// Label shown in the server's `clients` list (default: hostname)
    #[arg(long)]
    label: Option<String>,
    /// Disable TLS (plaintext; localhost/dev only)
    #[arg(long)]
    no_tls: bool,
    #[arg(long, default_value = "")]
    tls_server_name: String,
    /// Accept any TLS certificate (insecure; testing only)
    #[arg(long)]
    tls_skip_verify: bool,
}

#[derive(Parser, Debug, Clone)]
struct HttpArgs {
    /// Local port or host:port (e.g. 3000 or localhost:8080)
    addr: String,
    /// Subdomain name (default: random)
    #[arg(long, short)]
    name: Option<String>,
    /// Run in background and exit when connected
    #[arg(long, short = 'd')]
    detach: bool,
    /// Internal: child process after detach
    #[arg(long, hide = true)]
    daemon_child: bool,
}

#[derive(Parser, Debug)]
struct StopArgs {
    /// Tunnel name (omit to stop all background tunnels)
    name: Option<String>,
}

#[derive(Parser, Debug)]
struct UpgradeArgs {
    /// Install this version (e.g. 0.1.0) instead of the latest release
    #[arg(long)]
    version: Option<String>,
}

#[derive(Parser, Debug)]
struct UninstallArgs {
    #[arg(long, short)]
    yes: bool,
}

#[tokio::main]
async fn main() -> Result<()> {
    update::cleanup_after_upgrade();
    let cli = Cli::parse();
    match cli.command {
        Command::Config(cmd) => cmd_config(cmd),
        Command::Enroll(args) => cmd_enroll(args).await,
        Command::Http(args) => cmd_http(args).await,
        Command::Status => cmd_status(),
        Command::Stop(args) => cmd_stop(args),
        Command::Upgrade(args) => update::upgrade(args.version.as_deref()),
        Command::Uninstall(args) => {
            // Stop background tunnels first so nothing keeps running from
            // the directory we are about to delete.
            if !list_running_tunnels().unwrap_or_default().is_empty() {
                cmd_stop(StopArgs { name: None })?;
            }
            update::uninstall(args.yes)
        }
    }
}

fn tunnels_dir() -> Result<PathBuf> {
    let dir = config::config_dir()?.join("tunnels");
    std::fs::create_dir_all(&dir)?;
    Ok(dir)
}

fn pid_path(name: &str) -> Result<PathBuf> {
    Ok(tunnels_dir()?.join(format!("{}.pid", name)))
}

fn log_path(name: &str) -> Result<PathBuf> {
    Ok(tunnels_dir()?.join(format!("{}.log", name)))
}

fn read_pid(name: &str) -> Result<Option<u32>> {
    if nonla_tunnel_protocol::validate_client_id(name).is_err() {
        return Ok(None);
    }
    let path = pid_path(name)?;
    if !path.exists() {
        return Ok(None);
    }
    let s = std::fs::read_to_string(&path)?;
    let pid: u32 = s.trim().parse().unwrap_or(0);
    if pid == 0 {
        return Ok(None);
    }
    if platform::is_pid_alive(pid) && platform::pid_is_tunnel(pid, name) {
        Ok(Some(pid))
    } else {
        let _ = std::fs::remove_file(&path);
        Ok(None)
    }
}

fn write_pid(name: &str, pid: u32) -> Result<()> {
    config::write_private(&pid_path(name)?, format!("{}\n", pid).as_bytes())?;
    Ok(())
}

fn list_running_tunnels() -> Result<Vec<(String, u32)>> {
    let dir = tunnels_dir()?;
    let mut out = Vec::new();
    for entry in std::fs::read_dir(dir)? {
        let entry = entry?;
        let name = entry.file_name();
        let name = name.to_string_lossy();
        if let Some(stem) = name.strip_suffix(".pid") {
            if let Some(pid) = read_pid(stem)? {
                out.push((stem.to_string(), pid));
            }
        }
    }
    out.sort_by(|a, b| a.0.cmp(&b.0));
    Ok(out)
}

fn cmd_config(cmd: ConfigCmd) -> Result<()> {
    match cmd.action {
        ConfigAction::Set(args) => {
            if args.token.starts_with(nonla_tunnel_protocol::INVITE_PREFIX) {
                anyhow::bail!(
                    "that is a one-time invite, not a token. Run:\n  nonla-tunnel enroll --server {} --invite {}",
                    args.server,
                    args.token
                );
            }
            let tls = !args.no_tls;
            let server = config::normalize_server_addr(&args.server, tls);
            if !tls && !config::is_loopback_host(&server) {
                eprintln!(
                    "⚠️  --no-tls: the token will be sent unencrypted to {}. Use TLS unless this is a trusted network.",
                    server
                );
            }
            if args.tls_skip_verify {
                eprintln!(
                    "⚠️  --tls-skip-verify: server certificate is NOT checked (MITM possible)."
                );
            }
            let cfg = config::NonlaTunnelConfig {
                server,
                token: args.token,
                tls: config::ClientTlsConfig {
                    enabled: tls,
                    server_name: args.tls_server_name,
                    skip_verify: args.tls_skip_verify,
                },
            };
            cfg.save()?;
            println!("Saved {}", config::config_path()?.display());
            println!("  server: {}", cfg.server);
            println!("  token:  {}", cfg.masked_token());
            Ok(())
        }
        ConfigAction::Show => {
            let cfg = config::NonlaTunnelConfig::load()?;
            println!("server: {}", cfg.server);
            println!("token:  {}", cfg.masked_token());
            println!("tls:    {}", cfg.tls.enabled);
            Ok(())
        }
    }
}

fn hostname_label() -> Option<String> {
    std::env::var("HOSTNAME")
        .ok()
        .or_else(|| std::fs::read_to_string("/etc/hostname").ok())
        .or_else(|| {
            ProcCommand::new("hostname")
                .output()
                .ok()
                .map(|o| String::from_utf8_lossy(&o.stdout).into_owned())
        })
        .map(|h| h.trim().to_string())
        .filter(|h| !h.is_empty())
}

async fn cmd_enroll(args: EnrollArgs) -> Result<()> {
    let invite = args.invite.trim().to_string();
    if !invite.starts_with(nonla_tunnel_protocol::INVITE_PREFIX) {
        anyhow::bail!(
            "invite must start with '{}' (got something else — a token goes to `config set`)",
            nonla_tunnel_protocol::INVITE_PREFIX
        );
    }
    let tls = !args.no_tls;
    let server = config::normalize_server_addr(&args.server, tls);
    if !tls && !config::is_loopback_host(&server) {
        eprintln!(
            "⚠️  --no-tls: the invite and credential travel unencrypted to {}.",
            server
        );
    }
    if args.tls_skip_verify {
        eprintln!("⚠️  --tls-skip-verify: server certificate is NOT checked (MITM possible).");
    }
    let tls_cfg = config::ClientTlsConfig {
        enabled: tls,
        server_name: args.tls_server_name,
        skip_verify: args.tls_skip_verify,
    };
    let enroller = client::Client::new(
        server.clone(),
        String::new(),
        String::new(),
        String::new(),
        String::new(),
        tls_cfg.clone(),
    );
    let res = enroller
        .enroll(&invite, args.label.or_else(hostname_label))
        .await?;
    let token = match (res.success, res.token) {
        (true, Some(t)) if t.starts_with(nonla_tunnel_protocol::CREDENTIAL_PREFIX) => t,
        (true, _) => anyhow::bail!("server returned no credential"),
        (false, _) => return Err(client::AuthError(res.message).into()),
    };
    let cfg = config::NonlaTunnelConfig {
        server,
        token,
        tls: tls_cfg,
    };
    cfg.save()?;
    println!(
        "Enrolled as {} — credential saved to {}",
        res.client_ref.as_deref().unwrap_or("?"),
        config::config_path()?.display()
    );
    println!("  server: {}", cfg.server);
    println!("  token:  {}", cfg.masked_token());
    println!("The invite is used up. Next: nonla-tunnel http 3000 --name my-app -d");
    Ok(())
}

fn cmd_status() -> Result<()> {
    match config::NonlaTunnelConfig::load() {
        Ok(cfg) => {
            println!("nonla-tunnel v{}", env!("CARGO_PKG_VERSION"));
            println!("server: {}", cfg.server);
            println!("token:  {}", cfg.masked_token());
        }
        Err(_) => {
            println!("nonla-tunnel v{}", env!("CARGO_PKG_VERSION"));
            println!(
                "Not configured. Run: nonla-tunnel enroll --server connect.<domain> --invite <nti_...>"
            );
        }
    }

    let running = list_running_tunnels()?;
    if running.is_empty() {
        println!("tunnels: (none running in background)");
    } else {
        println!("tunnels:");
        for (name, pid) in running {
            println!("  {}  pid={}", name, pid);
        }
        println!("Stop: nonla-tunnel stop <name>   or   nonla-tunnel stop");
    }
    Ok(())
}

fn cmd_stop(args: StopArgs) -> Result<()> {
    let targets: Vec<String> = if let Some(name) = args.name {
        nonla_tunnel_protocol::validate_client_id(&name)
            .map_err(|e| anyhow::anyhow!("invalid tunnel name '{}': {}", name, e))?;
        vec![name]
    } else {
        list_running_tunnels()?
            .into_iter()
            .map(|(n, _)| n)
            .collect()
    };

    if targets.is_empty() {
        println!("No background tunnels running.");
        return Ok(());
    }

    for name in targets {
        match read_pid(&name)? {
            Some(pid) => {
                platform::terminate(pid);
                let _ = std::fs::remove_file(pid_path(&name)?);
                println!("Stopped '{}' (pid {})", name, pid);
            }
            None => println!("'{}' is not running", name),
        }
    }
    Ok(())
}

fn spawn_detached(args: &HttpArgs, client_id: &str) -> Result<()> {
    if read_pid(client_id)?.is_some() {
        anyhow::bail!(
            "Tunnel '{}' is already running in background. Stop it with: nonla-tunnel stop {}",
            client_id,
            client_id
        );
    }

    let log = log_path(client_id)?;
    let log_file = OpenOptions::new()
        .create(true)
        .truncate(true)
        .write(true)
        .open(&log)
        .with_context(|| format!("open log {}", log.display()))?;
    let log_err = log_file.try_clone()?;

    let exe = std::env::current_exe().context("current_exe")?;
    let mut cmd = ProcCommand::new(exe);
    cmd.arg("http").arg(&args.addr).arg("--name").arg(client_id);
    cmd.arg("--daemon-child");
    cmd.stdin(Stdio::null());
    cmd.stdout(Stdio::from(log_file));
    cmd.stderr(Stdio::from(log_err));

    platform::detach(&mut cmd);

    let mut child = cmd.spawn().context("spawn background nonla-tunnel")?;
    let pid = child.id();
    write_pid(client_id, pid)?;

    // Wait until connected (Forwarding line) or timeout
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(15);
    let mut offset = 0u64;
    let mut forwarding = None::<String>;
    while std::time::Instant::now() < deadline {
        // try_wait (not kill(pid, 0)): an exited child stays a zombie until reaped.
        if matches!(child.try_wait(), Ok(Some(_)) | Err(_)) {
            let _ = std::fs::remove_file(pid_path(client_id)?);
            let log_text = std::fs::read_to_string(log_path(client_id)?).unwrap_or_default();
            anyhow::bail!("Background tunnel exited early. Log:\n{}", log_text.trim());
        }
        if let Ok(mut f) = std::fs::File::open(log_path(client_id)?) {
            let _ = f.seek(SeekFrom::Start(offset));
            let mut buf = String::new();
            let _ = f.read_to_string(&mut buf);
            offset += buf.len() as u64;
            for line in buf.lines() {
                if let Some(rest) = line.strip_prefix("Forwarding  ") {
                    forwarding = Some(rest.to_string());
                    break;
                }
            }
        }
        if forwarding.is_some() {
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(200));
    }

    println!("nonla-tunnel v{}", env!("CARGO_PKG_VERSION"));
    if let Some(fwd) = forwarding {
        println!("Forwarding  {}", fwd);
    } else {
        println!(
            "Started '{}' in background (pid {}). Still connecting…",
            client_id, pid
        );
    }
    println!("Log:    {}", log_path(client_id)?.display());
    println!("Stop:   nonla-tunnel stop {}", client_id);
    println!("Status: nonla-tunnel status");
    Ok(())
}

async fn cmd_http(args: HttpArgs) -> Result<()> {
    let cfg = config::NonlaTunnelConfig::load()?;
    let local_addr = config::normalize_local_addr(&args.addr);
    let client_id = args.name.clone().unwrap_or_else(config::generate_name);
    nonla_tunnel_protocol::validate_client_id(&client_id)
        .map_err(|e| anyhow::anyhow!("invalid --name '{}': {}", client_id, e))?;

    if args.detach && !args.daemon_child {
        return spawn_detached(&args, &client_id);
    }

    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("warn")),
        )
        .with_target(false)
        .init();

    let claim_key = config::claim_key(&client_id)?;
    let client = client::Client::new(
        cfg.server.clone(),
        local_addr.clone(),
        client_id.clone(),
        cfg.token.clone(),
        claim_key,
        cfg.tls.clone(),
    );

    let cancel = CancellationToken::new();
    let cancel_clone = cancel.clone();
    tokio::spawn(async move {
        tokio::signal::ctrl_c().await.ok();
        cancel_clone.cancel();
    });

    let (status_tx, mut status_rx) = watch::channel(client::TunnelStatus::Connecting);
    let mut printed = false;
    let quiet = args.daemon_child;

    println!("nonla-tunnel v{}", env!("CARGO_PKG_VERSION"));
    println!("Connecting to {} as '{}'...", cfg.server, client_id);

    let printer = tokio::spawn(async move {
        loop {
            if status_rx.changed().await.is_err() {
                break;
            }
            let status = status_rx.borrow().clone();
            if let client::TunnelStatus::Connected { route, .. } = status {
                if !printed {
                    println!();
                    println!("Forwarding  {} -> http://{}", route, local_addr);
                    if !quiet {
                        println!();
                        println!("Press Ctrl+C to stop");
                    }
                    printed = true;
                }
            }
        }
    });

    let result = run_with_reconnect(&client, cancel, status_tx).await;
    printer.abort();
    let _ = std::fs::remove_file(pid_path(&client_id)?);
    result.context("tunnel session")
}

/// A session lasting at least this long resets the reconnect backoff.
const STABLE_SESSION_SECS: u64 = 30;

async fn run_with_reconnect(
    client: &client::Client,
    cancel: CancellationToken,
    status_tx: watch::Sender<client::TunnelStatus>,
) -> Result<()> {
    let mut backoff = 1u64;
    loop {
        if cancel.is_cancelled() {
            return Ok(());
        }
        let started = std::time::Instant::now();
        let outcome = client
            .run_cancellable(cancel.clone(), status_tx.clone())
            .await;
        // A session that stayed up for a while was healthy: start over at 1s
        // instead of keeping the 30s cap from earlier failures.
        if started.elapsed() >= std::time::Duration::from_secs(STABLE_SESSION_SECS) {
            backoff = 1;
        }
        match outcome {
            Ok(()) => {
                if cancel.is_cancelled() {
                    return Ok(());
                }
                eprintln!("Session ended, reconnecting in {}s...", backoff);
            }
            Err(e) => {
                if cancel.is_cancelled() {
                    return Ok(());
                }
                if e.chain().any(|c| c.is::<client::AuthError>()) {
                    eprintln!("Error: {:#}", e);
                    return Err(e);
                }
                eprintln!("Error: {:#}. Reconnecting in {}s...", e, backoff);
            }
        }
        tokio::select! {
            _ = cancel.cancelled() => return Ok(()),
            _ = tokio::time::sleep(std::time::Duration::from_secs(backoff)) => {}
        }
        backoff = (backoff * 2).min(30);
    }
}
