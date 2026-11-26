use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use tracing_subscriber::EnvFilter;

mod admin;
mod claims;
mod config;
mod credentials;
mod install;
mod metrics;
mod proxy;
mod proxy_protocol;
mod registry;
mod server;
mod traefik;

#[derive(Parser, Debug)]
#[command(
    name = "nonla-tunnel-server",
    about = "Nonla Tunnel server — run via Docker Compose with Traefik",
    version
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand, Debug)]
enum Command {
    /// Start the tunnel server in foreground (Docker).
    Start(StartArgs),
    /// Print the shared admin token(s). Prefer `invite` for agents.
    Token(TokenArgs),
    /// Create a one-time enrollment invite for a new client / agent.
    Invite(InviteArgs),
    /// List issued client credentials and pending invites.
    Clients(TokenArgs),
    /// Revoke a client credential (c_…) or delete a pending invite (i_…).
    Revoke(RevokeArgs),
    /// List tunnels currently connected to the running server.
    Sessions(SessionsArgs),
    /// Disconnect a connected tunnel (keeps its credential).
    Kick(KickArgs),
    /// Free a tunnel name from its current owner so another client can use it.
    ReleaseName(ReleaseNameArgs),
}

#[derive(Parser, Debug)]
struct ReleaseNameArgs {
    /// Tunnel name
    name: String,
    #[arg(long, env = "NONLA_CONFIG")]
    config: Option<String>,
}

#[derive(Parser, Debug)]
struct SessionsArgs {
    /// Print JSON (for scripts / agents)
    #[arg(long)]
    json: bool,
    #[arg(long, env = "NONLA_CONFIG")]
    config: Option<String>,
}

#[derive(Parser, Debug)]
struct KickArgs {
    /// Tunnel name
    name: String,
    /// Refuse reconnects of this name for this long (the client then exits).
    /// 0 = just drop the connection; the client reconnects.
    #[arg(long, default_value = "1m")]
    ban: String,
    #[arg(long, env = "NONLA_CONFIG")]
    config: Option<String>,
}

#[derive(Parser, Debug)]
struct TokenArgs {
    #[arg(long, env = "NONLA_CONFIG")]
    config: Option<String>,
}

#[derive(Parser, Debug)]
struct InviteArgs {
    /// Invite lifetime: 30m, 24h, 7d … (max 30d)
    #[arg(long, default_value = "24h")]
    ttl: String,
    /// Label stored with the credential (e.g. agent or machine name)
    #[arg(long, default_value = "")]
    label: String,
    /// Print only the invite code (for scripts)
    #[arg(long, short)]
    quiet: bool,
    #[arg(long, env = "NONLA_CONFIG")]
    config: Option<String>,
}

#[derive(Parser, Debug)]
struct RevokeArgs {
    /// Credential id (c_…) or invite id (i_…), from `clients`
    id: String,
    #[arg(long, env = "NONLA_CONFIG")]
    config: Option<String>,
}

#[derive(Parser, Debug)]
struct StartArgs {
    #[arg(long, env = "NONLA_DOMAIN")]
    domain: Option<String>,

    #[arg(long, env = "NONLA_TOKEN")]
    token: Option<String>,

    #[arg(long, env = "NONLA_CONTROL_PORT", default_value_t = 6200)]
    control_port: u16,

    #[arg(long, env = "NONLA_PUBLIC_PORT", default_value_t = 6210)]
    public_port: u16,

    #[arg(long, env = "NONLA_CONFIG")]
    config: Option<String>,

    #[arg(long)]
    force: bool,
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    match cli.command {
        Command::Start(args) => run_server(args).await,
        Command::Token(args) => print_token(args),
        Command::Invite(args) => cmd_invite(args),
        Command::Clients(args) => cmd_clients(args),
        Command::Revoke(args) => cmd_revoke(args),
        Command::Sessions(args) => cmd_sessions(args),
        Command::Kick(args) => cmd_kick(args),
        Command::ReleaseName(args) => cmd_release_name(args),
    }
}

fn cmd_release_name(args: ReleaseNameArgs) -> Result<()> {
    let cfg = load_effective_config(&resolve_config_path(args.config.as_ref()))?;
    let res = admin::request(
        &admin_socket(&cfg),
        &admin::AdminReq::ReleaseName {
            name: args.name.clone(),
        },
    )?;
    match (res.released.unwrap_or(false), res.kicked.unwrap_or(false)) {
        (true, true) => println!(
            "Released '{}' and disconnected its current session. The next client to connect owns it.",
            args.name
        ),
        (true, false) => println!("Released '{}'. The next client to connect owns it.", args.name),
        (false, _) => println!("'{}' had no owner; nothing to release.", args.name),
    }
    eprintln!("Note: if the old client still runs with its key it can reclaim the name first — revoke its credential.");
    Ok(())
}

fn admin_socket(cfg: &config::ServerConfig) -> std::path::PathBuf {
    cfg.admin_socket
        .clone()
        .expect("admin_socket filled by load_effective_config")
        .into()
}

fn human_bytes(n: u64) -> String {
    const U: [&str; 5] = ["B", "KB", "MB", "GB", "TB"];
    let mut v = n as f64;
    let mut i = 0;
    while v >= 1024.0 && i < U.len() - 1 {
        v /= 1024.0;
        i += 1;
    }
    if i == 0 {
        format!("{}B", n)
    } else {
        format!("{:.1}{}", v, U[i])
    }
}

fn human_duration(secs: u64) -> String {
    match secs {
        s if s < 60 => format!("{}s", s),
        s if s < 3600 => format!("{}m{}s", s / 60, s % 60),
        s if s < 86400 => format!("{}h{}m", s / 3600, (s % 3600) / 60),
        s => format!("{}d{}h", s / 86400, (s % 86400) / 3600),
    }
}

fn cmd_sessions(args: SessionsArgs) -> Result<()> {
    let cfg = load_effective_config(&resolve_config_path(args.config.as_ref()))?;
    let res = admin::request(&admin_socket(&cfg), &admin::AdminReq::Sessions)?;
    let sessions = res.sessions.unwrap_or_default();
    if args.json {
        println!("{}", serde_json::to_string_pretty(&sessions)?);
        return Ok(());
    }
    if sessions.is_empty() {
        println!("No tunnels connected.");
        return Ok(());
    }
    println!(
        "{:<20} {:<26} {:<22} {:>8} {:>7} {:>9} {:>9}  HEALTH",
        "NAME", "CLIENT", "PEER", "UPTIME", "REQS", "IN", "OUT"
    );
    for s in &sessions {
        let who = match (&s.credential, &s.label) {
            (Some(id), Some(l)) => format!("{} {}", id, l),
            (Some(id), None) => id.clone(),
            (None, _) => "admin-token".into(),
        };
        let who: String = who.chars().take(26).collect();
        let health = if s.healthy {
            "ok".to_string()
        } else {
            format!("stale ({} missed hb)", s.missed_heartbeats)
        };
        println!(
            "{:<20} {:<26} {:<22} {:>8} {:>7} {:>9} {:>9}  {}",
            s.name,
            who,
            s.peer,
            human_duration(s.connected_secs),
            s.requests,
            human_bytes(s.bytes_in),
            human_bytes(s.bytes_out),
            health
        );
    }
    println!("{} tunnel(s)", sessions.len());
    Ok(())
}

fn cmd_kick(args: KickArgs) -> Result<()> {
    let cfg = load_effective_config(&resolve_config_path(args.config.as_ref()))?;
    let ban_secs = if args.ban.trim() == "0" {
        0
    } else {
        credentials::parse_duration(&args.ban, 1)?
    };
    let res = admin::request(
        &admin_socket(&cfg),
        &admin::AdminReq::Kick {
            name: args.name.clone(),
            ban_secs,
        },
    )?;
    let kicked = res.kicked.unwrap_or(false);
    match (kicked, ban_secs) {
        (true, 0) => println!("Disconnected '{}' (it may reconnect).", args.name),
        (true, b) => println!(
            "Disconnected '{}'; reconnects refused for {}s (the client exits). To block it for good: revoke its credential.",
            args.name, b
        ),
        (false, 0) => anyhow::bail!("'{}' is not connected", args.name),
        (false, b) => println!(
            "'{}' is not connected; reconnects refused for {}s.",
            args.name, b
        ),
    }
    Ok(())
}

/// Load the config the way `start` sees it: env overrides applied and
/// state-file paths defaulted next to the config file.
fn load_effective_config(path: &std::path::Path) -> Result<config::ServerConfig> {
    let mut cfg = config::ServerConfig::load(path)
        .with_context(|| format!("load config {}", path.display()))?;
    apply_env_overrides(&mut cfg);
    fill_state_paths(&mut cfg, path);
    Ok(cfg)
}

fn fill_state_paths(cfg: &mut config::ServerConfig, config_path: &std::path::Path) {
    let dir = config_path
        .parent()
        .map(std::path::Path::to_path_buf)
        .unwrap_or_default();
    if cfg.claims_file.is_none() {
        cfg.claims_file = Some(dir.join("claims.json").to_string_lossy().into_owned());
    }
    if cfg.credentials_file.is_none() {
        cfg.credentials_file = Some(dir.join("credentials.json").to_string_lossy().into_owned());
    }
    if cfg.admin_socket.is_none() {
        cfg.admin_socket = Some(dir.join("admin.sock").to_string_lossy().into_owned());
    }
}

fn credential_store(cfg: &config::ServerConfig) -> credentials::CredentialStore {
    credentials::CredentialStore::new(
        cfg.credentials_file
            .clone()
            .expect("credentials_file filled by load_effective_config")
            .into(),
    )
}

/// `--server …` arguments a client needs for this deployment.
fn connect_args(cfg: &config::ServerConfig) -> String {
    let (server, flags) = cfg.client_endpoint();
    std::iter::once(format!("--server {}", server))
        .chain(flags)
        .collect::<Vec<_>>()
        .join(" ")
}

fn cmd_invite(args: InviteArgs) -> Result<()> {
    let cfg = load_effective_config(&resolve_config_path(args.config.as_ref()))?;
    let ttl = credentials::parse_ttl(&args.ttl)?;
    let (invite, code) = credential_store(&cfg).create_invite(ttl, &args.label)?;
    if args.quiet {
        println!("{}", code);
        return Ok(());
    }
    println!("{}", code);
    eprintln!();
    eprintln!(
        "One-time invite {} — expires {} ({}). Single use.",
        invite.id,
        credentials::fmt_time(invite.expires),
        args.ttl
    );
    eprintln!();
    eprintln!("Give the agent one of:");
    eprintln!("  Linux / macOS:");
    eprintln!(
        "    curl -fsSL https://{}/install | sh -s -- --invite {}",
        cfg.domain, code
    );
    eprintln!("  Windows (PowerShell):");
    eprintln!(
        "    $env:NONLA_INVITE='{}'; irm https://{}/install.ps1 | iex",
        code, cfg.domain
    );
    eprintln!("  Already installed:");
    eprintln!(
        "    nonla-tunnel enroll {} --invite {}",
        connect_args(&cfg),
        code
    );
    Ok(())
}

fn cmd_clients(args: TokenArgs) -> Result<()> {
    let cfg = load_effective_config(&resolve_config_path(args.config.as_ref()))?;
    let data = credential_store(&cfg).snapshot()?;
    let now = credentials::now_secs();
    println!("CLIENTS");
    if data.clients.is_empty() {
        println!("  (none)");
    }
    for c in &data.clients {
        let state = match c.revoked_at {
            Some(t) => format!("revoked {}", credentials::fmt_time(t)),
            None => "active".into(),
        };
        println!(
            "  {:<12} {:<22} created {}  last used {}  [{}]",
            c.id,
            if c.label.is_empty() { "-" } else { &c.label },
            credentials::fmt_time(c.created),
            credentials::fmt_time(c.last_used),
            state
        );
    }
    println!("PENDING INVITES");
    let pending: Vec<_> = data.invites.iter().filter(|i| i.expires > now).collect();
    if pending.is_empty() {
        println!("  (none)");
    }
    for i in pending {
        println!(
            "  {:<12} {:<22} expires {}",
            i.id,
            if i.label.is_empty() { "-" } else { &i.label },
            credentials::fmt_time(i.expires)
        );
    }
    Ok(())
}

fn cmd_revoke(args: RevokeArgs) -> Result<()> {
    let cfg = load_effective_config(&resolve_config_path(args.config.as_ref()))?;
    let store = credential_store(&cfg);
    let done = if args.id.starts_with("i_") {
        store.delete_invite(&args.id)?
    } else {
        store.revoke(&args.id)?
    };
    if !done {
        anyhow::bail!(
            "no active credential or pending invite with id '{}'",
            args.id
        );
    }
    if args.id.starts_with("i_") {
        println!("Deleted invite {} — it can no longer be used.", args.id);
    } else {
        println!(
            "Revoked {} — its connected sessions are dropped within ~15s.",
            args.id
        );
    }
    Ok(())
}

fn resolve_config_path(explicit: Option<&String>) -> std::path::PathBuf {
    explicit
        .map(std::path::PathBuf::from)
        .or_else(config::ServerConfig::resolve_config_path)
        .unwrap_or_else(config::ServerConfig::config_path)
}

/// Tokens are not written to logs; operators read them with this command
/// (e.g. `docker compose exec nonla-tunnel nonla-tunnel-server token`).
fn print_token(args: TokenArgs) -> Result<()> {
    let path = resolve_config_path(args.config.as_ref());
    let cfg = load_effective_config(&path)?;
    cfg.check_auth()?;
    for t in cfg.auth.tokens.iter().filter(|t| !t.is_empty()) {
        println!("{}", t);
    }
    eprintln!();
    eprintln!("Shared admin token — do not hand it to agents. For agents use:");
    eprintln!("  nonla-tunnel-server invite --label <name>");
    Ok(())
}

async fn run_server(args: StartArgs) -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .init();

    let config_path = resolve_config_path(args.config.as_ref());

    let mut cfg = if config_path.exists() && !args.force {
        config::ServerConfig::load(&config_path).context("load config")?
    } else {
        let domain = args.domain.clone().unwrap_or_else(|| {
            eprintln!("❌ --domain (or NONLA_DOMAIN) is required on first run");
            std::process::exit(1);
        });
        let cfg = build_config(&args, &domain);
        if let Some(parent) = config_path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let yaml = serde_yaml::to_string(&cfg)?;
        config::write_private(
            &config_path,
            format!(
                "# Nonla Tunnel Server Configuration\n# Config path: {}\n\n{}",
                config_path.display(),
                yaml
            )
            .as_bytes(),
        )?;
        tracing::info!("Config written to {}", config_path.display());
        cfg
    };

    apply_env_overrides(&mut cfg);
    cfg.check_auth()?;
    fill_state_paths(&mut cfg, &config_path);

    tracing::info!(
        "Nonla Tunnel Server v{} | Domain:*.{} | Control:{} | Public:{} | Traefik:{}",
        env!("CARGO_PKG_VERSION"),
        cfg.domain,
        cfg.control_port,
        cfg.public_port,
        cfg.traefik.enabled,
    );
    tracing::info!("Config: {}", config_path.display());
    tracing::info!("Install: https://{}/install", cfg.domain);
    tracing::info!("Client token: run `nonla-tunnel-server token` to print it");

    server::Server::new(cfg)
        .run()
        .await
        .context("server run failed")?;
    Ok(())
}

fn build_config(args: &StartArgs, domain: &str) -> config::ServerConfig {
    let client_token = args
        .token
        .as_ref()
        .filter(|t| !t.is_empty())
        .cloned()
        .unwrap_or_else(|| config::ServerConfig::generate_token(24));
    let mut cfg = config::ServerConfig {
        domain: domain.to_string(),
        control_port: args.control_port,
        public_port: args.public_port,
        ..Default::default()
    };
    cfg.auth.tokens = vec![client_token];
    cfg.traefik = traefik::TraefikConfig::auto_detect();
    cfg
}

fn apply_env_overrides(cfg: &mut config::ServerConfig) {
    if let Ok(dir) = std::env::var("NONLA_TRAEFIK_CONFIG_DIR") {
        cfg.traefik.enabled = true;
        cfg.traefik.config_dir = dir;
    }
    if let Ok(url) = std::env::var("NONLA_TRAEFIK_SERVICE_URL") {
        cfg.traefik.service_url = url;
    }
    if std::env::var("NONLA_TRAEFIK_ENABLED").ok().as_deref() == Some("true") {
        cfg.traefik.enabled = true;
    }
    if let Ok(addr) = std::env::var("NONLA_BIND_ADDR") {
        if !addr.is_empty() {
            cfg.bind_addr = Some(addr);
        }
    }
    // Env tokens always win when set (so .env changes apply without --force)
    if let Ok(token) = std::env::var("NONLA_TOKEN") {
        if !token.is_empty() {
            cfg.auth.tokens = vec![token];
        }
    }
}
