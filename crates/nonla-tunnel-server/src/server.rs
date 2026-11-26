//! Core server — control channel, public HTTP proxy, client install endpoint.

use crate::claims::ClaimStore;
use crate::config::ServerConfig;
use crate::credentials::CredentialStore;
use crate::install::{self, InstallState};
use crate::metrics::{AuthLimiter, Metrics, RateLimiter};
use crate::proxy;

use crate::registry::Registry;
use anyhow::{Context, Result};
use http_body_util::BodyExt;
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{Request, Response};
use hyper_util::rt::TokioIo;
use nonla_tunnel_protocol::*;
use std::future::poll_fn;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::task::Poll;
use std::time::Duration;
use tokio::net::TcpListener;
use tokio::sync::{mpsc, oneshot};
use tokio_util::compat::TokioAsyncReadCompatExt;

/// Command sent to the yamux driver task.
pub enum YamuxCmd {
    OpenStream {
        reply: oneshot::Sender<anyhow::Result<yamux::Stream>>,
    },
}

/// Handle to interact with the yamux driver — send commands to open streams.
#[derive(Clone)]
pub struct YamuxHandle {
    cmd_tx: mpsc::Sender<YamuxCmd>,
    abort: tokio::task::AbortHandle,
}

impl YamuxHandle {
    pub async fn open_stream(&self) -> anyhow::Result<yamux::Stream> {
        let (reply_tx, reply_rx) = oneshot::channel();
        self.cmd_tx
            .send(YamuxCmd::OpenStream { reply: reply_tx })
            .await
            .map_err(|_| anyhow::anyhow!("yamux driver gone"))?;
        reply_rx
            .await
            .map_err(|_| anyhow::anyhow!("yamux driver dropped"))?
    }

    pub fn abort(&self) {
        self.abort.abort();
    }

    #[allow(dead_code)]
    pub fn is_closed(&self) -> bool {
        self.cmd_tx.is_closed()
    }
}

#[cfg(test)]
impl YamuxHandle {
    pub fn mock() -> (Self, mpsc::Receiver<YamuxCmd>) {
        let (cmd_tx, cmd_rx) = mpsc::channel(1);
        let task = tokio::spawn(std::future::pending::<()>());
        (
            Self {
                cmd_tx,
                abort: task.abort_handle(),
            },
            cmd_rx,
        )
    }

    pub fn mock_closed() -> Self {
        let (cmd_tx, cmd_rx) = mpsc::channel(1);
        drop(cmd_rx);
        let task = tokio::spawn(async {});
        Self {
            cmd_tx,
            abort: task.abort_handle(),
        }
    }
}

enum DriveEvent {
    Inbound(Option<Result<yamux::Stream, yamux::ConnectionError>>),
    Outbound(Result<yamux::Stream, yamux::ConnectionError>),
}

/// Spawns a task that drives the yamux connection.
/// Returns a handle for opening outbound streams.
fn spawn_yamux_driver<S>(
    stream: S,
    mode: yamux::Mode,
    client_id: String,
    supports_heartbeat: bool,
    last_activity: Arc<std::sync::Mutex<std::time::Instant>>,
    missed_heartbeats: Arc<std::sync::atomic::AtomicU32>,
) -> (YamuxHandle, tokio::task::JoinHandle<()>)
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    let (cmd_tx, mut cmd_rx) = mpsc::channel::<YamuxCmd>(64);

    let task = tokio::spawn(async move {
        let compat = stream.compat();
        let cfg = yamux::Config::default();
        let mut conn = yamux::Connection::new(compat, cfg, mode);

        let mut heartbeat_interval =
            tokio::time::interval(Duration::from_secs(HEARTBEAT_INTERVAL_SECS));
        heartbeat_interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        heartbeat_interval.tick().await;
        const MAX_MISSED: u32 = 5;

        let mut pending_open: Option<oneshot::Sender<anyhow::Result<yamux::Stream>>> = None;
        let mut want_hb_stream = false;
        let mut hb_in_flight = false;
        let (hb_done_tx, mut hb_done_rx) = mpsc::channel::<Result<(), anyhow::Error>>(8);

        loop {
            let want_outbound = pending_open.is_some() || want_hb_stream;

            tokio::select! {
                event = poll_fn(|cx| {
                    match conn.poll_next_inbound(cx) {
                        Poll::Ready(v) => return Poll::Ready(DriveEvent::Inbound(v)),
                        Poll::Pending => {}
                    }
                    if want_outbound {
                        match conn.poll_new_outbound(cx) {
                            Poll::Ready(v) => return Poll::Ready(DriveEvent::Outbound(v)),
                            Poll::Pending => {}
                        }
                    }
                    Poll::Pending
                }) => {
                    match event {
                        DriveEvent::Inbound(result) => match result {
                            Some(Ok(_stream)) => {
                                tracing::debug!("Unexpected inbound stream from '{}'", client_id);
                            }
                            Some(Err(e)) => {
                                tracing::debug!("Yamux error for '{}': {}", client_id, e);
                                break;
                            }
                            None => {
                                tracing::info!("Yamux connection closed for '{}'", client_id);
                                break;
                            }
                        },
                        DriveEvent::Outbound(result) => match result {
                            Ok(stream) => {
                                if let Some(reply) = pending_open.take() {
                                    let _ = reply.send(Ok(stream));
                                } else if want_hb_stream {
                                    want_hb_stream = false;
                                    hb_in_flight = true;
                                    let tx = hb_done_tx.clone();
                                    tokio::spawn(async move {
                                        use futures::io::{AsyncReadExt, AsyncWriteExt};
                                        let result = tokio::time::timeout(
                                            Duration::from_secs(10),
                                            async {
                                                let mut stream = stream;
                                                stream.write_all(&[STREAM_TYPE_HEARTBEAT]).await?;
                                                let mut pong = [0u8; 1];
                                                stream.read_exact(&mut pong).await?;
                                                stream.close().await?;
                                                Ok::<(), anyhow::Error>(())
                                            },
                                        )
                                        .await;
                                        let mapped = match result {
                                            Ok(Ok(())) => Ok(()),
                                            Ok(Err(e)) => Err(e),
                                            Err(_) => Err(anyhow::anyhow!("heartbeat timeout")),
                                        };
                                        let _ = tx.send(mapped).await;
                                    });
                                }
                            }
                            Err(e) => {
                                if let Some(reply) = pending_open.take() {
                                    let _ = reply.send(Err(anyhow::anyhow!("yamux open: {}", e)));
                                }
                                if want_hb_stream && matches!(e, yamux::ConnectionError::TooManyStreams) {
                                    // Stream table full (load, not a dead link): retry next tick.
                                    want_hb_stream = false;
                                    tracing::debug!("Heartbeat deferred for '{}': too many streams", client_id);
                                } else if want_hb_stream {
                                    want_hb_stream = false;
                                    let n = missed_heartbeats.fetch_add(1, Ordering::Relaxed) + 1;
                                    tracing::warn!(
                                        "💔 Heartbeat open failed for '{}': {} ({}/{})",
                                        client_id,
                                        e,
                                        n,
                                        MAX_MISSED
                                    );
                                    if n >= MAX_MISSED {
                                        tracing::error!(
                                            "💀 Connection dead for '{}' — {} missed heartbeats, disconnecting",
                                            client_id,
                                            n
                                        );
                                        break;
                                    }
                                }
                            }
                        },
                    }
                }
                cmd = cmd_rx.recv(), if pending_open.is_none() => {
                    match cmd {
                        Some(YamuxCmd::OpenStream { reply }) => {
                            pending_open = Some(reply);
                        }
                        None => {
                            tracing::debug!("All yamux handles dropped for '{}'", client_id);
                            break;
                        }
                    }
                }
                _ = heartbeat_interval.tick(), if supports_heartbeat && !hb_in_flight && !want_hb_stream => {
                    want_hb_stream = true;
                }
                done = hb_done_rx.recv() => {
                    hb_in_flight = false;
                    match done {
                        Some(Ok(())) => {
                            missed_heartbeats.store(0, Ordering::Relaxed);
                            if let Ok(mut ts) = last_activity.lock() {
                                *ts = std::time::Instant::now();
                            }
                            tracing::trace!("💓 Heartbeat OK for '{}'", client_id);
                        }
                        Some(Err(e)) => {
                            let n = missed_heartbeats.fetch_add(1, Ordering::Relaxed) + 1;
                            tracing::warn!(
                                "💔 Heartbeat failed for '{}': {} ({}/{})",
                                client_id,
                                e,
                                n,
                                MAX_MISSED
                            );
                            if n >= MAX_MISSED {
                                tracing::error!(
                                    "💀 Connection dead for '{}' — {} missed heartbeats, disconnecting",
                                    client_id,
                                    n
                                );
                                break;
                            }
                        }
                        None => break,
                    }
                }
            }
        }
    });

    let handle = YamuxHandle {
        cmd_tx,
        abort: task.abort_handle(),
    };
    (handle, task)
}

/// Max control connections that have not finished auth yet.
const MAX_PREAUTH_CONNECTIONS: usize = 256;
/// Time a client gets to send its AuthReq.
const AUTH_TIMEOUT_SECS: u64 = 5;
/// Max control connections per client IP that have not finished auth.
const MAX_PREAUTH_PER_IP: usize = 8;
/// Delay before answering a wrong token.
const AUTH_FAILURE_DELAY_SECS: u64 = 1;
/// How often sessions are checked against revoked credentials.
const REVOCATION_CHECK_SECS: u64 = 15;
/// Housekeeping interval (idle Traefik routers, expired name claims).
const GC_INTERVAL_SECS: u64 = 3600;
/// Routers of disconnected tunnels are kept this long after last use so
/// reconnects never wait for a Traefik reload, then removed.
pub(crate) const ROUTER_IDLE_SECS: u64 = 24 * 3600;

/// Shared state for control-channel sessions.
pub(crate) struct ControlCtx {
    pub registry: Arc<Registry>,
    pub metrics: Arc<Metrics>,
    pub config: ServerConfig,
    pub traefik: Option<Arc<crate::traefik::TraefikManager>>,
    pub claims: ClaimStore,
    pub creds: Option<CredentialStore>,
    /// client_id → refuse reconnects until this instant (set by `kick --ban`).
    pub bans: dashmap::DashMap<String, std::time::Instant>,
    pub auth_limiter: AuthLimiter,
    pub preauth: Arc<tokio::sync::Semaphore>,
    /// Pending (pre-auth) connections per real client IP.
    pub preauth_per_ip: Arc<dashmap::DashMap<std::net::IpAddr, usize>>,
}

/// Holds one per-IP pre-auth slot; released on drop.
pub(crate) struct IpSlot {
    map: Arc<dashmap::DashMap<std::net::IpAddr, usize>>,
    ip: std::net::IpAddr,
}

impl IpSlot {
    /// Take a slot for `ip`, or `None` if it already has `max` pending.
    /// Loopback is exempt (direct local clients; behind Traefik real IPs
    /// come from the PROXY header).
    fn acquire(
        map: &Arc<dashmap::DashMap<std::net::IpAddr, usize>>,
        ip: std::net::IpAddr,
        max: usize,
    ) -> Option<Option<Self>> {
        if ip.is_loopback() {
            return Some(None);
        }
        let mut n = map.entry(ip).or_insert(0);
        if *n >= max {
            return None;
        }
        *n += 1;
        drop(n);
        Some(Some(Self {
            map: map.clone(),
            ip,
        }))
    }
}

impl Drop for IpSlot {
    fn drop(&mut self) {
        let empty = match self.map.get_mut(&self.ip) {
            Some(mut n) => {
                *n = n.saturating_sub(1);
                *n == 0
            }
            None => false,
        };
        if empty {
            self.map.remove_if(&self.ip, |_, n| *n == 0);
        }
    }
}

/// Both pre-auth slots (global + per IP), released together.
pub(crate) struct PreauthPermit {
    _global: tokio::sync::OwnedSemaphorePermit,
    _ip: Option<IpSlot>,
}

impl ControlCtx {
    /// Disconnect `client_id` (if connected) and optionally refuse
    /// reconnects for `ban`. Returns whether a session was dropped.
    pub fn kick(&self, client_id: &str, ban: Duration) -> bool {
        if !ban.is_zero() {
            self.bans
                .insert(client_id.to_string(), std::time::Instant::now() + ban);
        }
        match self.registry.get(client_id) {
            Some(entry) => {
                tracing::warn!(
                    "👢 '{}' kicked by operator (ban {}s)",
                    client_id,
                    ban.as_secs()
                );
                entry.handle.abort();
                true
            }
            None => false,
        }
    }

    /// Remaining ban for `client_id`, clearing expired entries.
    fn ban_remaining(&self, client_id: &str) -> Option<Duration> {
        let now = std::time::Instant::now();
        let until = *self.bans.get(client_id)?;
        if until > now {
            Some(until - now)
        } else {
            self.bans.remove(client_id);
            None
        }
    }
}

/// Core Nonla Tunnel server.
pub struct Server {
    config: ServerConfig,
}

impl Server {
    pub fn new(config: ServerConfig) -> Self {
        Self { config }
    }

    pub async fn run(&self) -> Result<()> {
        let registry = Arc::new(Registry::with_stream_limit(
            self.config.rate_limit.max_connections_per_client as usize,
        ));
        let metrics = Arc::new(Metrics::new());
        let rate_limiter = Arc::new(RateLimiter::new(self.config.rate_limit.requests_per_second));

        // ── Validate domain ──
        if self.config.domain.is_empty() {
            anyhow::bail!(
                "domain is required — run `nonla-tunnel-server setup --domain <domain>` first"
            );
        }
        let domain = &self.config.domain;
        self.config.check_domain()?;
        self.config.check_auth()?;
        let bind = self.config.effective_bind_addr();

        let claims = ClaimStore::load(self.config.claims_file.as_ref().map(Into::into))
            .context("load tunnel claims")?;

        // ── Bind control port ──
        let control_listener = TcpListener::bind((bind.as_str(), self.config.control_port))
            .await
            .with_context(|| format!("bind control port {}:{}", bind, self.config.control_port))?;
        tracing::info!(
            "🔌 Control channel on {}:{}",
            bind,
            self.config.control_port
        );
        if bind != "127.0.0.1" && bind != "::1" && bind != "localhost" {
            tracing::warn!(
                "⚠️  Control channel is plaintext on {}:{} — clients should connect through TLS (Traefik connect.{}:443)",
                bind,
                self.config.control_port,
                domain
            );
        }

        // ── Traefik dynamic routes ──
        let traefik_manager = if self.config.traefik.enabled {
            let mgr = Arc::new(crate::traefik::TraefikManager::new(
                self.config.traefik.clone(),
                domain.clone(),
                self.config.control_port,
            ));
            if let Err(e) = mgr.write_static_routes() {
                tracing::warn!("⚠️  Traefik static routes failed: {:#}", e);
            } else {
                tracing::info!(
                    "🔀 Traefik enabled — dynamic dir: {}",
                    self.config.traefik.config_dir
                );
            }
            Some(mgr)
        } else {
            None
        };

        // ── Client install endpoint (apex host) ──
        let (server, enroll_flags) = self.config.client_endpoint();
        let install_state = InstallState {
            version: env!("CARGO_PKG_VERSION").to_string(),
            server,
            enroll_flags,
        };

        tracing::info!(
            "📦 Client install: https://{0}/install (Linux/macOS), https://{0}/install.ps1 (Windows)",
            domain
        );

        // ── Spawn control channel acceptor ──
        let ctx = Arc::new(ControlCtx {
            registry: registry.clone(),
            metrics: metrics.clone(),
            config: self.config.clone(),
            traefik: traefik_manager.clone(),
            claims,
            creds: self
                .config
                .credentials_file
                .as_ref()
                .map(|p| CredentialStore::new(p.into())),
            bans: dashmap::DashMap::new(),
            auth_limiter: AuthLimiter::new(),
            preauth: Arc::new(tokio::sync::Semaphore::new(MAX_PREAUTH_CONNECTIONS)),
            preauth_per_ip: Arc::new(dashmap::DashMap::new()),
        });
        if let Some(store) = &ctx.creds {
            tracing::info!(
                "🎟️  Enrollment enabled — credentials: {}",
                store.path().display()
            );
        }
        if let Some(path) = self.config.admin_socket.clone() {
            let ctx_admin = ctx.clone();
            tokio::spawn(async move {
                crate::admin::serve(path.into(), ctx_admin).await;
            });
        }
        let ctx_gc = ctx.clone();
        tokio::spawn(async move {
            Self::housekeeping(ctx_gc).await;
        });
        let ctx_rev = ctx.clone();
        tokio::spawn(async move {
            Self::watch_revocations(ctx_rev).await;
        });
        let control_task = tokio::spawn(async move {
            Self::accept_clients(control_listener, ctx).await;
        });

        // ── Public HTTP listener (subdomain proxy + install) ──
        let public_listener = TcpListener::bind((bind.as_str(), self.config.public_port))
            .await
            .with_context(|| format!("bind public port {}:{}", bind, self.config.public_port))?;
        tracing::info!("🌐 Public HTTP on {}:{}", bind, self.config.public_port);

        let install_router = install::create_router(install_state);

        let reg_pub = registry.clone();
        let met_pub = metrics.clone();
        let rl_pub = rate_limiter.clone();
        let dom = domain.clone();
        let public_task = tokio::spawn(async move {
            Self::accept_public(
                public_listener,
                reg_pub,
                met_pub,
                rl_pub,
                dom,
                install_router,
            )
            .await;
        });

        tracing::info!("✅ Nonla Tunnel Server ready!");

        // ── Wait for shutdown ──
        let shutdown = async {
            tokio::signal::ctrl_c().await.ok();
            tracing::info!("🛑 Shutdown signal received, cleaning up...");
        };

        tokio::select! {
            _ = shutdown => {}
            _ = control_task => {
                tracing::error!("Control task ended unexpectedly");
            }
        }

        // ── Graceful cleanup ──
        tracing::info!("🧹 Cleaning up...");
        public_task.abort();

        // Keep Traefik client routers across restarts. Deleting them here used
        // to leave public hosts on Traefik 404 until every client reconnected —
        // and a wedged "already registered" session never rewrote the YAML.

        let connected = registry.count();
        if connected > 0 {
            tracing::info!("🔌 Disconnecting {} client(s)...", connected);
        }

        let snap = metrics.snapshot();
        tracing::info!(
            "📊 Final stats: {} requests served, {} connections total, uptime {}s",
            snap.total_requests,
            snap.total_connections,
            snap.uptime_secs
        );
        tracing::info!("👋 Nonla Tunnel Server stopped.");

        Ok(())
    }

    /// Accept and handle control channel connections from tunnel clients.
    async fn accept_clients(listener: TcpListener, ctx: Arc<ControlCtx>) {
        loop {
            match listener.accept().await {
                Ok((mut stream, peer)) => {
                    if ctx.auth_limiter.is_blocked(peer.ip()) {
                        tracing::debug!("🚫 {} blocked after repeated auth failures", peer);
                        continue; // drop the connection
                    }
                    let Ok(permit) = ctx.preauth.clone().try_acquire_owned() else {
                        tracing::warn!(
                            "🚫 Too many pending control connections, dropping {}",
                            peer
                        );
                        continue;
                    };
                    ctx.metrics
                        .total_connections
                        .fetch_add(1, Ordering::Relaxed);

                    if let Err(e) = Self::configure_tcp_keepalive(&stream) {
                        tracing::warn!("⚠️  TCP keepalive failed for {}: {}", peer, e);
                    }

                    let ctx = ctx.clone();
                    tokio::spawn(async move {
                        // Real client address from Traefik's PROXY header. Only
                        // parsed when Traefik is configured to send it (else a
                        // client could forge one) and only from loopback peers.
                        let addr = if ctx.config.traefik.enabled
                            && ctx.config.traefik.proxy_protocol
                        {
                            match tokio::time::timeout(
                                Duration::from_secs(AUTH_TIMEOUT_SECS),
                                crate::proxy_protocol::read_client_addr(&mut stream, peer),
                            )
                            .await
                            {
                                Ok(Ok(a)) => a,
                                Ok(Err(e)) => {
                                    tracing::warn!("PROXY header from {} rejected: {:#}", peer, e);
                                    return;
                                }
                                Err(_) => {
                                    tracing::debug!("PROXY header timeout from {}", peer);
                                    return;
                                }
                            }
                        } else {
                            peer
                        };
                        if addr != peer && ctx.auth_limiter.is_blocked(addr.ip()) {
                            tracing::debug!("🚫 {} blocked after repeated auth failures", addr);
                            return;
                        }
                        let Some(ip_slot) =
                            IpSlot::acquire(&ctx.preauth_per_ip, addr.ip(), MAX_PREAUTH_PER_IP)
                        else {
                            tracing::warn!("🚫 Too many pending connections from {}", addr.ip());
                            return;
                        };
                        let permit = PreauthPermit {
                            _global: permit,
                            _ip: ip_slot,
                        };
                        tracing::info!("📡 Client connecting from {}", addr);
                        if let Err(e) = Self::handle_client(stream, addr, ctx, permit).await {
                            tracing::warn!("Client {} error: {:#}", addr, e);
                        }
                    });
                }
                Err(e) => {
                    tracing::error!("Control accept error: {}", e);
                    tokio::time::sleep(std::time::Duration::from_millis(100)).await;
                }
            }
        }
    }

    /// Periodically drop idle Traefik routers and expired name claims, so
    /// one-off names (e.g. random `tunnel-xxxx`) do not accumulate forever
    /// in the shared Traefik config.
    async fn housekeeping(ctx: Arc<ControlCtx>) {
        let mut tick = tokio::time::interval(Duration::from_secs(GC_INTERVAL_SECS));
        loop {
            tick.tick().await;
            let c = ctx.clone();
            let _ = tokio::task::spawn_blocking(move || Self::gc_once(&c)).await;
        }
    }

    pub(crate) fn gc_once(ctx: &ControlCtx) {
        let connected = |n: &str| ctx.registry.get(n).is_some();
        let claims = ctx.claims.gc(connected);
        if claims > 0 {
            tracing::info!("🧹 Released {} expired tunnel name claim(s)", claims);
        }
        if let Some(mgr) = &ctx.traefik {
            if let Err(e) =
                mgr.gc_idle_routes(ROUTER_IDLE_SECS, connected, |n| ctx.claims.last_seen(n))
            {
                tracing::warn!("⚠️  Traefik route cleanup failed: {:#}", e);
            }
        }
    }

    /// Disconnect sessions whose credential was revoked (by the CLI, which
    /// edits the credentials file while the server runs).
    async fn watch_revocations(ctx: Arc<ControlCtx>) {
        let mut tick = tokio::time::interval(Duration::from_secs(REVOCATION_CHECK_SECS));
        loop {
            tick.tick().await;
            let with_creds: Vec<_> = ctx
                .registry
                .entries()
                .into_iter()
                .filter(|e| e.meta.get().is_some_and(|m| m.cred_id.is_some()))
                .collect();
            if with_creds.is_empty() {
                continue;
            }
            let c = ctx.clone();
            let snap =
                tokio::task::spawn_blocking(move || c.creds.as_ref().map(|s| s.snapshot())).await;
            let Ok(Some(Ok(data))) = snap else { continue };
            for entry in with_creds {
                let Some(cred_id) = entry.meta.get().and_then(|m| m.cred_id.clone()) else {
                    continue;
                };
                if !CredentialStore::is_active_id(&data, &cred_id) {
                    tracing::warn!(
                        "⛔ Credential {} revoked — disconnecting '{}'",
                        cred_id,
                        entry.client_id
                    );
                    entry.handle.abort();
                }
            }
        }
    }

    /// Handle an enrollment request: burn the invite, issue a credential.
    async fn handle_enroll<S>(
        mut stream: S,
        addr: std::net::SocketAddr,
        ctx: Arc<ControlCtx>,
        req: EnrollReq,
    ) -> Result<()>
    where
        S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
    {
        type Redeemed = std::result::Result<(crate::credentials::Credential, String), String>;
        let c = ctx.clone();
        let result: Redeemed = tokio::task::spawn_blocking(move || -> Result<Redeemed> {
            let Some(store) = c.creds.as_ref() else {
                return Ok(Err("enrollment is not enabled on this server".into()));
            };
            if !req.invite.starts_with(INVITE_PREFIX) {
                return Ok(Err("invalid or expired invite".into()));
            }
            store.redeem(&req.invite, req.label.as_deref())
        })
        .await
        .context("enroll task")??;

        let res = match result {
            Ok((cred, token)) => {
                tracing::info!("🎟️  Enrolled {} '{}' from {}", cred.id, cred.label, addr);
                EnrollRes {
                    success: true,
                    message: format!("Enrolled as {}", cred.id),
                    token: Some(token),
                    client_ref: Some(cred.id),
                }
            }
            Err(reason) => {
                tokio::time::sleep(Duration::from_secs(AUTH_FAILURE_DELAY_SECS)).await;
                ctx.metrics.failed_auth.fetch_add(1, Ordering::Relaxed);
                ctx.auth_limiter.record_failure(addr.ip());
                tracing::warn!("❌ Enrollment rejected from {}: {}", addr, reason);
                EnrollRes {
                    success: false,
                    message: reason,
                    token: None,
                    client_ref: None,
                }
            }
        };
        write_message(&mut stream, &Message::EnrollRes(res)).await?;
        Ok(())
    }

    /// Check an AuthReq. Returns the issued-credential id (None = shared
    /// token) or the rejection message.
    /// Order: token → name syntax → reserved → ownership claim.
    fn authorize(ctx: &ControlCtx, auth: &AuthReq) -> std::result::Result<Option<String>, String> {
        let cred_id = if ctx.config.validate_token(&auth.token) {
            None
        } else {
            match ctx.creds.as_ref().map(|s| s.authenticate(&auth.token)) {
                Some(Ok(Some(id))) => Some(id),
                Some(Err(e)) => {
                    tracing::error!("credential store error: {:#}", e);
                    return Err("Server error (temporary)".into());
                }
                _ => return Err("Invalid token".into()),
            }
        };
        validate_client_id(&auth.client_id).map_err(|e| format!("Invalid tunnel name: {}", e))?;
        if crate::config::RESERVED_SUBDOMAINS.contains(&auth.client_id.as_str()) {
            return Err(format!("Tunnel name '{}' is reserved", auth.client_id));
        }
        if let Some(left) = ctx.ban_remaining(&auth.client_id) {
            return Err(format!(
                "tunnel '{}' was disconnected by the operator; reconnect allowed in {}s",
                auth.client_id,
                left.as_secs() + 1
            ));
        }
        let connected = ctx.registry.get(&auth.client_id).is_some();
        let Some(claim_key) = auth.claim_key.as_deref() else {
            return Err("client did not send a claim key — use nonla-tunnel 0.1.0 or newer".into());
        };
        ctx.claims.check(&auth.client_id, claim_key, connected)?;
        Ok(cred_id)
    }

    /// Handle a single client session: auth → yamux → serve streams.
    async fn handle_client<S>(
        mut stream: S,
        addr: std::net::SocketAddr,
        ctx: Arc<ControlCtx>,
        preauth_permit: PreauthPermit,
    ) -> Result<()>
    where
        S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
    {
        let registry = ctx.registry.clone();
        let metrics = ctx.metrics.clone();
        let config = &ctx.config;

        let auth_msg = match tokio::time::timeout(
            std::time::Duration::from_secs(AUTH_TIMEOUT_SECS),
            read_message_max(&mut stream, MAX_AUTH_PAYLOAD_SIZE),
        )
        .await
        {
            Ok(m) => m.context("read auth message")?,
            Err(_) => {
                // Idle connections count as failures so they cannot be used
                // to hold pre-auth slots for free.
                ctx.auth_limiter.record_failure(addr.ip());
                anyhow::bail!(
                    "auth timeout: client did not send AuthReq within {}s",
                    AUTH_TIMEOUT_SECS
                );
            }
        };

        let (client_id, supports_heartbeat, cred_id, version) = match auth_msg {
            Message::EnrollReq(req) => {
                drop(preauth_permit);
                return Self::handle_enroll(stream, addr, ctx.clone(), req).await;
            }
            Message::AuthReq(auth) => {
                // {:?} escapes control characters in the not-yet-validated name.
                tracing::info!("🔑 Auth from {:?} ({})", auth.client_id, addr);

                // authorize() may touch the credentials file (blocking + flock).
                let c = ctx.clone();
                let (auth, verdict) = tokio::task::spawn_blocking(move || {
                    let v = Self::authorize(&c, &auth);
                    (auth, v)
                })
                .await
                .context("auth task")?;

                let cred_id = match verdict {
                    Ok(id) => id,
                    Err(reason) => {
                        // Free the pre-auth slot before the penalty sleep.
                        drop(preauth_permit);
                        let bad_token = reason == "Invalid token";
                        if bad_token {
                            // Slow down guessing on this connection only.
                            tokio::time::sleep(Duration::from_secs(AUTH_FAILURE_DELAY_SECS)).await;
                        }
                        let res = Message::AuthRes(AuthRes {
                            success: false,
                            message: reason.clone(),
                            public_port: None,
                            assigned_route: None,
                        });
                        write_message(&mut stream, &res).await?;
                        if bad_token {
                            metrics.failed_auth.fetch_add(1, Ordering::Relaxed);
                            ctx.auth_limiter.record_failure(addr.ip());
                        }
                        tracing::warn!(
                            "❌ Auth rejected for {:?} ({}): {}",
                            auth.client_id,
                            addr,
                            reason
                        );
                        return Ok(());
                    }
                };
                ctx.auth_limiter.record_success(addr.ip());

                let res = Message::AuthRes(AuthRes {
                    success: true,
                    message: format!("OK — {}.{}", auth.client_id, config.domain),
                    public_port: Some(config.public_port),
                    assigned_route: Some(auth.client_id.clone()),
                });
                write_message(&mut stream, &res).await?;

                tracing::info!(
                    "✅ '{}' authenticated → {}.{}",
                    auth.client_id,
                    auth.client_id,
                    config.domain
                );

                let supports_hb = auth.supports_heartbeat();
                (auth.client_id, supports_hb, cred_id, auth.version)
            }
            other => {
                tracing::warn!("Expected AuthReq, got {:?}", other);
                return Ok(());
            }
        };
        drop(preauth_permit);

        let last_activity = Arc::new(std::sync::Mutex::new(std::time::Instant::now()));
        let missed_heartbeats = Arc::new(std::sync::atomic::AtomicU32::new(0));
        let (yamux_handle, driver_task) = spawn_yamux_driver(
            stream,
            yamux::Mode::Server,
            client_id.clone(),
            supports_heartbeat,
            last_activity.clone(),
            missed_heartbeats.clone(),
        );

        let entry = match registry.register(
            client_id.clone(),
            yamux_handle.clone(),
            supports_heartbeat,
            last_activity,
            missed_heartbeats,
        ) {
            Ok((e, replaced)) => {
                if replaced {
                    tracing::info!(
                        "♻️  Took over session for '{}' (total: {})",
                        client_id,
                        registry.count()
                    );
                } else {
                    tracing::info!(
                        "🟢 Client '{}' registered (total: {})",
                        client_id,
                        registry.count()
                    );
                }
                e
            }
            Err(e) => {
                tracing::warn!("Registration failed for '{}': {}", client_id, e);
                driver_task.abort();
                return Ok(());
            }
        };

        // Always (re)write the Traefik router — repairs a missing YAML if the
        // file was deleted while a zombie session still held the name.
        let _ = entry.meta.set(crate::registry::SessionMeta {
            cred_id,
            peer: addr,
            version,
            connected_unix: crate::credentials::now_secs(),
        });

        if let Some(ref mgr) = ctx.traefik {
            if let Err(e) = mgr.add_client(&client_id) {
                tracing::warn!("⚠️  Traefik add route failed: {:#}", e);
            }
        }

        let _ = driver_task.await;

        // Only drop the registry slot if this session is still current.
        // A takeover registers a new session_id; the old task must not
        // unregister the replacement. Keep the Traefik YAML so reconnects
        // do not wait for a file-provider reload.
        ctx.claims.touch(&client_id);
        if registry.unregister(&client_id, entry.session_id) {
            tracing::info!(
                "🔴 Client '{}' disconnected (remaining: {})",
                client_id,
                registry.count()
            );
        } else {
            tracing::debug!(
                "♻️  Session for '{}' already replaced — skipping unregister",
                client_id
            );
        }

        Ok(())
    }

    /// Accept public HTTP connections — tunnel proxy + install endpoint.
    async fn accept_public(
        listener: TcpListener,
        registry: Arc<Registry>,
        metrics: Arc<Metrics>,
        rate_limiter: Arc<RateLimiter>,
        domain: String,
        install_router: axum::Router,
    ) {
        loop {
            let (tcp_stream, addr) = match listener.accept().await {
                Ok(s) => s,
                Err(e) => {
                    tracing::error!("Public accept error: {}", e);
                    tokio::time::sleep(std::time::Duration::from_millis(100)).await;
                    continue;
                }
            };

            let reg = registry.clone();
            let met = metrics.clone();
            let rl = rate_limiter.clone();
            let dom = domain.clone();
            let inst = install_router.clone();

            tokio::spawn(async move {
                let result =
                    Self::serve_http(TokioIo::new(tcp_stream), reg, met, rl, dom, inst).await;
                if let Err(e) = result {
                    tracing::debug!("HTTP error from {}: {}", addr, e);
                }
            });
        }
    }

    /// Serve a single HTTP connection — apex host → install router, subdomains → tunnel proxy.
    async fn serve_http<I>(
        io: I,
        registry: Arc<Registry>,
        metrics: Arc<Metrics>,
        rate_limiter: Arc<RateLimiter>,
        domain: String,
        install_router: axum::Router,
    ) -> Result<()>
    where
        I: hyper::rt::Read + hyper::rt::Write + Unpin + Send + 'static,
    {
        http1::Builder::new()
            .serve_connection(
                io,
                service_fn(move |req: Request<hyper::body::Incoming>| {
                    let reg = registry.clone();
                    let met = metrics.clone();
                    let rl = rate_limiter.clone();
                    let dom = domain.clone();
                    let inst = install_router.clone();
                    async move {
                        // Check Host header to decide routing
                        let host = req
                            .headers()
                            .get("host")
                            .and_then(|v| v.to_str().ok())
                            .unwrap_or("");
                        let host_no_port = host.split(':').next().unwrap_or(host);

                        // Installers on the apex host only
                        if host_no_port == dom {
                            Self::handle_install(req, inst).await
                        } else {
                            proxy::handle_proxy_request(req, reg, met, rl, dom).await
                        }
                    }
                }),
            )
            .await
            .context("serve HTTP connection")?;
        Ok(())
    }

    /// Forward a request to the install axum app.
    async fn handle_install(
        req: Request<hyper::body::Incoming>,
        router: axum::Router,
    ) -> Result<Response<proxy::BoxBody>, hyper::Error> {
        use tower::ServiceExt;

        // Convert hyper Incoming body → axum Body
        let (parts, body) = req.into_parts();
        let axum_body = axum::body::Body::new(body);
        let axum_req = Request::from_parts(parts, axum_body);

        // Call the axum router
        let axum_resp = router.oneshot(axum_req).await.unwrap_or_else(|_| {
            Response::builder()
                .status(500)
                .body(axum::body::Body::empty())
                .unwrap()
        });

        // Convert axum response → proxy BoxBody by collecting bytes
        let (parts, axum_body) = axum_resp.into_parts();
        let collected = axum_body
            .collect()
            .await
            .unwrap_or_else(|_| http_body_util::Collected::default());
        let box_body = http_body_util::Full::new(collected.to_bytes())
            .map_err(|never| match never {})
            .boxed();

        Ok(Response::from_parts(parts, box_body))
    }

    /// Configure TCP keepalive on a client socket.
    fn configure_tcp_keepalive(stream: &tokio::net::TcpStream) -> Result<()> {
        use socket2::SockRef;

        let sock = SockRef::from(stream);
        let keepalive = socket2::TcpKeepalive::new()
            .with_time(Duration::from_secs(HEARTBEAT_INTERVAL_SECS))
            .with_interval(Duration::from_secs(5));

        #[cfg(target_os = "linux")]
        let keepalive = keepalive.with_retries(3);

        sock.set_tcp_keepalive(&keepalive)
            .context("set TCP keepalive")?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn per_ip_preauth_slots() {
        let map = Arc::new(dashmap::DashMap::new());
        let ip: std::net::IpAddr = "203.0.113.5".parse().unwrap();
        let slots: Vec<_> = (0..3)
            .map(|_| IpSlot::acquire(&map, ip, 3).unwrap())
            .collect();
        assert!(
            IpSlot::acquire(&map, ip, 3).is_none(),
            "4th from same IP refused"
        );
        let other: std::net::IpAddr = "203.0.113.6".parse().unwrap();
        assert!(
            IpSlot::acquire(&map, other, 3).is_some(),
            "other IPs unaffected"
        );
        drop(slots);
        assert!(map.get(&ip).is_none(), "entry removed when last slot drops");
        assert!(IpSlot::acquire(&map, ip, 3).is_some());
        let lo: std::net::IpAddr = "127.0.0.1".parse().unwrap();
        for _ in 0..10 {
            assert!(
                matches!(IpSlot::acquire(&map, lo, 3), Some(None)),
                "loopback exempt"
            );
        }
    }
}
