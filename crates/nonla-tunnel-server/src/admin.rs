//! Local admin socket: lets the CLI (`sessions`, `kick`) query and control
//! the running server. Unix socket, mode 0600, next to `server.yaml` — no
//! network listener. One JSON request line in, one JSON response line out.

use crate::server::ControlCtx;
use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::Duration;

const MAX_REQUEST: usize = 4096;
const IO_TIMEOUT: Duration = Duration::from_secs(5);

#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "cmd", rename_all = "snake_case")]
pub enum AdminReq {
    Sessions,
    Kick {
        name: String,
        ban_secs: u64,
    },
    /// Forget a name's owner so another client can use it (also disconnects it).
    ReleaseName {
        name: String,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionInfo {
    pub name: String,
    pub url: String,
    /// Issued credential id; null = shared admin token.
    pub credential: Option<String>,
    pub label: Option<String>,
    /// Real client address (via PROXY protocol behind Traefik).
    pub peer: String,
    pub version: Option<String>,
    pub connected_at: u64,
    pub connected_secs: u64,
    pub requests: u64,
    pub bytes_in: u64,
    pub bytes_out: u64,
    pub active_streams: u64,
    pub missed_heartbeats: u32,
    pub healthy: bool,
}

#[derive(Debug, Default, Serialize, Deserialize)]
pub struct AdminRes {
    pub ok: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sessions: Option<Vec<SessionInfo>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kicked: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub released: Option<bool>,
}

/// Bind the socket with 0600 permissions. It is created inside a fresh 0700
/// directory and renamed into place, so it is never reachable with looser
/// permissions.
fn bind_private(path: &Path) -> Result<tokio::net::UnixListener> {
    let dir = path.parent().unwrap_or(Path::new("."));
    std::fs::create_dir_all(dir)?;
    if path.exists() {
        // A live server answers; a stale file from a crash does not.
        if std::os::unix::net::UnixStream::connect(path).is_ok() {
            anyhow::bail!(
                "admin socket {} is in use — is another server running?",
                path.display()
            );
        }
        std::fs::remove_file(path)?;
    }
    // sun_path holds 107 bytes + NUL. The temp socket is `<dir>/.aXXXXXXXX/s`.
    const SUN_PATH_MAX: usize = 107;
    let tmp_len = dir.as_os_str().len() + "/.a00000000/s".len();
    if path.as_os_str().len() > SUN_PATH_MAX || tmp_len > SUN_PATH_MAX {
        anyhow::bail!(
            "admin socket path too long ({} bytes): {} — set admin_socket to a shorter path",
            path.as_os_str().len(),
            path.display()
        );
    }
    let mut rnd = [0u8; 4];
    getrandom::getrandom(&mut rnd).map_err(|e| anyhow::anyhow!("getrandom: {e}"))?;
    let tmp_dir = dir.join(format!(
        ".a{}",
        rnd.iter().map(|b| format!("{:02x}", b)).collect::<String>()
    ));
    {
        use std::os::unix::fs::DirBuilderExt;
        std::fs::DirBuilder::new().mode(0o700).create(&tmp_dir)?;
    }
    let tmp_sock = tmp_dir.join("s");
    let result = (|| {
        let listener = std::os::unix::net::UnixListener::bind(&tmp_sock)?;
        crate::config::restrict_perms(&tmp_sock)?;
        std::fs::rename(&tmp_sock, path)?;
        listener.set_nonblocking(true)?;
        Ok::<_, std::io::Error>(listener)
    })();
    let _ = std::fs::remove_dir_all(&tmp_dir);
    Ok(tokio::net::UnixListener::from_std(result?)?)
}

pub async fn serve(path: PathBuf, ctx: Arc<ControlCtx>) {
    let listener = match bind_private(&path) {
        Ok(l) => l,
        Err(e) => {
            tracing::error!("⚠️  Admin socket disabled: {:#}", e);
            return;
        }
    };
    tracing::info!("🛠️  Admin socket: {}", path.display());
    loop {
        let (stream, _) = match listener.accept().await {
            Ok(s) => s,
            Err(e) => {
                tracing::warn!("admin accept: {}", e);
                tokio::time::sleep(Duration::from_millis(100)).await;
                continue;
            }
        };
        let ctx = ctx.clone();
        tokio::spawn(async move {
            if let Err(e) = handle(stream, ctx).await {
                tracing::debug!("admin request failed: {:#}", e);
            }
        });
    }
}

async fn handle(stream: tokio::net::UnixStream, ctx: Arc<ControlCtx>) -> Result<()> {
    use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
    let (rd, mut wr) = stream.into_split();
    let mut line = String::new();
    tokio::time::timeout(
        IO_TIMEOUT,
        BufReader::new(rd.take(MAX_REQUEST as u64)).read_line(&mut line),
    )
    .await
    .context("admin request timeout")??;
    let res = match serde_json::from_str::<AdminReq>(line.trim()) {
        Ok(req) => dispatch(req, &ctx).await,
        Err(e) => AdminRes {
            ok: false,
            error: Some(format!("bad request: {}", e)),
            ..Default::default()
        },
    };
    let mut out = serde_json::to_vec(&res)?;
    out.push(b'\n');
    wr.write_all(&out).await?;
    Ok(())
}

async fn dispatch(req: AdminReq, ctx: &Arc<ControlCtx>) -> AdminRes {
    match req {
        AdminReq::Sessions => AdminRes {
            ok: true,
            sessions: Some(collect_sessions(ctx).await),
            ..Default::default()
        },
        AdminReq::ReleaseName { name } => {
            if let Err(e) = nonla_tunnel_protocol::validate_client_id(&name) {
                return AdminRes {
                    ok: false,
                    error: Some(e),
                    ..Default::default()
                };
            }
            let released = ctx.claims.release(&name);
            let kicked = ctx.kick(&name, Duration::ZERO);
            AdminRes {
                ok: true,
                released: Some(released),
                kicked: Some(kicked),
                ..Default::default()
            }
        }
        AdminReq::Kick { name, ban_secs } => {
            if let Err(e) = nonla_tunnel_protocol::validate_client_id(&name) {
                return AdminRes {
                    ok: false,
                    error: Some(e),
                    ..Default::default()
                };
            }
            let ban = Duration::from_secs(ban_secs.min(crate::credentials::MAX_INVITE_TTL_SECS));
            AdminRes {
                ok: true,
                kicked: Some(ctx.kick(&name, ban)),
                ..Default::default()
            }
        }
    }
}

async fn collect_sessions(ctx: &Arc<ControlCtx>) -> Vec<SessionInfo> {
    // Credential labels live in the credentials file.
    let c = ctx.clone();
    let labels: std::collections::HashMap<String, String> =
        tokio::task::spawn_blocking(move || {
            c.creds
                .as_ref()
                .and_then(|s| s.snapshot().ok())
                .map(|d| d.clients.into_iter().map(|c| (c.id, c.label)).collect())
                .unwrap_or_default()
        })
        .await
        .unwrap_or_default();

    let now = crate::credentials::now_secs();
    let mut out: Vec<SessionInfo> = ctx
        .registry
        .entries()
        .into_iter()
        .filter_map(|entry| {
            let meta = entry.meta.get()?;
            let name = entry.client_id.clone();
            let label = meta
                .cred_id
                .as_ref()
                .and_then(|id| labels.get(id).cloned())
                .filter(|l| !l.is_empty());
            Some(SessionInfo {
                url: format!("https://{}.{}", name, ctx.config.domain),
                name,
                credential: meta.cred_id.clone(),
                label,
                peer: meta.peer.to_string(),
                version: meta.version.clone(),
                connected_at: meta.connected_unix,
                connected_secs: now.saturating_sub(meta.connected_unix),
                requests: entry.metrics.requests.load(Ordering::Relaxed),
                bytes_in: entry.metrics.bytes_in.load(Ordering::Relaxed),
                bytes_out: entry.metrics.bytes_out.load(Ordering::Relaxed),
                active_streams: entry.metrics.active_streams.load(Ordering::Relaxed),
                missed_heartbeats: entry.missed_heartbeats.load(Ordering::Relaxed),
                healthy: entry.is_alive(),
            })
        })
        .collect();
    out.sort_by(|a, b| a.name.cmp(&b.name));
    out
}

/// CLI side: send one request to the running server.
pub fn request(path: &Path, req: &AdminReq) -> Result<AdminRes> {
    use std::io::{BufRead, Write};
    let mut stream = std::os::unix::net::UnixStream::connect(path).with_context(|| {
        format!(
            "cannot reach the running server at {} — is `nonla-tunnel-server start` running (and are you the same user)?",
            path.display()
        )
    })?;
    stream.set_read_timeout(Some(IO_TIMEOUT))?;
    stream.set_write_timeout(Some(IO_TIMEOUT))?;
    let mut line = serde_json::to_vec(req)?;
    line.push(b'\n');
    stream.write_all(&line)?;
    let mut resp = String::new();
    std::io::BufReader::new(stream).read_line(&mut resp)?;
    let res: AdminRes = serde_json::from_str(resp.trim()).context("bad admin response")?;
    if !res.ok {
        anyhow::bail!(res.error.unwrap_or_else(|| "request failed".into()));
    }
    Ok(res)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn request_wire_format() {
        assert_eq!(
            serde_json::to_string(&AdminReq::Sessions).unwrap(),
            r#"{"cmd":"sessions"}"#
        );
        assert_eq!(
            serde_json::to_string(&AdminReq::Kick {
                name: "a".into(),
                ban_secs: 60
            })
            .unwrap(),
            r#"{"cmd":"kick","name":"a","ban_secs":60}"#
        );
    }

    #[tokio::test]
    async fn socket_is_private_and_stale_file_replaced() {
        let dir = std::env::temp_dir().join(format!("nonla-admin-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("admin.sock");
        std::fs::write(&path, "stale").unwrap();
        let _l = bind_private(&path).unwrap();
        use std::os::unix::fs::{FileTypeExt, PermissionsExt};
        let md = std::fs::metadata(&path).unwrap();
        assert!(md.file_type().is_socket());
        assert_eq!(md.permissions().mode() & 0o777, 0o600);
        // Second server must refuse to steal a live socket.
        assert!(bind_private(&path).is_err());
        // No temp dirs left behind.
        assert_eq!(std::fs::read_dir(&dir).unwrap().count(), 1);
        let _ = std::fs::remove_dir_all(&dir);
    }
}
