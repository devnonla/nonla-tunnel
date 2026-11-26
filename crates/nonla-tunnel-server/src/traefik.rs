//! Traefik file-provider integration (host Traefik + shared dynamic dir).
//!
//! Layout:
//! - `_nonla-tunnel-base.yml` — shared service + apex router (install endpoint)
//!   + TLS-terminating TCP router `connect.<domain>:443` → control channel
//! - `nonla-tunnel-{client}.yml` — router only, points at shared service

use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

const SHARED_SERVICE: &str = "nonla-tunnel-server";
const CONTROL_SERVICE: &str = "nonla-tunnel-control";
const BASE_FILE: &str = "_nonla-tunnel-base.yml";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TraefikConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default = "default_config_dir")]
    pub config_dir: String,
    #[serde(default = "default_entrypoint")]
    pub entrypoint: String,
    #[serde(default = "default_cert_resolver")]
    pub cert_resolver: String,
    #[serde(default = "default_service_url")]
    pub service_url: String,
    /// Backend address for the control channel TCP router.
    /// Unset = `127.0.0.1:<control_port>`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub control_address: Option<String>,
    /// Send PROXY protocol v2 to the control channel so the server sees real
    /// client IPs (sessions list, per-IP auth throttling).
    #[serde(default = "default_true")]
    pub proxy_protocol: bool,
}

fn default_true() -> bool {
    true
}

impl Default for TraefikConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            config_dir: default_config_dir(),
            entrypoint: default_entrypoint(),
            cert_resolver: default_cert_resolver(),
            service_url: default_service_url(),
            control_address: None,
            proxy_protocol: true,
        }
    }
}

fn default_config_dir() -> String {
    "/etc/traefik/dynamic".into()
}
fn default_entrypoint() -> String {
    "websecure".into()
}
fn default_cert_resolver() -> String {
    "letsencrypt".into()
}
fn default_service_url() -> String {
    "http://127.0.0.1:6210".into()
}

impl TraefikConfig {
    pub fn auto_detect() -> Self {
        for dir in ["/etc/traefik/dynamic", "/etc/traefik/conf.d"] {
            if Path::new(dir).is_dir() {
                return Self {
                    enabled: true,
                    config_dir: dir.into(),
                    ..Default::default()
                };
            }
        }
        Self::default()
    }
}

pub struct TraefikManager {
    config: TraefikConfig,
    domain: String,
    control_port: u16,
}

impl TraefikManager {
    pub fn new(config: TraefikConfig, domain: String, control_port: u16) -> Self {
        Self {
            config,
            domain,
            control_port,
        }
    }

    /// `tls:` block: certResolver when configured, otherwise Traefik's default cert.
    fn tls_block(&self, indent: &str) -> String {
        if self.config.cert_resolver.is_empty() {
            format!("{indent}tls: {{}}\n")
        } else {
            format!(
                "{indent}tls:\n{indent}  certResolver: {}\n",
                self.config.cert_resolver
            )
        }
    }

    pub fn ensure_dir(&self) -> anyhow::Result<()> {
        std::fs::create_dir_all(&self.config.config_dir)?;
        Ok(())
    }

    /// Write shared service + apex router + control-channel TCP router.
    ///
    /// The control channel is served on `connect.<domain>` through the HTTPS
    /// entrypoint: Traefik terminates TLS (HostSNI match) and forwards plain
    /// TCP to the server on localhost, so tokens never cross the network in
    /// cleartext and no extra port has to be opened.
    pub fn write_static_routes(&self) -> anyhow::Result<()> {
        self.ensure_dir()?;
        let control_address = self
            .config
            .control_address
            .clone()
            .filter(|a| !a.is_empty())
            .unwrap_or_else(|| format!("127.0.0.1:{}", self.control_port));
        let content = format!(
            r#"http:
  routers:
    nonla-tunnel-apex:
      rule: "Host(`{domain}`)"
      entryPoints:
        - "{ep}"
      service: {svc}
{tls_http}  services:
    {svc}:
      loadBalancer:
        servers:
          - url: "{url}"
tcp:
  routers:
    nonla-tunnel-control:
      rule: "HostSNI(`connect.{domain}`)"
      entryPoints:
        - "{ep}"
      service: {csvc}
{tls_tcp}  services:
    {csvc}:
      loadBalancer:
{pp}        servers:
          - address: "{caddr}"
"#,
            pp = if self.config.proxy_protocol {
                "        proxyProtocol:\n          version: 2\n"
            } else {
                ""
            },
            domain = self.domain,
            ep = self.config.entrypoint,
            svc = SHARED_SERVICE,
            csvc = CONTROL_SERVICE,
            tls_http = self.tls_block("      "),
            tls_tcp = self.tls_block("      "),
            url = self.config.service_url,
            caddr = control_address,
        );
        let path = Path::new(&self.config.config_dir).join(BASE_FILE);
        write_atomic(&path, &content)?;
        tracing::info!("🔀 Traefik: wrote {}", path.display());
        Ok(())
    }

    pub fn add_client(&self, client_id: &str) -> anyhow::Result<()> {
        // Defense in depth: the server validates names at auth, but this
        // string is interpolated into YAML and a Traefik rule — never write
        // anything that is not a plain DNS label.
        nonla_tunnel_protocol::validate_client_id(client_id)
            .map_err(|e| anyhow::anyhow!("refusing Traefik route for {:?}: {}", client_id, e))?;
        let safe = sanitize_id(client_id);
        let host = format!("{}.{}", client_id, self.domain);
        let content = format!(
            r#"http:
  routers:
    nonla-tunnel-{safe}:
      rule: "Host(`{host}`)"
      entryPoints:
        - "{ep}"
      service: {svc}
{tls}"#,
            safe = safe,
            host = host,
            ep = self.config.entrypoint,
            svc = SHARED_SERVICE,
            tls = self.tls_block("      "),
        );
        let path = self.client_file(&safe);
        if path.exists() {
            if let Ok(existing) = std::fs::read_to_string(&path) {
                if existing == content {
                    return Ok(());
                }
            }
        }
        write_atomic(&path, &content)?;
        tracing::info!("🔀 Traefik: added route for {}", host);
        Ok(())
    }

    /// Delete client routers of tunnels that are not connected and have been
    /// idle longer than `idle_secs`. `last_used(name)` gives the last use
    /// (unix secs) when known; otherwise the file's mtime is used.
    /// Keeps routers of live and recently used names, so short reconnects
    /// never hit a Traefik reload gap. Returns the names removed.
    pub fn gc_idle_routes(
        &self,
        idle_secs: u64,
        connected: impl Fn(&str) -> bool,
        last_used: impl Fn(&str) -> Option<u64>,
    ) -> anyhow::Result<Vec<String>> {
        let dir = Path::new(&self.config.config_dir);
        let now = std::time::SystemTime::now();
        let now_secs = now
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        let mut removed = Vec::new();
        for entry in std::fs::read_dir(dir)? {
            let entry = entry?;
            let file = entry.file_name();
            let file = file.to_string_lossy();
            let Some(name) = file
                .strip_prefix("nonla-tunnel-")
                .and_then(|f| f.strip_suffix(".yml"))
            else {
                continue;
            };
            if nonla_tunnel_protocol::validate_client_id(name).is_err() || connected(name) {
                continue;
            }
            let last = last_used(name).or_else(|| {
                entry
                    .metadata()
                    .ok()?
                    .modified()
                    .ok()?
                    .duration_since(std::time::UNIX_EPOCH)
                    .ok()
                    .map(|d| d.as_secs())
            });
            if let Some(last) = last {
                if now_secs.saturating_sub(last) > idle_secs {
                    std::fs::remove_file(entry.path())?;
                    removed.push(name.to_string());
                }
            }
        }
        if !removed.is_empty() {
            tracing::info!("🔀 Traefik: removed {} idle route(s)", removed.len());
        }
        Ok(removed)
    }

    fn client_file(&self, safe_id: &str) -> PathBuf {
        Path::new(&self.config.config_dir).join(format!("nonla-tunnel-{}.yml", safe_id))
    }
}

/// Write via a temp file + rename so Traefik never reads a half-written file.
/// The temp name does not end in `.yml`, so the file provider ignores it.
fn write_atomic(path: &Path, content: &str) -> anyhow::Result<()> {
    let tmp = path.with_extension("yml.tmp");
    std::fs::write(&tmp, content)?;
    std::fs::rename(&tmp, path)?;
    Ok(())
}

fn sanitize_id(id: &str) -> String {
    id.chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '-' || c == '_' {
                c
            } else {
                '_'
            }
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn mgr(dir: &Path) -> TraefikManager {
        TraefikManager::new(
            TraefikConfig {
                enabled: true,
                config_dir: dir.to_string_lossy().into(),
                ..Default::default()
            },
            "tunnel.example.com".into(),
            6200,
        )
    }

    #[test]
    fn gc_removes_only_idle_disconnected_routes() {
        let dir =
            std::env::temp_dir().join(format!("nonla-tunnel-traefik-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        let m = mgr(&dir);
        m.write_static_routes().unwrap();
        for n in ["idle", "live", "recent", "unknown"] {
            m.add_client(n).unwrap();
        }
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let removed = m
            .gc_idle_routes(
                3600,
                |n| n == "live",
                |n| match n {
                    "idle" | "live" => Some(0),
                    "recent" => Some(now),
                    _ => None, // falls back to mtime (just written → kept)
                },
            )
            .unwrap();
        assert_eq!(removed, vec!["idle".to_string()]);
        assert!(dir.join(BASE_FILE).exists());
        for n in ["live", "recent", "unknown"] {
            assert!(dir.join(format!("nonla-tunnel-{n}.yml")).exists(), "{n}");
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn add_client_rejects_injection() {
        let dir =
            std::env::temp_dir().join(format!("nonla-tunnel-traefik-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        let m = mgr(&dir);
        for bad in [
            "x`)\"\n    hijack:\n      rule: \"Host(`evil.com`)",
            "a`) || HostRegexp(`.+",
            "A",
            "a.b",
        ] {
            assert!(m.add_client(bad).is_err(), "{bad:?}");
        }
        assert_eq!(std::fs::read_dir(&dir).unwrap().count(), 0);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn static_routes_include_tls_control_router() {
        let dir =
            std::env::temp_dir().join(format!("nonla-tunnel-traefik-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        mgr(&dir).write_static_routes().unwrap();
        let yaml = std::fs::read_to_string(dir.join(BASE_FILE)).unwrap();
        let v: serde_yaml::Value = serde_yaml::from_str(&yaml).unwrap();
        let r = &v["tcp"]["routers"]["nonla-tunnel-control"];
        assert_eq!(
            r["rule"].as_str().unwrap(),
            "HostSNI(`connect.tunnel.example.com`)"
        );
        assert_eq!(r["tls"]["certResolver"].as_str().unwrap(), "letsencrypt");
        assert_eq!(
            v["tcp"]["services"]["nonla-tunnel-control"]["loadBalancer"]["servers"][0]["address"]
                .as_str()
                .unwrap(),
            "127.0.0.1:6200"
        );
        assert_eq!(
            v["tcp"]["services"]["nonla-tunnel-control"]["loadBalancer"]["proxyProtocol"]
                ["version"]
                .as_u64(),
            Some(2)
        );
        assert!(v["http"]["routers"]["nonla-tunnel-apex"].is_mapping());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn sanitize_keeps_safe_chars() {
        assert_eq!(sanitize_id("my-api_1"), "my-api_1");
        assert_eq!(sanitize_id("bad/name"), "bad_name");
    }

    #[test]
    fn add_client_skips_identical_rewrite() {
        let dir =
            std::env::temp_dir().join(format!("nonla-tunnel-traefik-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        let mgr = TraefikManager::new(
            TraefikConfig {
                enabled: true,
                config_dir: dir.to_string_lossy().into(),
                ..Default::default()
            },
            "tunnel.example.com".into(),
            6200,
        );
        mgr.add_client("omnivoice").unwrap();
        let path = dir.join("nonla-tunnel-omnivoice.yml");
        let first = std::fs::read_to_string(&path).unwrap();
        let mtime1 = std::fs::metadata(&path).unwrap().modified().unwrap();
        mgr.add_client("omnivoice").unwrap();
        let second = std::fs::read_to_string(&path).unwrap();
        let mtime2 = std::fs::metadata(&path).unwrap().modified().unwrap();
        assert_eq!(first, second);
        assert_eq!(mtime1, mtime2);
        let _ = std::fs::remove_dir_all(&dir);
    }
}
