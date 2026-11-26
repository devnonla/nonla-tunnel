//! Server configuration — YAML file + CLI override.

use serde::{Deserialize, Serialize};
use std::path::Path;
use subtle::ConstantTimeEq;

/// Minimum accepted client token length (bytes).
pub const MIN_TOKEN_LEN: usize = 16;

/// Write a file readable only by its owner (0600), creating or truncating it.
pub fn write_private(path: &Path, data: &[u8]) -> std::io::Result<()> {
    use std::io::Write;
    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    let mut f = opts.open(path)?;
    // mode() only applies on create; tighten files that already existed.
    restrict_perms(path)?;
    f.write_all(data)?;
    f.sync_all()
}

/// chmod 0600 (no-op on non-unix).
pub fn restrict_perms(path: &Path) -> std::io::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
    }
    let _ = path;
    Ok(())
}

/// Reserved subdomains that cannot be used as client IDs.
pub const RESERVED_SUBDOMAINS: &[&str] = &[
    "dashboard",
    "connect",
    "api",
    "www",
    "admin",
    "install",
    "download",
];

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerConfig {
    #[serde(default = "default_control_port")]
    pub control_port: u16,

    /// Public HTTP port (subdomain routing + install endpoint).
    #[serde(default = "default_public_port")]
    pub public_port: u16,

    /// Base domain for subdomain routing (e.g. "tunnel.example.com").
    /// Each client is accessible at <client_id>.<domain>.
    /// Client install script is at https://<domain>/install.
    pub domain: String,

    #[serde(default)]
    pub auth: AuthConfig,

    #[serde(default)]
    pub rate_limit: RateLimitConfig,

    #[serde(default)]
    pub traefik: crate::traefik::TraefikConfig,

    /// Directory containing client binaries served at /download/
    #[serde(default = "default_clients_dir")]
    pub clients_dir: String,

    #[serde(default = "default_log_level")]
    pub log_level: String,

    /// Address the control and public listeners bind to. Unset = `127.0.0.1`
    /// when Traefik fronts the server (TLS terminated there, plaintext ports
    /// never exposed), `0.0.0.0` otherwise.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bind_addr: Option<String>,

    /// Tunnel name claims file. Unset = `claims.json` next to the config file.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub claims_file: Option<String>,

    /// Enrollment invites + issued client credentials.
    /// Unset = `credentials.json` next to the config file.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub credentials_file: Option<String>,

    /// Local admin socket used by `sessions` / `kick`.
    /// Unset = `admin.sock` next to the config file.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub admin_socket: Option<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct AuthConfig {
    #[serde(default)]
    pub tokens: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RateLimitConfig {
    #[serde(default = "default_rps")]
    pub requests_per_second: u32,
    #[serde(default = "default_max_conn")]
    pub max_connections_per_client: u32,
}

impl Default for RateLimitConfig {
    fn default() -> Self {
        Self {
            requests_per_second: 100,
            max_connections_per_client: crate::registry::DEFAULT_STREAM_LIMIT as u32,
        }
    }
}

fn default_control_port() -> u16 {
    nonla_tunnel_protocol::DEFAULT_CONTROL_PORT
}
fn default_public_port() -> u16 {
    nonla_tunnel_protocol::DEFAULT_PUBLIC_PORT
}
fn default_log_level() -> String {
    "info".into()
}
fn default_clients_dir() -> String {
    "/var/lib/nonla-tunnel/clients".into()
}
fn default_rps() -> u32 {
    100
}
fn default_max_conn() -> u32 {
    crate::registry::DEFAULT_STREAM_LIMIT as u32
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            control_port: default_control_port(),
            public_port: default_public_port(),
            domain: String::new(),
            auth: AuthConfig::default(),
            rate_limit: RateLimitConfig::default(),
            traefik: crate::traefik::TraefikConfig::default(),
            clients_dir: default_clients_dir(),
            log_level: default_log_level(),
            bind_addr: None,
            claims_file: None,
            credentials_file: None,
            admin_socket: None,
        }
    }
}

impl ServerConfig {
    /// Config directory for saving (used by `start --domain`).
    /// - `/etc/nonla-tunnel/` when running as root
    /// - `~/.config/nonla-tunnel/` otherwise
    pub fn config_dir() -> std::path::PathBuf {
        if nix_is_root() {
            std::path::PathBuf::from("/etc/nonla-tunnel")
        } else {
            dirs_fallback().join("nonla-tunnel")
        }
    }

    /// Full path to the server config file (for saving).
    pub fn config_path() -> std::path::PathBuf {
        Self::config_dir().join("server.yaml")
    }

    /// Resolve the config path for loading.
    /// Checks /etc/nonla-tunnel/server.yaml first (system-wide),
    /// then falls back to ~/.config/nonla-tunnel/server.yaml.
    pub fn resolve_config_path() -> Option<std::path::PathBuf> {
        let system_path = std::path::PathBuf::from("/etc/nonla-tunnel/server.yaml");
        if system_path.exists() {
            return Some(system_path);
        }
        let user_path = dirs_fallback().join("nonla-tunnel").join("server.yaml");
        if user_path.exists() {
            return Some(user_path);
        }
        None
    }

    /// Load config from a specific YAML file.
    pub fn load(path: &Path) -> anyhow::Result<Self> {
        let content = std::fs::read_to_string(path)?;
        let config: ServerConfig = serde_yaml::from_str(&content)?;
        // The file holds client tokens; tighten it if it was created 0644 by hand.
        if let Err(e) = restrict_perms(path) {
            tracing::warn!("⚠️  Could not chmod 600 {}: {}", path.display(), e);
        }
        Ok(config)
    }

    /// Effective bind address for both listeners.
    pub fn effective_bind_addr(&self) -> String {
        match &self.bind_addr {
            Some(a) if !a.is_empty() => a.clone(),
            _ if self.traefik.enabled => "127.0.0.1".into(),
            _ => "0.0.0.0".into(),
        }
    }

    /// Save config to the system config path.
    #[allow(dead_code)]
    pub fn save(&self) -> anyhow::Result<std::path::PathBuf> {
        let dir = Self::config_dir();
        std::fs::create_dir_all(&dir)
            .map_err(|e| anyhow::anyhow!("Failed to create config dir {}: {}", dir.display(), e))?;

        let path = Self::config_path();
        let yaml = serde_yaml::to_string(self)?;

        // Add a header comment
        let content = format!(
            "# Nonla Tunnel Server Configuration\n\
             # Generated by: nonla-tunnel-server start --domain\n\
             # Config path: {}\n\
             #\n\
             # To reconfigure, run: nonla-tunnel-server start --domain YOUR_DOMAIN --force\n\
             \n{}",
            path.display(),
            yaml
        );

        write_private(&path, content.as_bytes())
            .map_err(|e| anyhow::anyhow!("Failed to write config to {}: {}", path.display(), e))?;

        Ok(path)
    }

    /// Generate a cryptographically secure random hex token.
    pub fn generate_token(len_bytes: usize) -> String {
        let mut buf = vec![0u8; len_bytes];
        getrandom::getrandom(&mut buf).expect("getrandom failed");
        buf.iter().map(|b| format!("{:02x}", b)).collect()
    }

    /// Check a client token in constant time. Fails closed: with no tokens
    /// configured nothing is accepted (the server also refuses to start).
    pub fn validate_token(&self, token: &str) -> bool {
        let provided = token.as_bytes();
        let mut ok = false;
        for t in &self.auth.tokens {
            if t.is_empty() {
                continue;
            }
            // Evaluate every token so timing does not reveal which one matched.
            ok |= bool::from(t.as_bytes().ct_eq(provided));
        }
        ok
    }

    /// `domain` ends up in Traefik YAML, rules and the install shell script,
    /// so it must be a plain DNS name.
    pub fn check_domain(&self) -> anyhow::Result<()> {
        let d = &self.domain;
        let ok = !d.is_empty()
            && d.len() <= 253
            && d.split('.').all(|l| {
                !l.is_empty()
                    && l.len() <= 63
                    && !l.starts_with('-')
                    && !l.ends_with('-')
                    && l.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
            });
        if !ok {
            anyhow::bail!(
                "invalid domain {:?}: expected a DNS name like tunnel.example.com",
                d
            );
        }
        Ok(())
    }

    /// Reject configs that would leave the control channel open.
    pub fn check_auth(&self) -> anyhow::Result<()> {
        if self.auth.tokens.iter().all(|t| t.is_empty()) {
            anyhow::bail!(
                "no client token configured — set NONLA_TOKEN / AUTH_TOKEN or auth.tokens in the config"
            );
        }
        if let Some(t) = self
            .auth
            .tokens
            .iter()
            .find(|t| !t.is_empty() && t.len() < MIN_TOKEN_LEN)
        {
            anyhow::bail!(
                "client token too short ({} chars, need at least {}) — generate one with: openssl rand -hex 24",
                t.len(),
                MIN_TOKEN_LEN
            );
        }
        Ok(())
    }
}

/// Check if running as root (uid 0).
fn nix_is_root() -> bool {
    unsafe { libc_geteuid() == 0 }
}

extern "C" {
    #[link_name = "geteuid"]
    fn libc_geteuid() -> u32;
}

/// Fallback config dir: ~/.config/
fn dirs_fallback() -> std::path::PathBuf {
    std::env::var("XDG_CONFIG_HOME")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|_| {
            let home = std::env::var("HOME").unwrap_or_else(|_| "/tmp".into());
            std::path::PathBuf::from(home).join(".config")
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config() {
        let cfg = ServerConfig::default();
        assert_eq!(cfg.control_port, 6200);
        assert_eq!(cfg.public_port, 6210);
        assert!(cfg.domain.is_empty());
        assert!(cfg.auth.tokens.is_empty());
    }

    #[test]
    fn test_validate_token_empty_denies_all() {
        let cfg = ServerConfig::default();
        assert!(!cfg.validate_token("anything"));
        assert!(!cfg.validate_token(""));
        assert!(cfg.check_auth().is_err());
    }

    #[test]
    fn test_check_auth_rejects_short_and_empty_tokens() {
        let mut cfg = ServerConfig::default();
        cfg.auth.tokens = vec!["".into()];
        assert!(cfg.check_auth().is_err());
        assert!(!cfg.validate_token(""));
        cfg.auth.tokens = vec!["short".into()];
        assert!(cfg.check_auth().is_err());
        cfg.auth.tokens = vec!["0123456789abcdef".into()];
        assert!(cfg.check_auth().is_ok());
    }

    #[test]
    fn test_check_domain() {
        let mut cfg = ServerConfig::default();
        for ok in ["tunnel.example.com", "t.local", "a-b.example.io"] {
            cfg.domain = ok.into();
            assert!(cfg.check_domain().is_ok(), "{ok}");
        }
        for bad in [
            "",
            "a..b",
            "-a.com",
            "a.com`)",
            "a.com\"\nx",
            "x y.com",
            "a.com/x",
        ] {
            cfg.domain = bad.into();
            assert!(cfg.check_domain().is_err(), "{bad:?}");
        }
    }

    #[test]
    fn test_bind_addr_defaults() {
        let mut cfg = ServerConfig::default();
        assert_eq!(cfg.effective_bind_addr(), "0.0.0.0");
        cfg.traefik.enabled = true;
        assert_eq!(cfg.effective_bind_addr(), "127.0.0.1");
        cfg.bind_addr = Some("0.0.0.0".into());
        assert_eq!(cfg.effective_bind_addr(), "0.0.0.0");
    }

    #[test]
    fn test_write_private_tightens_existing_file() {
        let path = std::env::temp_dir().join(format!("nonla-cfg-{}", uuid::Uuid::new_v4()));
        std::fs::write(&path, "old").unwrap();
        write_private(&path, b"new").unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o600);
        }
        assert_eq!(std::fs::read_to_string(&path).unwrap(), "new");
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn test_validate_token_checks_list() {
        let mut cfg = ServerConfig::default();
        cfg.auth.tokens = vec!["secret1".into(), "secret2".into()];

        assert!(cfg.validate_token("secret1"));
        assert!(cfg.validate_token("secret2"));
        assert!(!cfg.validate_token("wrong"));
        assert!(!cfg.validate_token(""));
    }

    #[test]
    fn test_yaml_parsing() {
        let yaml = r#"
control_port: 7777
public_port: 8888
domain: "test.example.com"
auth:
  tokens:
    - "tok1"
    - "tok2"
"#;
        let cfg: ServerConfig = serde_yaml::from_str(yaml).unwrap();
        assert_eq!(cfg.control_port, 7777);
        assert_eq!(cfg.public_port, 8888);
        assert_eq!(cfg.domain, "test.example.com");
        assert_eq!(cfg.auth.tokens, vec!["tok1", "tok2"]);
    }

    #[test]
    fn test_yaml_defaults_for_missing_fields() {
        let yaml = r#"domain: "tunnel.example.com""#;
        let cfg: ServerConfig = serde_yaml::from_str(yaml).unwrap();
        assert_eq!(cfg.control_port, 6200);
        assert_eq!(cfg.public_port, 6210);
        assert_eq!(cfg.domain, "tunnel.example.com");
        assert_eq!(cfg.log_level, "info");
    }
}
