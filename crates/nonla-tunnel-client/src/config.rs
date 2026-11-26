//! nonla-tunnel client config — `~/.nonla-tunnel/config.yaml`
//! (`%USERPROFILE%\.nonla-tunnel\config.yaml` on Windows).

use serde::{Deserialize, Serialize};
use std::path::PathBuf;

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ClientTlsConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default)]
    pub server_name: String,
    #[serde(default)]
    pub skip_verify: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NonlaTunnelConfig {
    pub server: String,
    pub token: String,
    #[serde(default)]
    pub tls: ClientTlsConfig,
}

/// `~/.nonla-tunnel` — config, claim keys, background tunnel state and the
/// installed binary (`bin/`). Removing it removes everything.
pub fn config_dir() -> anyhow::Result<PathBuf> {
    Ok(crate::platform::home_dir()?.join(".nonla-tunnel"))
}

pub fn config_path() -> anyhow::Result<PathBuf> {
    Ok(config_dir()?.join("config.yaml"))
}

impl NonlaTunnelConfig {
    pub fn load() -> anyhow::Result<Self> {
        let path = config_path()?;
        if !path.exists() {
            anyhow::bail!(
                "No config found at {}. Run: nonla-tunnel enroll --server connect.<domain> --invite <nti_...>",
                path.display()
            );
        }
        let content = std::fs::read_to_string(&path)?;
        Ok(serde_yaml::from_str(&content)?)
    }

    pub fn save(&self) -> anyhow::Result<()> {
        let dir = config_dir()?;
        std::fs::create_dir_all(&dir)?;
        crate::platform::restrict_dir(&dir)?;
        let path = config_path()?;
        write_private(&path, serde_yaml::to_string(self)?.as_bytes())?;
        Ok(())
    }

    pub fn masked_token(&self) -> String {
        // Show the ntc_ prefix (if any) plus 4 chars, never the secret part.
        let keep = if self
            .token
            .starts_with(nonla_tunnel_protocol::CREDENTIAL_PREFIX)
        {
            nonla_tunnel_protocol::CREDENTIAL_PREFIX.len() + 4
        } else {
            4
        };
        if self.token.chars().count() <= keep + 8 {
            "****".into()
        } else {
            // chars(), not byte slicing: a hand-edited non-ASCII token must not panic.
            format!("{}****", self.token.chars().take(keep).collect::<String>())
        }
    }
}

/// Write a file with 0600 permissions (also tightens an existing file).
pub fn write_private(path: &std::path::Path, data: &[u8]) -> std::io::Result<()> {
    use std::io::Write;
    let mut f = crate::platform::private_open_options()
        .write(true)
        .create(true)
        .truncate(true)
        .open(path)?;
    crate::platform::restrict_file(path)?;
    f.write_all(data)
}

/// Per-name ownership key sent to the server (`~/.nonla-tunnel/claims/<name>.key`).
/// Created on first use; the server binds the name to it so other clients
/// sharing the token cannot take the name over.
pub fn claim_key(name: &str) -> anyhow::Result<String> {
    nonla_tunnel_protocol::validate_client_id(name).map_err(|e| anyhow::anyhow!(e))?;
    let dir = config_dir()?.join("claims");
    std::fs::create_dir_all(&dir)?;
    crate::platform::restrict_dir(&dir)?;
    let path = dir.join(format!("{}.key", name));
    if let Ok(existing) = std::fs::read_to_string(&path) {
        let k = existing.trim().to_string();
        if k.len() >= 32 {
            return Ok(k);
        }
    }
    let mut buf = [0u8; 32];
    getrandom::getrandom(&mut buf).map_err(|e| anyhow::anyhow!("getrandom: {e}"))?;
    let key: String = buf.iter().map(|b| format!("{:02x}", b)).collect();
    // create_new: if a parallel process created it first, use theirs.
    match crate::platform::private_open_options()
        .write(true)
        .create_new(true)
        .open(&path)
    {
        Ok(mut f) => {
            use std::io::Write;
            f.write_all(key.as_bytes())?;
            Ok(key)
        }
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
            Ok(std::fs::read_to_string(&path)?.trim().to_string())
        }
        Err(e) => Err(e.into()),
    }
}

/// Add the default port when missing: 443 with TLS, 6200 without.
pub fn normalize_server_addr(server: &str, tls: bool) -> String {
    let has_port = server
        .rsplit_once(':')
        .map(|(_, p)| !p.is_empty() && p.bytes().all(|b| b.is_ascii_digit()))
        .unwrap_or(false);
    if has_port {
        server.to_string()
    } else {
        format!("{}:{}", server, if tls { 443 } else { 6200 })
    }
}

pub fn is_loopback_host(server: &str) -> bool {
    let host = server.rsplit_once(':').map(|(h, _)| h).unwrap_or(server);
    host == "localhost"
        || host
            .trim_matches(|c| c == '[' || c == ']')
            .parse::<std::net::IpAddr>()
            .map(|ip| ip.is_loopback())
            .unwrap_or(false)
}

pub fn generate_name() -> String {
    let mut buf = [0u8; 4];
    getrandom::getrandom(&mut buf).expect("getrandom");
    format!(
        "tunnel-{}",
        buf.iter().map(|b| format!("{:02x}", b)).collect::<String>()
    )
}

pub fn normalize_local_addr(addr: &str) -> String {
    if addr.contains(':') {
        addr.to_string()
    } else {
        format!("localhost:{}", addr)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalize_server_addr_defaults_port() {
        assert_eq!(
            normalize_server_addr("connect.t.example.com", true),
            "connect.t.example.com:443"
        );
        assert_eq!(
            normalize_server_addr("t.example.com", false),
            "t.example.com:6200"
        );
        assert_eq!(normalize_server_addr("h:7000", true), "h:7000");
    }

    #[test]
    fn loopback_detection() {
        assert!(is_loopback_host("127.0.0.1:6200"));
        assert!(is_loopback_host("localhost:6200"));
        assert!(!is_loopback_host("t.example.com:6200"));
        assert!(!is_loopback_host("10.0.0.1:6200"));
    }

    #[test]
    fn masked_token_never_panics_or_leaks() {
        let cfg = |t: &str| NonlaTunnelConfig {
            server: String::new(),
            token: t.into(),
            tls: ClientTlsConfig::default(),
        };
        assert_eq!(cfg("ntc_0123456789abcdef").masked_token(), "ntc_0123****");
        assert_eq!(cfg("short").masked_token(), "****");
        assert_eq!(cfg("ééééééééééééééééé").masked_token(), "éééé****");
    }

    #[test]
    fn generated_names_are_valid() {
        for _ in 0..20 {
            assert!(nonla_tunnel_protocol::validate_client_id(&generate_name()).is_ok());
        }
    }
}
