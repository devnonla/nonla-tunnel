//! Tunnel name ownership.
//!
//! All clients share one auth token, so the token alone cannot stop one client
//! from taking over another's name (and its public traffic). Each client sends
//! a random per-name `claim_key`; the first keyed session claims the name and
//! later sessions must present the same key. Only a SHA-256 of the key is
//! stored, in a 0600 JSON file next to `server.yaml`, so claims survive restarts.
//!
//! A claim expires after `CLAIM_TTL_SECS` without use (and never while the
//! name is connected), so abandoned names become free again.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};
use subtle::ConstantTimeEq;

pub const CLAIM_TTL_SECS: u64 = 30 * 24 * 3600;
const MIN_KEY_LEN: usize = 32;
const MAX_KEY_LEN: usize = 256;

#[derive(Debug, Clone, Serialize, Deserialize)]
struct Claim {
    key_sha256: String,
    last_seen: u64,
}

pub struct ClaimStore {
    path: Option<PathBuf>,
    claims: Mutex<HashMap<String, Claim>>,
}

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

impl ClaimStore {
    /// Load claims from `path` (missing file = no claims). `None` = in-memory only.
    pub fn load(path: Option<PathBuf>) -> anyhow::Result<Self> {
        let claims = match &path {
            Some(p) if p.exists() => {
                let data = std::fs::read_to_string(p)?;
                serde_json::from_str(&data)
                    .map_err(|e| anyhow::anyhow!("parse {}: {}", p.display(), e))?
            }
            _ => HashMap::new(),
        };
        Ok(Self {
            path,
            claims: Mutex::new(claims),
        })
    }

    /// Decide whether a session may use `name`. `connected` = the name is
    /// currently registered (its claim must not expire under it).
    /// On success the claim is created or refreshed.
    pub fn check(&self, name: &str, key: &str, connected: bool) -> Result<(), String> {
        if key.len() < MIN_KEY_LEN || key.len() > MAX_KEY_LEN {
            return Err("invalid claim key".into());
        }
        let now = now_secs();
        let mut claims = self.claims.lock().map_err(|_| "claim store poisoned")?;

        let expired = claims
            .get(name)
            .map(|c| !connected && now.saturating_sub(c.last_seen) > CLAIM_TTL_SECS)
            .unwrap_or(false);
        if expired {
            claims.remove(name);
        }

        match claims.get_mut(name) {
            Some(claim) => {
                let hash = nonla_tunnel_protocol::sha256_hex(key.as_bytes());
                if !bool::from(hash.as_bytes().ct_eq(claim.key_sha256.as_bytes())) {
                    return Err(format!(
                        "tunnel name '{}' is in use by another client",
                        name
                    ));
                }
                claim.last_seen = now;
            }
            None => {
                claims.insert(
                    name.to_string(),
                    Claim {
                        key_sha256: nonla_tunnel_protocol::sha256_hex(key.as_bytes()),
                        last_seen: now,
                    },
                );
            }
        }

        if let Err(e) = self.save(&claims) {
            tracing::warn!("⚠️  Failed to save tunnel claims: {:#}", e);
        }
        Ok(())
    }

    /// Drop claims unused for `CLAIM_TTL_SECS` whose name is not connected.
    /// Returns how many were removed.
    pub fn gc(&self, connected: impl Fn(&str) -> bool) -> usize {
        let now = now_secs();
        let Ok(mut claims) = self.claims.lock() else {
            return 0;
        };
        let before = claims.len();
        claims
            .retain(|name, c| connected(name) || now.saturating_sub(c.last_seen) <= CLAIM_TTL_SECS);
        let removed = before - claims.len();
        if removed > 0 {
            if let Err(e) = self.save(&claims) {
                tracing::warn!("⚠️  Failed to save tunnel claims: {:#}", e);
            }
        }
        removed
    }

    /// Forget a name's owner (operator action). Returns whether it was claimed.
    pub fn release(&self, name: &str) -> bool {
        let Ok(mut claims) = self.claims.lock() else {
            return false;
        };
        let had = claims.remove(name).is_some();
        if had {
            if let Err(e) = self.save(&claims) {
                tracing::warn!("⚠️  Failed to save tunnel claims: {:#}", e);
            }
        }
        had
    }

    /// Last use of a claimed name (unix secs).
    pub fn last_seen(&self, name: &str) -> Option<u64> {
        self.claims.lock().ok()?.get(name).map(|c| c.last_seen)
    }

    /// Refresh `last_seen` (called on disconnect so the TTL counts from last use).
    pub fn touch(&self, name: &str) {
        if let Ok(mut claims) = self.claims.lock() {
            if let Some(c) = claims.get_mut(name) {
                c.last_seen = now_secs();
                if let Err(e) = self.save(&claims) {
                    tracing::warn!("⚠️  Failed to save tunnel claims: {:#}", e);
                }
            }
        }
    }

    fn save(&self, claims: &HashMap<String, Claim>) -> anyhow::Result<()> {
        let Some(path) = &self.path else {
            return Ok(());
        };
        if let Some(dir) = path.parent() {
            std::fs::create_dir_all(dir)?;
        }
        let tmp = path.with_extension("json.tmp");
        crate::config::write_private(&tmp, serde_json::to_string_pretty(claims)?.as_bytes())?;
        std::fs::rename(&tmp, path)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const K1: &str = "11111111111111111111111111111111";
    const K2: &str = "22222222222222222222222222222222";

    #[test]
    fn first_keyed_session_claims_name() {
        let s = ClaimStore::load(None).unwrap();
        assert!(s.check("app", K1, false).is_ok());
        assert!(s.check("app", K1, true).is_ok(), "owner reconnect");
        assert!(s.check("app", K2, true).is_err(), "other key");
        assert!(s.check("other", K2, false).is_ok());
    }

    #[test]
    fn gc_and_release() {
        let s = ClaimStore::load(None).unwrap();
        s.check("old", K1, false).unwrap();
        s.check("live", K1, false).unwrap();
        s.check("fresh", K1, false).unwrap();
        for n in ["old", "live"] {
            s.claims.lock().unwrap().get_mut(n).unwrap().last_seen = 0;
        }
        assert_eq!(s.gc(|n| n == "live"), 1);
        assert!(s.last_seen("old").is_none());
        assert!(s.last_seen("live").is_some());
        assert!(s.release("fresh"));
        assert!(!s.release("fresh"));
        assert!(s.check("fresh", K2, false).is_ok(), "released name is free");
    }

    #[test]
    fn short_key_rejected() {
        let s = ClaimStore::load(None).unwrap();
        assert!(s.check("app", "short", false).is_err());
    }

    #[test]
    fn expired_claim_released_unless_connected() {
        let s = ClaimStore::load(None).unwrap();
        s.check("app", K1, false).unwrap();
        s.claims.lock().unwrap().get_mut("app").unwrap().last_seen = 0;
        assert!(s.check("app", K2, true).is_err(), "connected: kept");
        assert!(s.check("app", K2, false).is_ok(), "idle: released");
    }

    #[test]
    fn claims_persist_with_private_perms() {
        let dir = std::env::temp_dir().join(format!("nonla-claims-{}", uuid::Uuid::new_v4()));
        let path = dir.join("claims.json");
        let s = ClaimStore::load(Some(path.clone())).unwrap();
        s.check("app", K1, false).unwrap();
        let raw = std::fs::read_to_string(&path).unwrap();
        assert!(!raw.contains(K1), "raw key must not be stored");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o600);
        }
        let s2 = ClaimStore::load(Some(path)).unwrap();
        assert!(s2.check("app", K2, false).is_err());
        let _ = std::fs::remove_dir_all(&dir);
    }
}
