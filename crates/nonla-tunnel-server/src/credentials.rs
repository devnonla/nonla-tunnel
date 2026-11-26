//! Enrollment: one-time invites and per-client credentials.
//!
//! Flow: the operator runs `nonla-tunnel-server invite` → a single-use,
//! expiring `nti_…` code. The agent enrolls with it; the server burns the
//! invite and issues a random `ntc_…` credential bound to a client id. The
//! client stores only that credential. Credentials can be listed and revoked.
//!
//! Only SHA-256 hashes of invites and credentials are stored, in a 0600 JSON
//! file next to `server.yaml`. The running server and the CLI subcommands
//! share the file; every read-modify-write holds an exclusive `flock` on
//! `<file>.lock`, and writes are atomic (tmp + rename).

use nonla_tunnel_protocol::{sha256_hex, CREDENTIAL_PREFIX, INVITE_PREFIX};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

/// Longest allowed invite lifetime.
pub const MAX_INVITE_TTL_SECS: u64 = 30 * 24 * 3600;
/// `last_used` is only persisted when older than this (limits disk writes).
const LAST_USED_RESOLUTION_SECS: u64 = 60;
const MAX_LABEL_LEN: usize = 64;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Invite {
    pub id: String,
    pub sha256: String,
    pub label: String,
    pub created: u64,
    pub expires: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Credential {
    pub id: String,
    pub sha256: String,
    pub label: String,
    pub created: u64,
    #[serde(default)]
    pub last_used: u64,
    #[serde(default)]
    pub invite_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub revoked_at: Option<u64>,
}

impl Credential {
    pub fn is_active(&self) -> bool {
        self.revoked_at.is_none()
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct StoreData {
    #[serde(default)]
    pub invites: Vec<Invite>,
    #[serde(default)]
    pub clients: Vec<Credential>,
}

pub struct CredentialStore {
    path: PathBuf,
}

pub fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn random_hex(bytes: usize) -> String {
    let mut buf = vec![0u8; bytes];
    getrandom::getrandom(&mut buf).expect("getrandom failed");
    buf.iter().map(|b| format!("{:02x}", b)).collect()
}

/// Keep labels printable and short (they come from operators and clients).
pub fn clean_label(raw: &str) -> String {
    raw.chars()
        .filter(|c| c.is_ascii_graphic() || *c == ' ')
        .take(MAX_LABEL_LEN)
        .collect::<String>()
        .trim()
        .to_string()
}

/// Exclusive advisory lock on `<path>.lock`, released on drop.
struct FileLock(#[allow(dead_code)] std::fs::File);

impl FileLock {
    fn acquire(path: &Path) -> anyhow::Result<Self> {
        let lock_path = path.with_extension("lock");
        let mut opts = std::fs::OpenOptions::new();
        opts.create(true).truncate(false).write(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            opts.mode(0o600);
        }
        let f = opts.open(&lock_path)?;
        #[cfg(unix)]
        {
            use std::os::unix::io::AsRawFd;
            if unsafe { libc::flock(f.as_raw_fd(), libc::LOCK_EX) } != 0 {
                return Err(std::io::Error::last_os_error().into());
            }
        }
        Ok(Self(f))
    }
}

impl CredentialStore {
    pub fn new(path: PathBuf) -> Self {
        Self { path }
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    fn load_unlocked(&self) -> anyhow::Result<StoreData> {
        match std::fs::read_to_string(&self.path) {
            Ok(s) => serde_json::from_str(&s)
                .map_err(|e| anyhow::anyhow!("parse {}: {}", self.path.display(), e)),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(StoreData::default()),
            Err(e) => Err(e.into()),
        }
    }

    fn save_unlocked(&self, data: &StoreData) -> anyhow::Result<()> {
        let tmp = self.path.with_extension("json.tmp");
        crate::config::write_private(&tmp, serde_json::to_string_pretty(data)?.as_bytes())?;
        std::fs::rename(&tmp, &self.path)?;
        Ok(())
    }

    /// Run `f` on the store under the file lock; save if it returns `true`.
    fn update<T>(&self, f: impl FnOnce(&mut StoreData) -> (bool, T)) -> anyhow::Result<T> {
        if let Some(dir) = self.path.parent() {
            std::fs::create_dir_all(dir)?;
        }
        let _lock = FileLock::acquire(&self.path)?;
        let mut data = self.load_unlocked()?;
        let (changed, out) = f(&mut data);
        if changed {
            self.save_unlocked(&data)?;
        }
        Ok(out)
    }

    /// Read-only snapshot.
    pub fn snapshot(&self) -> anyhow::Result<StoreData> {
        self.update(|d| (false, d.clone()))
    }

    /// Create a single-use invite. Returns it and the plaintext code (shown once).
    pub fn create_invite(&self, ttl_secs: u64, label: &str) -> anyhow::Result<(Invite, String)> {
        let ttl = ttl_secs.clamp(60, MAX_INVITE_TTL_SECS);
        let code = format!("{}{}", INVITE_PREFIX, random_hex(24));
        let now = now_secs();
        let invite = Invite {
            id: format!("i_{}", random_hex(4)),
            sha256: sha256_hex(code.as_bytes()),
            label: clean_label(label),
            created: now,
            expires: now + ttl,
        };
        let inv = invite.clone();
        self.update(move |d| {
            d.invites.retain(|i| i.expires > now);
            d.invites.push(inv);
            (true, ())
        })?;
        Ok((invite, code))
    }

    /// Burn an invite and issue a credential. Returns `(credential id, token)`.
    /// The invite is consumed even if the response never reaches the client —
    /// single use is strict; the operator issues a new invite in that case.
    pub fn redeem(
        &self,
        invite_code: &str,
        client_label: Option<&str>,
    ) -> anyhow::Result<Result<(Credential, String), String>> {
        let now = now_secs();
        let hash = sha256_hex(invite_code.as_bytes());
        let client_label = client_label.map(clean_label).unwrap_or_default();
        self.update(move |d| {
            let before = d.invites.len();
            d.invites.retain(|i| i.expires > now);
            let pruned = d.invites.len() != before;
            let Some(pos) = d.invites.iter().position(|i| i.sha256 == hash) else {
                return (pruned, Err("invalid or expired invite".to_string()));
            };
            let invite = d.invites.remove(pos);
            let token = format!("{}{}", CREDENTIAL_PREFIX, random_hex(32));
            let label = match (invite.label.is_empty(), client_label.is_empty()) {
                (false, true) => invite.label.clone(),
                (false, false) => format!("{} ({})", invite.label, client_label),
                (true, _) => client_label.clone(),
            };
            let cred = Credential {
                id: format!("c_{}", random_hex(4)),
                sha256: sha256_hex(token.as_bytes()),
                label,
                created: now,
                last_used: 0,
                invite_id: invite.id,
                revoked_at: None,
            };
            d.clients.push(cred.clone());
            (true, Ok((cred, token)))
        })
    }

    /// Look up an active credential by token; refreshes `last_used`.
    /// Returns the credential id.
    pub fn authenticate(&self, token: &str) -> anyhow::Result<Option<String>> {
        if !token.starts_with(CREDENTIAL_PREFIX) {
            return Ok(None);
        }
        let hash = sha256_hex(token.as_bytes());
        let now = now_secs();
        self.update(move |d| {
            match d
                .clients
                .iter_mut()
                .find(|c| c.is_active() && c.sha256 == hash)
            {
                Some(c) => {
                    let stale = now.saturating_sub(c.last_used) >= LAST_USED_RESOLUTION_SECS;
                    if stale {
                        c.last_used = now;
                    }
                    (stale, Some(c.id.clone()))
                }
                None => (false, None),
            }
        })
    }

    /// Revoke by credential id. Returns false if no active credential matched.
    pub fn revoke(&self, id: &str) -> anyhow::Result<bool> {
        let now = now_secs();
        self.update(
            |d| match d.clients.iter_mut().find(|c| c.id == id && c.is_active()) {
                Some(c) => {
                    c.revoked_at = Some(now);
                    (true, true)
                }
                None => (false, false),
            },
        )
    }

    /// Delete an unused invite by id.
    pub fn delete_invite(&self, id: &str) -> anyhow::Result<bool> {
        self.update(|d| {
            let before = d.invites.len();
            d.invites.retain(|i| i.id != id);
            let changed = d.invites.len() != before;
            (changed, changed)
        })
    }

    /// Ids of credentials that are not active (revoked or deleted from the file).
    pub fn is_active_id(data: &StoreData, id: &str) -> bool {
        data.clients.iter().any(|c| c.id == id && c.is_active())
    }
}

/// Invite lifetime: 1m..30d.
pub fn parse_ttl(s: &str) -> anyhow::Result<u64> {
    parse_duration(s, 60)
}

/// `30m`, `24h`, `7d`, `90s` or plain seconds, between `min_secs` and 30d.
pub fn parse_duration(s: &str, min_secs: u64) -> anyhow::Result<u64> {
    let s = s.trim();
    let (num, mult) = match s.chars().last() {
        Some('s') => (&s[..s.len() - 1], 1),
        Some('m') => (&s[..s.len() - 1], 60),
        Some('h') => (&s[..s.len() - 1], 3600),
        Some('d') => (&s[..s.len() - 1], 86400),
        _ => (s, 1),
    };
    let n: u64 = num
        .parse()
        .map_err(|_| anyhow::anyhow!("invalid duration '{}': use e.g. 30m, 24h, 7d", s))?;
    let secs = n.saturating_mul(mult);
    if !(min_secs..=MAX_INVITE_TTL_SECS).contains(&secs) {
        anyhow::bail!("duration must be between {}s and 30d", min_secs);
    }
    Ok(secs)
}

/// Unix seconds → `YYYY-MM-DD HH:MM UTC`.
pub fn fmt_time(ts: u64) -> String {
    if ts == 0 {
        return "-".into();
    }
    let days = (ts / 86400) as i64;
    let rem = ts % 86400;
    // Civil-from-days (Howard Hinnant).
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    format!(
        "{:04}-{:02}-{:02} {:02}:{:02} UTC",
        y,
        m,
        d,
        rem / 3600,
        (rem % 3600) / 60
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn store() -> (CredentialStore, PathBuf) {
        let dir = std::env::temp_dir().join(format!("nonla-cred-{}", uuid::Uuid::new_v4()));
        (CredentialStore::new(dir.join("credentials.json")), dir)
    }

    #[test]
    fn invite_is_single_use_and_issues_credential() {
        let (s, dir) = store();
        let (_inv, code) = s.create_invite(3600, "agent-1").unwrap();
        assert!(code.starts_with(INVITE_PREFIX));
        let (cred, token) = s.redeem(&code, Some("host-a")).unwrap().unwrap();
        assert!(token.starts_with(CREDENTIAL_PREFIX));
        assert_eq!(cred.label, "agent-1 (host-a)");
        assert!(s.redeem(&code, None).unwrap().is_err(), "second use");
        assert_eq!(s.authenticate(&token).unwrap(), Some(cred.id.clone()));
        assert_eq!(
            s.authenticate(&code).unwrap(),
            None,
            "invite is not a credential"
        );
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn expired_invite_rejected_and_pruned() {
        let (s, dir) = store();
        let (_inv, code) = s.create_invite(3600, "").unwrap();
        s.update(|d| {
            d.invites[0].expires = 1;
            (true, ())
        })
        .unwrap();
        assert!(s.redeem(&code, None).unwrap().is_err());
        assert!(s.snapshot().unwrap().invites.is_empty());
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn revoke_disables_credential() {
        let (s, dir) = store();
        let (_i, code) = s.create_invite(3600, "").unwrap();
        let (cred, token) = s.redeem(&code, None).unwrap().unwrap();
        assert!(s.revoke(&cred.id).unwrap());
        assert!(!s.revoke(&cred.id).unwrap(), "already revoked");
        assert_eq!(s.authenticate(&token).unwrap(), None);
        let snap = s.snapshot().unwrap();
        assert!(!CredentialStore::is_active_id(&snap, &cred.id));
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn stores_only_hashes_with_private_perms() {
        let (s, dir) = store();
        let (_i, code) = s.create_invite(3600, "").unwrap();
        let raw = std::fs::read_to_string(s.path()).unwrap();
        assert!(!raw.contains(&code));
        let (_c, token) = s.redeem(&code, None).unwrap().unwrap();
        let raw = std::fs::read_to_string(s.path()).unwrap();
        assert!(!raw.contains(&token));
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(s.path()).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o600);
        }
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn concurrent_redeem_only_one_wins() {
        let (s, dir) = store();
        let (_i, code) = s.create_invite(3600, "").unwrap();
        let s = std::sync::Arc::new(s);
        let handles: Vec<_> = (0..8)
            .map(|_| {
                let s = s.clone();
                let code = code.clone();
                std::thread::spawn(move || s.redeem(&code, None).unwrap().is_ok())
            })
            .collect();
        let wins = handles
            .into_iter()
            .filter(|_| true)
            .map(|h| h.join().unwrap())
            .filter(|w| *w)
            .count();
        assert_eq!(wins, 1);
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn labels_are_cleaned() {
        assert_eq!(clean_label("a\nb\x1b[31m c"), "ab[31m c");
        assert_eq!(clean_label(&"x".repeat(200)).len(), MAX_LABEL_LEN);
    }

    #[test]
    fn ttl_parsing() {
        assert_eq!(parse_ttl("30m").unwrap(), 1800);
        assert_eq!(parse_ttl("24h").unwrap(), 86400);
        assert_eq!(parse_ttl("7d").unwrap(), 7 * 86400);
        assert!(parse_ttl("5s").is_err());
        assert!(parse_ttl("31d").is_err());
        assert!(parse_ttl("abc").is_err());
    }

    #[test]
    fn time_formatting() {
        assert_eq!(fmt_time(0), "-");
        assert_eq!(fmt_time(1_700_000_000), "2023-11-14 22:13 UTC");
    }
}
