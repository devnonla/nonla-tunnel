//! Client registry — tracks connected tunnel clients.

use crate::server::YamuxHandle;
use dashmap::DashMap;
use nonla_tunnel_protocol::{SESSION_STALE_SECS, TAKEOVER_AFTER_MISSED_HEARTBEATS};
use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

/// Default cap on concurrent proxied requests per tunnel. Must stay well
/// below yamux's `max_num_streams` (512) so heartbeats always get a stream.
pub const DEFAULT_STREAM_LIMIT: usize = 128;
pub const MAX_STREAM_LIMIT: usize = 400;

/// Who is behind a session (for `sessions`, `kick`, revocation).
#[derive(Debug, Clone)]
pub struct SessionMeta {
    /// Issued credential id; `None` = shared admin token.
    pub cred_id: Option<String>,
    /// Real client address (from PROXY protocol behind Traefik).
    pub peer: std::net::SocketAddr,
    pub version: Option<String>,
    pub connected_unix: u64,
}

/// Handle to a connected client's yamux session.
#[allow(dead_code)] // some fields are diagnostics-only
pub struct ClientEntry {
    pub client_id: String,
    pub session_id: u64,
    pub handle: YamuxHandle,
    pub connected_at: Instant,
    pub last_activity: Arc<Mutex<Instant>>,
    pub missed_heartbeats: Arc<AtomicU32>,
    pub metrics: ClientMetrics,
    pub supports_heartbeat: bool,
    /// Set once right after registration. Lives on the entry itself so a
    /// racing takeover can never attach one session's details to another.
    pub meta: std::sync::OnceLock<SessionMeta>,
    /// Concurrent proxied requests allowed on this tunnel.
    pub stream_slots: Arc<tokio::sync::Semaphore>,
}

impl ClientEntry {
    pub fn touch(&self) {
        if let Ok(mut ts) = self.last_activity.lock() {
            *ts = Instant::now();
        }
    }

    /// Whether this session still looks healthy for diagnostics.
    ///
    /// Registration no longer gates on this — reconnects always take over
    /// (last writer wins) so a half-open zombie cannot wedge a tunnel name
    /// while Traefik still points at a dead or missing route.
    ///
    /// A poisoned `last_activity` lock is treated as dead.
    #[allow(dead_code)]
    pub fn is_alive(&self) -> bool {
        if self.handle.is_closed() {
            return false;
        }
        if self.supports_heartbeat
            && self.missed_heartbeats.load(Ordering::Relaxed) >= TAKEOVER_AFTER_MISSED_HEARTBEATS
        {
            return false;
        }
        self.last_activity
            .lock()
            .map(|ts| ts.elapsed() < Duration::from_secs(SESSION_STALE_SECS))
            .unwrap_or(false)
    }
}

/// Per-client traffic metrics.
#[allow(dead_code)]
pub struct ClientMetrics {
    pub bytes_in: Arc<AtomicU64>,
    pub bytes_out: Arc<AtomicU64>,
    pub requests: AtomicU64,
    pub active_streams: AtomicU64,
}

impl ClientMetrics {
    pub fn new() -> Self {
        Self {
            bytes_in: Arc::new(AtomicU64::new(0)),
            bytes_out: Arc::new(AtomicU64::new(0)),
            requests: AtomicU64::new(0),
            active_streams: AtomicU64::new(0),
        }
    }
}

/// Thread-safe client registry.
pub struct Registry {
    clients: DashMap<String, Arc<ClientEntry>>,
    next_session: AtomicU64,
    stream_limit: usize,
}

impl Registry {
    #[cfg(test)]
    pub fn new() -> Self {
        Self::with_stream_limit(DEFAULT_STREAM_LIMIT)
    }

    pub fn with_stream_limit(limit: usize) -> Self {
        Self {
            clients: DashMap::new(),
            next_session: AtomicU64::new(1),
            stream_limit: limit.clamp(1, MAX_STREAM_LIMIT),
        }
    }

    /// Snapshot of all current sessions.
    pub fn entries(&self) -> Vec<Arc<ClientEntry>> {
        self.clients.iter().map(|e| e.value().clone()).collect()
    }

    /// Register a client. Same `client_id` always replaces the previous session
    /// (last writer wins) so reconnects recover from zombie/half-open TCP.
    /// Returns `(entry, replaced)`. Errors only if the id is reserved.
    pub fn register(
        &self,
        client_id: String,
        handle: YamuxHandle,
        supports_heartbeat: bool,
        last_activity: Arc<Mutex<Instant>>,
        missed_heartbeats: Arc<AtomicU32>,
    ) -> anyhow::Result<(Arc<ClientEntry>, bool)> {
        use dashmap::mapref::entry::Entry;

        if crate::config::RESERVED_SUBDOMAINS.contains(&client_id.as_str()) {
            anyhow::bail!(
                "Client ID '{}' is reserved (conflicts with system subdomain)",
                client_id
            );
        }

        let session_id = self.next_session.fetch_add(1, Ordering::Relaxed);
        let entry = Arc::new(ClientEntry {
            client_id: client_id.clone(),
            session_id,
            handle,
            connected_at: Instant::now(),
            last_activity,
            missed_heartbeats,
            metrics: ClientMetrics::new(),
            supports_heartbeat,
            meta: std::sync::OnceLock::new(),
            stream_slots: Arc::new(tokio::sync::Semaphore::new(self.stream_limit)),
        });

        match self.clients.entry(client_id.clone()) {
            Entry::Occupied(mut occupied) => {
                let old = occupied.insert(entry.clone());
                // Drop the previous yamux driver so its task exits and does not
                // keep answering heartbeats / proxying under the old session.
                old.handle.abort();
                Ok((entry, true))
            }
            Entry::Vacant(vacant) => {
                vacant.insert(entry.clone());
                Ok((entry, false))
            }
        }
    }

    /// Unregister a session. No-op if a newer session already replaced it.
    pub fn unregister(&self, client_id: &str, session_id: u64) -> bool {
        self.clients
            .remove_if(client_id, |_, e| e.session_id == session_id)
            .is_some()
    }

    /// Get a client entry by ID.
    pub fn get(&self, client_id: &str) -> Option<Arc<ClientEntry>> {
        self.clients.get(client_id).map(|e| e.value().clone())
    }

    /// Count connected clients.
    pub fn count(&self) -> usize {
        self.clients.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::server::YamuxHandle;

    fn live_handle() -> (
        YamuxHandle,
        tokio::sync::mpsc::Receiver<crate::server::YamuxCmd>,
    ) {
        YamuxHandle::mock()
    }

    fn dead_handle() -> YamuxHandle {
        YamuxHandle::mock_closed()
    }

    fn activity(age_secs: u64, missed: u32) -> (Arc<Mutex<Instant>>, Arc<AtomicU32>) {
        (
            Arc::new(Mutex::new(Instant::now() - Duration::from_secs(age_secs))),
            Arc::new(AtomicU32::new(missed)),
        )
    }

    #[tokio::test]
    async fn stream_slots_cap_concurrency() {
        let reg = Registry::with_stream_limit(2);
        let (h, _rx) = live_handle();
        let (last, missed) = activity(0, 0);
        let (e, _) = reg.register("app".into(), h, true, last, missed).unwrap();
        let a = e.stream_slots.clone().try_acquire_owned().unwrap();
        let _b = e.stream_slots.clone().try_acquire_owned().unwrap();
        assert!(e.stream_slots.clone().try_acquire_owned().is_err());
        drop(a);
        assert!(e.stream_slots.clone().try_acquire_owned().is_ok());
        assert_eq!(
            Registry::with_stream_limit(100_000).stream_limit,
            MAX_STREAM_LIMIT
        );
    }

    #[tokio::test]
    async fn meta_belongs_to_its_own_session() {
        // A takeover must not inherit or overwrite the old session's meta.
        let reg = Registry::new();
        let (h1, _r1) = live_handle();
        let (l1, m1) = activity(0, 0);
        let (a, _) = reg.register("app".into(), h1, true, l1, m1).unwrap();
        let (h2, _r2) = live_handle();
        let (l2, m2) = activity(0, 0);
        let (b, replaced) = reg.register("app".into(), h2, true, l2, m2).unwrap();
        assert!(replaced);
        let meta = |c: &str| SessionMeta {
            cred_id: Some(c.into()),
            peer: "127.0.0.1:1".parse().unwrap(),
            version: None,
            connected_unix: 0,
        };
        b.meta.set(meta("c_b")).unwrap();
        a.meta.set(meta("c_a")).unwrap(); // late write from the old session
        let current = reg.get("app").unwrap();
        assert_eq!(current.session_id, b.session_id);
        assert_eq!(current.meta.get().unwrap().cred_id.as_deref(), Some("c_b"));
        assert_eq!(reg.entries().len(), 1);
    }

    #[tokio::test]
    async fn register_fresh_session() {
        let reg = Registry::new();
        let (handle, _rx) = live_handle();
        let (last, missed) = activity(0, 0);
        let (entry, replaced) = reg
            .register("app".into(), handle, true, last, missed)
            .expect("register");
        assert!(!replaced);
        assert_eq!(reg.count(), 1);
        assert!(reg.unregister("app", entry.session_id));
        assert_eq!(reg.count(), 0);
    }

    #[tokio::test]
    async fn healthy_duplicate_is_taken_over() {
        // Reconnect must replace a still-"alive" session. Refusing here is what
        // wedged omnivoice behind Traefik 404 while the zombie kept the name.
        let reg = Registry::new();
        let (h1, _rx) = live_handle();
        let (last, missed) = activity(0, 0);
        let (first, _) = reg
            .register("app".into(), h1, true, last, missed)
            .expect("first");
        let (h2, _rx2) = live_handle();
        let (last2, missed2) = activity(0, 0);
        let (second, replaced) = reg
            .register("app".into(), h2, true, last2, missed2)
            .expect("takeover");
        assert!(replaced);
        assert_ne!(first.session_id, second.session_id);
        assert_eq!(reg.get("app").unwrap().session_id, second.session_id);
        assert!(!reg.unregister("app", first.session_id));
        assert!(reg.unregister("app", second.session_id));
    }

    #[tokio::test]
    async fn takeover_aborts_previous_even_with_one_missed_heartbeat() {
        let reg = Registry::new();
        let (h1, _rx) = live_handle();
        let (last, missed) = activity(25, 1);
        let (old, _) = reg
            .register("app".into(), h1, true, last, missed)
            .expect("old");
        let (h2, _rx2) = live_handle();
        let (last2, missed2) = activity(0, 0);
        let (new, replaced) = reg
            .register("app".into(), h2, true, last2, missed2)
            .expect("takeover");
        assert!(replaced);
        assert_ne!(old.session_id, new.session_id);
    }

    #[tokio::test]
    async fn takeover_after_two_missed_heartbeats() {
        let reg = Registry::new();
        let (h1, _rx) = live_handle();
        let (last, missed) = activity(20, TAKEOVER_AFTER_MISSED_HEARTBEATS);
        let (old, _) = reg
            .register("app".into(), h1, true, last, missed)
            .expect("old");
        let (h2, _rx2) = live_handle();
        let (last2, missed2) = activity(0, 0);
        let (new, replaced) = reg
            .register("app".into(), h2, true, last2, missed2)
            .expect("takeover");
        assert!(replaced);
        assert_ne!(old.session_id, new.session_id);
        assert!(!reg.unregister("app", old.session_id));
        assert!(reg.unregister("app", new.session_id));
    }

    #[tokio::test]
    async fn takeover_after_wall_clock_stale() {
        let reg = Registry::new();
        let (h1, _rx) = live_handle();
        let (stale, missed) = activity(SESSION_STALE_SECS + 1, 0);
        let (old, _) = reg
            .register("app".into(), h1, true, stale, missed)
            .expect("old");
        let (h2, _rx2) = live_handle();
        let (last2, missed2) = activity(0, 0);
        let (new, replaced) = reg
            .register("app".into(), h2, true, last2, missed2)
            .expect("takeover");
        assert!(replaced);
        assert_ne!(old.session_id, new.session_id);
    }

    #[tokio::test]
    async fn takeover_closed_driver_even_if_recent() {
        let reg = Registry::new();
        let h1 = dead_handle();
        let (last, missed) = activity(0, 0);
        let (old, _) = reg
            .register("app".into(), h1, true, last, missed)
            .expect("old");
        let (h2, _rx) = live_handle();
        let (last2, missed2) = activity(0, 0);
        let (new, replaced) = reg
            .register("app".into(), h2, true, last2, missed2)
            .expect("takeover");
        assert!(replaced);
        assert_ne!(old.session_id, new.session_id);
    }

    #[tokio::test]
    async fn no_heartbeat_session_reconnect_takes_over() {
        let reg = Registry::new();
        let (h1, _rx) = live_handle();
        let (last, missed) = activity(25, 0);
        let (old, _) = reg
            .register("app".into(), h1, false, last, missed)
            .expect("old");
        let (h2, _rx2) = live_handle();
        let (last2, missed2) = activity(0, 0);
        let (new, replaced) = reg
            .register("app".into(), h2, false, last2, missed2)
            .expect("takeover");
        assert!(replaced);
        assert_ne!(old.session_id, new.session_id);
    }

    #[tokio::test]
    async fn no_heartbeat_session_takeover_after_idle() {
        let reg = Registry::new();
        let (h1, _rx) = live_handle();
        let (stale, missed) = activity(SESSION_STALE_SECS + 1, 0);
        let (old, _) = reg
            .register("app".into(), h1, false, stale, missed)
            .expect("old");
        let (h2, _rx2) = live_handle();
        let (last2, missed2) = activity(0, 0);
        let (new, replaced) = reg
            .register("app".into(), h2, false, last2, missed2)
            .expect("takeover");
        assert!(replaced);
        assert_ne!(old.session_id, new.session_id);
    }

    #[tokio::test]
    async fn reject_reserved_subdomain() {
        let reg = Registry::new();
        let (handle, _rx) = live_handle();
        let (last, missed) = activity(0, 0);
        match reg.register("dashboard".into(), handle, true, last, missed) {
            Ok(_) => panic!("expected reserved id to fail"),
            Err(e) => assert!(e.to_string().contains("reserved")),
        }
    }
}
