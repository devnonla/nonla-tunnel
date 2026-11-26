//! Global server metrics.

use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Instant;

/// Server-wide metrics.
pub struct Metrics {
    pub started_at: Instant,
    pub total_requests: AtomicU64,
    pub total_bytes_in: std::sync::Arc<AtomicU64>,
    pub total_bytes_out: std::sync::Arc<AtomicU64>,
    pub active_connections: AtomicU64,
    pub total_connections: AtomicU64,
    pub failed_auth: AtomicU64,
    pub rate_limited: AtomicU64,
}

impl Metrics {
    pub fn new() -> Self {
        Self {
            started_at: Instant::now(),
            total_requests: AtomicU64::new(0),
            total_bytes_in: std::sync::Arc::new(AtomicU64::new(0)),
            total_bytes_out: std::sync::Arc::new(AtomicU64::new(0)),
            active_connections: AtomicU64::new(0),
            total_connections: AtomicU64::new(0),
            failed_auth: AtomicU64::new(0),
            rate_limited: AtomicU64::new(0),
        }
    }
}

/// Serializable metrics snapshot (logged on shutdown).
#[derive(serde::Serialize)]
pub struct MetricsSnapshot {
    pub uptime_secs: u64,
    pub total_requests: u64,
    pub total_bytes_in: u64,
    pub total_bytes_out: u64,
    pub active_connections: u64,
    pub total_connections: u64,
    pub failed_auth: u64,
    pub rate_limited: u64,
}

impl Metrics {
    pub fn snapshot(&self) -> MetricsSnapshot {
        MetricsSnapshot {
            uptime_secs: self.started_at.elapsed().as_secs(),
            total_requests: self.total_requests.load(Ordering::Relaxed),
            total_bytes_in: self.total_bytes_in.load(Ordering::Relaxed),
            total_bytes_out: self.total_bytes_out.load(Ordering::Relaxed),
            active_connections: self.active_connections.load(Ordering::Relaxed),
            total_connections: self.total_connections.load(Ordering::Relaxed),
            failed_auth: self.failed_auth.load(Ordering::Relaxed),
            rate_limited: self.rate_limited.load(Ordering::Relaxed),
        }
    }
}

/// Drop expired rate-limit windows once the map grows past this size.
const RATE_LIMIT_PRUNE_AT: usize = 1024;

/// Failed control-channel auth attempts allowed per IP per window.
pub const AUTH_MAX_FAILURES: u32 = 10;
pub const AUTH_FAILURE_WINDOW_SECS: u64 = 60;

/// Per-IP failed-auth throttle for the control channel (token brute force).
///
/// Loopback peers are never blocked: behind Traefik every client arrives
/// from 127.0.0.1, so blocking that address would let anyone lock out all
/// legitimate clients with a few bad tokens. Those connections are slowed
/// per attempt instead (see `AUTH_FAILURE_DELAY_SECS`).
pub struct AuthLimiter {
    failures: dashmap::DashMap<std::net::IpAddr, (Instant, u32)>,
}

impl AuthLimiter {
    pub fn new() -> Self {
        Self {
            failures: dashmap::DashMap::new(),
        }
    }

    fn window_active(start: Instant, now: Instant) -> bool {
        now.duration_since(start).as_secs() < AUTH_FAILURE_WINDOW_SECS
    }

    /// True if this IP is currently blocked.
    pub fn is_blocked(&self, ip: std::net::IpAddr) -> bool {
        if ip.is_loopback() {
            return false;
        }
        let now = Instant::now();
        match self.failures.get(&ip) {
            Some(e) => Self::window_active(e.0, now) && e.1 >= AUTH_MAX_FAILURES,
            None => false,
        }
    }

    pub fn record_failure(&self, ip: std::net::IpAddr) {
        if ip.is_loopback() {
            return;
        }
        let now = Instant::now();
        if self.failures.len() > RATE_LIMIT_PRUNE_AT {
            self.failures
                .retain(|_, (start, _)| Self::window_active(*start, now));
        }
        let mut e = self.failures.entry(ip).or_insert((now, 0));
        if !Self::window_active(e.0, now) {
            *e = (now, 0);
        }
        e.1 += 1;
    }

    pub fn record_success(&self, ip: std::net::IpAddr) {
        self.failures.remove(&ip);
    }
}

/// Simple per-key sliding-window rate limiter.
pub struct RateLimiter {
    max_per_second: u32,
    counters: dashmap::DashMap<String, (Instant, u32)>,
}

impl RateLimiter {
    pub fn new(max_per_second: u32) -> Self {
        Self {
            max_per_second,
            counters: dashmap::DashMap::new(),
        }
    }

    /// Returns true if the request is allowed.
    pub fn check(&self, key: &str) -> bool {
        if self.max_per_second == 0 {
            return true;
        }
        let now = Instant::now();
        if self.counters.len() > RATE_LIMIT_PRUNE_AT {
            self.counters
                .retain(|_, (start, _)| now.duration_since(*start).as_secs() < 1);
        }
        let mut entry = self.counters.entry(key.to_string()).or_insert((now, 0));
        let (window_start, count) = entry.value_mut();

        if now.duration_since(*window_start).as_secs() >= 1 {
            *window_start = now;
            *count = 1;
            true
        } else if *count < self.max_per_second {
            *count += 1;
            true
        } else {
            false
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_auth_limiter_blocks_after_max_failures() {
        let al = AuthLimiter::new();
        let ip: std::net::IpAddr = "203.0.113.7".parse().unwrap();
        let other: std::net::IpAddr = "203.0.113.8".parse().unwrap();
        for _ in 0..AUTH_MAX_FAILURES - 1 {
            al.record_failure(ip);
        }
        assert!(!al.is_blocked(ip));
        al.record_failure(ip);
        assert!(al.is_blocked(ip));
        assert!(!al.is_blocked(other));
        al.record_success(ip);
        assert!(!al.is_blocked(ip));
    }

    #[test]
    fn test_auth_limiter_never_blocks_loopback() {
        // Behind Traefik all clients share 127.0.0.1.
        let al = AuthLimiter::new();
        let lo: std::net::IpAddr = "127.0.0.1".parse().unwrap();
        for _ in 0..AUTH_MAX_FAILURES * 3 {
            al.record_failure(lo);
        }
        assert!(!al.is_blocked(lo));
    }

    #[test]
    fn test_rate_limiter_prunes_stale_keys() {
        let rl = RateLimiter::new(10);
        for i in 0..RATE_LIMIT_PRUNE_AT + 10 {
            rl.check(&format!("k{i}"));
        }
        // Age every window, then one more check triggers the prune.
        for mut e in rl.counters.iter_mut() {
            e.value_mut().0 = Instant::now() - std::time::Duration::from_secs(5);
        }
        rl.check("fresh");
        assert_eq!(rl.counters.len(), 1);
    }

    #[test]
    fn test_rate_limiter_disabled() {
        let rl = RateLimiter::new(0);
        // When max_per_second is 0, all requests are allowed
        for _ in 0..1000 {
            assert!(rl.check("test"));
        }
    }

    #[test]
    fn test_rate_limiter_basic() {
        let rl = RateLimiter::new(3);
        assert!(rl.check("client-a")); // 1
        assert!(rl.check("client-a")); // 2
        assert!(rl.check("client-a")); // 3
        assert!(!rl.check("client-a")); // 4 → rejected

        // Different key should have its own counter
        assert!(rl.check("client-b"));
    }

    #[test]
    fn test_metrics_snapshot() {
        let m = Metrics::new();
        m.total_requests.fetch_add(42, Ordering::Relaxed);
        m.failed_auth.fetch_add(3, Ordering::Relaxed);

        let snap = m.snapshot();
        assert_eq!(snap.total_requests, 42);
        assert_eq!(snap.failed_auth, 3);
        assert_eq!(snap.active_connections, 0);
        assert!(snap.uptime_secs < 2); // just created
    }
}
