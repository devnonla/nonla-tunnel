//! PROXY protocol (v1 + v2) on the control channel.
//!
//! Behind Traefik every control connection arrives from 127.0.0.1. Traefik
//! prepends a PROXY header carrying the real client address, which the
//! server uses for session listings and per-IP auth throttling.
//!
//! The header is only honoured from loopback peers (where Traefik runs) and
//! from peers inside the configured `trusted_proxies` CIDR ranges (e.g. a
//! Traefik container on a Docker Swarm overlay network). It is optional
//! there, so direct clients keep working. From any other peer it is never
//! parsed — a remote client cannot spoof its address.

use anyhow::{bail, Context, Result};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::time::Duration;
use tokio::io::AsyncReadExt;
use tokio::net::TcpStream;

const V2_SIG: [u8; 12] = *b"\r\n\r\n\0\r\nQUIT\n";
const V1_PREFIX: &[u8] = b"PROXY ";
const V1_MAX: usize = 107;
const HEADER_TIMEOUT: Duration = Duration::from_secs(5);

/// An IP range in CIDR notation (`10.0.0.0/8`, `fd00::/8`, or a bare IP).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Cidr {
    net: IpAddr,
    prefix: u8,
}

impl Cidr {
    pub fn parse(s: &str) -> Result<Self> {
        let s = s.trim();
        let (ip, prefix) = match s.split_once('/') {
            Some((ip, p)) => (ip, Some(p)),
            None => (s, None),
        };
        let net: IpAddr = ip
            .parse()
            .with_context(|| format!("trusted_proxies: invalid IP in {s:?}"))?;
        let max = if net.is_ipv4() { 32 } else { 128 };
        let prefix = match prefix {
            Some(p) => p
                .parse::<u8>()
                .ok()
                .filter(|p| *p <= max)
                .with_context(|| format!("trusted_proxies: invalid prefix in {s:?}"))?,
            None => max,
        };
        Ok(Self { net, prefix })
    }

    pub fn contains(&self, ip: IpAddr) -> bool {
        // An IPv4-mapped IPv6 peer (::ffff:a.b.c.d) is matched as IPv4.
        let ip = match ip {
            IpAddr::V6(v6) => v6.to_ipv4_mapped().map(IpAddr::V4).unwrap_or(ip),
            v4 => v4,
        };
        match (self.net, ip) {
            (IpAddr::V4(n), IpAddr::V4(a)) => {
                mask_eq(u32::from(n) as u128, u32::from(a) as u128, 32, self.prefix)
            }
            (IpAddr::V6(n), IpAddr::V6(a)) => {
                mask_eq(u128::from(n), u128::from(a), 128, self.prefix)
            }
            _ => false,
        }
    }
}

fn mask_eq(a: u128, b: u128, bits: u32, prefix: u8) -> bool {
    if prefix == 0 {
        return true;
    }
    let shift = bits - prefix as u32;
    (a >> shift) == (b >> shift)
}

/// Parse the `trusted_proxies` config list.
pub fn parse_trusted(list: &[String]) -> Result<Vec<Cidr>> {
    list.iter().map(|s| Cidr::parse(s)).collect()
}

/// Whether this peer may send a PROXY header: loopback, or inside one of
/// the configured `trusted` ranges.
pub fn trusted_peer(peer: &SocketAddr, trusted: &[Cidr]) -> bool {
    let ip = peer.ip();
    ip.is_loopback() || trusted.iter().any(|c| c.contains(ip))
}

/// Peek until at least `n` bytes are buffered (or the peer stops sending).
async fn peek_n(stream: &TcpStream, buf: &mut [u8], n: usize) -> Result<usize> {
    let deadline = tokio::time::Instant::now() + HEADER_TIMEOUT;
    loop {
        let got = tokio::time::timeout_at(deadline, stream.peek(buf))
            .await
            .context("timeout waiting for client data")??;
        if got >= n || got == 0 {
            return Ok(got);
        }
        if tokio::time::Instant::now() >= deadline {
            return Ok(got);
        }
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
}

/// Consume a PROXY header if one is present and the peer is trusted.
/// Returns the real client address (or `peer` when there is no header).
pub async fn read_client_addr(
    stream: &mut TcpStream,
    peer: SocketAddr,
    trusted: &[Cidr],
) -> Result<SocketAddr> {
    if !trusted_peer(&peer, trusted) {
        return Ok(peer);
    }
    let mut buf = [0u8; 16];
    let got = peek_n(stream, &mut buf, 1).await?;
    if got == 0 {
        return Ok(peer);
    }
    match buf[0] {
        b'\r' => {
            if peek_n(stream, &mut buf, 16).await? < 16 || buf[..12] != V2_SIG {
                return Ok(peer);
            }
            read_v2(stream, peer).await
        }
        b'P' => {
            if peek_n(stream, &mut buf, V1_PREFIX.len()).await? < V1_PREFIX.len()
                || &buf[..V1_PREFIX.len()] != V1_PREFIX
            {
                return Ok(peer);
            }
            read_v1(stream, peer).await
        }
        _ => Ok(peer),
    }
}

async fn read_v2(stream: &mut TcpStream, peer: SocketAddr) -> Result<SocketAddr> {
    let mut hdr = [0u8; 16];
    stream.read_exact(&mut hdr).await?;
    let ver_cmd = hdr[12];
    let fam = hdr[13];
    let len = u16::from_be_bytes([hdr[14], hdr[15]]) as usize;
    if ver_cmd >> 4 != 2 {
        bail!("PROXY v2: bad version");
    }
    if len > 512 {
        bail!("PROXY v2: header too long");
    }
    let mut body = vec![0u8; len];
    stream.read_exact(&mut body).await?;
    parse_v2(ver_cmd, fam, &body, peer)
}

fn parse_v2(ver_cmd: u8, fam: u8, body: &[u8], peer: SocketAddr) -> Result<SocketAddr> {
    // LOCAL command (health checks) or unspecified family: keep the peer.
    if ver_cmd & 0x0f == 0 {
        return Ok(peer);
    }
    match fam {
        0x11 | 0x12 if body.len() >= 12 => {
            let ip = Ipv4Addr::new(body[0], body[1], body[2], body[3]);
            let port = u16::from_be_bytes([body[8], body[9]]);
            Ok(SocketAddr::new(IpAddr::V4(ip), port))
        }
        0x21 | 0x22 if body.len() >= 36 => {
            let mut a = [0u8; 16];
            a.copy_from_slice(&body[..16]);
            let port = u16::from_be_bytes([body[32], body[33]]);
            Ok(SocketAddr::new(IpAddr::V6(Ipv6Addr::from(a)), port))
        }
        0x11 | 0x12 | 0x21 | 0x22 => bail!("PROXY v2: truncated address"),
        _ => Ok(peer),
    }
}

async fn read_v1(stream: &mut TcpStream, peer: SocketAddr) -> Result<SocketAddr> {
    let mut line = Vec::with_capacity(V1_MAX);
    loop {
        let b = stream.read_u8().await?;
        line.push(b);
        if line.ends_with(b"\r\n") {
            break;
        }
        if line.len() >= V1_MAX {
            bail!("PROXY v1: header too long");
        }
    }
    parse_v1(&line, peer)
}

fn parse_v1(line: &[u8], peer: SocketAddr) -> Result<SocketAddr> {
    let text = std::str::from_utf8(line).context("PROXY v1: not utf-8")?;
    let parts: Vec<&str> = text.trim_end().split(' ').collect();
    match parts.as_slice() {
        ["PROXY", "UNKNOWN", ..] => Ok(peer),
        ["PROXY", "TCP4" | "TCP6", src, _dst, sport, _dport] => {
            let ip: IpAddr = src.parse().context("PROXY v1: bad source address")?;
            let port: u16 = sport.parse().context("PROXY v1: bad source port")?;
            Ok(SocketAddr::new(ip, port))
        }
        _ => bail!("PROXY v1: malformed header"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::AsyncWriteExt;

    fn lo() -> SocketAddr {
        "127.0.0.1:5000".parse().unwrap()
    }

    #[test]
    fn v2_ipv4_and_ipv6() {
        let body = [203, 0, 113, 7, 127, 0, 0, 1, 0x30, 0x39, 0x01, 0xbb];
        assert_eq!(
            parse_v2(0x21, 0x11, &body, lo()).unwrap(),
            "203.0.113.7:12345".parse().unwrap()
        );
        let mut b6 = vec![0u8; 36];
        b6[15] = 1; // ::1 → use 2001:db8::1
        b6[0] = 0x20;
        b6[1] = 0x01;
        b6[2] = 0x0d;
        b6[3] = 0xb8;
        b6[32] = 0x00;
        b6[33] = 0x50;
        assert_eq!(
            parse_v2(0x21, 0x21, &b6, lo()).unwrap(),
            "[2001:db8::1]:80".parse().unwrap()
        );
        assert_eq!(parse_v2(0x20, 0x11, &body, lo()).unwrap(), lo(), "LOCAL");
        assert!(parse_v2(0x21, 0x11, &body[..4], lo()).is_err());
    }

    #[test]
    fn v1_parsing() {
        assert_eq!(
            parse_v1(b"PROXY TCP4 198.51.100.2 127.0.0.1 40000 443\r\n", lo()).unwrap(),
            "198.51.100.2:40000".parse().unwrap()
        );
        assert_eq!(parse_v1(b"PROXY UNKNOWN\r\n", lo()).unwrap(), lo());
        assert!(parse_v1(b"PROXY TCP4 nope\r\n", lo()).is_err());
    }

    async fn pair() -> (TcpStream, TcpStream, SocketAddr) {
        let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let a = TcpStream::connect(l.local_addr().unwrap()).await.unwrap();
        let (b, peer) = l.accept().await.unwrap();
        (a, b, peer)
    }

    #[tokio::test]
    async fn header_consumed_and_payload_kept() {
        let (mut c, mut s, peer) = pair().await;
        let mut msg = V2_SIG.to_vec();
        msg.extend_from_slice(&[0x21, 0x11, 0x00, 0x0c]);
        msg.extend_from_slice(&[198, 51, 100, 9, 127, 0, 0, 1, 0x9c, 0x40, 0x01, 0xbb]);
        msg.extend_from_slice(&[0x01, 0x01, 0xAA]); // our protocol bytes follow
        c.write_all(&msg).await.unwrap();
        let addr = read_client_addr(&mut s, peer, &[]).await.unwrap();
        assert_eq!(addr, "198.51.100.9:40000".parse().unwrap());
        let mut rest = [0u8; 3];
        s.read_exact(&mut rest).await.unwrap();
        assert_eq!(rest, [0x01, 0x01, 0xAA]);
    }

    #[tokio::test]
    async fn no_header_leaves_stream_untouched() {
        let (mut c, mut s, peer) = pair().await;
        c.write_all(&[0x01, 0x01, 0x00]).await.unwrap();
        assert_eq!(read_client_addr(&mut s, peer, &[]).await.unwrap(), peer);
        let mut rest = [0u8; 3];
        s.read_exact(&mut rest).await.unwrap();
        assert_eq!(rest, [0x01, 0x01, 0x00]);
    }

    #[test]
    fn untrusted_peer_never_parsed() {
        assert!(!trusted_peer(&"203.0.113.1:1".parse().unwrap(), &[]));
        assert!(trusted_peer(&lo(), &[]));
        // An overlay peer is untrusted unless its range is configured.
        let overlay: SocketAddr = "10.0.3.7:1".parse().unwrap();
        assert!(!trusted_peer(&overlay, &[]));
    }

    #[test]
    fn trusted_proxies_cidr() {
        let t =
            parse_trusted(&["10.0.0.0/8".into(), "172.18.0.5".into(), "fd00::/8".into()]).unwrap();
        let ok = |s: &str| trusted_peer(&s.parse().unwrap(), &t);
        assert!(ok("10.0.3.7:1"));
        assert!(ok("10.255.255.255:1"));
        assert!(!ok("11.0.0.1:1"));
        assert!(ok("172.18.0.5:1"));
        assert!(!ok("172.18.0.6:1"));
        assert!(ok("[fd12::1]:1"));
        assert!(!ok("[fe80::1]:1"));
        assert!(ok("[::ffff:10.1.2.3]:1"), "v4-mapped peer");
        assert!(!ok("203.0.113.1:1"));
        // /0 trusts everything (allowed, but the operator asked for it).
        assert!(Cidr::parse("0.0.0.0/0")
            .unwrap()
            .contains("8.8.8.8".parse().unwrap()));
        assert!(Cidr::parse("10.0.0.0/33").is_err());
        assert!(Cidr::parse("nope").is_err());
        assert!(Cidr::parse("10.0.0.0/x").is_err());
    }

    #[tokio::test]
    async fn header_parsed_from_configured_range() {
        let (mut c, mut s, peer) = pair().await; // peer is 127.0.0.1 here
        let _ = peer;
        // Pretend the peer is an overlay address.
        let overlay: SocketAddr = "10.0.3.7:5000".parse().unwrap();
        let trusted = parse_trusted(&["10.0.0.0/8".into()]).unwrap();
        let mut msg = V2_SIG.to_vec();
        msg.extend_from_slice(&[0x21, 0x11, 0x00, 0x0c]);
        msg.extend_from_slice(&[198, 51, 100, 9, 10, 0, 3, 7, 0x9c, 0x40, 0x01, 0xbb]);
        c.write_all(&msg).await.unwrap();
        let addr = read_client_addr(&mut s, overlay, &trusted).await.unwrap();
        assert_eq!(addr, "198.51.100.9:40000".parse().unwrap());
    }

    #[tokio::test]
    async fn header_ignored_from_unconfigured_overlay_peer() {
        let (mut c, mut s, _) = pair().await;
        let overlay: SocketAddr = "10.0.3.7:5000".parse().unwrap();
        let mut msg = V2_SIG.to_vec();
        msg.extend_from_slice(&[0x21, 0x11, 0x00, 0x0c]);
        msg.extend_from_slice(&[198, 51, 100, 9, 10, 0, 3, 7, 0x9c, 0x40, 0x01, 0xbb]);
        c.write_all(&msg).await.unwrap();
        assert_eq!(
            read_client_addr(&mut s, overlay, &[]).await.unwrap(),
            overlay
        );
    }
}
