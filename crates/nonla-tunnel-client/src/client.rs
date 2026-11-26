//! Nonla Tunnel client — connects to server, accepts yamux streams, proxies to local service.

use crate::config::ClientTlsConfig;
use anyhow::{bail, Context, Result};
use nonla_tunnel_protocol::*;
use std::future::poll_fn;
use std::sync::Arc;
use tokio::io;
use tokio::net::TcpStream;
use tokio::sync::watch;
use tokio_util::compat::{FuturesAsyncReadCompatExt, TokioAsyncReadCompatExt};
use tokio_util::sync::CancellationToken;

/// Server rejected the token. Permanent — retrying cannot succeed.
#[derive(Debug)]
pub struct AuthError(pub String);

impl std::fmt::Display for AuthError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Authentication failed: {}", self.0)
    }
}

impl std::error::Error for AuthError {}

/// Rejections worth retrying (server-side trouble, not a bad credential/name).
/// Everything else — invalid token, revoked, name taken, banned — is permanent.
pub fn is_transient_auth_failure(message: &str) -> bool {
    message.starts_with("Server error")
}

#[derive(Debug, Clone, Default)]
#[allow(dead_code)]
pub enum TunnelStatus {
    #[default]
    Stopped,
    Connecting,
    Connected {
        route: String,
        since: std::time::Instant,
    },
    Error {
        message: String,
    },
}

pub struct Client {
    server_addr: String,
    local_addr: String,
    client_id: String,
    token: String,
    claim_key: String,
    tls_config: ClientTlsConfig,
}

impl Client {
    pub fn new(
        server_addr: String,
        local_addr: String,
        client_id: String,
        token: String,
        claim_key: String,
        tls_config: ClientTlsConfig,
    ) -> Self {
        Self {
            server_addr,
            local_addr,
            client_id,
            token,
            claim_key,
            tls_config,
        }
    }

    pub async fn run_cancellable(
        &self,
        cancel: CancellationToken,
        status_tx: watch::Sender<TunnelStatus>,
    ) -> Result<()> {
        let _ = status_tx.send(TunnelStatus::Connecting);

        tokio::select! {
            result = self.run_with_status(&status_tx) => {
                if let Err(ref e) = result {
                    let _ = status_tx.send(TunnelStatus::Error {
                        message: format!("{:#}", e),
                    });
                }
                result
            }
            _ = cancel.cancelled() => {
                tracing::info!("Tunnel '{}' cancelled", self.client_id);
                let _ = status_tx.send(TunnelStatus::Stopped);
                Ok(())
            }
        }
    }

    async fn run_with_status(&self, status_tx: &watch::Sender<TunnelStatus>) -> Result<()> {
        let stream = TcpStream::connect(&self.server_addr)
            .await
            .with_context(|| format!("connect to {}", self.server_addr))?;

        if let Err(e) = Self::configure_tcp_keepalive(&stream) {
            tracing::warn!("TCP keepalive failed: {}", e);
        }

        tracing::info!("Connected to {}", self.server_addr);

        if self.tls_config.enabled {
            let tls_stream = self.tls_connect(stream).await?;
            self.run_session_with_status(tls_stream, status_tx).await
        } else {
            self.run_session_with_status(stream, status_tx).await
        }
    }

    /// Trade a one-time invite for a permanent credential (see `EnrollReq`).
    /// Only `server_addr` and `tls_config` of `self` are used.
    pub async fn enroll(&self, invite: &str, label: Option<String>) -> Result<EnrollRes> {
        let stream = TcpStream::connect(&self.server_addr)
            .await
            .with_context(|| format!("connect to {}", self.server_addr))?;
        if self.tls_config.enabled {
            let s = self.tls_connect(stream).await?;
            Self::enroll_on(s, invite, label).await
        } else {
            Self::enroll_on(stream, invite, label).await
        }
    }

    async fn enroll_on<S>(mut stream: S, invite: &str, label: Option<String>) -> Result<EnrollRes>
    where
        S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
    {
        let req = Message::EnrollReq(EnrollReq {
            invite: invite.to_string(),
            label,
        });
        write_message(&mut stream, &req).await?;
        let res = tokio::time::timeout(std::time::Duration::from_secs(20), read_message(&mut stream))
            .await
            .map_err(|_| anyhow::anyhow!("timed out waiting for enrollment response"))?
            .map_err(|e| {
                anyhow::anyhow!(
                    "server closed the connection during enrollment ({:#}) — is the server upgraded to a version with enrollment?",
                    e
                )
            })?;
        match res {
            Message::EnrollRes(r) => Ok(r),
            other => bail!("Expected EnrollRes, got {:?}", other),
        }
    }

    async fn tls_connect(
        &self,
        stream: TcpStream,
    ) -> Result<tokio_rustls::client::TlsStream<TcpStream>> {
        use tokio_rustls::rustls;

        let config = if self.tls_config.skip_verify {
            let crypto_provider = rustls::crypto::ring::default_provider();
            rustls::ClientConfig::builder_with_provider(Arc::new(crypto_provider))
                .with_safe_default_protocol_versions()
                .context("build TLS protocol versions")?
                .dangerous()
                .with_custom_certificate_verifier(Arc::new(NoVerifier))
                .with_no_client_auth()
        } else {
            let root_store =
                rustls::RootCertStore::from_iter(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
            let crypto_provider = rustls::crypto::ring::default_provider();
            rustls::ClientConfig::builder_with_provider(Arc::new(crypto_provider))
                .with_safe_default_protocol_versions()
                .context("build TLS protocol versions")?
                .with_root_certificates(root_store)
                .with_no_client_auth()
        };

        let connector = tokio_rustls::TlsConnector::from(Arc::new(config));
        let server_name = self.resolve_server_name()?;
        connector
            .connect(server_name, stream)
            .await
            .context("TLS handshake failed")
    }

    fn resolve_server_name(&self) -> Result<tokio_rustls::rustls::pki_types::ServerName<'static>> {
        use tokio_rustls::rustls::pki_types::ServerName;

        let name = if !self.tls_config.server_name.is_empty() {
            self.tls_config.server_name.clone()
        } else {
            self.server_addr
                .split(':')
                .next()
                .unwrap_or(&self.server_addr)
                .to_string()
        };

        ServerName::try_from(name.clone()).map_err(|_| {
            anyhow::anyhow!(
                "Invalid TLS server name '{}'. Use --tls-server-name if connecting by IP.",
                name
            )
        })
    }

    async fn run_session_with_status<S>(
        &self,
        mut stream: S,
        status_tx: &watch::Sender<TunnelStatus>,
    ) -> Result<()>
    where
        S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
    {
        let auth_req = Message::AuthReq(AuthReq {
            client_id: self.client_id.clone(),
            token: self.token.clone(),
            version: Some(env!("CARGO_PKG_VERSION").to_string()),
            claim_key: Some(self.claim_key.clone()),
        });
        write_message(&mut stream, &auth_req).await?;

        let auth_res = read_message(&mut stream)
            .await
            .context("read auth response")?;
        match auth_res {
            Message::AuthRes(res) => {
                if !res.success {
                    if is_transient_auth_failure(&res.message) {
                        bail!("Server rejected the session temporarily: {}", res.message);
                    }
                    return Err(AuthError(res.message).into());
                }

                let host = res
                    .message
                    .strip_prefix("OK — ")
                    .unwrap_or(res.assigned_route.as_deref().unwrap_or("-"));

                let route = format!("https://{}", host);
                let _ = status_tx.send(TunnelStatus::Connected {
                    route: route.clone(),
                    since: std::time::Instant::now(),
                });

                tracing::info!("Authenticated — {}", route);
            }
            other => bail!("Expected AuthRes, got {:?}", other),
        }

        let compat_stream = stream.compat();
        let yamux_config = yamux::Config::default();
        let mut conn = yamux::Connection::new(compat_stream, yamux_config, yamux::Mode::Client);

        loop {
            let maybe_stream = poll_fn(|cx| conn.poll_next_inbound(cx)).await;
            match maybe_stream {
                Some(Ok(yamux_stream)) => {
                    let local_addr = self.local_addr.clone();
                    tokio::spawn(async move {
                        let mut yamux_stream = yamux_stream;
                        let mut marker = [0u8; 1];
                        let marker_result =
                            tokio::time::timeout(std::time::Duration::from_secs(5), async {
                                use futures::io::AsyncReadExt;
                                yamux_stream.read_exact(&mut marker).await
                            })
                            .await;

                        match marker_result {
                            Ok(Ok(_)) if marker[0] == STREAM_TYPE_HEARTBEAT => {
                                use futures::io::AsyncWriteExt;
                                let _ = yamux_stream.write_all(&[STREAM_TYPE_HEARTBEAT]).await;
                                let _ = yamux_stream.close().await;
                            }
                            Ok(Ok(_)) => {
                                let _ = Self::handle_tunnel_stream(yamux_stream, &local_addr).await;
                            }
                            _ => {}
                        }
                    });
                }
                Some(Err(e)) => {
                    tracing::error!("Yamux error: {}", e);
                    break;
                }
                None => break,
            }
        }

        Ok(())
    }

    async fn handle_tunnel_stream(yamux_stream: yamux::Stream, local_addr: &str) -> Result<()> {
        let mut compat_stream = yamux_stream.compat();
        let mut local_stream = TcpStream::connect(local_addr)
            .await
            .with_context(|| format!("connect to local {}", local_addr))?;
        let _ = io::copy_bidirectional(&mut compat_stream, &mut local_stream).await;
        Ok(())
    }

    fn configure_tcp_keepalive(stream: &TcpStream) -> Result<()> {
        use socket2::SockRef;
        use std::time::Duration;

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

#[derive(Debug)]
struct NoVerifier;

impl tokio_rustls::rustls::client::danger::ServerCertVerifier for NoVerifier {
    fn verify_server_cert(
        &self,
        _end_entity: &tokio_rustls::rustls::pki_types::CertificateDer<'_>,
        _intermediates: &[tokio_rustls::rustls::pki_types::CertificateDer<'_>],
        _server_name: &tokio_rustls::rustls::pki_types::ServerName<'_>,
        _ocsp_response: &[u8],
        _now: tokio_rustls::rustls::pki_types::UnixTime,
    ) -> Result<tokio_rustls::rustls::client::danger::ServerCertVerified, tokio_rustls::rustls::Error>
    {
        Ok(tokio_rustls::rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &tokio_rustls::rustls::pki_types::CertificateDer<'_>,
        _dss: &tokio_rustls::rustls::DigitallySignedStruct,
    ) -> Result<
        tokio_rustls::rustls::client::danger::HandshakeSignatureValid,
        tokio_rustls::rustls::Error,
    > {
        Ok(tokio_rustls::rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &tokio_rustls::rustls::pki_types::CertificateDer<'_>,
        _dss: &tokio_rustls::rustls::DigitallySignedStruct,
    ) -> Result<
        tokio_rustls::rustls::client::danger::HandshakeSignatureValid,
        tokio_rustls::rustls::Error,
    > {
        Ok(tokio_rustls::rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<tokio_rustls::rustls::SignatureScheme> {
        tokio_rustls::rustls::crypto::ring::default_provider()
            .signature_verification_algorithms
            .supported_schemes()
    }
}

#[cfg(test)]
mod tests {
    use super::is_transient_auth_failure;

    #[test]
    fn transient_vs_permanent_rejections() {
        assert!(is_transient_auth_failure("Server error (temporary)"));
        for permanent in [
            "Invalid token",
            "tunnel name 'a' is in use by another client",
            "tunnel 'a' was disconnected by the operator; reconnect allowed in 60s",
            "Invalid tunnel name: x",
        ] {
            assert!(!is_transient_auth_failure(permanent), "{permanent}");
        }
    }
}
