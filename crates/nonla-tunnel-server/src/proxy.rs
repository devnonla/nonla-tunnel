//! HTTP reverse proxy — routes public requests to the correct tunnel client.
//! Uses subdomain-based routing: <client_id>.<domain> → client_id
use crate::metrics::{Metrics, RateLimiter};
use crate::registry::Registry;
use anyhow::Context;
use http_body_util::BodyExt;
use hyper::body::Incoming;
use hyper::{Request, Response, StatusCode};
use hyper_util::rt::TokioIo;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use tokio_util::compat::FuturesAsyncReadCompatExt;

pub type BoxBody = http_body_util::combinators::BoxBody<bytes::Bytes, hyper::Error>;

fn full_body(data: impl Into<bytes::Bytes>) -> BoxBody {
    http_body_util::Full::new(data.into())
        .map_err(|never| match never {})
        .boxed()
}

fn error_response(status: StatusCode, msg: &str) -> Response<BoxBody> {
    let body = serde_json::json!({ "error": msg, "status": status.as_u16() }).to_string();
    Response::builder()
        .status(status)
        .header("content-type", "application/json")
        .header("x-powered-by", "nonla-tunnel")
        .body(full_body(body))
        .unwrap()
}

/// Extract client_id and forwarded path from an HTTP request.
/// Uses subdomain routing: <client_id>.<domain> → (client_id, original_path)
fn extract_routing(req: &Request<Incoming>, domain: &str) -> Option<(String, String)> {
    let host = req.headers().get("host").and_then(|v| v.to_str().ok())?;
    let client_id = client_id_from_host(host, domain)?;
    Some((client_id, req.uri().path().to_string()))
}

/// `<name>.<domain>[:port]` → `name`, only if `name` is a valid tunnel name.
/// Host names are case-insensitive; tunnel names are lowercase.
fn client_id_from_host(host: &str, domain: &str) -> Option<String> {
    let host_no_port = host.split(':').next().unwrap_or(host).to_ascii_lowercase();
    let suffix = format!(".{}", domain.to_ascii_lowercase());
    let client_id = host_no_port.strip_suffix(&suffix)?;
    nonla_tunnel_protocol::validate_client_id(client_id).ok()?;
    Some(client_id.to_string())
}

/// Wrap a body so every data frame adds its length to `counters`.
/// `hold` (e.g. a stream-slot permit) is released when the body is dropped.
fn counted<B>(
    body: B,
    counters: [Arc<std::sync::atomic::AtomicU64>; 2],
    hold: Option<tokio::sync::OwnedSemaphorePermit>,
) -> BoxBody
where
    B: hyper::body::Body<Data = bytes::Bytes, Error = hyper::Error> + Send + Sync + 'static,
{
    body.map_frame(move |frame| {
        let _hold = &hold;
        if let Some(data) = frame.data_ref() {
            for c in &counters {
                c.fetch_add(data.len() as u64, Ordering::Relaxed);
            }
        }
        frame
    })
    .boxed()
}

/// Build a forwarded request, rewriting the path and adding proxy headers.
fn build_forwarded_request<B>(
    req: Request<B>,
    path: &str,
    client_id: &str,
) -> anyhow::Result<Request<B>> {
    let (mut parts, body) = req.into_parts();

    // Build new URI with rewritten path
    let query = parts
        .uri
        .query()
        .map(|q| format!("?{}", q))
        .unwrap_or_default();
    let new_uri: hyper::Uri = format!("{}{}", path, query)
        .parse()
        .context("build forwarded uri")?;
    parts.uri = new_uri;

    // Add forwarding headers
    if let Ok(val) = hyper::header::HeaderValue::from_str(client_id) {
        parts.headers.insert("x-nonla-tunnel-client", val);
    }

    // Force Connection: close for clean stream lifecycle
    parts.headers.insert(
        hyper::header::CONNECTION,
        hyper::header::HeaderValue::from_static("close"),
    );

    Ok(Request::from_parts(parts, body))
}

/// Handle an incoming public HTTP request by routing it through a tunnel.
pub async fn handle_proxy_request(
    req: Request<Incoming>,
    registry: Arc<Registry>,
    metrics: Arc<Metrics>,
    rate_limiter: Arc<RateLimiter>,
    domain: String,
) -> Result<Response<BoxBody>, hyper::Error> {
    metrics.total_requests.fetch_add(1, Ordering::Relaxed);

    // Extract routing from subdomain. Never list connected tunnels: names
    // are private to whoever created them.
    let Some((client_id, path)) = extract_routing(&req, &domain) else {
        return Ok(error_response(StatusCode::NOT_FOUND, "Tunnel not found"));
    };

    // Find the client first, so unknown hosts never allocate rate-limit state.
    let Some(client) = registry.get(&client_id) else {
        return Ok(error_response(
            StatusCode::BAD_GATEWAY,
            "Tunnel not found or offline",
        ));
    };

    // Rate limiting
    if !rate_limiter.check(&client_id) {
        metrics.rate_limited.fetch_add(1, Ordering::Relaxed);
        return Ok(error_response(
            StatusCode::TOO_MANY_REQUESTS,
            "Rate limit exceeded",
        ));
    }

    // Concurrency cap per tunnel: slow/hung requests cannot exhaust the
    // yamux stream table (which would starve heartbeats and drop the agent).
    // The permit is held until the response body is fully sent.
    let Ok(slot) = client.stream_slots.clone().try_acquire_owned() else {
        metrics.rate_limited.fetch_add(1, Ordering::Relaxed);
        return Ok(error_response(
            StatusCode::SERVICE_UNAVAILABLE,
            "Tunnel busy: too many concurrent requests",
        ));
    };

    // Track metrics
    client.metrics.requests.fetch_add(1, Ordering::Relaxed);
    client
        .metrics
        .active_streams
        .fetch_add(1, Ordering::Relaxed);
    metrics.active_connections.fetch_add(1, Ordering::Relaxed);

    // Open yamux stream to the client
    let mut yamux_stream = match client.handle.open_stream().await {
        Ok(s) => s,
        Err(e) => {
            client
                .metrics
                .active_streams
                .fetch_sub(1, Ordering::Relaxed);
            metrics.active_connections.fetch_sub(1, Ordering::Relaxed);
            tracing::error!("Failed to open yamux stream to '{}': {}", client_id, e);
            return Ok(error_response(
                StatusCode::BAD_GATEWAY,
                &format!("Tunnel '{}' connection error", client_id),
            ));
        }
    };

    // Write stream type marker so client can distinguish proxy vs heartbeat (only if client supports it)
    if client.supports_heartbeat {
        use futures::io::AsyncWriteExt;
        if let Err(e) = yamux_stream
            .write_all(&[nonla_tunnel_protocol::STREAM_TYPE_PROXY])
            .await
        {
            client
                .metrics
                .active_streams
                .fetch_sub(1, Ordering::Relaxed);
            metrics.active_connections.fetch_sub(1, Ordering::Relaxed);
            tracing::error!("Failed to write stream marker to '{}': {}", client_id, e);
            return Ok(error_response(
                StatusCode::BAD_GATEWAY,
                &format!("Tunnel '{}' connection error", client_id),
            ));
        }
    }

    // Compat: yamux uses futures-io, hyper needs tokio-io
    let compat_stream = yamux_stream.compat();
    let io = TokioIo::new(compat_stream);

    // HTTP/1.1 handshake over the yamux stream
    let (mut sender, conn) = match hyper::client::conn::http1::handshake(io).await {
        Ok(r) => r,
        Err(e) => {
            client
                .metrics
                .active_streams
                .fetch_sub(1, Ordering::Relaxed);
            metrics.active_connections.fetch_sub(1, Ordering::Relaxed);
            tracing::error!("HTTP handshake to '{}' failed: {}", client_id, e);
            return Ok(error_response(
                StatusCode::BAD_GATEWAY,
                "Tunnel HTTP handshake failed",
            ));
        }
    };

    // Drive the HTTP connection in background
    let cid = client_id.clone();
    tokio::spawn(async move {
        if let Err(e) = conn.await {
            tracing::debug!("HTTP conn to '{}' done: {}", cid, e);
        }
    });

    // Build and forward the request
    // Count request bytes (public → tunnel) per client and server-wide.
    let req = {
        let (parts, body) = req.into_parts();
        let counters = [
            client.metrics.bytes_in.clone(),
            metrics.total_bytes_in.clone(),
        ];
        Request::from_parts(parts, counted(body, counters, None))
    };
    let forwarded = match build_forwarded_request(req, &path, &client_id) {
        Ok(r) => r,
        Err(e) => {
            client
                .metrics
                .active_streams
                .fetch_sub(1, Ordering::Relaxed);
            metrics.active_connections.fetch_sub(1, Ordering::Relaxed);
            tracing::error!("Build forwarded request failed: {}", e);
            return Ok(error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                "Request forwarding error",
            ));
        }
    };

    let resp = match sender.send_request(forwarded).await {
        Ok(resp) => resp,
        Err(e) => {
            client
                .metrics
                .active_streams
                .fetch_sub(1, Ordering::Relaxed);
            metrics.active_connections.fetch_sub(1, Ordering::Relaxed);
            tracing::error!("Proxy request to '{}' failed: {}", client_id, e);
            return Ok(error_response(
                StatusCode::BAD_GATEWAY,
                &format!("Tunnel '{}' did not respond", client_id),
            ));
        }
    };

    client
        .metrics
        .active_streams
        .fetch_sub(1, Ordering::Relaxed);
    metrics.active_connections.fetch_sub(1, Ordering::Relaxed);

    client.touch();
    tracing::info!(
        "→ {} {} → '{}' → {}",
        resp.status().as_u16(),
        path,
        client_id,
        resp.status()
    );

    // Convert response body
    let (parts, body) = resp.into_parts();
    let counters = [
        client.metrics.bytes_out.clone(),
        metrics.total_bytes_out.clone(),
    ];
    Ok(Response::from_parts(
        parts,
        counted(body, counters, Some(slot)),
    ))
}

#[cfg(test)]
mod tests {

    use super::client_id_from_host;

    fn extract_subdomain_routing(host: &str, path: &str, domain: &str) -> Option<(String, String)> {
        client_id_from_host(host, domain).map(|c| (c, path.to_string()))
    }

    #[test]
    fn test_subdomain_rejects_invalid_names_and_lowercases() {
        let d = "tunnel.example.com";
        assert_eq!(
            client_id_from_host("MyApp.Tunnel.Example.com", d),
            Some("myapp".into())
        );
        assert_eq!(client_id_from_host("a.b.tunnel.example.com", d), None);
        assert_eq!(client_id_from_host("a_b.tunnel.example.com", d), None);
        assert_eq!(client_id_from_host(".tunnel.example.com", d), None);
        assert_eq!(client_id_from_host("tunnel.example.com", d), None);
    }

    #[test]
    fn test_error_response_is_valid_json() {
        let resp = super::error_response(hyper::StatusCode::NOT_FOUND, "a\"b");
        assert_eq!(resp.status(), 404);
    }

    #[test]
    fn test_subdomain_routing_basic() {
        let result = extract_subdomain_routing(
            "webapp.tunnel.example.com",
            "/api/users",
            "tunnel.example.com",
        );
        assert_eq!(result, Some(("webapp".into(), "/api/users".into())));
    }

    #[test]
    fn test_subdomain_routing_with_port() {
        let result =
            extract_subdomain_routing("webapp.tunnel.example.com:6210", "/", "tunnel.example.com");
        assert_eq!(result, Some(("webapp".into(), "/".into())));
    }

    #[test]
    fn test_subdomain_routing_no_match() {
        let result = extract_subdomain_routing("other.domain.com", "/", "tunnel.example.com");
        assert_eq!(result, None);
    }

    #[test]
    fn test_subdomain_exact_domain_no_subdomain() {
        let result = extract_subdomain_routing("tunnel.example.com", "/", "tunnel.example.com");
        assert_eq!(result, None);
    }

    #[test]
    fn test_subdomain_path_preserved() {
        let result = extract_subdomain_routing(
            "myapp.tunnel.example.com",
            "/dashboard/settings?tab=profile",
            "tunnel.example.com",
        );
        assert_eq!(
            result,
            Some(("myapp".into(), "/dashboard/settings?tab=profile".into()))
        );
    }

    #[test]
    fn test_subdomain_deep_path() {
        let result = extract_subdomain_routing(
            "api.tunnel.example.com",
            "/v2/users/123/posts",
            "tunnel.example.com",
        );
        assert_eq!(result, Some(("api".into(), "/v2/users/123/posts".into())));
    }
}
