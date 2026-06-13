// Copyright 2025 Tree xie.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// This file implements HTTP request functionality with support for HTTP/1.1, HTTP/2, and HTTP/3
// It includes features like DNS resolution, TLS handshake, and request/response handling

use super::decompress::decompress;
use super::error::{Error, Result};
use super::finish_with_error;
use super::grpc::grpc_request;
use super::net::{dns_resolve, parse_certificates, quic_connect, tcp_connect, tls_handshake};
use super::proxy::{http_connect, socks5_connect, ProxyConfig, ProxyKind};
use super::stats::{
    parse_alt_svc, parse_hsts, parse_server_timing, HttpStat, ALPN_HTTP3, FIRST_CHUNK_BYTES,
};
use super::HttpRequest;
use bytes::{Buf, Bytes, BytesMut};
use futures::future;

use http::Request;
use http::Response;
use http::Version;
use http_body::{Body, Frame, SizeHint};
use http_body_util::BodyExt;
use hyper::body::Incoming;
use hyper_util::rt::TokioExecutor;
use hyper_util::rt::TokioIo;
use std::pin::Pin;
use std::sync::{Arc, Once, OnceLock};
use std::task::{Context, Poll};
use std::time::Duration;
use std::time::Instant;
use tokio::net::TcpStream;
use tokio::sync::oneshot;
use tokio::time::timeout;
use tokio_rustls::client::TlsStream;

/// Request body that records the `Instant` at which hyper finished consuming it.
///
/// Hyper does not expose a "request body fully sent" hook, but it does pull frames
/// from this `Body` impl until `poll_frame` returns `Ready(None)`. We capture the
/// timestamp at that boundary, which is the closest available signal to "last
/// request byte handed to the transport." Used to split the new `request_send`
/// phase from `server_processing`.
pub(crate) struct TrackedBody {
    data: Option<Bytes>,
    done: Arc<OnceLock<Instant>>,
}

impl TrackedBody {
    pub(crate) fn new(data: Bytes) -> (Self, Arc<OnceLock<Instant>>) {
        let done = Arc::new(OnceLock::new());
        (
            Self {
                data: Some(data),
                done: done.clone(),
            },
            done,
        )
    }
}

impl Body for TrackedBody {
    type Data = Bytes;
    type Error = std::convert::Infallible;

    fn poll_frame(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
    ) -> Poll<Option<std::result::Result<Frame<Self::Data>, Self::Error>>> {
        let this = self.get_mut();
        if let Some(bytes) = this.data.take() {
            Poll::Ready(Some(Ok(Frame::data(bytes))))
        } else {
            let _ = this.done.set(Instant::now());
            Poll::Ready(None)
        }
    }

    fn is_end_stream(&self) -> bool {
        // Always force hyper to poll us so we can record completion.
        false
    }

    fn size_hint(&self) -> SizeHint {
        match &self.data {
            Some(b) => SizeHint::with_exact(b.len() as u64),
            None => SizeHint::with_exact(0),
        }
    }
}

/// Build a hyper `Request<TrackedBody>` plus the shared done-handle.
fn build_tracked_request(
    req: &HttpRequest,
    is_http1: bool,
) -> Result<(Request<TrackedBody>, Arc<OnceLock<Instant>>)> {
    let body = req.body.clone().unwrap_or_default();
    let (tracked, done) = TrackedBody::new(body);
    let request = req
        .builder(is_http1)
        .body(tracked)
        .map_err(|e| Error::Http { source: e })?;
    Ok((request, done))
}

/// Split a captured `send_request` future window into request_send + server_processing
/// using a `TrackedBody`'s completion timestamp. Falls back to lumping into
/// server_processing if the body wasn't consumed before the response arrived
/// (which shouldn't happen for normal request/response flows).
fn record_send_split(
    stat: &mut HttpStat,
    send_start: Instant,
    response_at: Instant,
    done: &Arc<OnceLock<Instant>>,
) {
    match done.get().copied() {
        Some(done_at) if done_at >= send_start && done_at <= response_at => {
            stat.request_send = Some(done_at.duration_since(send_start));
            stat.server_processing = Some(response_at.duration_since(done_at));
        }
        _ => {
            stat.server_processing = Some(response_at.duration_since(send_start));
        }
    }
}

/// Populate `stat.server_timing` from response headers (RFC 8673).
fn capture_server_timing(stat: &mut HttpStat, headers: &http::HeaderMap) {
    let values: Vec<&str> = headers
        .get_all("server-timing")
        .iter()
        .filter_map(|v| v.to_str().ok())
        .collect();
    if !values.is_empty() {
        stat.server_timing = parse_server_timing(values.iter().copied());
    }
}

/// Populate `stat.alt_svc` and `stat.hsts` from response headers.
/// Pure header parse — no extra network cost.
fn capture_protocol_advertisements(stat: &mut HttpStat, headers: &http::HeaderMap) {
    let alt_svc_values: Vec<&str> = headers
        .get_all("alt-svc")
        .iter()
        .filter_map(|v| v.to_str().ok())
        .collect();
    if !alt_svc_values.is_empty() {
        stat.alt_svc = parse_alt_svc(alt_svc_values.iter().copied());
    }
    if let Some(v) = headers
        .get("strict-transport-security")
        .and_then(|v| v.to_str().ok())
    {
        stat.hsts = parse_hsts(v);
    }
}

/// Drain a streaming response body frame-by-frame, recording the moment the
/// accumulator first crosses [`FIRST_CHUNK_BYTES`]. The returned tuple is
/// `(body_bytes, time_to_first_100k)`. `time_to_first_100k` is `None` when
/// the body is smaller than the threshold — there's no split to report.
async fn drain_body_with_split(
    body: Incoming,
    start: Instant,
) -> std::result::Result<(Bytes, Option<Duration>), String> {
    let mut body = body;
    let mut buf = BytesMut::new();
    let mut first_chunk_at: Option<Duration> = None;
    while let Some(frame_res) = body.frame().await {
        let frame = frame_res.map_err(|e| format!("Failed to read response body: {e}"))?;
        if let Ok(data) = frame.into_data() {
            buf.extend_from_slice(&data);
            if first_chunk_at.is_none() && buf.len() >= FIRST_CHUNK_BYTES {
                first_chunk_at = Some(start.elapsed());
            }
        }
    }
    Ok((buf.freeze(), first_chunk_at))
}

// Initialize crypto provider once
static INIT: Once = Once::new();

fn ensure_crypto_provider() {
    INIT.call_once(|| {
        let _ = tokio_rustls::rustls::crypto::ring::default_provider().install_default();
    });
}

// Send HTTP/1.1 request over any stream (plain TCP or TLS)
async fn send_http1_request<S>(
    req: Request<TrackedBody>,
    done: Arc<OnceLock<Instant>>,
    stream: S,
    request_timeout: Option<Duration>,
    tx: oneshot::Sender<String>,
    stat: &mut HttpStat,
) -> Result<Response<Incoming>>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    let (mut sender, conn) = timeout(
        request_timeout.unwrap_or(Duration::from_secs(30)),
        hyper::client::conn::http1::handshake(TokioIo::new(stream)),
    )
    .await
    .map_err(|e| Error::Timeout { source: e })?
    .map_err(|e| Error::Hyper { source: e })?;

    // Spawn connection task
    tokio::spawn(async move {
        if let Err(e) = conn.await {
            let _ = tx.send(e.to_string());
        }
    });

    let send_start = Instant::now();
    let resp = sender
        .send_request(req)
        .await
        .map_err(|e| Error::Hyper { source: e })?;
    let response_at = Instant::now();
    record_send_split(stat, send_start, response_at, &done);
    Ok(resp)
}

// Send HTTP/2 request
async fn send_https2_request(
    req: Request<TrackedBody>,
    done: Arc<OnceLock<Instant>>,
    tls_stream: TlsStream<TcpStream>,
    request_timeout: Option<Duration>,
    tx: oneshot::Sender<String>,
    stat: &mut HttpStat,
) -> Result<Response<Incoming>> {
    let (mut sender, conn) = timeout(
        request_timeout.unwrap_or(Duration::from_secs(30)),
        hyper::client::conn::http2::handshake(TokioExecutor::new(), TokioIo::new(tls_stream)),
    )
    .await
    .map_err(|e| Error::Timeout { source: e })?
    .map_err(|e| Error::Hyper { source: e })?;

    // Spawn connection task
    tokio::spawn(async move {
        if let Err(e) = conn.await {
            let _ = tx.send(e.to_string());
        }
    });

    let mut req = req;
    *req.version_mut() = hyper::Version::HTTP_2;
    // Remove Host header for HTTP/2 as it's replaced by :authority
    req.headers_mut().remove("Host");

    let send_start = Instant::now();
    let resp = sender
        .send_request(req)
        .await
        .map_err(|e| Error::Hyper { source: e })?;
    let response_at = Instant::now();
    record_send_split(stat, send_start, response_at, &done);
    Ok(resp)
}

// Handle HTTP/3 request
async fn http3_request(http_req: HttpRequest) -> HttpStat {
    let start = Instant::now();
    let mut stat = HttpStat {
        alpn: Some(ALPN_HTTP3.to_string()),
        ..Default::default()
    };

    // DNS resolution
    let dns_result = dns_resolve(&http_req, &mut stat).await;
    let (addr, host) = match dns_result {
        Ok(result) => result,
        Err(e) => {
            return finish_with_error(stat, e, start);
        }
    };

    // Establish QUIC connection
    let (client_endpoint, conn) = match timeout(
        http_req.quic_timeout.unwrap_or(Duration::from_secs(30)),
        quic_connect(
            host,
            addr,
            http_req.skip_verify,
            http_req.client_cert.as_deref(),
            http_req.client_key.as_deref(),
            http_req.bind_addr,
            &mut stat,
        ),
    )
    .await
    {
        Ok(Ok(result)) => result,
        Ok(Err(e)) => {
            return finish_with_error(stat, e, start);
        }
        Err(e) => {
            return finish_with_error(stat, e, start);
        }
    };

    // Set TLS information
    stat.tls = Some("tls 1.3".to_string()); // QUIC always uses TLS 1.3
    stat.alpn = Some(ALPN_HTTP3.to_string()); // We always use HTTP/3 for QUIC

    // Extract certificate information
    if let Some(peer_identity) = conn.peer_identity() {
        if let Ok(certs) = peer_identity.downcast::<Vec<rustls::pki_types::CertificateDer>>() {
            // Set cipher from first cert's signature algorithm (HTTP/3 specific)
            if let Some(first_cert) = certs.first() {
                if let Ok((_, cert)) = x509_parser::parse_x509_certificate(first_cert.as_ref()) {
                    let oid_str = match cert.signature_algorithm.algorithm.to_string().as_str() {
                        "1.2.840.113549.1.1.11" => "AES_256_GCM_SHA384".to_string(),
                        "1.2.840.113549.1.1.12" => "AES_128_GCM_SHA256".to_string(),
                        "1.2.840.113549.1.1.13" => "CHACHA20_POLY1305_SHA256".to_string(),
                        "1.2.840.10045.4.3.2" => "AES_256_GCM_SHA384".to_string(),
                        "1.2.840.10045.4.3.3" => "AES_128_GCM_SHA256".to_string(),
                        "1.2.840.10045.4.3.4" => "CHACHA20_POLY1305_SHA256".to_string(),
                        "1.3.101.112" => "AES_256_GCM_SHA384".to_string(),
                        "1.3.101.113" => "AES_128_GCM_SHA256".to_string(),
                        _ => format!("{:?}", cert.signature_algorithm.algorithm),
                    };
                    stat.cert_cipher = Some(oid_str);
                }
            }
            parse_certificates(&certs, &mut stat);
        }
    }

    // Create HTTP/3 connection
    let quinn_conn = h3_quinn::Connection::new(conn);

    let (mut driver, mut send_request) = match timeout(
        http_req.request_timeout.unwrap_or(Duration::from_secs(30)),
        h3::client::new(quinn_conn),
    )
    .await
    {
        Ok(Ok(result)) => result,
        Ok(Err(e)) => {
            return finish_with_error(stat, e, start);
        }
        Err(e) => {
            return finish_with_error(stat, e, start);
        }
    };

    // Prepare request
    let mut req = match http_req.builder(false).body(()) {
        Ok(req) => req,
        Err(e) => {
            return finish_with_error(stat, e, start);
        }
    };
    *req.version_mut() = Version::HTTP_3;
    stat.request_headers = req.headers().clone();
    let body = http_req.body.unwrap_or_default();

    // Handle connection driver
    let drive = async move {
        Err::<(), h3::error::ConnectionError>(future::poll_fn(|cx| driver.poll_close(cx)).await)
    };

    // Send request and handle response
    let request = async move {
        let mut sub_stat = HttpStat::default();

        let request_send_start = Instant::now();
        let mut stream = send_request.send_request(req).await?;
        stream.send_data(body).await?;
        // Finish sending — last request byte is now on the wire (or in QUIC's buffer).
        stream.finish().await?;
        sub_stat.request_send = Some(request_send_start.elapsed());

        let server_processing_start = Instant::now();
        let resp = stream.recv_response().await?;
        sub_stat.server_processing = Some(server_processing_start.elapsed());

        sub_stat.status = Some(resp.status());
        sub_stat.headers = Some(resp.headers().clone());
        capture_server_timing(&mut sub_stat, resp.headers());
        capture_protocol_advertisements(&mut sub_stat, resp.headers());

        // Receive response body. Capture the first-100KB instant so we can
        // split throughput into "slow start" vs "steady state" later.
        let content_transfer_start = Instant::now();
        let mut buf = BytesMut::new();
        let mut first_chunk_at: Option<Duration> = None;
        while let Some(chunk) = stream.recv_data().await? {
            buf.extend(chunk.chunk());
            if first_chunk_at.is_none() && buf.len() >= FIRST_CHUNK_BYTES {
                first_chunk_at = Some(content_transfer_start.elapsed());
            }
        }
        sub_stat.content_transfer = Some(content_transfer_start.elapsed());
        sub_stat.wire_body_size = Some(buf.len());
        sub_stat.time_to_first_100k = first_chunk_at;
        sub_stat.body = Some(Bytes::from(buf));
        Ok::<HttpStat, h3::error::StreamError>(sub_stat)
    };

    // Execute request and handle results
    let (req_res, drive_res) = tokio::join!(request, drive);
    match req_res {
        Ok(sub_stat) => {
            stat.request_send = sub_stat.request_send;
            stat.server_processing = sub_stat.server_processing;
            stat.content_transfer = sub_stat.content_transfer;
            stat.status = sub_stat.status;
            stat.headers = sub_stat.headers;
            stat.body = sub_stat.body;
            stat.wire_body_size = sub_stat.wire_body_size;
            stat.time_to_first_100k = sub_stat.time_to_first_100k;
            stat.server_timing = sub_stat.server_timing;
        }
        Err(err) => {
            if !err.is_h3_no_error() {
                stat.error = Some(err.to_string());
            }
        }
    }
    if let Err(err) = drive_res {
        if !err.is_h3_no_error() {
            stat.error = Some(err.to_string());
        }
    }

    stat.total = Some(start.elapsed());
    // Close the connection immediately instead of waiting for idle
    client_endpoint.close(0u32.into(), b"done");

    stat
}

/// Connect to the effective TCP endpoint (direct or via proxy).
/// Returns `(stream, target_host, is_http_forward_proxy, tcp_info_probe)`.
/// - Direct: uses dns_resolve + tcp_connect, sets stat.dns_lookup / stat.addr / stat.tcp_connect.
/// - Proxy:  connects to proxy (system DNS), sets stat.addr / stat.tcp_connect.
///
/// `tcp_info_probe` is a `dup(2)`'d FD pointing at the socket we'll actually
/// use for HTTP traffic. Through a proxy the probe reflects the
/// client-to-proxy socket, not the origin — `getsockopt(TCP_INFO)` can't see
/// past the proxy.
async fn tcp_via_proxy(
    http_req: &HttpRequest,
    stat: &mut HttpStat,
) -> Result<(
    TcpStream,
    String,
    bool,
    Option<crate::tcp_info::TcpInfoProbe>,
)> {
    let uri = &http_req.uri;
    let is_https = uri.scheme() == Some(&http::uri::Scheme::HTTPS);
    let target_host = uri.host().unwrap_or_default().to_string();
    let target_port = http_req.get_port();

    if let Some(proxy) = http_req.proxy.as_deref().and_then(ProxyConfig::parse) {
        let proxy_addr = format!("{}:{}", proxy.host, proxy.port);
        let tcp_start = Instant::now();
        let proxy_stream = timeout(
            http_req.tcp_timeout.unwrap_or(Duration::from_secs(5)),
            TcpStream::connect(&proxy_addr),
        )
        .await
        .map_err(|e| Error::Timeout { source: e })?
        .map_err(|e| Error::Io { source: e })?;

        if let Ok(peer) = proxy_stream.peer_addr() {
            stat.addr = Some(peer.to_string());
        }

        // Sample baseline TCP_INFO on the proxy connection (what we'll
        // actually carry traffic over) before any SOCKS5/HTTP CONNECT bytes.
        let (baseline, probe) = crate::tcp_info::TcpInfoProbe::capture(&proxy_stream);
        stat.tcp_info_post_connect = baseline;

        // HTTP proxy + plain HTTP target: forward mode, no tunnel
        let is_http_forward = !is_https && matches!(proxy.kind, ProxyKind::Http);
        let stream = if is_http_forward {
            proxy_stream
        } else {
            match proxy.kind {
                ProxyKind::Socks5 => {
                    socks5_connect(proxy_stream, &target_host, target_port).await?
                }
                ProxyKind::Http => http_connect(proxy_stream, &target_host, target_port).await?,
            }
        };
        stat.tcp_connect = Some(tcp_start.elapsed());
        Ok((stream, target_host, is_http_forward, probe))
    } else {
        let (addr, host) = dns_resolve(http_req, stat).await?;
        let (stream, probe) =
            tcp_connect(addr, http_req.tcp_timeout, http_req.bind_addr, stat).await?;
        Ok((stream, host, false, probe))
    }
}

async fn http1_2_request(mut http_req: HttpRequest) -> HttpStat {
    let start = Instant::now();
    let mut stat = HttpStat::default();

    let is_https = http_req.uri.scheme() == Some(&http::uri::Scheme::HTTPS);

    // Establish TCP (direct or via proxy)
    let (tcp_stream, host, is_http_forward, tcp_probe) =
        match tcp_via_proxy(&http_req, &mut stat).await {
            Ok(r) => r,
            Err(e) => return finish_with_error(stat, e, start),
        };

    // HTTP forward proxy: request must use the full absolute URI
    if is_http_forward {
        http_req.use_absolute_uri = true;
    }

    // Create channel for connection errors
    let (tx, mut rx) = oneshot::channel();

    // Send request based on protocol
    let resp = if is_https {
        // TLS handshake
        let tls_result = tls_handshake(host.clone(), tcp_stream, &http_req, &mut stat).await;
        let (tls_stream, is_http2) = match tls_result {
            Ok(result) => result,
            Err(e) => {
                return finish_with_error(stat, e, start);
            }
        };

        // Send HTTPS request
        if is_http2 {
            let (req, done) = match build_tracked_request(&http_req, false) {
                Ok(r) => r,
                Err(e) => {
                    return finish_with_error(stat, e, start);
                }
            };
            stat.request_headers = req.headers().clone();
            match send_https2_request(
                req,
                done,
                tls_stream,
                http_req.request_timeout,
                tx,
                &mut stat,
            )
            .await
            {
                Ok(resp) => resp,
                Err(e) => {
                    return finish_with_error(stat, e, start);
                }
            }
        } else {
            let (req, done) = match build_tracked_request(&http_req, true) {
                Ok(r) => r,
                Err(e) => {
                    return finish_with_error(stat, e, start);
                }
            };
            stat.request_headers = req.headers().clone();
            match send_http1_request(
                req,
                done,
                tls_stream,
                http_req.request_timeout,
                tx,
                &mut stat,
            )
            .await
            {
                Ok(resp) => resp,
                Err(e) => {
                    return finish_with_error(stat, e, start);
                }
            }
        }
    } else {
        let (req, done) = match build_tracked_request(&http_req, true) {
            Ok(r) => r,
            Err(e) => {
                return finish_with_error(stat, e, start);
            }
        };
        stat.request_headers = req.headers().clone();
        // Send HTTP request
        match send_http1_request(
            req,
            done,
            tcp_stream,
            http_req.request_timeout,
            tx,
            &mut stat,
        )
        .await
        {
            Ok(resp) => resp,
            Err(e) => {
                return finish_with_error(stat, e, start);
            }
        }
    };

    // Process response
    stat.status = Some(resp.status());
    stat.headers = Some(resp.headers().clone());
    capture_server_timing(&mut stat, resp.headers());
    capture_protocol_advertisements(&mut stat, resp.headers());

    // Check for connection errors
    if let Ok(error) = rx.try_recv() {
        stat.error = Some(error);
    }
    // Read response body — stream frame-by-frame so we can timestamp the
    // moment 100 KiB has arrived. Combined with content_transfer, this lets
    // us split throughput into "first 100 KB" (TCP slow-start dominated)
    // and "tail" (steady-state server send rate).
    let content_transfer_start = Instant::now();
    let drain_result = drain_body_with_split(resp.into_body(), content_transfer_start).await;
    let (body_bytes, time_to_first_100k) = match drain_result {
        Ok(p) => p,
        Err(e) => return finish_with_error(stat, e, start),
    };
    stat.wire_body_size = Some(body_bytes.len());
    stat.time_to_first_100k = time_to_first_100k;
    stat.body = Some(body_bytes);
    stat.content_transfer = Some(content_transfer_start.elapsed());

    // Second kernel TCP sample: retransmits accumulated during the body read,
    // final RTT/cwnd. dup'd FD is dropped here (closes only the duplicate;
    // the real socket lives on inside hyper).
    if let Some(probe) = &tcp_probe {
        stat.tcp_info_final = probe.sample();
    }

    stat.total = Some(start.elapsed());
    stat
}

/// Performs an HTTP request and returns detailed statistics about the request lifecycle.
///
/// This function handles HTTP/1.1, HTTP/2, and HTTP/3 requests with the following features:
/// - Automatic protocol selection based on ALPN negotiation
/// - DNS resolution with support for custom IP mappings
/// - TLS handshake with certificate verification
/// - Response body handling with optional file output
/// - Detailed timing statistics for each phase of the request
///
/// # Arguments
///
/// * `http_req` - An `HttpRequest` struct containing the request configuration including:
///   - URI and HTTP method
///   - ALPN protocols to negotiate
///   - Custom DNS resolutions
///   - Headers and request body
///   - TLS verification settings
///   - Output file path (optional)
///
/// # Returns
///
/// Returns an `HttpStat` struct containing:
/// - DNS lookup time
/// - QUIC connection time
/// - TCP connection time
/// - TLS handshake time (for HTTPS)
/// - Server processing time
/// - Content transfer time
/// - Total request time
/// - Response status and headers
/// - Response body (if not written to file)
/// - TLS and certificate information (for HTTPS)
/// - Any errors that occurred during the request
/// ```
pub async fn request(http_req: HttpRequest) -> HttpStat {
    ensure_crypto_provider();
    let schema = if let Some(schema) = http_req.uri.scheme() {
        schema.to_string()
    } else {
        "".to_string()
    };

    // Handle HTTP/3 request
    let mut stat = if ["grpc", "grpcs"].contains(&schema.as_str()) {
        grpc_request(http_req).await
    } else if http_req.alpn_protocols.contains(&ALPN_HTTP3.to_string()) {
        http3_request(http_req).await
    } else {
        http1_2_request(http_req).await
    };
    if let Some(body) = &stat.body {
        stat.body_size = Some(body.len());
    }
    let encoding = if let Some(headers) = &stat.headers {
        headers
            .get("content-encoding")
            .map(|v| v.to_str().unwrap_or_default())
            .unwrap_or_default()
    } else {
        ""
    };

    if !encoding.is_empty() {
        if let Some(body) = &stat.body {
            match decompress(encoding, body) {
                Ok(data) => {
                    stat.body = Some(data);
                }
                Err(e) => {
                    stat.error = Some(e.to_string());
                }
            }
        }
    }

    stat
}

// --- Connection reuse API ---

enum ConnectionSender {
    Http1(hyper::client::conn::http1::SendRequest<TrackedBody>),
    Http2(hyper::client::conn::http2::SendRequest<TrackedBody>),
}

/// A reusable HTTP connection handle for benchmarking.
pub struct HttpConnection {
    sender: ConnectionSender,
    is_http2: bool,
    /// dup'd FD so we can sample TCP_INFO after each `send()` even though
    /// the original socket has been moved into hyper. None on non-Unix or
    /// when `dup(2)` failed.
    tcp_probe: Option<crate::tcp_info::TcpInfoProbe>,
    /// Most recent TCP_INFO snapshot. Used as the "post-connect" baseline
    /// for the next `send()`'s delta calculation, so each iteration's
    /// `retransmits_during` reflects only that iteration's window.
    last_tcp_info: Option<crate::TcpInfo>,
}

async fn establish_http1<S>(
    stream: S,
    handshake_timeout: Duration,
    mut stat: HttpStat,
    tcp_probe: Option<crate::tcp_info::TcpInfoProbe>,
    start: Instant,
) -> (HttpStat, Option<HttpConnection>)
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    match timeout(
        handshake_timeout,
        hyper::client::conn::http1::handshake(TokioIo::new(stream)),
    )
    .await
    {
        Ok(Ok((sender, conn))) => {
            tokio::spawn(async move {
                let _ = conn.await;
            });
            stat.total = Some(start.elapsed());
            let last_tcp_info = stat.tcp_info_post_connect.clone();
            (
                stat,
                Some(HttpConnection {
                    sender: ConnectionSender::Http1(sender),
                    is_http2: false,
                    tcp_probe,
                    last_tcp_info,
                }),
            )
        }
        Ok(Err(e)) => (
            finish_with_error(stat, Error::Hyper { source: e }, start),
            None,
        ),
        Err(e) => (
            finish_with_error(stat, Error::Timeout { source: e }, start),
            None,
        ),
    }
}

async fn establish_http2<S>(
    stream: S,
    handshake_timeout: Duration,
    mut stat: HttpStat,
    tcp_probe: Option<crate::tcp_info::TcpInfoProbe>,
    start: Instant,
) -> (HttpStat, Option<HttpConnection>)
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    match timeout(
        handshake_timeout,
        hyper::client::conn::http2::handshake(TokioExecutor::new(), TokioIo::new(stream)),
    )
    .await
    {
        Ok(Ok((sender, conn))) => {
            tokio::spawn(async move {
                let _ = conn.await;
            });
            stat.total = Some(start.elapsed());
            let last_tcp_info = stat.tcp_info_post_connect.clone();
            (
                stat,
                Some(HttpConnection {
                    sender: ConnectionSender::Http2(sender),
                    is_http2: true,
                    tcp_probe,
                    last_tcp_info,
                }),
            )
        }
        Ok(Err(e)) => (
            finish_with_error(stat, Error::Hyper { source: e }, start),
            None,
        ),
        Err(e) => (
            finish_with_error(stat, Error::Timeout { source: e }, start),
            None,
        ),
    }
}

/// Establish an HTTP/1.1 or HTTP/2 connection and return a reusable handle.
///
/// Returns `(connect_stat, Some(conn))` on success, or `(error_stat, None)` on failure.
/// Only supports HTTP/1.1 and HTTP/2. For HTTP/3 or gRPC, use `request()` directly.
pub async fn connect(http_req: &HttpRequest) -> (HttpStat, Option<HttpConnection>) {
    ensure_crypto_provider();
    let start = Instant::now();
    let mut stat = HttpStat::default();

    let is_https = http_req.uri.scheme() == Some(&http::uri::Scheme::HTTPS);

    let (tcp_stream, host, _is_http_forward, tcp_probe) =
        match tcp_via_proxy(http_req, &mut stat).await {
            Ok(r) => r,
            Err(e) => return (finish_with_error(stat, e, start), None),
        };

    let handshake_timeout = http_req.request_timeout.unwrap_or(Duration::from_secs(30));

    if is_https {
        let (tls_stream, is_h2) = match tls_handshake(host, tcp_stream, http_req, &mut stat).await {
            Ok(r) => r,
            Err(e) => return (finish_with_error(stat, e, start), None),
        };

        if is_h2 {
            establish_http2(tls_stream, handshake_timeout, stat, tcp_probe, start).await
        } else {
            establish_http1(tls_stream, handshake_timeout, stat, tcp_probe, start).await
        }
    } else {
        establish_http1(tcp_stream, handshake_timeout, stat, tcp_probe, start).await
    }
}

impl HttpConnection {
    /// Send a request on the existing connection, returning only request-phase timing.
    pub async fn send(&mut self, http_req: &HttpRequest) -> HttpStat {
        let start = Instant::now();
        // Seed the per-iteration TCP_INFO baseline from the previous send's
        // final sample (or the connection's post-connect snapshot for the
        // first iteration). This way each iteration's retransmits_during
        // counts only retransmits in *this* iteration's window.
        let mut stat = HttpStat {
            tcp_info_post_connect: self.last_tcp_info.clone(),
            ..HttpStat::default()
        };

        let is_http1 = !self.is_http2;
        let (req, done) = match build_tracked_request(http_req, is_http1) {
            Ok(r) => r,
            Err(e) => return finish_with_error(stat, e, start),
        };
        stat.request_headers = req.headers().clone();

        // Ensure the connection is ready (especially important for HTTP/1.1 keep-alive)
        match &mut self.sender {
            ConnectionSender::Http1(sender) => {
                if let Err(e) = sender.ready().await {
                    return finish_with_error(stat, Error::Hyper { source: e }, start);
                }
            }
            ConnectionSender::Http2(sender) => {
                if let Err(e) = sender.ready().await {
                    return finish_with_error(stat, Error::Hyper { source: e }, start);
                }
            }
        }

        let send_start = Instant::now();
        let resp = match &mut self.sender {
            ConnectionSender::Http1(sender) => sender.send_request(req).await,
            ConnectionSender::Http2(sender) => {
                let mut req = req;
                *req.version_mut() = Version::HTTP_2;
                req.headers_mut().remove("Host");
                sender.send_request(req).await
            }
        };

        let resp = match resp {
            Ok(resp) => resp,
            Err(e) => return finish_with_error(stat, Error::Hyper { source: e }, start),
        };
        let response_at = Instant::now();
        record_send_split(&mut stat, send_start, response_at, &done);
        stat.status = Some(resp.status());
        stat.headers = Some(resp.headers().clone());
        capture_server_timing(&mut stat, resp.headers());
        capture_protocol_advertisements(&mut stat, resp.headers());

        // Read response body — frame-by-frame so we capture the
        // time-to-first-100K marker for throughput-split diagnosis (matches
        // the http1_2_request path).
        let content_transfer_start = Instant::now();
        match drain_body_with_split(resp.into_body(), content_transfer_start).await {
            Ok((body_bytes, first_100k)) => {
                stat.wire_body_size = Some(body_bytes.len());
                stat.time_to_first_100k = first_100k;
                stat.body = Some(body_bytes);
                stat.content_transfer = Some(content_transfer_start.elapsed());
            }
            Err(e) => {
                return finish_with_error(stat, e, start);
            }
        }

        // End-of-iteration kernel TCP snapshot. Cache it as the baseline for
        // the next send() so successive iterations don't double-count
        // retransmits.
        if let Some(probe) = &self.tcp_probe {
            let now = probe.sample();
            stat.tcp_info_final = now.clone();
            if now.is_some() {
                self.last_tcp_info = now;
            }
        }

        stat.total = Some(start.elapsed());

        // Handle decompression
        if let Some(body) = &stat.body {
            stat.body_size = Some(body.len());
        }
        let encoding = stat
            .headers
            .as_ref()
            .and_then(|h| h.get("content-encoding"))
            .and_then(|v| v.to_str().ok())
            .unwrap_or_default();
        if !encoding.is_empty() {
            if let Some(body) = &stat.body {
                match decompress(encoding, body) {
                    Ok(data) => stat.body = Some(data),
                    Err(e) => stat.error = Some(e.to_string()),
                }
            }
        }

        stat
    }
}
