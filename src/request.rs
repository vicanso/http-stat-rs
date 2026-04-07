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

use super::build_http_request;
use super::decompress::decompress;
use super::error::{Error, Result};
use super::finish_with_error;
use super::grpc::grpc_request;
use super::net::{dns_resolve, parse_certificates, quic_connect, tcp_connect, tls_handshake};
use super::proxy::{http_connect, socks5_connect, ProxyConfig, ProxyKind};
use super::stats::{HttpStat, ALPN_HTTP3};
use super::HttpRequest;
use bytes::{Buf, Bytes, BytesMut};
use futures::future;

use http::Request;
use http::Response;
use http::Version;
use http_body_util::{BodyExt, Full};
use hyper::body::Incoming;
use hyper_util::rt::TokioExecutor;
use hyper_util::rt::TokioIo;
use std::sync::Once;
use std::time::Duration;
use std::time::Instant;
use tokio::net::TcpStream;
use tokio::sync::oneshot;
use tokio::time::timeout;
use tokio_rustls::client::TlsStream;

// Initialize crypto provider once
static INIT: Once = Once::new();

fn ensure_crypto_provider() {
    INIT.call_once(|| {
        let _ = tokio_rustls::rustls::crypto::ring::default_provider().install_default();
    });
}

// Send HTTP/1.1 request over any stream (plain TCP or TLS)
async fn send_http1_request<S>(
    req: Request<Full<Bytes>>,
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

    let server_processing_start = Instant::now();
    let resp = sender
        .send_request(req)
        .await
        .map_err(|e| Error::Hyper { source: e })?;
    stat.server_processing = Some(server_processing_start.elapsed());
    Ok(resp)
}

// Send HTTP/2 request
async fn send_https2_request(
    req: Request<Full<Bytes>>,
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

    let server_processing_start = Instant::now();
    let resp = sender
        .send_request(req)
        .await
        .map_err(|e| Error::Hyper { source: e })?;
    stat.server_processing = Some(server_processing_start.elapsed());
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
        let mut stream = send_request.send_request(req).await?;
        stream.send_data(body).await?;

        let mut sub_stat = HttpStat::default();

        // Finish sending
        stream.finish().await?;

        let server_processing_start = Instant::now();

        let resp = stream.recv_response().await?;
        sub_stat.server_processing = Some(server_processing_start.elapsed());

        sub_stat.status = Some(resp.status());
        sub_stat.headers = Some(resp.headers().clone());

        // Receive response body
        let content_transfer_start = Instant::now();
        let mut buf = BytesMut::new();
        while let Some(chunk) = stream.recv_data().await? {
            buf.extend(chunk.chunk());
        }
        sub_stat.content_transfer = Some(content_transfer_start.elapsed());
        sub_stat.body = Some(Bytes::from(buf));
        Ok::<HttpStat, h3::error::StreamError>(sub_stat)
    };

    // Execute request and handle results
    let (req_res, drive_res) = tokio::join!(request, drive);
    match req_res {
        Ok(sub_stat) => {
            stat.server_processing = sub_stat.server_processing;
            stat.content_transfer = sub_stat.content_transfer;
            stat.status = sub_stat.status;
            stat.headers = sub_stat.headers;
            stat.body = sub_stat.body;
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
/// Returns `(stream, target_host, is_http_forward_proxy)`.
/// - Direct: uses dns_resolve + tcp_connect, sets stat.dns_lookup / stat.addr / stat.tcp_connect.
/// - Proxy:  connects to proxy (system DNS), sets stat.addr / stat.tcp_connect.
async fn tcp_via_proxy(
    http_req: &HttpRequest,
    stat: &mut HttpStat,
) -> Result<(TcpStream, String, bool)> {
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
        Ok((stream, target_host, is_http_forward))
    } else {
        let (addr, host) = dns_resolve(http_req, stat).await?;
        let stream = tcp_connect(addr, http_req.tcp_timeout, http_req.bind_addr, stat).await?;
        Ok((stream, host, false))
    }
}

async fn http1_2_request(mut http_req: HttpRequest) -> HttpStat {
    let start = Instant::now();
    let mut stat = HttpStat::default();

    let is_https = http_req.uri.scheme() == Some(&http::uri::Scheme::HTTPS);

    // Establish TCP (direct or via proxy)
    let (tcp_stream, host, is_http_forward) = match tcp_via_proxy(&http_req, &mut stat).await {
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
            let req = match build_http_request(&http_req, false) {
                Ok(req) => req,
                Err(e) => {
                    return finish_with_error(stat, e, start);
                }
            };
            stat.request_headers = req.headers().clone();
            match send_https2_request(req, tls_stream, http_req.request_timeout, tx, &mut stat)
                .await
            {
                Ok(resp) => resp,
                Err(e) => {
                    return finish_with_error(stat, e, start);
                }
            }
        } else {
            let req = match build_http_request(&http_req, true) {
                Ok(req) => req,
                Err(e) => {
                    return finish_with_error(stat, e, start);
                }
            };
            stat.request_headers = req.headers().clone();
            match send_http1_request(req, tls_stream, http_req.request_timeout, tx, &mut stat).await
            {
                Ok(resp) => resp,
                Err(e) => {
                    return finish_with_error(stat, e, start);
                }
            }
        }
    } else {
        let req = match build_http_request(&http_req, true) {
            Ok(req) => req,
            Err(e) => {
                return finish_with_error(stat, e, start);
            }
        };
        stat.request_headers = req.headers().clone();
        // Send HTTP request
        match send_http1_request(req, tcp_stream, http_req.request_timeout, tx, &mut stat).await {
            Ok(resp) => resp,
            Err(e) => {
                return finish_with_error(stat, e, start);
            }
        }
    };

    // Process response
    stat.status = Some(resp.status());
    stat.headers = Some(resp.headers().clone());

    // Check for connection errors
    if let Ok(error) = rx.try_recv() {
        stat.error = Some(error);
    }
    // Read response body
    let content_transfer_start = Instant::now();
    let body_result = resp.collect().await;
    let body = match body_result {
        Ok(body) => body,
        Err(e) => {
            return finish_with_error(stat, format!("Failed to read response body: {e}"), start);
        }
    };

    let body_bytes = body.to_bytes();
    stat.body = Some(body_bytes);
    stat.content_transfer = Some(content_transfer_start.elapsed());

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
    Http1(hyper::client::conn::http1::SendRequest<Full<Bytes>>),
    Http2(hyper::client::conn::http2::SendRequest<Full<Bytes>>),
}

/// A reusable HTTP connection handle for benchmarking.
pub struct HttpConnection {
    sender: ConnectionSender,
    is_http2: bool,
}

async fn establish_http1<S>(
    stream: S,
    handshake_timeout: Duration,
    mut stat: HttpStat,
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
            (
                stat,
                Some(HttpConnection {
                    sender: ConnectionSender::Http1(sender),
                    is_http2: false,
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
            (
                stat,
                Some(HttpConnection {
                    sender: ConnectionSender::Http2(sender),
                    is_http2: true,
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

    let (tcp_stream, host, _is_http_forward) = match tcp_via_proxy(http_req, &mut stat).await {
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
            establish_http2(tls_stream, handshake_timeout, stat, start).await
        } else {
            establish_http1(tls_stream, handshake_timeout, stat, start).await
        }
    } else {
        establish_http1(tcp_stream, handshake_timeout, stat, start).await
    }
}

impl HttpConnection {
    /// Send a request on the existing connection, returning only request-phase timing.
    pub async fn send(&mut self, http_req: &HttpRequest) -> HttpStat {
        let start = Instant::now();
        let mut stat = HttpStat::default();

        let is_http1 = !self.is_http2;
        let req = match build_http_request(http_req, is_http1) {
            Ok(req) => req,
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

        let server_processing_start = Instant::now();
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
        stat.server_processing = Some(server_processing_start.elapsed());
        stat.status = Some(resp.status());
        stat.headers = Some(resp.headers().clone());

        // Read response body
        let content_transfer_start = Instant::now();
        match resp.collect().await {
            Ok(body) => {
                let body_bytes = body.to_bytes();
                stat.body = Some(body_bytes);
                stat.content_transfer = Some(content_transfer_start.elapsed());
            }
            Err(e) => {
                return finish_with_error(
                    stat,
                    format!("Failed to read response body: {e}"),
                    start,
                );
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
