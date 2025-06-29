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
use super::net::{dns_resolve, quic_connect, tcp_connect, tls_handshake};
use super::stats::{HttpStat, ALPN_HTTP3};
use super::HttpRequest;
use bytes::{Buf, Bytes, BytesMut};
use chrono::{Local, TimeZone};
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

// Format timestamp to human-readable string
fn format_time(timestamp_seconds: i64) -> String {
    Local
        .timestamp_nanos(timestamp_seconds * 1_000_000_000)
        .to_string()
}

// Initialize crypto provider once
static INIT: Once = Once::new();

fn ensure_crypto_provider() {
    INIT.call_once(|| {
        let _ = tokio_rustls::rustls::crypto::ring::default_provider().install_default();
    });
}

// Send HTTP/1.1 request
async fn send_http_request(
    req: Request<Full<Bytes>>,
    tcp_stream: TcpStream,
    request_timeout: Option<Duration>,
    tx: oneshot::Sender<String>,
    stat: &mut HttpStat,
) -> Result<Response<Incoming>> {
    let (mut sender, conn) = timeout(
        request_timeout.unwrap_or(Duration::from_secs(30)),
        hyper::client::conn::http1::handshake(TokioIo::new(tcp_stream)),
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

// Send HTTPS request
async fn send_https_request(
    req: Request<Full<Bytes>>,
    tls_stream: TlsStream<TcpStream>,
    request_timeout: Option<Duration>,
    tx: oneshot::Sender<String>,
    stat: &mut HttpStat,
) -> Result<Response<Incoming>> {
    let (mut sender, conn) = timeout(
        request_timeout.unwrap_or(Duration::from_secs(30)),
        hyper::client::conn::http1::handshake(TokioIo::new(tls_stream)),
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
    tx: oneshot::Sender<String>,
    stat: &mut HttpStat,
) -> Result<Response<Incoming>> {
    let (mut sender, conn) = timeout(
        Duration::from_secs(30),
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
        quic_connect(host, addr, http_req.skip_verify, &mut stat),
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
            if let Some(cert) = certs.first() {
                if let Ok((_, cert)) = x509_parser::parse_x509_certificate(cert.as_ref()) {
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
                    stat.subject = Some(cert.subject().to_string());
                    stat.issuer = Some(cert.issuer().to_string());
                    stat.cert_cipher = Some(oid_str);
                    stat.cert_not_before =
                        Some(format_time(cert.validity().not_before.timestamp()));
                    stat.cert_not_after = Some(format_time(cert.validity().not_after.timestamp()));
                    if let Ok(Some(sans)) = cert.subject_alternative_name() {
                        let mut domains = Vec::new();
                        for san in sans.value.general_names.iter() {
                            if let x509_parser::extensions::GeneralName::DNSName(domain) = san {
                                domains.push(domain.to_string());
                            }
                        }
                        stat.cert_domains = Some(domains);
                    };
                }
            }
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

async fn http1_2_request(http_req: HttpRequest) -> HttpStat {
    let start = Instant::now();
    let mut stat = HttpStat::default();

    // DNS resolution
    let dns_result = dns_resolve(&http_req, &mut stat).await;
    let (addr, host) = match dns_result {
        Ok(result) => result,
        Err(e) => {
            return finish_with_error(stat, e, start);
        }
    };

    let uri = &http_req.uri;
    let is_https = uri.scheme() == Some(&http::uri::Scheme::HTTPS);

    // // Convert request to hyper Request
    // let req: Request<Full<Bytes>> = match (&http_req).try_into() {
    //     Ok(req) => req,
    //     Err(e) => {
    //         return finish_with_error(stat, e, start);
    //     }
    // };
    // stat.request_headers = req.headers().clone();

    // TCP connection
    let tcp_stream = match tcp_connect(addr, http_req.tcp_timeout, &mut stat).await {
        Ok(stream) => stream,
        Err(e) => {
            return finish_with_error(stat, e, start);
        }
    };

    // Create channel for connection errors
    let (tx, mut rx) = oneshot::channel();

    // Send request based on protocol
    let resp = if is_https {
        // TLS handshake
        let tls_result = tls_handshake(
            host.clone(),
            tcp_stream,
            http_req.tls_timeout,
            http_req.alpn_protocols.clone(),
            http_req.skip_verify,
            &mut stat,
        )
        .await;
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
            match send_https2_request(req, tls_stream, tx, &mut stat).await {
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
            match send_https_request(req, tls_stream, http_req.request_timeout, tx, &mut stat).await
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
        match send_http_request(req, tcp_stream, http_req.request_timeout, tx, &mut stat).await {
            Ok(resp) => resp,
            Err(e) => {
                return finish_with_error(stat, e, start);
            }
        }
    };

    // Process response
    stat.status = Some(resp.status());
    stat.headers = Some(resp.headers().clone());

    // Read response body
    let content_transfer_start = Instant::now();
    let body_result = resp.collect().await;
    let body = match body_result {
        Ok(body) => body,
        Err(e) => {
            return finish_with_error(stat, format!("Failed to read response body: {}", e), start);
        }
    };

    let body_bytes = body.to_bytes();
    stat.body = Some(body_bytes);
    stat.content_transfer = Some(content_transfer_start.elapsed());

    // Check for connection errors
    if let Ok(error) = rx.try_recv() {
        stat.error = Some(error);
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
