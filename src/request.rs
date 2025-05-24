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
use super::stats::{HttpStat, ALPN_HTTP1, ALPN_HTTP2, ALPN_HTTP3};
use super::SkipVerifier;
use bytes::{Buf, Bytes, BytesMut};
use chrono::{Local, TimeZone};
use futures::future;
use hickory_resolver::config::{
    LookupIpStrategy, NameServerConfigGroup, ResolverConfig, CLOUDFLARE_IPS, GOOGLE_IPS, QUAD9_IPS,
};
use hickory_resolver::name_server::TokioConnectionProvider;
use hickory_resolver::TokioResolver;
use http::request::Builder;
use http::HeaderValue;
use http::Request;
use http::Response;
use http::Uri;
use http::{HeaderMap, Method};
use http_body_util::{BodyExt, Full};
use hyper::body::Incoming;
use hyper_util::rt::TokioExecutor;
use hyper_util::rt::TokioIo;
use std::net::IpAddr;
use std::net::SocketAddr;
use std::str::FromStr;
use std::sync::Arc;
use std::sync::Once;
use std::time::Duration;
use std::time::Instant;
use tokio::net::TcpStream;
use tokio::sync::oneshot;
use tokio::time::timeout;
use tokio_rustls::client::TlsStream;
use tokio_rustls::rustls::{ClientConfig, RootCertStore};
use tokio_rustls::TlsConnector;

// Version information from Cargo.toml
const VERSION: &str = env!("CARGO_PKG_VERSION");

// Format TLS protocol version for display
fn format_tls_protocol(protocol: &str) -> String {
    match protocol {
        "TLSv1_3" => "tls v1.3".to_string(),
        "TLSv1_2" => "tls v1.2".to_string(),
        "TLSv1_1" => "tls v1.1".to_string(),
        _ => protocol.to_string(),
    }
}

// Format timestamp to human-readable string
fn format_time(timestamp_seconds: i64) -> String {
    Local
        .timestamp_nanos(timestamp_seconds * 1_000_000_000)
        .to_string()
}

// HttpRequest struct to hold request configuration
#[derive(Default, Debug, Clone)]
pub struct HttpRequest {
    pub uri: Uri,                                // Target URI
    pub method: Option<String>,                  // HTTP method (GET, POST, etc.)
    pub alpn_protocols: Vec<String>,             // Supported ALPN protocols
    pub resolve: Option<IpAddr>,                 // Custom DNS resolution
    pub headers: Option<HeaderMap<HeaderValue>>, // Custom HTTP headers
    pub ip_version: Option<i32>,                 // IP version (4 for IPv4, 6 for IPv6)
    pub skip_verify: bool,                       // Skip TLS certificate verification
    pub body: Option<Bytes>,                     // Request body
    pub silent: bool,                            // Silent mode
    pub dns_servers: Option<Vec<String>>,        // DNS servers
    pub dns_timeout: Option<Duration>,           // DNS resolution timeout
    pub tcp_timeout: Option<Duration>,           // TCP connection timeout
    pub tls_timeout: Option<Duration>,           // TLS handshake timeout
    pub request_timeout: Option<Duration>,       // HTTP request timeout
    pub quic_timeout: Option<Duration>,          // QUIC connection timeout
}

impl HttpRequest {
    pub fn get_port(&self) -> u16 {
        let default_port = if self.uri.scheme() == Some(&http::uri::Scheme::HTTPS) {
            443
        } else {
            80
        };
        self.uri.port_u16().unwrap_or(default_port)
    }
    // Build HTTP request with proper headers
    fn builder(&self) -> Builder {
        let uri = &self.uri;
        let method = if let Some(method) = &self.method {
            Method::from_str(method).unwrap_or(Method::GET)
        } else {
            Method::GET
        };
        let mut builder = Request::builder().uri(uri).method(method);
        let mut set_host = false;
        let mut set_user_agent = false;

        // Add custom headers if provided
        if let Some(headers) = &self.headers {
            for (key, value) in headers.iter() {
                builder = builder.header(key, value);
                match key.to_string().to_lowercase().as_str() {
                    "host" => set_host = true,
                    "user-agent" => set_user_agent = true,
                    _ => {}
                }
            }
        }

        // Set default Host header if not provided
        if !set_host {
            if let Some(host) = uri.host() {
                builder = builder.header("Host", host);
            }
        }

        // Set default User-Agent if not provided
        if !set_user_agent {
            builder = builder.header("User-Agent", format!("httpstat.rs/{}", VERSION));
        }
        builder
    }
}

// Convert string URL to HttpRequest
impl TryFrom<&str> for HttpRequest {
    type Error = Error;

    fn try_from(url: &str) -> Result<Self> {
        let value = if url.starts_with("http://") || url.starts_with("https://") {
            url.to_string()
        } else {
            format!("http://{}", url)
        };
        let uri = value.parse::<Uri>().map_err(|e| Error::Uri { source: e })?;
        Ok(Self {
            uri,
            alpn_protocols: vec![ALPN_HTTP2.to_string(), ALPN_HTTP1.to_string()],
            ..Default::default()
        })
    }
}

// Convert HttpRequest to hyper Request
impl TryFrom<&HttpRequest> for Request<Full<Bytes>> {
    type Error = Error;
    fn try_from(req: &HttpRequest) -> Result<Self> {
        req.builder()
            .body(Full::new(req.body.clone().unwrap_or_default()))
            .map_err(|e| Error::Http { source: e })
    }
}

// Initialize crypto provider once
static INIT: Once = Once::new();

fn ensure_crypto_provider() {
    INIT.call_once(|| {
        let _ = tokio_rustls::rustls::crypto::ring::default_provider().install_default();
    });
}

// Perform DNS resolution
async fn dns_resolve(req: &HttpRequest, stat: &mut HttpStat) -> Result<(SocketAddr, String)> {
    let host = req
        .uri
        .host()
        .ok_or(Error::Common {
            category: "http".to_string(),
            message: "host is required".to_string(),
        })?
        .to_string();
    let port = req.get_port();

    if let Ok(addr) = host.parse::<IpAddr>() {
        let addr = SocketAddr::new(addr, port);
        stat.addr = Some(addr.to_string());
        return Ok((addr, host));
    }

    // Check custom DNS resolutions first
    if let Some(resolve) = &req.resolve {
        let addr = SocketAddr::new(*resolve, port);
        stat.addr = Some(addr.to_string());
        return Ok((addr, host));
    }

    // Configure DNS resolver
    let provider = TokioConnectionProvider::default();
    let mut servers = vec![];
    if let Some(dns_servers) = &req.dns_servers {
        for server in dns_servers {
            match server.as_str() {
                "google" => {
                    servers = GOOGLE_IPS.to_vec();
                    break;
                }
                "cloudflare" => {
                    servers = CLOUDFLARE_IPS.to_vec();
                    break;
                }
                "quad9" => {
                    servers = QUAD9_IPS.to_vec();
                    break;
                }
                _ => {
                    if let Ok(addr) = server.parse::<IpAddr>() {
                        servers.push(addr);
                    }
                }
            }
        }
    }

    let mut builder = if !servers.is_empty() {
        let mut config = ResolverConfig::new();
        for server in NameServerConfigGroup::from_ips_clear(&servers, 53, true).into_inner() {
            config.add_name_server(server);
        }
        TokioResolver::builder_with_config(config, provider)
    } else {
        TokioResolver::builder(provider).map_err(|e| Error::Resolve { source: e })?
    };

    if let Some(ip_version) = req.ip_version {
        match ip_version {
            4 => builder.options_mut().ip_strategy = LookupIpStrategy::Ipv4Only,
            6 => builder.options_mut().ip_strategy = LookupIpStrategy::Ipv6Only,
            _ => {}
        }
    }

    // Perform DNS lookup
    let resolver = builder.build();
    let dns_start = Instant::now();
    let addr = timeout(
        req.dns_timeout.unwrap_or(Duration::from_secs(5)),
        resolver.lookup_ip(&host),
    )
    .await
    .map_err(|e| Error::Timeout { source: e })?
    .map_err(|e| Error::Resolve { source: e })?;
    stat.dns_lookup = Some(dns_start.elapsed());
    let addr = addr.into_iter().next().ok_or(Error::Common {
        category: "http".to_string(),
        message: "dns lookup failed".to_string(),
    })?;
    let addr = SocketAddr::new(addr, port);
    stat.addr = Some(addr.to_string());

    Ok((addr, host))
}

// Establish TCP connection
async fn tcp_connect(
    addr: SocketAddr,
    tcp_timeout: Option<Duration>,
    stat: &mut HttpStat,
) -> Result<TcpStream> {
    let tcp_start = Instant::now();
    let tcp_stream = timeout(
        tcp_timeout.unwrap_or(Duration::from_secs(5)),
        TcpStream::connect(addr),
    )
    .await
    .map_err(|e| Error::Timeout { source: e })?
    .map_err(|e| Error::Io { source: e })?;
    stat.tcp_connect = Some(tcp_start.elapsed());
    Ok(tcp_stream)
}

// Perform TLS handshake
async fn tls_handshake(
    host: String,
    tcp_stream: TcpStream,
    tls_timeout: Option<Duration>,
    alpn_protocols: Vec<String>,
    skip_verify: bool,
    stat: &mut HttpStat,
) -> Result<(TlsStream<TcpStream>, bool)> {
    let tls_start = Instant::now();
    let mut root_store = RootCertStore::empty();
    let certs = rustls_native_certs::load_native_certs().certs;

    // Add root certificates
    for cert in certs {
        root_store
            .add(cert)
            .map_err(|e| Error::Rustls { source: e })?;
    }

    // Configure TLS client
    let mut config = ClientConfig::builder()
        .with_root_certificates(root_store)
        .with_no_client_auth();

    // Skip certificate verification if requested
    if skip_verify {
        config
            .dangerous()
            .set_certificate_verifier(Arc::new(SkipVerifier));
    }

    // Set ALPN protocols
    config.alpn_protocols = alpn_protocols
        .iter()
        .map(|s| s.as_bytes().to_vec())
        .collect();

    let connector = TlsConnector::from(Arc::new(config));

    // Perform TLS handshake
    let tls_stream = timeout(
        tls_timeout.unwrap_or(Duration::from_secs(5)),
        connector.connect(
            host.clone()
                .try_into()
                .map_err(|e| Error::InvalidDnsName { source: e })?,
            tcp_stream,
        ),
    )
    .await
    .map_err(|e| Error::Timeout { source: e })?
    .map_err(|e| Error::Io { source: e })?;
    stat.tls_handshake = Some(tls_start.elapsed());

    // Get TLS session information
    let (_, session) = tls_stream.get_ref();

    stat.tls = session
        .protocol_version()
        .map(|v| format_tls_protocol(v.as_str().unwrap_or_default()));

    // Extract certificate information
    if let Some(certs) = session.peer_certificates() {
        if let Some(cert) = certs.first() {
            if let Ok((_, cert)) = x509_parser::parse_x509_certificate(cert.as_ref()) {
                stat.subject = Some(cert.subject().to_string());
                stat.cert_not_before = Some(format_time(cert.validity().not_before.timestamp()));
                stat.cert_not_after = Some(format_time(cert.validity().not_after.timestamp()));
                stat.issuer = Some(cert.issuer().to_string());
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

    // Get cipher suite information
    if let Some(cipher) = session.negotiated_cipher_suite() {
        let cipher = format!("{:?}", cipher);
        if let Some((_, cipher)) = cipher.split_once("_") {
            stat.cert_cipher = Some(cipher.to_string());
        } else {
            stat.cert_cipher = Some(cipher);
        }
    }

    // Check if HTTP/2 is negotiated
    let mut is_http2 = false;
    if let Some(protocol) = session.alpn_protocol() {
        let alpn = String::from_utf8_lossy(protocol).to_string();
        is_http2 = alpn == ALPN_HTTP2;
        stat.alpn = Some(alpn);
    }
    Ok((tls_stream, is_http2))
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

// Handle request error and update statistics
fn finish_with_error(mut stat: HttpStat, error: impl ToString, start: Instant) -> HttpStat {
    stat.error = Some(error.to_string());
    stat.total = Some(start.elapsed());
    stat
}

// Establish QUIC connection for HTTP/3
async fn quic_connect(
    host: String,
    addr: SocketAddr,
    skip_verify: bool,
    stat: &mut HttpStat,
) -> Result<(quinn::Endpoint, quinn::Connection)> {
    let quic_start = Instant::now();
    let mut root_store = RootCertStore::empty();
    let certs = rustls_native_certs::load_native_certs().certs;

    // Add root certificates
    for cert in certs {
        root_store
            .add(cert)
            .map_err(|e| Error::Rustls { source: e })?;
    }

    // Configure QUIC client
    let mut config = ClientConfig::builder()
        .with_root_certificates(root_store)
        .with_no_client_auth();
    config.enable_early_data = true;
    config.alpn_protocols = vec![ALPN_HTTP3.as_bytes().to_vec()];

    // Skip certificate verification if requested
    if skip_verify {
        config
            .dangerous()
            .set_certificate_verifier(Arc::new(SkipVerifier));
    }

    // Create QUIC endpoint
    let mut client_endpoint =
        h3_quinn::quinn::Endpoint::client("[::]:0".parse().map_err(|_| Error::Common {
            category: "parse".to_string(),
            message: "failed to parse address".to_string(),
        })?)
        .map_err(|e| Error::Io { source: e })?;

    let h3_config =
        quinn::crypto::rustls::QuicClientConfig::try_from(config).map_err(|e| Error::Common {
            category: "quic".to_string(),
            message: e.to_string(),
        })?;

    let client_config = quinn::ClientConfig::new(Arc::new(h3_config));
    client_endpoint.set_default_client_config(client_config);

    // Establish QUIC connection
    let conn = client_endpoint
        .connect(addr, &host)
        .map_err(|e| Error::QuicConnect { source: e })?
        .await
        .map_err(|e| Error::QuicConnection { source: e })?;

    stat.quic_connect = Some(quic_start.elapsed());
    Ok((client_endpoint, conn))
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
    let req = match http_req.builder().body(()) {
        Ok(req) => req,
        Err(e) => {
            return finish_with_error(stat, e, start);
        }
    };
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

    // Convert request to hyper Request
    let req: Request<Full<Bytes>> = match (&http_req).try_into() {
        Ok(req) => req,
        Err(e) => {
            return finish_with_error(stat, e, start);
        }
    };

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
            http_req.alpn_protocols,
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
            match send_https2_request(req, tls_stream, tx, &mut stat).await {
                Ok(resp) => resp,
                Err(e) => {
                    return finish_with_error(stat, e, start);
                }
            }
        } else {
            match send_https_request(req, tls_stream, http_req.request_timeout, tx, &mut stat).await
            {
                Ok(resp) => resp,
                Err(e) => {
                    return finish_with_error(stat, e, start);
                }
            }
        }
    } else {
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
    let silent = http_req.silent;

    // Handle HTTP/3 request
    let mut stat = if http_req.alpn_protocols.contains(&ALPN_HTTP3.to_string()) {
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

    stat.silent = silent;

    stat
}
