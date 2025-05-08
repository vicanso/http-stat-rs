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

use super::error::{Error, Result};
use super::stats::{HttpStat, ALPN_HTTP1, ALPN_HTTP2, ALPN_HTTP3};
use super::SkipVerifier;
use bytes::{Buf, Bytes, BytesMut};
use chrono::{Local, TimeZone};
use futures::future;
use hickory_resolver::config::LookupIpStrategy;
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
use std::collections::HashMap;
use std::net::IpAddr;
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::Once;
use std::time::Duration;
use std::time::Instant;
use tokio::fs;
use tokio::net::TcpStream;
use tokio::sync::oneshot;
use tokio::time::timeout;
use tokio_rustls::client::TlsStream;
use tokio_rustls::rustls::{ClientConfig, RootCertStore};
use tokio_rustls::TlsConnector;

const VERSION: &str = env!("CARGO_PKG_VERSION");

fn format_tls_protocol(protocol: &str) -> String {
    match protocol {
        "TLSv1_3" => "tls v1.3".to_string(),
        "TLSv1_2" => "tls v1.2".to_string(),
        "TLSv1_1" => "tls v1.1".to_string(),
        _ => protocol.to_string(),
    }
}
fn format_time(timestamp_seconds: i64) -> String {
    Local
        .timestamp_nanos(timestamp_seconds * 1_000_000_000)
        .to_string()
}

#[derive(Default, Debug, Clone)]
pub struct HttpRequest {
    pub uri: Uri,
    pub method: Option<Method>,
    pub alpn_protocols: Vec<String>,
    pub resolves: Option<HashMap<String, IpAddr>>,
    pub headers: Option<HeaderMap<HeaderValue>>,
    pub ip_version: Option<i32>, // 4 for IPv4, 6 for IPv6
    pub skip_verify: bool,
    pub output: Option<String>,
    pub body: Option<Bytes>,
}

impl HttpRequest {
    fn builder(&self) -> Builder {
        let uri = &self.uri;
        let mut builder = Request::builder()
            .uri(uri)
            .method(self.method.clone().unwrap_or(Method::GET));
        let mut set_host = false;
        let mut set_user_agent = false;
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
        if !set_host {
            if let Some(host) = uri.host() {
                builder = builder.header("Host", host);
            }
        }
        if !set_user_agent {
            builder = builder.header("User-Agent", format!("httpstat.rs/{}", VERSION));
        }
        builder
    }
}

impl TryFrom<&str> for HttpRequest {
    type Error = Error;

    fn try_from(url: &str) -> Result<Self> {
        let uri = url.parse::<Uri>().map_err(|e| Error::Uri { source: e })?;
        Ok(Self {
            uri,
            method: None,
            alpn_protocols: vec![ALPN_HTTP2.to_string(), ALPN_HTTP1.to_string()],
            resolves: None,
            headers: None,
            ip_version: None,
            skip_verify: false,
            output: None,
            body: None,
        })
    }
}

impl TryFrom<&HttpRequest> for Request<Full<Bytes>> {
    type Error = Error;
    fn try_from(req: &HttpRequest) -> Result<Self> {
        req.builder()
            .body(Full::new(req.body.clone().unwrap_or_default()))
            .map_err(|e| Error::Http { source: e })
    }
}

static INIT: Once = Once::new();

fn ensure_crypto_provider() {
    INIT.call_once(|| {
        let _ = tokio_rustls::rustls::crypto::ring::default_provider().install_default();
    });
}

async fn dns_resolve(req: &HttpRequest, stat: &mut HttpStat) -> Result<(SocketAddr, String)> {
    let host = req
        .uri
        .host()
        .ok_or(Error::Common {
            category: "http".to_string(),
            message: "host is required".to_string(),
        })?
        .to_string();
    let default_port = if req.uri.scheme() == Some(&http::uri::Scheme::HTTPS) {
        443
    } else {
        80
    };
    let port = req.uri.port_u16().unwrap_or(default_port);

    // Check if we have a resolve entry for this host:port
    if let Some(resolves) = &req.resolves {
        let host_port = format!("{}:{}", host, port);
        if let Some(ip) = resolves.get(&host_port) {
            let addr = SocketAddr::new(*ip, port);
            stat.addr = Some(addr.to_string());
            return Ok((addr, host));
        }
    }

    let provider = TokioConnectionProvider::default();
    let mut builder = TokioResolver::builder(provider).map_err(|e| Error::Resolve { source: e })?;
    if let Some(ip_version) = req.ip_version {
        match ip_version {
            4 => builder.options_mut().ip_strategy = LookupIpStrategy::Ipv4Only,
            6 => builder.options_mut().ip_strategy = LookupIpStrategy::Ipv6Only,
            _ => {}
        }
    }

    let resolver = builder.build();
    let dns_start = Instant::now();
    let addr = timeout(Duration::from_secs(10), resolver.lookup_ip(&host))
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

async fn tcp_connect(addr: SocketAddr, stat: &mut HttpStat) -> Result<TcpStream> {
    let tcp_start = Instant::now();
    let tcp_stream = timeout(Duration::from_secs(10), TcpStream::connect(addr))
        .await
        .map_err(|e| Error::Timeout { source: e })?
        .map_err(|e| Error::Io { source: e })?;
    stat.tcp_connect = Some(tcp_start.elapsed());
    Ok(tcp_stream)
}

async fn tls_handshake(
    host: String,
    tcp_stream: TcpStream,
    alpn_protocols: Vec<String>,
    skip_verify: bool,
    stat: &mut HttpStat,
) -> Result<(TlsStream<TcpStream>, bool)> {
    let tls_start = Instant::now();
    let mut root_store = RootCertStore::empty();
    let certs = rustls_native_certs::load_native_certs().certs;

    for cert in certs {
        root_store
            .add(cert)
            .map_err(|e| Error::Rustls { source: e })?;
    }
    let mut config = ClientConfig::builder()
        .with_root_certificates(root_store)
        .with_no_client_auth();

    // Skip certificate verification if requested
    if skip_verify {
        config
            .dangerous()
            .set_certificate_verifier(Arc::new(SkipVerifier));
    }

    config.alpn_protocols = alpn_protocols
        .iter()
        .map(|s| s.as_bytes().to_vec())
        .collect();

    let connector = TlsConnector::from(Arc::new(config));

    // Perform TLS handshake
    let tls_stream = timeout(
        Duration::from_secs(30),
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

    let (_, session) = tls_stream.get_ref();

    stat.tls = session
        .protocol_version()
        .map(|v| format_tls_protocol(v.as_str().unwrap_or_default()));

    if let Some(certs) = session.peer_certificates() {
        if let Some(cert) = certs.first() {
            if let Ok((_, cert)) = x509_parser::parse_x509_certificate(cert.as_ref()) {
                stat.cert_not_before = Some(format_time(cert.validity().not_before.timestamp()));
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
    if let Some(cipher) = session.negotiated_cipher_suite() {
        let cipher = format!("{:?}", cipher);
        if let Some((_, cipher)) = cipher.split_once("_") {
            stat.cert_cipher = Some(cipher.to_string());
        } else {
            stat.cert_cipher = Some(cipher);
        }
    }
    let mut is_http2 = false;
    if let Some(protocol) = session.alpn_protocol() {
        let alpn = String::from_utf8_lossy(protocol).to_string();
        is_http2 = alpn == ALPN_HTTP2;
        stat.alpn = Some(alpn);
    }
    Ok((tls_stream, is_http2))
}

async fn send_http_request(
    req: Request<Full<Bytes>>,
    tcp_stream: TcpStream,
    tx: oneshot::Sender<String>,
    stat: &mut HttpStat,
) -> Result<Response<Incoming>> {
    let (mut sender, conn) = timeout(
        Duration::from_secs(30),
        hyper::client::conn::http1::handshake(TokioIo::new(tcp_stream)),
    )
    .await
    .map_err(|e| Error::Timeout { source: e })?
    .map_err(|e| Error::Hyper { source: e })?;
    // Spawn the connection task
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

async fn send_https_request(
    req: Request<Full<Bytes>>,
    tls_stream: TlsStream<TcpStream>,
    tx: oneshot::Sender<String>,
    stat: &mut HttpStat,
) -> Result<Response<Incoming>> {
    let (mut sender, conn) = timeout(
        Duration::from_secs(30),
        hyper::client::conn::http1::handshake(TokioIo::new(tls_stream)),
    )
    .await
    .map_err(|e| Error::Timeout { source: e })?
    .map_err(|e| Error::Hyper { source: e })?;
    // Spawn the connection task
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
    // Spawn the connection task
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

fn finish_with_error(mut stat: HttpStat, error: impl ToString, start: Instant) -> HttpStat {
    stat.error = Some(error.to_string());
    stat.total = Some(start.elapsed());
    stat
}

async fn quic_connect(
    host: String,
    addr: SocketAddr,
    skip_verify: bool,
    stat: &mut HttpStat,
) -> Result<(quinn::Endpoint, quinn::Connection)> {
    let quic_start = Instant::now();
    let mut root_store = RootCertStore::empty();
    let certs = rustls_native_certs::load_native_certs().certs;

    for cert in certs {
        root_store
            .add(cert)
            .map_err(|e| Error::Rustls { source: e })?;
    }
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

    let conn = client_endpoint
        .connect(addr, &host)
        .map_err(|e| Error::QuicConnect { source: e })?
        .await
        .map_err(|e| Error::QuicConnection { source: e })?;

    stat.quic_connect = Some(quic_start.elapsed());
    Ok((client_endpoint, conn))
}

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

    let (client_endpoint, conn) = match timeout(
        Duration::from_secs(30),
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

    // Get TLS information from the connection
    stat.tls = Some("tls 1.3".to_string()); // QUIC always uses TLS 1.3
    stat.alpn = Some(ALPN_HTTP3.to_string()); // We always use HTTP/3 for QUIC

    // Get certificate information from the connection
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

    let quinn_conn = h3_quinn::Connection::new(conn);

    let (mut driver, mut send_request) = match h3::client::new(quinn_conn)
        .await
        .map_err(|e| Error::H3ConnectionError { source: e })
    {
        Ok(result) => result,
        Err(e) => {
            return finish_with_error(stat, e, start);
        }
    };

    let req = match http_req.builder().body(()) {
        Ok(req) => req,
        Err(e) => {
            return finish_with_error(stat, e, start);
        }
    };
    let body = http_req.body.unwrap_or_default();

    let drive = async move {
        Err::<(), h3::error::ConnectionError>(future::poll_fn(|cx| driver.poll_close(cx)).await)
    };

    let request = async move {
        let mut stream = send_request.send_request(req).await?;
        stream.send_data(body).await?;

        let mut sub_stat = HttpStat::default();

        // finish on the sending side
        stream.finish().await?;

        let server_processing_start = Instant::now();

        let resp = stream.recv_response().await?;
        sub_stat.server_processing = Some(server_processing_start.elapsed());

        sub_stat.status = Some(resp.status());
        sub_stat.headers = Some(resp.headers().clone());

        let content_transfer_start = Instant::now();
        let mut buf = BytesMut::new();
        while let Some(chunk) = stream.recv_data().await? {
            buf.extend(chunk.chunk());
        }
        sub_stat.content_transfer = Some(content_transfer_start.elapsed());
        sub_stat.body = Some(Bytes::from(buf));

        Ok::<HttpStat, h3::error::StreamError>(sub_stat)
    };

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

pub async fn request(http_req: HttpRequest) -> HttpStat {
    ensure_crypto_provider();

    if http_req.alpn_protocols.contains(&ALPN_HTTP3.to_string()) {
        return http3_request(http_req).await;
    }

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

    let req: Request<Full<Bytes>> = match (&http_req).try_into() {
        Ok(req) => req,
        Err(e) => {
            return finish_with_error(stat, e, start);
        }
    };

    // TCP connection
    let tcp_stream = match tcp_connect(addr, &mut stat).await {
        Ok(stream) => stream,
        Err(e) => {
            return finish_with_error(stat, e, start);
        }
    };

    // Create a channel to receive connection errors
    let (tx, mut rx) = oneshot::channel();

    // Send the request based on protocol
    let resp = if is_https {
        // TLS handshake
        let tls_result = tls_handshake(
            host.clone(),
            tcp_stream,
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
            match send_https_request(req, tls_stream, tx, &mut stat).await {
                Ok(resp) => resp,
                Err(e) => {
                    return finish_with_error(stat, e, start);
                }
            }
        }
    } else {
        // Send HTTP request
        match send_http_request(req, tcp_stream, tx, &mut stat).await {
            Ok(resp) => resp,
            Err(e) => {
                return finish_with_error(stat, e, start);
            }
        }
    };

    stat.status = Some(resp.status());
    stat.headers = Some(resp.headers().clone());

    // Read the response body
    let content_transfer_start = Instant::now();
    let body_result = resp.collect().await;
    let body = match body_result {
        Ok(body) => body,
        Err(e) => {
            return finish_with_error(stat, format!("Failed to read response body: {}", e), start);
        }
    };

    let body_bytes = body.to_bytes();
    if let Some(output) = http_req.output {
        match fs::write(output, body_bytes).await {
            Ok(_) => {}
            Err(e) => {
                return finish_with_error(
                    stat,
                    format!("Failed to write response body to file: {}", e),
                    start,
                );
            }
        }
    } else {
        stat.body = Some(body_bytes);
    }
    stat.content_transfer = Some(content_transfer_start.elapsed());

    // Check for connection errors
    if let Ok(error) = rx.try_recv() {
        stat.error = Some(error);
    }

    stat.total = Some(start.elapsed());
    stat
}
