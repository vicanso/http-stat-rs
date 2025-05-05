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
use super::stats::{HttpStat, ALPN_HTTP1, ALPN_HTTP2};
use super::SkipVerifier;
use bytes::Bytes;
use hickory_resolver::config::LookupIpStrategy;
use hickory_resolver::name_server::TokioConnectionProvider;
use hickory_resolver::TokioResolver;
use http::HeaderValue;
use http::Response;
use http::Uri;
use http::{HeaderMap, Method};
use http_body_util::{BodyExt, Full};
use hyper::body::Incoming;
use hyper::Request;
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

#[derive(Default, Debug, Clone)]
pub struct HttpRequest {
    pub uri: Uri,
    pub method: Option<Method>,
    pub alpn_protocols: Vec<String>,
    pub resolves: Option<HashMap<String, IpAddr>>,
    pub headers: Option<HeaderMap<HeaderValue>>,
    pub ip_version: Option<i32>, // -4 for IPv4, -6 for IPv6
    pub skip_verify: bool,
    pub output: Option<String>,
    pub body: Option<Bytes>,
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
    let addr = resolver
        .lookup_ip(&host)
        .await
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
    let tls_stream = connector
        .connect(
            host.clone()
                .try_into()
                .map_err(|e| Error::InvalidDnsName { source: e })?,
            tcp_stream,
        )
        .await
        .map_err(|e| Error::Io { source: e })?;
    stat.tls_handshake = Some(tls_start.elapsed());

    let (_, session) = tls_stream.get_ref();

    stat.tls = session
        .protocol_version()
        .map(|v| v.as_str().unwrap_or_default().to_string());

    if let Some(certs) = session.peer_certificates() {
        if let Some(cert) = certs.first() {
            if let Ok((_, cert)) = x509_parser::parse_x509_certificate(cert.as_ref()) {
                stat.cert_not_before = Some(cert.validity().not_before.to_string());
                stat.cert_not_after = Some(cert.validity().not_after.to_string());
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
        stat.cert_cipher = Some(format!("{:?}", cipher));
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
    let (mut sender, conn) = hyper::client::conn::http1::handshake(TokioIo::new(tcp_stream))
        .await
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
    let (mut sender, conn) = hyper::client::conn::http1::handshake(TokioIo::new(tls_stream))
        .await
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
    let (mut sender, conn) =
        hyper::client::conn::http2::handshake(TokioExecutor::new(), TokioIo::new(tls_stream))
            .await
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

pub async fn request(http_req: HttpRequest) -> HttpStat {
    ensure_crypto_provider();
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

    // TCP connection
    let tcp_stream = match tcp_connect(addr, &mut stat).await {
        Ok(stream) => stream,
        Err(e) => {
            return finish_with_error(stat, e, start);
        }
    };

    let uri = http_req.uri;
    let is_https = uri.scheme() == Some(&http::uri::Scheme::HTTPS);
    let mut builder = Request::builder()
        .uri(&uri)
        .method(http_req.method.unwrap_or(Method::GET));
    let mut set_host = false;
    if let Some(headers) = http_req.headers {
        for (key, value) in headers.iter() {
            builder = builder.header(key, value);
            if key.to_string().to_lowercase() == "host" {
                set_host = true;
            }
        }
    }
    if !set_host {
        builder = builder.header("Host", host.clone());
    }

    // Build the request
    let req = match builder.body(Full::new(http_req.body.unwrap_or_default())) {
        Ok(req) => req,
        Err(e) => {
            return finish_with_error(stat, format!("Failed to build request: {}", e), start);
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
