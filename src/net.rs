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

use super::error::{Error, Result};
use super::stats::{HttpStat, ALPN_HTTP2, ALPN_HTTP3};
use super::HttpRequest;
use super::SkipVerifier;
use chrono::{Local, TimeZone};
use hickory_resolver::config::{
    LookupIpStrategy, NameServerConfigGroup, ResolverConfig, CLOUDFLARE_IPS, GOOGLE_IPS, QUAD9_IPS,
};
use hickory_resolver::name_server::TokioConnectionProvider;
use hickory_resolver::TokioResolver;
use std::net::IpAddr;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use std::time::Instant;
use tokio::net::TcpStream;
use tokio::time::timeout;
use tokio_rustls::client::TlsStream;
use tokio_rustls::rustls::{ClientConfig, RootCertStore};
use tokio_rustls::TlsConnector;

// Format timestamp to human-readable string
fn format_time(timestamp_seconds: i64) -> String {
    Local
        .timestamp_nanos(timestamp_seconds * 1_000_000_000)
        .to_string()
}

// Format TLS protocol version for display
fn format_tls_protocol(protocol: &str) -> String {
    match protocol {
        "TLSv1_3" => "tls v1.3".to_string(),
        "TLSv1_2" => "tls v1.2".to_string(),
        "TLSv1_1" => "tls v1.1".to_string(),
        _ => protocol.to_string(),
    }
}

// Perform DNS resolution
pub(crate) async fn dns_resolve(
    req: &HttpRequest,
    stat: &mut HttpStat,
) -> Result<(SocketAddr, String)> {
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
pub(crate) async fn tcp_connect(
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
pub(crate) async fn tls_handshake(
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

// Establish QUIC connection for HTTP/3
pub(crate) async fn quic_connect(
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
