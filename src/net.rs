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
use super::http_request::ConnectTo;
use super::stats::{format_time, Certificate, HttpStat, ALPN_HTTP2, ALPN_HTTP3};
use super::HttpRequest;
use super::SkipVerifier;
use hickory_resolver::config::{
    LookupIpStrategy, NameServerConfigGroup, ResolverConfig, CLOUDFLARE_IPS, GOOGLE_IPS, QUAD9_IPS,
};
use hickory_resolver::name_server::TokioConnectionProvider;
use hickory_resolver::TokioResolver;
use rustls_pki_types::pem::PemObject;
use rustls_pki_types::{CertificateDer, PrivateKeyDer};
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

// Format TLS protocol version for display
fn format_tls_protocol(protocol: &str) -> String {
    match protocol {
        "TLSv1_3" => "tls v1.3".to_string(),
        "TLSv1_2" => "tls v1.2".to_string(),
        "TLSv1_1" => "tls v1.1".to_string(),
        _ => protocol.to_string(),
    }
}

// Parse X.509 certificates and populate stat fields
pub(crate) fn parse_certificates(certs: &[impl AsRef<[u8]>], stat: &mut HttpStat) {
    let mut certificates = vec![];
    for (index, cert_data) in certs.iter().enumerate() {
        if let Ok((_, cert)) = x509_parser::parse_x509_certificate(cert_data.as_ref()) {
            let subject = cert.subject().to_string();
            let issuer = cert.issuer().to_string();
            let not_before = format_time(cert.validity().not_before.timestamp());
            let not_after = format_time(cert.validity().not_after.timestamp());
            if index == 0 {
                stat.subject = Some(subject);
                stat.cert_not_before = Some(not_before);
                stat.cert_not_after = Some(not_after);
                stat.issuer = Some(issuer);
                if let Ok(Some(sans)) = cert.subject_alternative_name() {
                    let mut domains = vec![];
                    for san in sans.value.general_names.iter() {
                        if let x509_parser::extensions::GeneralName::DNSName(domain) = san {
                            domains.push(domain.to_string());
                        }
                    }
                    stat.cert_domains = Some(domains);
                };
                continue;
            }
            certificates.push(Certificate {
                subject,
                issuer,
                not_before,
                not_after,
            });
        }
    }
    if !certificates.is_empty() {
        stat.certificates = Some(certificates);
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

    // Apply --connect-to override: redirect target host:port to another host:port.
    // TLS SNI and the HTTP Host header keep using the original `host`.
    let (lookup_host, port) = req
        .connect_to
        .iter()
        .filter_map(|s| ConnectTo::parse(s))
        .find(|ct| ct.matches(&host, port))
        .map(|ct| {
            let h = if ct.dst_host.is_empty() {
                host.clone()
            } else {
                ct.dst_host.clone()
            };
            let p = ct.dst_port.unwrap_or(port);
            (h, p)
        })
        .unwrap_or_else(|| (host.clone(), port));

    if let Ok(addr) = lookup_host.parse::<IpAddr>() {
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
    let mut server_group: Option<NameServerConfigGroup> = None;
    if let Some(dns_servers) = &req.dns_servers {
        let mut plain_ips: Vec<IpAddr> = vec![];
        for server in dns_servers {
            match server.as_str() {
                // Plain UDP presets
                "google" => {
                    server_group =
                        Some(NameServerConfigGroup::from_ips_clear(GOOGLE_IPS, 53, true));
                    plain_ips.clear();
                    break;
                }
                "cloudflare" => {
                    server_group = Some(NameServerConfigGroup::from_ips_clear(
                        CLOUDFLARE_IPS,
                        53,
                        true,
                    ));
                    plain_ips.clear();
                    break;
                }
                "quad9" => {
                    server_group = Some(NameServerConfigGroup::from_ips_clear(QUAD9_IPS, 53, true));
                    plain_ips.clear();
                    break;
                }
                // DNS-over-HTTPS presets
                "google-doh" => {
                    server_group = Some(NameServerConfigGroup::from_ips_https(
                        &[IpAddr::from([8, 8, 8, 8]), IpAddr::from([8, 8, 4, 4])],
                        443,
                        "dns.google".to_string(),
                        true,
                    ));
                    plain_ips.clear();
                    break;
                }
                "cloudflare-doh" => {
                    server_group = Some(NameServerConfigGroup::from_ips_https(
                        &[IpAddr::from([1, 1, 1, 1]), IpAddr::from([1, 0, 0, 1])],
                        443,
                        "cloudflare-dns.com".to_string(),
                        true,
                    ));
                    plain_ips.clear();
                    break;
                }
                "quad9-doh" => {
                    server_group = Some(NameServerConfigGroup::from_ips_https(
                        &[
                            IpAddr::from([9, 9, 9, 9]),
                            IpAddr::from([149, 112, 112, 112]),
                        ],
                        443,
                        "dns.quad9.net".to_string(),
                        true,
                    ));
                    plain_ips.clear();
                    break;
                }
                // DNS-over-TLS presets
                "google-dot" => {
                    server_group = Some(NameServerConfigGroup::from_ips_tls(
                        &[IpAddr::from([8, 8, 8, 8]), IpAddr::from([8, 8, 4, 4])],
                        853,
                        "dns.google".to_string(),
                        true,
                    ));
                    plain_ips.clear();
                    break;
                }
                "cloudflare-dot" => {
                    server_group = Some(NameServerConfigGroup::from_ips_tls(
                        &[IpAddr::from([1, 1, 1, 1]), IpAddr::from([1, 0, 0, 1])],
                        853,
                        "cloudflare-dns.com".to_string(),
                        true,
                    ));
                    plain_ips.clear();
                    break;
                }
                "quad9-dot" => {
                    server_group = Some(NameServerConfigGroup::from_ips_tls(
                        &[
                            IpAddr::from([9, 9, 9, 9]),
                            IpAddr::from([149, 112, 112, 112]),
                        ],
                        853,
                        "dns.quad9.net".to_string(),
                        true,
                    ));
                    plain_ips.clear();
                    break;
                }
                _ => {
                    if let Ok(addr) = server.parse::<IpAddr>() {
                        plain_ips.push(addr);
                    }
                }
            }
        }
        if !plain_ips.is_empty() {
            server_group = Some(NameServerConfigGroup::from_ips_clear(&plain_ips, 53, true));
        }
    }

    let mut builder = if let Some(group) = server_group {
        let mut config = ResolverConfig::new();
        for server in group.into_inner() {
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
        resolver.lookup_ip(&lookup_host),
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
    http_req: &HttpRequest,
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

    let builder = ClientConfig::builder().with_root_certificates(root_store);

    // Configure TLS client (with or without client auth)
    let mut config = if let (Some(cert_pem), Some(key_pem)) = (
        http_req.client_cert.as_deref(),
        http_req.client_key.as_deref(),
    ) {
        let cert_chain: Vec<CertificateDer<'static>> = CertificateDer::pem_slice_iter(cert_pem)
            .collect::<std::result::Result<Vec<_>, _>>()
            .map_err(|e| Error::Common {
                category: "cert".to_string(),
                message: e.to_string(),
            })?;
        let key = PrivateKeyDer::from_pem_slice(key_pem).map_err(|e| Error::Common {
            category: "key".to_string(),
            message: e.to_string(),
        })?;
        builder
            .with_client_auth_cert(cert_chain, key)
            .map_err(|e| Error::Rustls { source: e })?
    } else {
        builder.with_no_client_auth()
    };

    // Skip certificate verification if requested
    if http_req.skip_verify {
        config
            .dangerous()
            .set_certificate_verifier(Arc::new(SkipVerifier));
    }

    // Set ALPN protocols
    config.alpn_protocols = http_req
        .alpn_protocols
        .iter()
        .map(|s| s.as_bytes().to_vec())
        .collect();

    let connector = TlsConnector::from(Arc::new(config));

    // Perform TLS handshake
    let tls_stream = timeout(
        http_req.tls_timeout.unwrap_or(Duration::from_secs(5)),
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
        parse_certificates(certs, stat);
    }

    // Get cipher suite information
    if let Some(cipher) = session.negotiated_cipher_suite() {
        let cipher = format!("{cipher:?}");
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
    client_cert: Option<&[u8]>,
    client_key: Option<&[u8]>,
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

    let builder = ClientConfig::builder().with_root_certificates(root_store);

    // Configure QUIC client (with or without client auth)
    let mut config = if let (Some(cert_pem), Some(key_pem)) = (client_cert, client_key) {
        let cert_chain: Vec<CertificateDer<'static>> = CertificateDer::pem_slice_iter(cert_pem)
            .collect::<std::result::Result<Vec<_>, _>>()
            .map_err(|e| Error::Common {
                category: "cert".to_string(),
                message: e.to_string(),
            })?;
        let key = PrivateKeyDer::from_pem_slice(key_pem).map_err(|e| Error::Common {
            category: "key".to_string(),
            message: e.to_string(),
        })?;
        builder
            .with_client_auth_cert(cert_chain, key)
            .map_err(|e| Error::Rustls { source: e })?
    } else {
        builder.with_no_client_auth()
    };
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
