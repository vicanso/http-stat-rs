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
use super::skip_verifier::CapturingVerifier;
use super::stats::{format_time, Certificate, HttpStat, ALPN_HTTP2, ALPN_HTTP3};
use super::tcp_info::TcpInfoProbe;
use super::HttpRequest;
use super::SkipVerifier;
use hickory_resolver::config::{
    LookupIpStrategy, NameServerConfig, ResolverConfig, CLOUDFLARE, GOOGLE, QUAD9,
};
use hickory_resolver::net::runtime::TokioRuntimeProvider;
use hickory_resolver::TokioResolver;
use rustls_pki_types::pem::PemObject;
use rustls_pki_types::{CertificateDer, PrivateKeyDer};
use std::net::IpAddr;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use std::time::Instant;
use tokio::net::TcpSocket;
use tokio::net::TcpStream;
use tokio::time::timeout;
use tokio_rustls::client::TlsStream;
use tokio_rustls::rustls::client::{Resumption, WebPkiServerVerifier};
use tokio_rustls::rustls::{ClientConfig, HandshakeKind, RootCertStore};
use tokio_rustls::TlsConnector;

/// Transport used by a DoH/DoT preset, captured so we can run a parallel
/// cold-connect probe and split `dns_lookup` into `dns_connect` + `dns_query`.
#[cfg(feature = "doh")]
#[derive(Debug, Clone, Copy)]
enum DnsTransport {
    Doh,
    Dot,
}

#[cfg(feature = "doh")]
#[derive(Debug, Clone)]
struct DnsProbeEndpoint {
    transport: DnsTransport,
    ip: IpAddr,
    port: u16,
    sni: String,
}

/// Measure the cold TCP + TLS handshake cost to a DoH/DoT server. Returns
/// `None` on any failure — the main resolver call is the source of truth and
/// will surface real errors via `dns_lookup`. Designed to run in parallel
/// with the resolver via `tokio::join!`, so it doesn't inflate wall-clock
/// (the resolver's connect+query path dominates).
#[cfg(feature = "doh")]
async fn probe_dns_endpoint(ep: &DnsProbeEndpoint, max: Duration) -> Option<Duration> {
    let work = async move {
        let start = Instant::now();
        let addr: SocketAddr = (ep.ip, ep.port).into();
        let tcp = TcpStream::connect(addr).await.ok()?;

        let mut roots = RootCertStore::empty();
        for cert in rustls_native_certs::load_native_certs().certs {
            let _ = roots.add(cert);
        }
        let mut config = ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth();
        config.alpn_protocols = match ep.transport {
            DnsTransport::Doh => vec![b"h2".to_vec(), b"http/1.1".to_vec()],
            DnsTransport::Dot => vec![b"dot".to_vec()],
        };
        let connector = TlsConnector::from(Arc::new(config));
        let server_name = ep.sni.clone().try_into().ok()?;
        let _tls = connector.connect(server_name, tcp).await.ok()?;
        Some(start.elapsed())
    };
    timeout(max, work).await.ok().flatten()
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
    let provider = TokioRuntimeProvider::default();
    let mut server_config: Option<ResolverConfig> = None;
    // When a DoH/DoT preset matches, remember its endpoint so we can probe
    // the cold connect cost in parallel with the actual resolver call.
    #[cfg(feature = "doh")]
    let mut probe_endpoint: Option<DnsProbeEndpoint> = None;
    if let Some(dns_servers) = &req.dns_servers {
        let mut plain_ips: Vec<IpAddr> = vec![];
        for server in dns_servers {
            match server.as_str() {
                // Plain UDP/TCP presets
                "google" => {
                    server_config = Some(ResolverConfig::udp_and_tcp(&GOOGLE));
                    plain_ips.clear();
                    break;
                }
                "cloudflare" => {
                    server_config = Some(ResolverConfig::udp_and_tcp(&CLOUDFLARE));
                    plain_ips.clear();
                    break;
                }
                "quad9" => {
                    server_config = Some(ResolverConfig::udp_and_tcp(&QUAD9));
                    plain_ips.clear();
                    break;
                }
                // DNS-over-HTTPS presets
                #[cfg(feature = "doh")]
                "google-doh" => {
                    server_config = Some(ResolverConfig::https(&GOOGLE));
                    probe_endpoint = Some(DnsProbeEndpoint {
                        transport: DnsTransport::Doh,
                        ip: IpAddr::from([8, 8, 8, 8]),
                        port: 443,
                        sni: "dns.google".to_string(),
                    });
                    plain_ips.clear();
                    break;
                }
                #[cfg(feature = "doh")]
                "cloudflare-doh" => {
                    server_config = Some(ResolverConfig::https(&CLOUDFLARE));
                    probe_endpoint = Some(DnsProbeEndpoint {
                        transport: DnsTransport::Doh,
                        ip: IpAddr::from([1, 1, 1, 1]),
                        port: 443,
                        sni: "cloudflare-dns.com".to_string(),
                    });
                    plain_ips.clear();
                    break;
                }
                #[cfg(feature = "doh")]
                "quad9-doh" => {
                    server_config = Some(ResolverConfig::https(&QUAD9));
                    probe_endpoint = Some(DnsProbeEndpoint {
                        transport: DnsTransport::Doh,
                        ip: IpAddr::from([9, 9, 9, 9]),
                        port: 443,
                        sni: "dns.quad9.net".to_string(),
                    });
                    plain_ips.clear();
                    break;
                }
                // DNS-over-TLS presets
                #[cfg(feature = "doh")]
                "google-dot" => {
                    server_config = Some(ResolverConfig::tls(&GOOGLE));
                    probe_endpoint = Some(DnsProbeEndpoint {
                        transport: DnsTransport::Dot,
                        ip: IpAddr::from([8, 8, 8, 8]),
                        port: 853,
                        sni: "dns.google".to_string(),
                    });
                    plain_ips.clear();
                    break;
                }
                #[cfg(feature = "doh")]
                "cloudflare-dot" => {
                    server_config = Some(ResolverConfig::tls(&CLOUDFLARE));
                    probe_endpoint = Some(DnsProbeEndpoint {
                        transport: DnsTransport::Dot,
                        ip: IpAddr::from([1, 1, 1, 1]),
                        port: 853,
                        sni: "cloudflare-dns.com".to_string(),
                    });
                    plain_ips.clear();
                    break;
                }
                #[cfg(feature = "doh")]
                "quad9-dot" => {
                    server_config = Some(ResolverConfig::tls(&QUAD9));
                    probe_endpoint = Some(DnsProbeEndpoint {
                        transport: DnsTransport::Dot,
                        ip: IpAddr::from([9, 9, 9, 9]),
                        port: 853,
                        sni: "dns.quad9.net".to_string(),
                    });
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
            let servers: Vec<NameServerConfig> = plain_ips
                .into_iter()
                .map(NameServerConfig::udp_and_tcp)
                .collect();
            server_config = Some(ResolverConfig::from_parts(None, vec![], servers));
        }
    }

    let mut builder = if let Some(config) = server_config {
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

    // Perform DNS lookup. For DoH/DoT, race a connect-only probe in parallel
    // so we can split the reported `dns_lookup` into `dns_connect` (TCP+TLS to
    // the DNS server) and a derived `dns_query`. The probe is fire-and-forget
    // accurate — failures leave `dns_connect` as None and never block the
    // real resolver result.
    let resolver = builder.build().map_err(|e| Error::Resolve { source: e })?;
    let dns_timeout = req.dns_timeout.unwrap_or(Duration::from_secs(5));
    let dns_start = Instant::now();
    let lookup_fut = timeout(dns_timeout, resolver.lookup_ip(&lookup_host));

    #[cfg(feature = "doh")]
    let (lookup_result, probe_result) = {
        let probe_fut = async {
            match &probe_endpoint {
                Some(ep) => probe_dns_endpoint(ep, dns_timeout).await,
                None => None,
            }
        };
        tokio::join!(lookup_fut, probe_fut)
    };
    #[cfg(not(feature = "doh"))]
    let (lookup_result, probe_result) = (lookup_fut.await, None::<Duration>);

    let addr = lookup_result
        .map_err(|e| Error::Timeout { source: e })?
        .map_err(|e| Error::Resolve { source: e })?;
    stat.dns_lookup = Some(dns_start.elapsed());
    stat.dns_connect = probe_result;
    let addr = addr.iter().next().ok_or(Error::Common {
        category: "http".to_string(),
        message: "dns lookup failed".to_string(),
    })?;
    let addr = SocketAddr::new(addr, port);
    stat.addr = Some(addr.to_string());

    Ok((addr, host))
}

// Establish TCP connection
//
// Returns the live `TcpStream` plus an optional [`TcpInfoProbe`] holding a
// `dup(2)`'d FD pointing at the same kernel socket. The probe lets a later
// caller (after the response body has been read) take a second TCP_INFO
// sample, so we can compute retransmits-during-transfer even after hyper
// has taken ownership of the original stream.
pub(crate) async fn tcp_connect(
    addr: SocketAddr,
    tcp_timeout: Option<Duration>,
    bind_addr: Option<IpAddr>,
    stat: &mut HttpStat,
) -> Result<(TcpStream, Option<TcpInfoProbe>)> {
    let tcp_start = Instant::now();
    let connect_fut = async {
        if let Some(src_ip) = bind_addr {
            let socket = if src_ip.is_ipv6() {
                TcpSocket::new_v6()
            } else {
                TcpSocket::new_v4()
            }
            .map_err(|e| Error::Io { source: e })?;
            let bind: SocketAddr = (src_ip, 0).into();
            socket.bind(bind).map_err(|e| Error::Io { source: e })?;
            socket
                .connect(addr)
                .await
                .map_err(|e| Error::Io { source: e })
        } else {
            TcpStream::connect(addr)
                .await
                .map_err(|e| Error::Io { source: e })
        }
    };
    let tcp_stream = timeout(tcp_timeout.unwrap_or(Duration::from_secs(5)), connect_fut)
        .await
        .map_err(|e| Error::Timeout { source: e })??;
    stat.tcp_connect = Some(tcp_start.elapsed());
    // Baseline kernel TCP stats + a dup'd FD for the post-transfer sample.
    let (baseline, probe) = TcpInfoProbe::capture(&tcp_stream);
    stat.tcp_info_post_connect = baseline;
    Ok((tcp_stream, probe))
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

    // Build a webpki-backed verifier that we can wrap to observe OCSP stapling.
    // When `--skip-verify` is set we fall through to SkipVerifier and leave
    // `tls_ocsp_stapled` as None (OCSP detection is meaningless without
    // verification).
    let builder = ClientConfig::builder().with_root_certificates(root_store.clone());

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

    // Install verifier: SkipVerifier when --skip-verify, otherwise wrap the
    // default WebPkiServerVerifier so we can record whether the server stapled
    // an OCSP response.
    let ocsp_handle: Option<Arc<std::sync::OnceLock<bool>>> = if http_req.skip_verify {
        config
            .dangerous()
            .set_certificate_verifier(Arc::new(SkipVerifier));
        None
    } else {
        let inner = WebPkiServerVerifier::builder(Arc::new(root_store))
            .build()
            .map_err(|e| Error::Common {
                category: "tls".to_string(),
                message: e.to_string(),
            })?;
        let (capturing, handle) = CapturingVerifier::new(inner);
        config
            .dangerous()
            .set_certificate_verifier(Arc::new(capturing));
        Some(handle)
    };

    // Enable 0-RTT and wire the session store (if the caller provided one,
    // e.g. the -n benchmark loop), so a resumed handshake can occur and we
    // can report whether early data was actually accepted.
    config.enable_early_data = true;
    if let Some(store) = &http_req.tls_session_store {
        config.resumption = Resumption::store(store.clone());
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

    // Resumption: rustls reports `HandshakeKind::Resumed` for a session-ticket
    // resumption. Full / FullWithHelloRetryRequest both collapse to "Full" for
    // the user-facing label.
    stat.tls_resumed = session
        .handshake_kind()
        .map(|k| matches!(k, HandshakeKind::Resumed));
    // Early data is meaningful only when the client actually requested it,
    // which requires a prior session. On a cold handshake `is_early_data_accepted`
    // returns false but the question wasn't really asked — only report when
    // we attempted resumption.
    if matches!(stat.tls_resumed, Some(true)) {
        stat.tls_early_data_accepted = Some(session.is_early_data_accepted());
    }
    // OCSP: from the wrapping verifier. Left as None when --skip-verify or when
    // (unlikely) the verifier was bypassed via cached cert.
    if let Some(handle) = &ocsp_handle {
        stat.tls_ocsp_stapled = handle.get().copied();
    }

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
    bind_addr: Option<IpAddr>,
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

    // Create QUIC endpoint, binding to the requested source IP (or wildcard)
    let quic_bind: SocketAddr = match bind_addr {
        Some(ip) => (ip, 0).into(),
        None => {
            if addr.is_ipv6() {
                "[::]:0".parse().unwrap()
            } else {
                "0.0.0.0:0".parse().unwrap()
            }
        }
    };
    let mut client_endpoint =
        h3_quinn::quinn::Endpoint::client(quic_bind).map_err(|e| Error::Io { source: e })?;

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
