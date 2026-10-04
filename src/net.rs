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

// DNS, TCP, TLS, and QUIC connection setup.

#[cfg(feature = "doh")]
use super::dns_msg::{encode_query, parse_records, QTYPE_A, QTYPE_AAAA};
use super::error::{Error, Result};
use super::happy::{self, race_tcp_inner};
use super::http_request::ConnectTo;
use super::proxy::ProxyConfig;
#[cfg(feature = "doh")]
use super::request::{OriginIo, TrackedBody};
use super::skip_verifier::CapturingVerifier;
use super::stats::{format_time, Certificate, HttpStat, ALPN_HTTP2, ALPN_HTTP3};
use super::tcp_info::TcpInfoProbe;
use super::HttpRequest;
use super::SkipVerifier;
use futures::stream::{FuturesUnordered, StreamExt};
use hickory_resolver::config::{
    LookupIpStrategy, NameServerConfig, ResolverConfig, CLOUDFLARE, GOOGLE, QUAD9,
};
use hickory_resolver::net::runtime::TokioRuntimeProvider;
use hickory_resolver::TokioResolver;
#[cfg(feature = "doh")]
use http_body_util::BodyExt;
#[cfg(feature = "doh")]
use hyper_util::rt::{TokioExecutor, TokioIo};
use rustls_pki_types::pem::PemObject;
use rustls_pki_types::{CertificateDer, PrivateKeyDer};
use std::collections::VecDeque;
use std::net::IpAddr;
use std::net::SocketAddr;
use std::sync::{Arc, Once, OnceLock};
use std::time::Duration;
use std::time::Instant;
use tokio::io::{AsyncRead, AsyncWrite};
#[cfg(feature = "doh")]
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::timeout;
use tokio_rustls::client::TlsStream;
use tokio_rustls::rustls::client::{Resumption, WebPkiServerVerifier};
use tokio_rustls::rustls::{ClientConfig, HandshakeKind, RootCertStore};
use tokio_rustls::TlsConnector;

static CRYPTO: Once = Once::new();

fn ensure_crypto_provider() {
    CRYPTO.call_once(|| {
        let _ = tokio_rustls::rustls::crypto::ring::default_provider().install_default();
    });
}

/// Addresses to try, plus the names the rest of the stack needs.
///
/// `host` is the TLS SNI / HTTP host (the original URI host). `cache_host`
/// is the name that was looked up, after `--connect-to`.
pub(crate) struct Resolved {
    pub addrs: Vec<SocketAddr>,
    pub host: String,
    pub cache_host: String,
    pub cache_port: u16,
}

/// A DNS-over-HTTPS or DNS-over-TLS resolver.
#[cfg(feature = "doh")]
#[derive(Debug, PartialEq)]
struct SecureDns {
    /// Name (or IP) on the resolver's certificate: TLS SNI and DoH `Host`.
    host: String,
    /// Address to dial. The presets pin one; a custom resolver is looked up
    /// by `host` through the system resolver.
    ip: Option<IpAddr>,
    port: u16,
    /// DoH request target.
    path: String,
    dot: bool,
}

#[cfg(feature = "doh")]
const DOH_PATH: &str = "/dns-query";

#[cfg(feature = "doh")]
impl SecureDns {
    fn preset(host: &str, ip: [u8; 4], dot: bool) -> Self {
        Self {
            host: host.to_string(),
            ip: Some(IpAddr::from(ip)),
            port: if dot { 853 } else { 443 },
            path: DOH_PATH.to_string(),
            dot,
        }
    }

    /// A preset name, a DoH URL (`https://host[:port][/path]`) or a DoT
    /// address (`tls://host[:port]`).
    fn parse(server: &str) -> Option<Self> {
        let (provider, dot) = match server.rsplit_once('-') {
            Some((provider, "doh")) => (provider, false),
            Some((provider, "dot")) => (provider, true),
            _ => return Self::parse_url(server),
        };
        match provider {
            "google" => Some(Self::preset("dns.google", [8, 8, 8, 8], dot)),
            "cloudflare" => Some(Self::preset("cloudflare-dns.com", [1, 1, 1, 1], dot)),
            "quad9" => Some(Self::preset("dns.quad9.net", [9, 9, 9, 9], dot)),
            _ => Self::parse_url(server),
        }
    }

    fn parse_url(server: &str) -> Option<Self> {
        let dot = Self::is_url(server)?;
        let uri = server.parse::<http::Uri>().ok()?;
        // `Uri::host` keeps the brackets of an IPv6 literal.
        let host = uri.host()?.trim_matches(['[', ']']);
        if host.is_empty() {
            return None;
        }
        let path = match uri.path_and_query().map(|p| p.as_str()) {
            Some(path) if !dot && path != "/" && !path.is_empty() => path,
            _ => DOH_PATH,
        };
        Some(Self {
            host: host.to_string(),
            ip: host.parse().ok(),
            port: uri.port_u16().unwrap_or(if dot { 853 } else { 443 }),
            path: path.to_string(),
            dot,
        })
    }

    /// `Some(dot)` when `server` is written as a DoH or DoT URL.
    fn is_url(server: &str) -> Option<bool> {
        if server.starts_with("https://") {
            Some(false)
        } else if server.starts_with("tls://") {
            Some(true)
        } else {
            None
        }
    }

    /// `Host` header value for DoH.
    fn authority(&self) -> String {
        let host = if self.host.contains(':') {
            format!("[{}]", self.host)
        } else {
            self.host.clone()
        };
        if self.port == 443 {
            host
        } else {
            format!("{host}:{}", self.port)
        }
    }
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

fn cache_servers(req: &HttpRequest) -> String {
    req.dns_servers
        .as_ref()
        .map(|s| s.join(","))
        .unwrap_or_default()
}

fn finish_lookup(
    req: &HttpRequest,
    stat: &mut HttpStat,
    host: String,
    cache_host: String,
    cache_port: u16,
    ips: Vec<IpAddr>,
    valid_until: Instant,
) -> Result<Resolved> {
    if ips.is_empty() {
        return Err(Error::Common {
            category: "http".to_string(),
            message: "dns lookup failed".to_string(),
        });
    }
    let addrs: Vec<SocketAddr> = ips
        .into_iter()
        .map(|ip| SocketAddr::new(ip, cache_port))
        .collect();
    let addrs = happy::interleave(addrs);
    let floor = Instant::now() + Duration::from_secs(1);
    if let Some(cache) = &req.dns_cache {
        cache.put(
            &cache_host,
            cache_port,
            &cache_servers(req),
            req.ip_version.unwrap_or(0),
            addrs.clone(),
            valid_until.max(floor),
        );
    }
    if addrs.len() > 1 {
        stat.candidates = addrs.iter().map(|a| a.to_string()).collect();
    }
    stat.addr = addrs.first().map(|a| a.to_string());
    Ok(Resolved {
        addrs,
        host,
        cache_host,
        cache_port,
    })
}

fn literal_resolved(
    addr: SocketAddr,
    host: String,
    cache_host: String,
    cache_port: u16,
    stat: &mut HttpStat,
) -> Resolved {
    stat.addr = Some(addr.to_string());
    stat.dns_attempted = false;
    Resolved {
        addrs: vec![addr],
        host,
        cache_host,
        cache_port,
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
            let not_after_ts = cert.validity().not_after.timestamp();
            let not_after = format_time(not_after_ts);
            if index == 0 {
                stat.subject = Some(subject);
                stat.cert_not_before = Some(not_before);
                stat.cert_not_after = Some(not_after);
                stat.cert_not_after_unix = Some(not_after_ts);
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

/// Copy QUIC peer certificates onto `stat` when the handshake has produced
/// them. 0-RTT can return before the certificate is available.
pub(crate) fn capture_quic_certs(conn: &quinn::Connection, stat: &mut HttpStat) {
    if stat.subject.is_some() {
        return;
    }
    if let Some(peer_identity) = conn.peer_identity() {
        if let Ok(certs) = peer_identity.downcast::<Vec<CertificateDer<'static>>>() {
            parse_certificates(&certs, stat);
        }
    }
}

// Perform DNS resolution
pub(crate) async fn dns_resolve(req: &HttpRequest, stat: &mut HttpStat) -> Result<Resolved> {
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
        return Ok(literal_resolved(addr, host, lookup_host, port, stat));
    }

    if let Some(resolve) = &req.resolve {
        let addr = SocketAddr::new(*resolve, port);
        return Ok(literal_resolved(addr, host, lookup_host, port, stat));
    }

    let servers = cache_servers(req);
    if let Some(cache) = &req.dns_cache {
        if let Some(addrs) = cache.get(&lookup_host, port, &servers, req.ip_version.unwrap_or(0)) {
            stat.dns_cached = true;
            stat.dns_lookup = Some(Duration::ZERO);
            stat.dns_attempted = false;
            let winner = addrs[0];
            stat.addr = Some(winner.to_string());
            return Ok(Resolved {
                addrs: vec![winner],
                host,
                cache_host: lookup_host,
                cache_port: port,
            });
        }
    }

    // A real resolver runs from here on.
    stat.dns_attempted = true;

    let provider = TokioRuntimeProvider::default();
    let mut server_config: Option<ResolverConfig> = None;
    #[cfg(feature = "doh")]
    let mut secure: Option<SecureDns> = None;
    if let Some(dns_servers) = &req.dns_servers {
        let mut plain_ips: Vec<IpAddr> = vec![];
        for server in dns_servers {
            match server.as_str() {
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
                _ => {
                    #[cfg(feature = "doh")]
                    {
                        if let Some(dns) = SecureDns::parse(server) {
                            secure = Some(dns);
                            plain_ips.clear();
                            break;
                        }
                        // Written as a DoH/DoT URL but not usable as one:
                        // do not fall back to another resolver silently.
                        if SecureDns::is_url(server).is_some() {
                            return Err(Error::Common {
                                category: "dns".to_string(),
                                message: format!("invalid dns server {server}"),
                            });
                        }
                    }
                    if let Ok(addr) = server.parse::<IpAddr>() {
                        plain_ips.push(addr);
                    }
                }
            }
        }
        if !plain_ips.is_empty() && server_config.is_none() {
            #[cfg(feature = "doh")]
            let preset_chosen = secure.is_some();
            #[cfg(not(feature = "doh"))]
            let preset_chosen = false;
            if !preset_chosen {
                let servers: Vec<NameServerConfig> = plain_ips
                    .into_iter()
                    .map(NameServerConfig::udp_and_tcp)
                    .collect();
                server_config = Some(ResolverConfig::from_parts(None, vec![], servers));
            }
        }
    }

    let dns_timeout = req.dns_timeout.unwrap_or(Duration::from_secs(5));
    let dns_start = Instant::now();

    #[cfg(feature = "doh")]
    if let Some(dns) = secure {
        return resolve_secure(
            req,
            stat,
            host,
            lookup_host,
            port,
            dns,
            dns_timeout,
            dns_start,
        )
        .await;
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

    let resolver = builder.build().map_err(|e| Error::Resolve { source: e })?;
    let lookup = timeout(dns_timeout, resolver.lookup_ip(&lookup_host))
        .await
        .map_err(|e| Error::Timeout { source: e })?
        .map_err(|e| Error::Resolve { source: e })?;
    stat.dns_lookup = Some(dns_start.elapsed());
    let until = lookup.valid_until();
    let ips: Vec<IpAddr> = lookup.iter().collect();
    finish_lookup(req, stat, host, lookup_host, port, ips, until)
}

#[cfg(feature = "doh")]
#[allow(clippy::too_many_arguments)]
async fn resolve_secure(
    req: &HttpRequest,
    stat: &mut HttpStat,
    host: String,
    lookup_host: String,
    port: u16,
    dns: SecureDns,
    dns_timeout: Duration,
    dns_start: Instant,
) -> Result<Resolved> {
    let work = async {
        let tcp = match dns.ip {
            Some(ip) => TcpStream::connect((ip, dns.port)).await,
            None => TcpStream::connect((dns.host.as_str(), dns.port)).await,
        }
        .map_err(|e| Error::Io { source: e })?;
        let alpn = if dns.dot {
            vec![b"dot".to_vec()]
        } else {
            // RFC 8484 recommends HTTP/2, and some resolvers speak nothing
            // else.
            vec![b"h2".to_vec(), b"http/1.1".to_vec()]
        };
        let tls = tls_connect_stream(&dns.host, tcp, alpn, false, None).await?;
        let connect_at = dns_start.elapsed();
        let mut transport = if dns.dot {
            SecureTransport::Dot(tls)
        } else if tls.get_ref().1.alpn_protocol() == Some(b"h2") {
            let io: OriginIo = Box::new(tls);
            let (sender, conn) =
                hyper::client::conn::http2::handshake(TokioExecutor::new(), TokioIo::new(io))
                    .await
                    .map_err(|e| Error::Hyper { source: e })?;
            tokio::spawn(async move {
                let _ = conn.await;
            });
            SecureTransport::Doh2(sender)
        } else {
            SecureTransport::Doh1(tls)
        };
        let authority = dns.authority();
        let qtypes: Vec<u16> = match req.ip_version {
            Some(4) => vec![QTYPE_A],
            Some(6) => vec![QTYPE_AAAA],
            _ => vec![QTYPE_A, QTYPE_AAAA],
        };
        let mut records = Vec::new();
        let mut any_ok = false;
        let mut last_err: Option<Error> = None;
        for (i, qtype) in qtypes.into_iter().enumerate() {
            let query = encode_query((i as u16) + 1, &lookup_host, qtype);
            let result = match &mut transport {
                SecureTransport::Dot(tls) => dot_exchange(tls, &query).await,
                SecureTransport::Doh1(tls) => {
                    doh_exchange(tls, &authority, &dns.path, &query).await
                }
                SecureTransport::Doh2(sender) => {
                    doh2_exchange(sender, &authority, &dns.path, &query).await
                }
            };
            match result {
                Ok(msg) => match parse_records(&msg) {
                    Ok(recs) => {
                        any_ok = true;
                        records.extend(recs);
                    }
                    Err(e) => {
                        last_err = Some(Error::Common {
                            category: "dns".to_string(),
                            message: e,
                        });
                    }
                },
                Err(e) => last_err = Some(e),
            }
        }
        if !any_ok {
            return Err(last_err.unwrap_or(Error::Common {
                category: "dns".to_string(),
                message: "dns lookup failed".to_string(),
            }));
        }
        Ok((connect_at, records))
    };

    let (connect_at, records) = timeout(dns_timeout, work)
        .await
        .map_err(|e| Error::Timeout { source: e })??;
    stat.dns_connect = Some(connect_at);
    stat.dns_lookup = Some(dns_start.elapsed());
    if records.is_empty() {
        return Err(Error::Common {
            category: "http".to_string(),
            message: "dns lookup failed".to_string(),
        });
    }
    let min_ttl = records.iter().map(|r| r.ttl).min().unwrap_or(1).max(1);
    let ips = records.into_iter().map(|r| r.addr).collect();
    let until = Instant::now() + Duration::from_secs(min_ttl as u64);
    finish_lookup(req, stat, host, lookup_host, port, ips, until)
}

/// The connection to a DoH/DoT resolver once TLS is up.
#[cfg(feature = "doh")]
enum SecureTransport {
    Dot(TlsStream<TcpStream>),
    /// DoH over HTTP/1.1, for a resolver that does not negotiate `h2`.
    Doh1(TlsStream<TcpStream>),
    Doh2(hyper::client::conn::http2::SendRequest<TrackedBody>),
}

/// One DoH query over HTTP/2.
#[cfg(feature = "doh")]
async fn doh2_exchange(
    sender: &mut hyper::client::conn::http2::SendRequest<TrackedBody>,
    authority: &str,
    path: &str,
    query: &[u8],
) -> Result<Vec<u8>> {
    let (body, _) = TrackedBody::new(bytes::Bytes::copy_from_slice(query));
    let request = http::Request::post(format!("https://{authority}{path}"))
        .header(http::header::CONTENT_TYPE, "application/dns-message")
        .header(http::header::ACCEPT, "application/dns-message")
        .body(body)
        .map_err(|e| Error::Http { source: e })?;
    sender
        .ready()
        .await
        .map_err(|e| Error::Hyper { source: e })?;
    let response = sender
        .send_request(request)
        .await
        .map_err(|e| Error::Hyper { source: e })?;
    if response.status() != http::StatusCode::OK {
        return Err(Error::Common {
            category: "dns".to_string(),
            message: format!("doh status {}", response.status().as_u16()),
        });
    }
    let mut body = response.into_body();
    let mut message = Vec::new();
    while let Some(frame) = body.frame().await {
        let frame = frame.map_err(|e| Error::Hyper { source: e })?;
        if let Ok(data) = frame.into_data() {
            message.extend_from_slice(&data);
            // A DNS message is at most 65535 bytes.
            if message.len() > usize::from(u16::MAX) {
                return Err(Error::Common {
                    category: "dns".to_string(),
                    message: "doh response too large".to_string(),
                });
            }
        }
    }
    Ok(message)
}

#[cfg(feature = "doh")]
async fn doh_exchange<S>(stream: &mut S, host: &str, path: &str, query: &[u8]) -> Result<Vec<u8>>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let req = format!(
        "POST {path} HTTP/1.1\r\nHost: {host}\r\nContent-Type: application/dns-message\r\nAccept: application/dns-message\r\nContent-Length: {}\r\nConnection: keep-alive\r\n\r\n",
        query.len()
    );
    stream
        .write_all(req.as_bytes())
        .await
        .map_err(|e| Error::Io { source: e })?;
    stream
        .write_all(query)
        .await
        .map_err(|e| Error::Io { source: e })?;

    let mut header = Vec::with_capacity(256);
    let mut byte = [0u8; 1];
    loop {
        stream
            .read_exact(&mut byte)
            .await
            .map_err(|e| Error::Io { source: e })?;
        header.push(byte[0]);
        if header.ends_with(b"\r\n\r\n") {
            break;
        }
        if header.len() > 8192 {
            return Err(Error::Common {
                category: "dns".to_string(),
                message: "doh response header too large".to_string(),
            });
        }
    }
    let text = String::from_utf8_lossy(&header);
    let status = text
        .lines()
        .next()
        .and_then(|l| l.split_whitespace().nth(1))
        .and_then(|s| s.parse::<u16>().ok())
        .unwrap_or(0);
    if status != 200 {
        return Err(Error::Common {
            category: "dns".to_string(),
            message: format!("doh status {status}"),
        });
    }
    let mut length: Option<usize> = None;
    let mut chunked = false;
    for line in text.lines().skip(1) {
        let Some((name, value)) = line.split_once(':') else {
            continue;
        };
        if name.eq_ignore_ascii_case("content-length") {
            length = value.trim().parse().ok();
        } else if name.eq_ignore_ascii_case("transfer-encoding")
            && value.to_ascii_lowercase().contains("chunked")
        {
            chunked = true;
        }
    }
    if chunked {
        return Err(Error::Common {
            category: "dns".to_string(),
            message: "doh response used chunked encoding".to_string(),
        });
    }
    let Some(length) = length else {
        return Err(Error::Common {
            category: "dns".to_string(),
            message: "doh response missing content-length".to_string(),
        });
    };
    let mut body = vec![0u8; length];
    stream
        .read_exact(&mut body)
        .await
        .map_err(|e| Error::Io { source: e })?;
    Ok(body)
}

#[cfg(feature = "doh")]
async fn dot_exchange<S>(stream: &mut S, query: &[u8]) -> Result<Vec<u8>>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    if query.len() > u16::MAX as usize {
        return Err(Error::Common {
            category: "dns".to_string(),
            message: "dot query too large".to_string(),
        });
    }
    let len = (query.len() as u16).to_be_bytes();
    stream
        .write_all(&len)
        .await
        .map_err(|e| Error::Io { source: e })?;
    stream
        .write_all(query)
        .await
        .map_err(|e| Error::Io { source: e })?;
    let mut len_buf = [0u8; 2];
    stream
        .read_exact(&mut len_buf)
        .await
        .map_err(|e| Error::Io { source: e })?;
    let n = u16::from_be_bytes(len_buf) as usize;
    let mut body = vec![0u8; n];
    stream
        .read_exact(&mut body)
        .await
        .map_err(|e| Error::Io { source: e })?;
    Ok(body)
}

fn filter_bind(mut addrs: Vec<SocketAddr>, bind_addr: Option<IpAddr>) -> Vec<SocketAddr> {
    if let Some(bind) = bind_addr {
        addrs.retain(|a| a.is_ipv6() == bind.is_ipv6());
    }
    addrs
}

// Establish TCP connection. Multiple addresses are raced (RFC 8305).
//
// Returns the live `TcpStream`, an optional [`TcpInfoProbe`], and the address
// that won. `stat.tcp_connect` is the wall time of the race.
pub(crate) async fn tcp_connect(
    addrs: Vec<SocketAddr>,
    tcp_timeout: Option<Duration>,
    bind_addr: Option<IpAddr>,
    stat: &mut HttpStat,
) -> Result<(TcpStream, Option<TcpInfoProbe>, SocketAddr)> {
    let addrs = filter_bind(addrs, bind_addr);
    if addrs.is_empty() {
        return Err(Error::Common {
            category: "tcp".to_string(),
            message: "no address matches --bind".to_string(),
        });
    }
    let tcp_start = Instant::now();
    let overall = tcp_timeout.unwrap_or(Duration::from_secs(5));
    // One outer timeout. Per-attempt timers would be shorter than the 250 ms
    // stagger and would retire a candidate before the next one starts.
    let (winner, tcp_stream) = timeout(overall, race_tcp_inner(addrs, bind_addr))
        .await
        .map_err(|e| Error::Timeout { source: e })?
        .map_err(|e| Error::Io { source: e })?;
    stat.tcp_connect = Some(tcp_start.elapsed());
    stat.addr = Some(winner.to_string());
    let (baseline, probe) = TcpInfoProbe::capture(&tcp_stream);
    stat.tcp_info_post_connect = baseline;
    Ok((tcp_stream, probe, winner))
}

static ROOTS: OnceLock<Arc<RootCertStore>> = OnceLock::new();

/// The platform trust store, read once per process. Reading it is slow
/// (about 80 ms on macOS), so callers fetch it before they start a phase
/// timer.
fn root_store() -> Arc<RootCertStore> {
    ROOTS
        .get_or_init(|| {
            let mut roots = RootCertStore::empty();
            for cert in rustls_native_certs::load_native_certs().certs {
                let _ = roots.add(cert);
            }
            Arc::new(roots)
        })
        .clone()
}

/// Whether `req` opens a TLS or QUIC session: to the origin, to an
/// `https://` proxy, or to a DoH/DoT resolver.
fn uses_tls(req: &HttpRequest) -> bool {
    #[cfg(feature = "doh")]
    let secure_dns = req
        .dns_servers
        .iter()
        .flatten()
        .any(|s| SecureDns::parse(s).is_some());
    #[cfg(not(feature = "doh"))]
    let secure_dns = false;
    matches!(req.uri.scheme_str(), Some("https" | "grpcs"))
        || req.alpn_protocols.iter().any(|p| p == ALPN_HTTP3)
        || req
            .proxy
            .as_deref()
            .and_then(ProxyConfig::parse)
            .is_some_and(|p| p.tls)
        || secure_dns
}

/// Read the trust store ahead of a request that needs it, so the cost stays
/// out of `total` as well as out of the individual phases.
pub(crate) fn preload_roots(req: &HttpRequest) {
    if uses_tls(req) {
        root_store();
    }
}

fn client_auth(
    builder: rustls::ConfigBuilder<ClientConfig, rustls::client::WantsClientCert>,
    cert_pem: Option<&[u8]>,
    key_pem: Option<&[u8]>,
) -> Result<ClientConfig> {
    if let (Some(cert_pem), Some(key_pem)) = (cert_pem, key_pem) {
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
            .map_err(|e| Error::Rustls { source: e })
    } else {
        Ok(builder.with_no_client_auth())
    }
}

/// TLS to a proxy or a DoH/DoT server. Does not write origin certificate
/// fields into `stat`.
pub(crate) async fn tls_connect_stream<S>(
    host: &str,
    stream: S,
    alpn: Vec<Vec<u8>>,
    skip_verify: bool,
    tls_timeout: Option<Duration>,
) -> Result<TlsStream<S>>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    ensure_crypto_provider();
    let builder = ClientConfig::builder().with_root_certificates(root_store());
    let mut config = builder.with_no_client_auth();
    if skip_verify {
        config
            .dangerous()
            .set_certificate_verifier(Arc::new(SkipVerifier));
    }
    config.alpn_protocols = alpn;
    let connector = TlsConnector::from(Arc::new(config));
    let name = host
        .to_string()
        .try_into()
        .map_err(|e| Error::InvalidDnsName { source: e })?;
    let handshake = connector.connect(name, stream);
    let tls = if let Some(limit) = tls_timeout {
        timeout(limit, handshake)
            .await
            .map_err(|e| Error::Timeout { source: e })?
    } else {
        handshake.await
    }
    .map_err(|e| Error::Io { source: e })?;
    Ok(tls)
}

// Perform TLS handshake
pub(crate) async fn tls_handshake<S>(
    host: String,
    tcp_stream: S,
    http_req: &HttpRequest,
    stat: &mut HttpStat,
) -> Result<(TlsStream<S>, bool)>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    ensure_crypto_provider();
    // Fetched before the clock starts: reading the trust store is not part
    // of the handshake.
    let roots = root_store();
    let tls_start = Instant::now();
    let builder = ClientConfig::builder().with_root_certificates(roots.clone());
    let mut config = client_auth(
        builder,
        http_req.client_cert.as_deref(),
        http_req.client_key.as_deref(),
    )?;

    let ocsp_handle: Option<Arc<std::sync::OnceLock<bool>>> = if http_req.skip_verify {
        config
            .dangerous()
            .set_certificate_verifier(Arc::new(SkipVerifier));
        None
    } else {
        let inner = WebPkiServerVerifier::builder(roots)
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

    config.enable_early_data = true;
    if let Some(store) = &http_req.tls_session_store {
        config.resumption = Resumption::store(store.clone());
    }

    config.alpn_protocols = http_req
        .alpn_protocols
        .iter()
        .map(|s| s.as_bytes().to_vec())
        .collect();

    let connector = TlsConnector::from(Arc::new(config));
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

    let (_, session) = tls_stream.get_ref();

    stat.tls = session
        .protocol_version()
        .map(|v| format_tls_protocol(v.as_str().unwrap_or_default()));

    stat.tls_resumed = session
        .handshake_kind()
        .map(|k| matches!(k, HandshakeKind::Resumed));
    if matches!(stat.tls_resumed, Some(true)) {
        stat.tls_early_data_accepted = Some(session.is_early_data_accepted());
    }
    if let Some(handle) = &ocsp_handle {
        stat.tls_ocsp_stapled = handle.get().copied();
    }

    if let Some(certs) = session.peer_certificates() {
        parse_certificates(certs, stat);
    }

    if let Some(cipher) = session.negotiated_cipher_suite() {
        let cipher = format!("{cipher:?}");
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

/// A QUIC connection plus the endpoint that owns its socket.
///
/// `early` is set only for the single-address 0-RTT path. Await it after
/// `stat.total` is recorded; `Ok` from `into_0rtt` is not a completed handshake.
pub(crate) struct QuicConnect {
    pub endpoint: quinn::Endpoint,
    pub conn: quinn::Connection,
    pub early: Option<quinn::ZeroRttAccepted>,
}

fn quic_client_config(
    http_req: &HttpRequest,
    roots: Arc<RootCertStore>,
) -> Result<quinn::ClientConfig> {
    ensure_crypto_provider();
    let builder = ClientConfig::builder().with_root_certificates(roots);
    let mut config = client_auth(
        builder,
        http_req.client_cert.as_deref(),
        http_req.client_key.as_deref(),
    )?;
    config.enable_early_data = true;
    if let Some(store) = &http_req.tls_session_store {
        config.resumption = Resumption::store(store.clone());
    }
    config.alpn_protocols = vec![ALPN_HTTP3.as_bytes().to_vec()];
    if http_req.skip_verify {
        config
            .dangerous()
            .set_certificate_verifier(Arc::new(SkipVerifier));
    }
    let h3_config =
        quinn::crypto::rustls::QuicClientConfig::try_from(config).map_err(|e| Error::Common {
            category: "quic".to_string(),
            message: e.to_string(),
        })?;
    Ok(quinn::ClientConfig::new(Arc::new(h3_config)))
}

fn bind_endpoint(
    v6: bool,
    bind: Option<IpAddr>,
    config: quinn::ClientConfig,
) -> Result<quinn::Endpoint> {
    let addr: SocketAddr = match bind {
        Some(ip) => SocketAddr::new(ip, 0),
        None if v6 => "[::]:0".parse().unwrap(),
        None => "0.0.0.0:0".parse().unwrap(),
    };
    let mut endpoint = quinn::Endpoint::client(addr).map_err(|e| Error::Io { source: e })?;
    endpoint.set_default_client_config(config);
    Ok(endpoint)
}

fn start_quic(
    endpoint: &quinn::Endpoint,
    addr: SocketAddr,
    host: &str,
) -> Result<quinn::Connecting> {
    endpoint
        .connect(addr, host)
        .map_err(|e| Error::QuicConnect { source: e })
}

fn family_endpoint<'a>(
    addr: SocketAddr,
    ep4: &'a Option<quinn::Endpoint>,
    ep6: &'a Option<quinn::Endpoint>,
) -> &'a quinn::Endpoint {
    if addr.is_ipv6() {
        ep6.as_ref().expect("v6 endpoint")
    } else {
        ep4.as_ref().expect("v4 endpoint")
    }
}

async fn finish_quic(
    addr: SocketAddr,
    connecting: quinn::Connecting,
) -> Result<(SocketAddr, quinn::Connection)> {
    let conn = connecting
        .await
        .map_err(|e| Error::QuicConnection { source: e })?;
    Ok((addr, conn))
}

async fn race_quic(
    host: &str,
    addrs: Vec<SocketAddr>,
    config: quinn::ClientConfig,
    bind: Option<IpAddr>,
) -> Result<(quinn::Endpoint, quinn::Connection, SocketAddr)> {
    let addrs = happy::interleave(addrs);
    let need_v4 = addrs.iter().any(|a| a.is_ipv4());
    let need_v6 = addrs.iter().any(|a| a.is_ipv6());
    let ep4 = if need_v4 {
        Some(bind_endpoint(false, bind, config.clone())?)
    } else {
        None
    };
    let ep6 = if need_v6 {
        Some(bind_endpoint(true, bind, config)?)
    } else {
        None
    };

    let mut pending: VecDeque<SocketAddr> = addrs.into();
    let mut inflight = FuturesUnordered::new();
    let first = pending.pop_front().ok_or(Error::Common {
        category: "quic".to_string(),
        message: "dns lookup returned no address".to_string(),
    })?;
    let connecting = start_quic(family_endpoint(first, &ep4, &ep6), first, host)?;
    inflight.push(finish_quic(first, connecting));

    let mut stagger = Box::pin(tokio::time::sleep(Duration::from_millis(250)));
    let mut last_err = Error::Common {
        category: "quic".to_string(),
        message: "quic connect failed".to_string(),
    };
    let (winner, conn) = loop {
        tokio::select! {
            _ = &mut stagger, if !pending.is_empty() => {
                if let Some(addr) = pending.pop_front() {
                    match start_quic(family_endpoint(addr, &ep4, &ep6), addr, host) {
                        Ok(connecting) => {
                            inflight.push(finish_quic(addr, connecting));
                        }
                        Err(e) => {
                            last_err = e;
                            if inflight.is_empty() && pending.is_empty() {
                                return Err(last_err);
                            }
                        }
                    }
                }
                stagger = Box::pin(tokio::time::sleep(Duration::from_millis(250)));
            }
            done = inflight.next(), if !inflight.is_empty() => {
                match done {
                    Some(Ok(pair)) => break pair,
                    Some(Err(err)) => {
                        last_err = err;
                        if inflight.is_empty() && pending.is_empty() {
                            return Err(last_err);
                        }
                    }
                    None => return Err(last_err),
                }
            }
        }
    };

    let endpoint = if winner.is_ipv6() {
        drop(ep4);
        ep6.expect("v6 endpoint")
    } else {
        drop(ep6);
        ep4.expect("v4 endpoint")
    };
    Ok((endpoint, conn, winner))
}

// Establish a QUIC connection. Full handshakes are raced across addresses.
// 0-RTT is used only when a single address remains: `into_0rtt` succeeds
// locally and would otherwise win the race against a blackholed path.
pub(crate) async fn quic_connect(
    host: String,
    addrs: Vec<SocketAddr>,
    http_req: &HttpRequest,
    stat: &mut HttpStat,
) -> Result<QuicConnect> {
    // Fetched before the clock starts: reading the trust store is not part
    // of the connection.
    let roots = root_store();
    let quic_start = Instant::now();
    let overall = http_req.quic_timeout.unwrap_or(Duration::from_secs(30));
    let addrs = filter_bind(addrs, http_req.bind_addr);
    if addrs.is_empty() {
        return Err(Error::Common {
            category: "quic".to_string(),
            message: "no address matches --bind".to_string(),
        });
    }
    let config = quic_client_config(http_req, roots)?;
    stat.tls = Some("tls 1.3".to_string());
    stat.alpn = Some(ALPN_HTTP3.to_string());

    let connected = if addrs.len() == 1 {
        let addr = addrs[0];
        let endpoint = bind_endpoint(addr.is_ipv6(), http_req.bind_addr, config)?;
        let connecting = start_quic(&endpoint, addr, &host)?;
        match connecting.into_0rtt() {
            Ok((conn, accepted)) => {
                stat.tls_resumed = Some(true);
                stat.quic_connect = Some(quic_start.elapsed());
                stat.addr = Some(addr.to_string());
                capture_quic_certs(&conn, stat);
                return Ok(QuicConnect {
                    endpoint,
                    conn,
                    early: Some(accepted),
                });
            }
            Err(connecting) => {
                let conn = timeout(overall, connecting)
                    .await
                    .map_err(|e| Error::Timeout { source: e })?
                    .map_err(|e| Error::QuicConnection { source: e })?;
                (endpoint, conn, addr, false)
            }
        }
    } else {
        let (endpoint, conn, addr) =
            timeout(overall, race_quic(&host, addrs, config, http_req.bind_addr))
                .await
                .map_err(|e| Error::Timeout { source: e })??;
        (endpoint, conn, addr, false)
    };

    let (endpoint, conn, addr, _resumed) = connected;
    stat.tls_resumed = Some(false);
    stat.quic_connect = Some(quic_start.elapsed());
    stat.addr = Some(addr.to_string());
    capture_quic_certs(&conn, stat);
    Ok(QuicConnect {
        endpoint,
        conn,
        early: None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn req(url: &str) -> HttpRequest {
        HttpRequest::try_from(url).unwrap()
    }

    #[test]
    fn root_store_is_read_once() {
        assert!(Arc::ptr_eq(&root_store(), &root_store()));
    }

    #[test]
    fn uses_tls_follows_the_origin_scheme() {
        assert!(uses_tls(&req("https://example.com/")));
        assert!(uses_tls(&req("grpcs://example.com/")));
        assert!(!uses_tls(&req("http://example.com/")));
        assert!(!uses_tls(&req("grpc://example.com/")));
    }

    #[test]
    fn uses_tls_for_http3() {
        let mut http3 = req("http://example.com/");
        http3.alpn_protocols = vec![ALPN_HTTP3.to_string()];
        assert!(uses_tls(&http3));
    }

    #[test]
    fn uses_tls_for_an_https_proxy_only() {
        let mut proxied = req("http://example.com/");
        proxied.proxy = Some("https://proxy.local:8443".to_string());
        assert!(uses_tls(&proxied));
        for plain in ["http://proxy.local:8080", "socks5://proxy.local:1080"] {
            proxied.proxy = Some(plain.to_string());
            assert!(!uses_tls(&proxied), "{plain}");
        }
    }

    #[test]
    fn uses_tls_for_secure_dns_presets() {
        let mut dns = req("http://example.com/");
        dns.dns_servers = Some(vec!["1.1.1.1".to_string(), "cloudflare".to_string()]);
        assert!(!uses_tls(&dns));
        for secure in [
            "cloudflare-doh",
            "quad9-dot",
            "https://dns.example.com/dns-query",
            "tls://dns.example.com",
        ] {
            dns.dns_servers = Some(vec![secure.to_string()]);
            assert_eq!(uses_tls(&dns), cfg!(feature = "doh"), "{secure}");
        }
    }

    #[cfg(feature = "doh")]
    #[test]
    fn secure_dns_presets_pin_an_address() {
        let doh = SecureDns::parse("google-doh").unwrap();
        assert_eq!(
            doh,
            SecureDns {
                host: "dns.google".to_string(),
                ip: Some(IpAddr::from([8, 8, 8, 8])),
                port: 443,
                path: "/dns-query".to_string(),
                dot: false,
            }
        );
        let dot = SecureDns::parse("quad9-dot").unwrap();
        assert_eq!(
            (dot.host.as_str(), dot.ip, dot.port, dot.dot),
            ("dns.quad9.net", Some(IpAddr::from([9, 9, 9, 9])), 853, true)
        );
        for name in [
            "cloudflare-doh",
            "cloudflare-dot",
            "quad9-doh",
            "google-dot",
        ] {
            assert!(SecureDns::parse(name).is_some(), "{name}");
        }
    }

    #[cfg(feature = "doh")]
    #[test]
    fn secure_dns_parses_doh_urls() {
        let dns = SecureDns::parse("https://dns.example.com").unwrap();
        assert_eq!(
            (
                dns.host.as_str(),
                dns.ip,
                dns.port,
                dns.path.as_str(),
                dns.dot
            ),
            ("dns.example.com", None, 443, "/dns-query", false)
        );
        assert_eq!(dns.authority(), "dns.example.com");

        let dns = SecureDns::parse("https://my-doh.example.com:8443/custom/abc?x=1").unwrap();
        assert_eq!(
            (dns.host.as_str(), dns.port, dns.path.as_str()),
            ("my-doh.example.com", 8443, "/custom/abc?x=1")
        );
        assert_eq!(dns.authority(), "my-doh.example.com:8443");

        // An IP literal is dialed directly, with no lookup of its own.
        let dns = SecureDns::parse("https://1.1.1.1/dns-query").unwrap();
        assert_eq!(dns.ip, Some(IpAddr::from([1, 1, 1, 1])));
        let dns = SecureDns::parse("https://[2606:4700:4700::1111]/dns-query").unwrap();
        assert_eq!(dns.host, "2606:4700:4700::1111");
        assert!(dns.ip.is_some_and(|ip| ip.is_ipv6()));
        assert_eq!(dns.authority(), "[2606:4700:4700::1111]");
    }

    #[cfg(feature = "doh")]
    #[test]
    fn secure_dns_parses_dot_addresses() {
        let dns = SecureDns::parse("tls://dns.example.com").unwrap();
        assert_eq!(
            (dns.host.as_str(), dns.ip, dns.port, dns.dot),
            ("dns.example.com", None, 853, true)
        );
        let dns = SecureDns::parse("tls://9.9.9.9:8853").unwrap();
        assert_eq!(
            (dns.ip, dns.port, dns.dot),
            (Some(IpAddr::from([9, 9, 9, 9])), 8853, true)
        );
    }

    #[cfg(feature = "doh")]
    #[test]
    fn secure_dns_ignores_everything_else() {
        for server in [
            "google",
            "1.1.1.1",
            "unknown-doh",
            "http://dns.example.com/dns-query",
            "https://",
            "tls://",
            "",
        ] {
            assert_eq!(SecureDns::parse(server), None, "{server}");
        }
    }
}
