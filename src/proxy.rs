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
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

pub(crate) enum ProxyKind {
    Http,
    Socks5,
}

pub(crate) struct ProxyConfig {
    pub kind: ProxyKind,
    pub host: String,
    pub port: u16,
    pub username: Option<String>,
    pub password: Option<String>,
    /// `true` for an `https://` proxy: TLS to the proxy, then CONNECT.
    pub tls: bool,
}

impl ProxyConfig {
    /// Parse a proxy URL.
    ///
    /// Accepts `http://`, `https://`, `socks5://`, or a bare `host:port`.
    /// Userinfo (`user:pass@`) is percent-decoded and kept for proxy auth.
    pub fn parse(url: &str) -> Option<Self> {
        let url = url.trim();
        let (kind, tls, rest) = if let Some(r) = url.strip_prefix("socks5://") {
            (ProxyKind::Socks5, false, r)
        } else if let Some(r) = url.strip_prefix("https://") {
            (ProxyKind::Http, true, r)
        } else if let Some(r) = url.strip_prefix("http://") {
            (ProxyKind::Http, false, r)
        } else if let Some(r) = url.strip_prefix("socks5h://") {
            (ProxyKind::Socks5, false, r)
        } else {
            (ProxyKind::Http, false, url)
        };

        let host_port = rest.split(['/', '?', '#']).next().unwrap_or(rest);
        let (creds, host_port) = split_userinfo(host_port);

        let default_port: u16 = match kind {
            ProxyKind::Http => {
                if tls {
                    443
                } else {
                    8080
                }
            }
            ProxyKind::Socks5 => 1080,
        };

        let (host, port) = parse_host_port(host_port, default_port)?;
        if host.is_empty() {
            return None;
        }
        Some(ProxyConfig {
            kind,
            host,
            port,
            username: creds.as_ref().map(|(u, _)| u.clone()),
            password: creds.as_ref().map(|(_, p)| p.clone()),
            tls,
        })
    }
}

/// True when `NO_PROXY` / `no_proxy` says this origin should skip the proxy.
pub fn proxy_bypassed(host: &str, port: u16) -> bool {
    let raw = std::env::var("NO_PROXY")
        .or_else(|_| std::env::var("no_proxy"))
        .unwrap_or_default();
    no_proxy_matches(&raw, host, port)
}

/// curl-like matcher: `*` matches all; comma list; a leading dot is a suffix;
/// `host:port` also checks the port; a host pattern matches itself and any
/// subdomain.
pub fn no_proxy_matches(list: &str, host: &str, port: u16) -> bool {
    let host = host.trim().trim_end_matches('.').to_ascii_lowercase();
    if host.is_empty() {
        return false;
    }
    for item in list.split(',') {
        let item = item.trim();
        if item.is_empty() {
            continue;
        }
        if item == "*" {
            return true;
        }
        let (pattern, pat_port) = match item.rsplit_once(':') {
            Some((h, p)) if !h.is_empty() && !h.ends_with(']') && p.parse::<u16>().is_ok() => {
                (h, p.parse::<u16>().ok())
            }
            _ => (item, None),
        };
        if let Some(p) = pat_port {
            if p != port {
                continue;
            }
        }
        let pattern = pattern
            .trim()
            .trim_start_matches('[')
            .trim_end_matches(']')
            .trim_start_matches('.')
            .trim_end_matches('.')
            .to_ascii_lowercase();
        if pattern.is_empty() {
            continue;
        }
        if host == pattern || host.ends_with(&format!(".{pattern}")) {
            return true;
        }
    }
    false
}

fn split_userinfo(host_port: &str) -> (Option<(String, String)>, &str) {
    // The last '@' separates userinfo. An IPv6 host is bracketed and contains
    // no '@', so this does not split the address itself.
    let Some((userinfo, rest)) = host_port.rsplit_once('@') else {
        return (None, host_port);
    };
    if rest.is_empty() {
        return (None, host_port);
    }
    let userinfo = percent_decode(userinfo);
    let (user, pass) = match userinfo.split_once(':') {
        Some((u, p)) => (u.to_string(), percent_decode(p)),
        None => (userinfo, String::new()),
    };
    (Some((user, pass)), rest)
}

fn parse_host_port(host_port: &str, default_port: u16) -> Option<(String, u16)> {
    if host_port.starts_with('[') {
        let end = host_port.find(']')?;
        let host = host_port[1..end].to_string();
        let port = host_port
            .get(end + 2..)
            .filter(|s| !s.is_empty())
            .map(|s| s.parse().ok())
            .unwrap_or(Some(default_port))?;
        return Some((host, port));
    }
    if let Some((h, p)) = host_port.rsplit_once(':') {
        if let Ok(port) = p.parse::<u16>() {
            return Some((h.to_string(), port));
        }
    }
    Some((host_port.to_string(), default_port))
}

pub(crate) fn percent_decode(input: &str) -> String {
    let bytes = input.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            if let Ok(v) =
                u8::from_str_radix(std::str::from_utf8(&bytes[i + 1..i + 3]).unwrap_or(""), 16)
            {
                out.push(v);
                i += 3;
                continue;
            }
        }
        out.push(bytes[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

pub(crate) fn basic_auth_header(username: &str, password: &str) -> String {
    let raw = format!("{username}:{password}");
    format!("Basic {}", base64_encode(raw.as_bytes()))
}

fn base64_encode(data: &[u8]) -> String {
    const TABLE: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(data.len().div_ceil(3) * 4);
    let mut i = 0;
    while i + 3 <= data.len() {
        let n = ((data[i] as u32) << 16) | ((data[i + 1] as u32) << 8) | data[i + 2] as u32;
        out.push(TABLE[((n >> 18) & 0x3f) as usize] as char);
        out.push(TABLE[((n >> 12) & 0x3f) as usize] as char);
        out.push(TABLE[((n >> 6) & 0x3f) as usize] as char);
        out.push(TABLE[(n & 0x3f) as usize] as char);
        i += 3;
    }
    match data.len() - i {
        1 => {
            let n = (data[i] as u32) << 16;
            out.push(TABLE[((n >> 18) & 0x3f) as usize] as char);
            out.push(TABLE[((n >> 12) & 0x3f) as usize] as char);
            out.push('=');
            out.push('=');
        }
        2 => {
            let n = ((data[i] as u32) << 16) | ((data[i + 1] as u32) << 8);
            out.push(TABLE[((n >> 18) & 0x3f) as usize] as char);
            out.push(TABLE[((n >> 12) & 0x3f) as usize] as char);
            out.push(TABLE[((n >> 6) & 0x3f) as usize] as char);
            out.push('=');
        }
        _ => {}
    }
    out
}

pub(crate) fn host_header(host: &str, port: u16) -> String {
    if host.contains(':') {
        format!("[{host}]:{port}")
    } else {
        format!("{host}:{port}")
    }
}

/// SOCKS5 CONNECT. Offers username/password (RFC 1929) when credentials are
/// present, and no-auth otherwise. The server picks.
pub(crate) async fn socks5_connect<S>(
    mut stream: S,
    target_host: &str,
    target_port: u16,
    username: Option<&str>,
    password: Option<&str>,
) -> Result<S>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let have_creds = username.is_some();
    if have_creds {
        stream
            .write_all(&[0x05, 0x02, 0x00, 0x02])
            .await
            .map_err(|e| Error::Io { source: e })?;
    } else {
        stream
            .write_all(&[0x05, 0x01, 0x00])
            .await
            .map_err(|e| Error::Io { source: e })?;
    }

    let mut buf = [0u8; 2];
    stream
        .read_exact(&mut buf)
        .await
        .map_err(|e| Error::Io { source: e })?;
    if buf[0] != 0x05 {
        return Err(Error::Common {
            category: "socks5".to_string(),
            message: "socks5 auth negotiation failed".to_string(),
        });
    }
    match buf[1] {
        0x00 => {}
        0x02 if have_creds => {
            let user = username.unwrap_or("");
            let pass = password.unwrap_or("");
            if user.len() > 255 || pass.len() > 255 {
                return Err(Error::Common {
                    category: "socks5".to_string(),
                    message: "socks5 username or password is longer than 255 bytes".to_string(),
                });
            }
            let mut auth = Vec::with_capacity(3 + user.len() + pass.len());
            auth.push(0x01);
            auth.push(user.len() as u8);
            auth.extend_from_slice(user.as_bytes());
            auth.push(pass.len() as u8);
            auth.extend_from_slice(pass.as_bytes());
            stream
                .write_all(&auth)
                .await
                .map_err(|e| Error::Io { source: e })?;
            let mut status = [0u8; 2];
            stream
                .read_exact(&mut status)
                .await
                .map_err(|e| Error::Io { source: e })?;
            if status[1] != 0x00 {
                return Err(Error::Common {
                    category: "socks5".to_string(),
                    message: "socks5 username/password rejected".to_string(),
                });
            }
        }
        0xff => {
            return Err(Error::Common {
                category: "socks5".to_string(),
                message: "socks5 proxy requires authentication".to_string(),
            });
        }
        other => {
            return Err(Error::Common {
                category: "socks5".to_string(),
                message: format!("socks5 auth negotiation failed: method {other:#04x}"),
            });
        }
    }

    let host_bytes = target_host.as_bytes();
    if host_bytes.len() > 255 {
        return Err(Error::Common {
            category: "socks5".to_string(),
            message: format!(
                "target host too long for socks5 domain addressing ({} bytes, max 255)",
                host_bytes.len()
            ),
        });
    }
    let mut req = vec![0x05, 0x01, 0x00, 0x03, host_bytes.len() as u8];
    req.extend_from_slice(host_bytes);
    req.push((target_port >> 8) as u8);
    req.push((target_port & 0xff) as u8);
    stream
        .write_all(&req)
        .await
        .map_err(|e| Error::Io { source: e })?;

    let mut header = [0u8; 4];
    stream
        .read_exact(&mut header)
        .await
        .map_err(|e| Error::Io { source: e })?;
    if header[0] != 0x05 {
        return Err(Error::Common {
            category: "socks5".to_string(),
            message: "invalid socks5 response version".to_string(),
        });
    }
    if header[1] != 0x00 {
        let msg = match header[1] {
            0x01 => "general failure",
            0x02 => "connection not allowed by ruleset",
            0x03 => "network unreachable",
            0x04 => "host unreachable",
            0x05 => "connection refused",
            0x06 => "TTL expired",
            0x07 => "command not supported",
            0x08 => "address type not supported",
            _ => "unknown error",
        };
        return Err(Error::Common {
            category: "socks5".to_string(),
            message: format!("socks5 connect failed: {msg}"),
        });
    }

    let addr_len = match header[3] {
        0x01 => 4 + 2,
        0x04 => 16 + 2,
        0x03 => {
            let mut len = [0u8; 1];
            stream
                .read_exact(&mut len)
                .await
                .map_err(|e| Error::Io { source: e })?;
            len[0] as usize + 2
        }
        _ => {
            return Err(Error::Common {
                category: "socks5".to_string(),
                message: "unknown socks5 bound address type".to_string(),
            })
        }
    };
    let mut drain = vec![0u8; addr_len];
    stream
        .read_exact(&mut drain)
        .await
        .map_err(|e| Error::Io { source: e })?;
    Ok(stream)
}

/// HTTP CONNECT. `authorization` is a full header value (`Basic ...`) when
/// the proxy URL carried userinfo.
pub(crate) async fn http_connect<S>(
    mut stream: S,
    target_host: &str,
    target_port: u16,
    authorization: Option<&str>,
) -> Result<S>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let target = host_header(target_host, target_port);
    let auth = match authorization {
        Some(v) => format!("Proxy-Authorization: {v}\r\n"),
        None => String::new(),
    };
    let msg = format!(
        "CONNECT {target} HTTP/1.1\r\nHost: {target}\r\n{auth}Proxy-Connection: keep-alive\r\n\r\n"
    );
    stream
        .write_all(msg.as_bytes())
        .await
        .map_err(|e| Error::Io { source: e })?;

    let mut response: Vec<u8> = Vec::with_capacity(256);
    let mut byte = [0u8; 1];
    loop {
        stream
            .read_exact(&mut byte)
            .await
            .map_err(|e| Error::Io { source: e })?;
        response.push(byte[0]);
        if response.ends_with(b"\r\n\r\n") {
            break;
        }
        if response.len() > 8192 {
            return Err(Error::Common {
                category: "proxy".to_string(),
                message: "proxy CONNECT response too large".to_string(),
            });
        }
    }

    let status = response
        .split(|&b| b == b'\n')
        .next()
        .and_then(|l| std::str::from_utf8(l).ok())
        .and_then(|l| l.split_ascii_whitespace().nth(1))
        .and_then(|s| s.parse::<u16>().ok())
        .unwrap_or(0);

    if status != 200 {
        let status_line =
            std::str::from_utf8(response.split(|&b| b == b'\n').next().unwrap_or(&[]))
                .unwrap_or_default()
                .trim()
                .to_string();
        return Err(Error::Common {
            category: "proxy".to_string(),
            message: format!("proxy CONNECT failed: {status_line}"),
        });
    }
    Ok(stream)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_schemes_and_ports() {
        let h = ProxyConfig::parse("http://127.0.0.1:3128").unwrap();
        assert!(matches!(h.kind, ProxyKind::Http));
        assert_eq!(h.host, "127.0.0.1");
        assert_eq!(h.port, 3128);
        assert!(!h.tls);

        let s = ProxyConfig::parse("socks5://localhost:1080").unwrap();
        assert!(matches!(s.kind, ProxyKind::Socks5));
        assert_eq!(s.port, 1080);

        let hs = ProxyConfig::parse("https://proxy:8443").unwrap();
        assert!(matches!(hs.kind, ProxyKind::Http));
        assert!(hs.tls);
        assert_eq!(hs.port, 8443);
    }

    #[test]
    fn parse_defaults_credentials_and_path() {
        let bare = ProxyConfig::parse("proxy.local").unwrap();
        assert!(matches!(bare.kind, ProxyKind::Http));
        assert_eq!(bare.host, "proxy.local");
        assert_eq!(bare.port, 8080);

        assert_eq!(ProxyConfig::parse("socks5://h").unwrap().port, 1080);

        let creds = ProxyConfig::parse("http://user:pass@host:3128").unwrap();
        assert_eq!(creds.host, "host");
        assert_eq!(creds.port, 3128);
        assert_eq!(creds.username.as_deref(), Some("user"));
        assert_eq!(creds.password.as_deref(), Some("pass"));

        let encoded = ProxyConfig::parse("http://us%65r:p%40ss@host:3128").unwrap();
        assert_eq!(encoded.username.as_deref(), Some("user"));
        assert_eq!(encoded.password.as_deref(), Some("p@ss"));

        let path = ProxyConfig::parse("http://host:3128/ignored").unwrap();
        assert_eq!(path.host, "host");
        assert_eq!(path.port, 3128);
    }

    #[test]
    fn parse_ipv6_bracketed() {
        let v6 = ProxyConfig::parse("http://[::1]:3128").unwrap();
        assert_eq!(v6.host, "::1");
        assert_eq!(v6.port, 3128);

        let v6d = ProxyConfig::parse("socks5://[::1]").unwrap();
        assert_eq!(v6d.host, "::1");
        assert_eq!(v6d.port, 1080);
    }

    #[test]
    fn no_proxy_matches_curl_rules() {
        assert!(no_proxy_matches("*", "example.com", 443));
        assert!(no_proxy_matches("example.com", "example.com", 443));
        assert!(no_proxy_matches("example.com", "www.example.com", 443));
        assert!(!no_proxy_matches("example.com", "notexample.com", 443));
        assert!(no_proxy_matches(".example.com", "a.example.com", 80));
        assert!(no_proxy_matches("example.com:443", "example.com", 443));
        assert!(!no_proxy_matches("example.com:443", "example.com", 80));
        assert!(no_proxy_matches(
            "127.0.0.1, example.com",
            "example.com",
            443
        ));
        assert!(!no_proxy_matches("other.com", "example.com", 443));
    }

    #[test]
    fn basic_auth_is_standard_base64() {
        assert_eq!(basic_auth_header("user", "pass"), "Basic dXNlcjpwYXNz");
    }
}
