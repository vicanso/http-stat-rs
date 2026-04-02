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
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

pub(crate) enum ProxyKind {
    Http,
    Socks5,
}

pub(crate) struct ProxyConfig {
    pub kind: ProxyKind,
    pub host: String,
    pub port: u16,
}

impl ProxyConfig {
    /// Parse a proxy URL.
    /// Accepts: `http://host:port`, `https://host:port`, `socks5://host:port`, or bare `host:port`.
    pub fn parse(url: &str) -> Option<Self> {
        let url = url.trim();
        let (kind, rest) = if let Some(r) = url.strip_prefix("socks5://") {
            (ProxyKind::Socks5, r)
        } else if let Some(r) = url.strip_prefix("https://") {
            (ProxyKind::Http, r)
        } else if let Some(r) = url.strip_prefix("http://") {
            (ProxyKind::Http, r)
        } else {
            (ProxyKind::Http, url)
        };

        // Strip any path, query, or fragment
        let host_port = rest.split('/').next().unwrap_or(rest);
        // Strip credentials (user:pass@host:port)
        let host_port = host_port.split('@').next_back().unwrap_or(host_port);

        let default_port: u16 = match kind {
            ProxyKind::Http => 8080,
            ProxyKind::Socks5 => 1080,
        };

        // Handle IPv6 bracketed address: [::1]:port
        if host_port.starts_with('[') {
            let end = host_port.find(']')?;
            let host = host_port[1..end].to_string();
            let port = host_port
                .get(end + 2..)
                .and_then(|s| s.parse().ok())
                .unwrap_or(default_port);
            return Some(ProxyConfig { kind, host, port });
        }

        if let Some((h, p)) = host_port.rsplit_once(':') {
            if let Ok(port) = p.parse::<u16>() {
                return Some(ProxyConfig {
                    kind,
                    host: h.to_string(),
                    port,
                });
            }
        }
        Some(ProxyConfig {
            kind,
            host: host_port.to_string(),
            port: default_port,
        })
    }
}

/// Perform SOCKS5 handshake (no-auth) to tunnel to `target_host:target_port`.
pub(crate) async fn socks5_connect(
    mut stream: TcpStream,
    target_host: &str,
    target_port: u16,
) -> Result<TcpStream> {
    // Greeting: version=5, nmethods=1, method=0x00 (no authentication)
    stream
        .write_all(&[0x05, 0x01, 0x00])
        .await
        .map_err(|e| Error::Io { source: e })?;

    let mut buf = [0u8; 2];
    stream
        .read_exact(&mut buf)
        .await
        .map_err(|e| Error::Io { source: e })?;
    if buf[0] != 0x05 || buf[1] != 0x00 {
        return Err(Error::Common {
            category: "socks5".to_string(),
            message: if buf[1] == 0xff {
                "socks5 proxy requires authentication".to_string()
            } else {
                format!("socks5 auth negotiation failed: method {:#04x}", buf[1])
            },
        });
    }

    // CONNECT request using domain name address type (0x03)
    let host_bytes = target_host.as_bytes();
    let mut req = vec![
        0x05,                   // version
        0x01,                   // command: CONNECT
        0x00,                   // reserved
        0x03,                   // address type: domain name
        host_bytes.len() as u8, // domain name length
    ];
    req.extend_from_slice(host_bytes);
    req.push((target_port >> 8) as u8);
    req.push((target_port & 0xff) as u8);
    stream
        .write_all(&req)
        .await
        .map_err(|e| Error::Io { source: e })?;

    // Response: VER, REP, RSV, ATYP
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

    // Drain the bound address field (length depends on ATYP)
    let addr_len = match header[3] {
        0x01 => 4 + 2,  // IPv4 (4 bytes) + port (2 bytes)
        0x04 => 16 + 2, // IPv6 (16 bytes) + port (2 bytes)
        0x03 => {
            let mut len = [0u8; 1];
            stream
                .read_exact(&mut len)
                .await
                .map_err(|e| Error::Io { source: e })?;
            len[0] as usize + 2 // domain length + port
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

/// Send an HTTP CONNECT request and wait for `200 Connection established`.
pub(crate) async fn http_connect(
    mut stream: TcpStream,
    target_host: &str,
    target_port: u16,
) -> Result<TcpStream> {
    let msg = format!(
        "CONNECT {target_host}:{target_port} HTTP/1.1\r\nHost: {target_host}:{target_port}\r\nProxy-Connection: keep-alive\r\n\r\n"
    );
    stream
        .write_all(msg.as_bytes())
        .await
        .map_err(|e| Error::Io { source: e })?;

    // Read until end of response headers (\r\n\r\n)
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

    // Parse status code from first line
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
