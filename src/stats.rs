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

use bytes::Bytes;
use bytesize::ByteSize;
use heck::ToTrainCase;
use http::HeaderMap;
use http::HeaderValue;
use http::StatusCode;
use nu_ansi_term::Color::{LightCyan, LightGreen, LightRed};
use std::fmt;
use std::time::Duration;
use unicode_truncate::Alignment;
use unicode_truncate::UnicodeTruncateStr;

pub static ALPN_HTTP2: &str = "h2";
pub static ALPN_HTTP1: &str = "http/1.1";
pub static ALPN_HTTP3: &str = "h3";

fn format_duration(duration: Duration) -> String {
    if duration > Duration::from_secs(1) {
        return format!("{:.2}s", duration.as_secs_f64());
    }
    if duration > Duration::from_millis(1) {
        return format!("{}ms", duration.as_millis());
    }
    format!("{}µs", duration.as_micros())
}

struct Timeline {
    name: String,
    duration: Duration,
}

/// Statistics and information collected during an HTTP request.
///
/// This struct contains timing information for each phase of the request,
/// connection details, TLS information, and response data.
///
/// # Fields
///
/// * `dns_lookup` - Time taken for DNS resolution
/// * `quic_connect` - Time taken to establish QUIC connection (for HTTP/3)
/// * `tcp_connect` - Time taken to establish TCP connection
/// * `tls_handshake` - Time taken for TLS handshake (for HTTPS)
/// * `server_processing` - Time taken for server to process the request
/// * `content_transfer` - Time taken to transfer the response body
/// * `total` - Total time taken for the entire request
/// * `addr` - Resolved IP address and port
/// * `status` - HTTP response status code
/// * `tls` - TLS protocol version used
/// * `alpn` - Application-Layer Protocol Negotiation (ALPN) protocol selected
/// * `cert_not_before` - Certificate validity start time
/// * `cert_not_after` - Certificate validity end time
/// * `cert_cipher` - TLS cipher suite used
/// * `cert_domains` - List of domains in the certificate's Subject Alternative Names
/// * `body` - Response body content
/// * `headers` - Response headers
/// * `error` - Any error that occurred during the request
#[derive(Default, Debug)]
pub struct HttpStat {
    pub request_headers: HeaderMap<HeaderValue>,
    pub dns_lookup: Option<Duration>,
    pub quic_connect: Option<Duration>,
    pub tcp_connect: Option<Duration>,
    pub tls_handshake: Option<Duration>,
    pub server_processing: Option<Duration>,
    pub content_transfer: Option<Duration>,
    pub total: Option<Duration>,
    pub addr: Option<String>,
    pub status: Option<StatusCode>,
    pub tls: Option<String>,
    pub alpn: Option<String>,
    pub subject: Option<String>,
    pub issuer: Option<String>,
    pub cert_not_before: Option<String>,
    pub cert_not_after: Option<String>,
    pub cert_cipher: Option<String>,
    pub cert_domains: Option<Vec<String>>,
    pub body: Option<Bytes>,
    pub body_size: Option<usize>,
    pub headers: Option<HeaderMap<HeaderValue>>,
    pub error: Option<String>,
    pub silent: bool,
    pub verbose: bool,
    pub pretty: bool,
}

impl HttpStat {
    pub fn is_success(&self) -> bool {
        if self.error.is_some() {
            return false;
        }
        let Some(status) = &self.status else {
            return false;
        };
        if status.as_u16() >= 400 {
            return false;
        }
        true
    }
}

impl fmt::Display for HttpStat {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if let Some(addr) = &self.addr {
            let mut text = format!(
                "{} {}",
                LightGreen.paint("Connected to"),
                LightCyan.paint(addr)
            );
            if self.silent {
                if let Some(status) = &self.status {
                    let alpn = self.alpn.clone().unwrap_or_else(|| ALPN_HTTP1.to_string());
                    let status_code = status.as_u16();
                    let status = if status_code < 400 {
                        LightGreen.paint(status.to_string())
                    } else {
                        LightRed.paint(status.to_string())
                    };
                    text = format!(
                        "{text} --> {} {}",
                        LightCyan.paint(alpn.to_uppercase()),
                        status
                    );
                } else {
                    text = format!("{text} --> {}", LightRed.paint("FAIL"));
                }
                text = format!("{text} {}", format_duration(self.total.unwrap_or_default()));
            }
            writeln!(f, "{}", text)?;
        }
        if let Some(error) = &self.error {
            writeln!(f, "Error: {}", LightRed.paint(error))?;
        }
        if self.silent {
            return Ok(());
        }
        if self.verbose {
            for (key, value) in self.request_headers.iter() {
                writeln!(
                    f,
                    "{}: {}",
                    key.to_string().to_train_case(),
                    LightCyan.paint(value.to_str().unwrap_or_default())
                )?;
            }
            writeln!(f)?;
        }

        if let Some(status) = &self.status {
            let alpn = self.alpn.clone().unwrap_or_else(|| ALPN_HTTP1.to_string());
            let status_code = status.as_u16();
            let status = if status_code < 400 {
                LightGreen.paint(status.to_string())
            } else {
                LightRed.paint(status.to_string())
            };
            writeln!(f, "{} {}", LightCyan.paint(alpn.to_uppercase()), status)?;
        }

        if let Some(tls) = &self.tls {
            writeln!(f)?;
            writeln!(f, "Tls: {}", LightCyan.paint(tls))?;
            writeln!(
                f,
                "Cipher: {}",
                LightCyan.paint(self.cert_cipher.clone().unwrap_or_default())
            )?;
            writeln!(
                f,
                "Not Before: {}",
                LightCyan.paint(self.cert_not_before.clone().unwrap_or_default())
            )?;
            writeln!(
                f,
                "Not After: {}",
                LightCyan.paint(self.cert_not_after.clone().unwrap_or_default())
            )?;
            if self.verbose {
                writeln!(
                    f,
                    "Subject: {}",
                    LightCyan.paint(self.subject.clone().unwrap_or_default())
                )?;
                writeln!(
                    f,
                    "Issuer: {}",
                    LightCyan.paint(self.issuer.clone().unwrap_or_default())
                )?;
                writeln!(
                    f,
                    "Certificate Domains: {}",
                    LightCyan.paint(self.cert_domains.clone().unwrap_or_default().join(", "))
                )?;
            }
            writeln!(f)?;
        }

        let mut is_text = false;
        let mut is_json = false;
        if let Some(headers) = &self.headers {
            for (key, value) in headers.iter() {
                let value = value.to_str().unwrap_or_default();
                if key.to_string().to_lowercase() == "content-type" {
                    if value.contains("text/") || value.contains("application/json") {
                        is_text = true;
                    }
                    if value.contains("application/json") {
                        is_json = true;
                    }
                }
                writeln!(
                    f,
                    "{}: {}",
                    key.to_string().to_train_case(),
                    LightCyan.paint(value)
                )?;
            }
            writeln!(f)?;
        }

        let width = 20;

        let mut timelines = vec![];
        if let Some(value) = self.dns_lookup {
            timelines.push(Timeline {
                name: "DNS Lookup".to_string(),
                duration: value,
            });
        }

        if let Some(value) = self.tcp_connect {
            timelines.push(Timeline {
                name: "TCP Connect".to_string(),
                duration: value,
            });
        }

        if let Some(value) = self.tls_handshake {
            timelines.push(Timeline {
                name: "TLS Handshake".to_string(),
                duration: value,
            });
        }
        if let Some(value) = self.quic_connect {
            timelines.push(Timeline {
                name: "QUIC Connect".to_string(),
                duration: value,
            });
        }

        if let Some(value) = self.server_processing {
            timelines.push(Timeline {
                name: "Server Processing".to_string(),
                duration: value,
            });
        }

        if let Some(value) = self.content_transfer {
            timelines.push(Timeline {
                name: "Content Transfer".to_string(),
                duration: value,
            });
        }

        if !timelines.is_empty() {
            // print name
            write!(f, " ")?;
            for (i, timeline) in timelines.iter().enumerate() {
                write!(
                    f,
                    "{}",
                    timeline.name.unicode_pad(width, Alignment::Center, true)
                )?;
                if i < timelines.len() - 1 {
                    write!(f, " ")?;
                }
            }
            writeln!(f)?;

            // print duration
            write!(f, "[")?;
            for (i, timeline) in timelines.iter().enumerate() {
                write!(
                    f,
                    "{}",
                    LightCyan.paint(
                        format_duration(timeline.duration)
                            .unicode_pad(width, Alignment::Center, true)
                            .to_string(),
                    )
                )?;
                if i < timelines.len() - 1 {
                    write!(f, "|")?;
                }
            }
            writeln!(f, "]")?;
        }

        // print | line
        write!(f, " ")?;
        for _ in 0..timelines.len() {
            write!(f, "{}", " ".repeat(width))?;
            write!(f, "|")?;
        }
        writeln!(f)?;
        write!(f, "{}", " ".repeat(width * timelines.len()))?;
        write!(
            f,
            "Total:{}\n\n",
            LightCyan.paint(format_duration(self.total.unwrap_or_default()))
        )?;

        if let Some(body) = &self.body {
            let status = self.status.unwrap_or(StatusCode::OK).as_u16();
            let mut body = std::str::from_utf8(body.as_ref())
                .unwrap_or_default()
                .to_string();
            if self.pretty {
                if is_json {
                    if let Ok(json_body) = serde_json::from_str::<serde_json::Value>(&body) {
                        if let Ok(value) = serde_json::to_string_pretty(&json_body) {
                            body = value;
                        }
                    }
                }
            }
            if self.verbose || (is_text && body.len() < 1024) {
                let text = format!(
                    "Body size: {}",
                    ByteSize(self.body_size.unwrap_or(0) as u64)
                );
                writeln!(f, "{}\n", LightCyan.paint(text))?;
                if status >= 400 {
                    writeln!(f, "{}", LightRed.paint(body))?;
                } else {
                    writeln!(f, "{}", body)?;
                }
            } else {
                let text = format!(
                    "Body discarded {}",
                    ByteSize(self.body_size.unwrap_or(0) as u64)
                );
                writeln!(f, "{}", LightCyan.paint(text))?;
            }
        }

        Ok(())
    }
}
