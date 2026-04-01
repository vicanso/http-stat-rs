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
use chrono::{Local, TimeZone};
use heck::ToTrainCase;
use http::HeaderMap;
use http::HeaderValue;
use http::StatusCode;
use nu_ansi_term::Color::{LightCyan, LightGreen, LightRed};
use std::fmt;
use std::io::Write;
use std::time::Duration;
use tempfile::NamedTempFile;
use unicode_truncate::Alignment;
use unicode_truncate::UnicodeTruncateStr;

pub static ALPN_HTTP2: &str = "h2";
pub static ALPN_HTTP1: &str = "http/1.1";
pub static ALPN_HTTP3: &str = "h3";

// Format timestamp to human-readable string
pub(crate) fn format_time(timestamp_seconds: i64) -> String {
    Local
        .timestamp_nanos(timestamp_seconds * 1_000_000_000)
        .to_string()
}

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
#[derive(Default, Debug, Clone)]
pub struct HttpStat {
    pub is_grpc: bool,
    pub request_headers: HeaderMap<HeaderValue>,
    pub dns_lookup: Option<Duration>,
    pub quic_connect: Option<Duration>,
    pub tcp_connect: Option<Duration>,
    pub tls_handshake: Option<Duration>,
    pub server_processing: Option<Duration>,
    pub content_transfer: Option<Duration>,
    pub total: Option<Duration>,
    pub addr: Option<String>,
    pub grpc_status: Option<String>,
    pub status: Option<StatusCode>,
    pub tls: Option<String>,
    pub alpn: Option<String>,
    pub subject: Option<String>,
    pub issuer: Option<String>,
    pub cert_not_before: Option<String>,
    pub cert_not_after: Option<String>,
    pub cert_cipher: Option<String>,
    pub cert_domains: Option<Vec<String>>,
    pub certificates: Option<Vec<Certificate>>,
    pub body: Option<Bytes>,
    pub body_size: Option<usize>,
    pub headers: Option<HeaderMap<HeaderValue>>,
    pub error: Option<String>,
    pub silent: bool,
    pub verbose: bool,
    pub pretty: bool,
}

#[derive(Debug, Clone)]
pub struct Certificate {
    pub subject: String,
    pub issuer: String,
    pub not_before: String,
    pub not_after: String,
}

impl HttpStat {
    pub fn is_success(&self) -> bool {
        if self.error.is_some() {
            return false;
        }
        if self.is_grpc {
            if let Some(grpc_status) = &self.grpc_status {
                return grpc_status == "0";
            }
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
                    let alpn = self.alpn.as_deref().unwrap_or(ALPN_HTTP1);
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
            writeln!(f, "{text}")?;
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
            let alpn = self.alpn.as_deref().unwrap_or(ALPN_HTTP1);
            let status_code = status.as_u16();
            let status = if status_code < 400 {
                LightGreen.paint(status.to_string())
            } else {
                LightRed.paint(status.to_string())
            };
            writeln!(f, "{} {}", LightCyan.paint(alpn.to_uppercase()), status)?;
        }
        if self.is_grpc {
            if self.is_success() {
                writeln!(f, "{}", LightGreen.paint("GRPC OK"))?;
            }
            writeln!(f)?;
        }

        if let Some(tls) = &self.tls {
            writeln!(f)?;
            writeln!(f, "Tls: {}", LightCyan.paint(tls))?;
            writeln!(
                f,
                "Cipher: {}",
                LightCyan.paint(self.cert_cipher.as_deref().unwrap_or_default())
            )?;
            writeln!(
                f,
                "Not Before: {}",
                LightCyan.paint(self.cert_not_before.as_deref().unwrap_or_default())
            )?;
            writeln!(
                f,
                "Not After: {}",
                LightCyan.paint(self.cert_not_after.as_deref().unwrap_or_default())
            )?;
            if self.verbose {
                writeln!(
                    f,
                    "Subject: {}",
                    LightCyan.paint(self.subject.as_deref().unwrap_or_default())
                )?;
                writeln!(
                    f,
                    "Issuer: {}",
                    LightCyan.paint(self.issuer.as_deref().unwrap_or_default())
                )?;
                writeln!(
                    f,
                    "Certificate Domains: {}",
                    LightCyan.paint(self.cert_domains.as_deref().unwrap_or_default().join(", "))
                )?;
            }
            writeln!(f)?;

            if self.verbose {
                if let Some(certificates) = &self.certificates {
                    writeln!(f, "Certificate Chain")?;
                    for (index, cert) in certificates.iter().enumerate() {
                        writeln!(
                            f,
                            " {index} Subject: {}",
                            LightCyan.paint(cert.subject.as_str())
                        )?;
                        writeln!(f, "   Issuer: {}", LightCyan.paint(cert.issuer.as_str()))?;
                        writeln!(
                            f,
                            "   Not Before: {}",
                            LightCyan.paint(cert.not_before.as_str())
                        )?;
                        writeln!(
                            f,
                            "   Not After: {}",
                            LightCyan.paint(cert.not_after.as_str())
                        )?;
                        writeln!(f)?;
                    }
                }
            }
        }

        let mut is_text = false;
        let mut is_json = false;
        if let Some(headers) = &self.headers {
            for (key, value) in headers.iter() {
                let value = value.to_str().unwrap_or_default();
                if key == http::header::CONTENT_TYPE {
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
            if self.pretty && is_json {
                if let Ok(json_body) = serde_json::from_str::<serde_json::Value>(&body) {
                    if let Ok(value) = serde_json::to_string_pretty(&json_body) {
                        body = value;
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
                    writeln!(f, "{body}")?;
                }
            } else {
                let mut save_tips = "".to_string();
                if let Ok(mut file) = NamedTempFile::new() {
                    if let Ok(()) = file.write_all(body.as_bytes()) {
                        save_tips = format!("saved to: {}", file.path().display());
                        let _ = file.keep();
                    }
                }
                let text = format!(
                    "Body discarded {}",
                    ByteSize(self.body_size.unwrap_or(0) as u64)
                );
                writeln!(f, "{} {}", LightCyan.paint(text), save_tips)?;
            }
        }

        Ok(())
    }
}

pub struct BenchmarkSummary {
    pub stats: Vec<HttpStat>,
}

impl BenchmarkSummary {
    fn collect_sorted(&self, f: impl Fn(&HttpStat) -> Option<Duration>) -> Vec<Duration> {
        let mut v: Vec<Duration> = self.stats.iter().filter_map(f).collect();
        v.sort();
        v
    }

    fn percentile(sorted: &[Duration], p: f64) -> Option<Duration> {
        if sorted.is_empty() {
            return None;
        }
        let idx = ((p * sorted.len() as f64).ceil() as usize).saturating_sub(1);
        Some(sorted[idx.min(sorted.len() - 1)])
    }
}

impl fmt::Display for BenchmarkSummary {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let total = self.stats.len();
        if total == 0 {
            return Ok(());
        }

        let phases: Vec<(&str, Vec<Duration>)> = [
            ("DNS Lookup", self.collect_sorted(|s| s.dns_lookup)),
            ("TCP Connect", self.collect_sorted(|s| s.tcp_connect)),
            ("TLS Handshake", self.collect_sorted(|s| s.tls_handshake)),
            ("QUIC Connect", self.collect_sorted(|s| s.quic_connect)),
            (
                "Server Process",
                self.collect_sorted(|s| s.server_processing),
            ),
            ("Content Xfer", self.collect_sorted(|s| s.content_transfer)),
            ("Total", self.collect_sorted(|s| s.total)),
        ]
        .into_iter()
        .filter(|(_, v)| !v.is_empty())
        .collect();

        if phases.is_empty() {
            return Ok(());
        }

        writeln!(f)?;
        writeln!(
            f,
            "{}",
            LightGreen.paint(format!("--- Benchmark Results ({total} requests) ---"))
        )?;
        writeln!(f)?;

        let col_w = 18;
        let label_w = 6;

        // Header row
        write!(f, "{:>label_w$} ", "")?;
        for (name, _) in &phases {
            write!(f, "{}", name.unicode_pad(col_w, Alignment::Center, true))?;
        }
        writeln!(f)?;

        // Stats rows
        let rows: [(&str, f64); 6] = [
            ("min", 0.0),
            ("max", f64::INFINITY),
            ("avg", f64::NAN),
            ("p50", 0.5),
            ("p95", 0.95),
            ("p99", 0.99),
        ];

        for (label, p) in &rows {
            write!(f, "{} ", LightGreen.paint(format!("{label:>label_w$}")))?;
            for (_, sorted) in &phases {
                let val = if p.is_nan() {
                    // avg
                    if sorted.is_empty() {
                        None
                    } else {
                        let sum: Duration = sorted.iter().sum();
                        Some(sum / sorted.len() as u32)
                    }
                } else if *p == 0.0 {
                    sorted.first().copied()
                } else if p.is_infinite() {
                    sorted.last().copied()
                } else {
                    Self::percentile(sorted, *p)
                };
                let text = match val {
                    Some(d) => format_duration(d),
                    None => "-".to_string(),
                };
                write!(
                    f,
                    "{}",
                    LightCyan.paint(text.unicode_pad(col_w, Alignment::Center, true).to_string())
                )?;
            }
            writeln!(f)?;
        }

        writeln!(f)?;
        let success = self.stats.iter().filter(|s| s.is_success()).count();
        let pct = (success as f64 / total as f64) * 100.0;
        let success_text = format!("Success: {success}/{total} ({pct:.1}%)");
        if success == total {
            writeln!(f, "  {}", LightGreen.paint(success_text))?;
        } else {
            writeln!(f, "  {}", LightRed.paint(success_text))?;
        }

        Ok(())
    }
}
