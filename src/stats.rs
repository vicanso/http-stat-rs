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
use serde_json::{json, Map, Value};
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

pub fn format_duration(duration: Duration) -> String {
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
    pub include_headers: Option<Vec<String>>,
    pub exclude_headers: Option<Vec<String>>,
    pub waterfall: bool,
    pub jq_filter: Option<String>,
}

#[derive(Debug, Clone)]
pub struct Certificate {
    pub subject: String,
    pub issuer: String,
    pub not_before: String,
    pub not_after: String,
}

/// Apply a simple jq-style field selector to a JSON string.
/// Supported syntax:
///   .                    identity (pretty-print)
///   .field               object key access
///   .field.sub           nested key access
///   .[0]                 array index
///   .[]                  iterate all array/object values
///   combinations: .items[].name, .a.b[2].c, etc.
fn apply_jq_filter(body: &str, filter: &str) -> Option<String> {
    let root: serde_json::Value = serde_json::from_str(body).ok()?;
    let filter = filter.trim();
    // Allow omitting the leading '.' for convenience (e.g. "os" → ".os")
    let owned;
    let filter = if !filter.starts_with('.') {
        owned = format!(".{filter}");
        owned.as_str()
    } else {
        filter
    };

    // Tokenise the filter string into a list of access steps.
    #[derive(Debug)]
    enum Step {
        Key(String),
        Index(usize),
        Iter,
    }

    fn tokenize(s: &str) -> Option<Vec<Step>> {
        let s = s.strip_prefix('.')?;
        if s.is_empty() {
            return Some(vec![]);
        }
        let mut steps = Vec::new();
        // Split on '.' but keep bracket expressions attached to the preceding key.
        // We walk char-by-char to handle `key[0].next` etc.
        let mut remaining = s;
        while !remaining.is_empty() {
            if remaining.starts_with('[') {
                // bracket at the start: .[0] or .[]
                let end = remaining.find(']')?;
                let inner = &remaining[1..end];
                if inner.is_empty() {
                    steps.push(Step::Iter);
                } else {
                    let idx: usize = inner.parse().ok()?;
                    steps.push(Step::Index(idx));
                }
                remaining = &remaining[end + 1..];
                if remaining.starts_with('.') {
                    remaining = &remaining[1..];
                }
            } else {
                // read up to next '.' or '['
                let end = remaining.find(['.', '[']).unwrap_or(remaining.len());
                let key = &remaining[..end];
                if !key.is_empty() {
                    steps.push(Step::Key(key.to_string()));
                }
                remaining = &remaining[end..];
                if remaining.starts_with('.') {
                    remaining = &remaining[1..];
                }
            }
        }
        Some(steps)
    }

    fn apply_steps(values: Vec<serde_json::Value>, steps: &[Step]) -> Vec<serde_json::Value> {
        if steps.is_empty() {
            return values;
        }
        let mut current = values;
        for step in steps {
            current = match step {
                Step::Key(k) => current
                    .into_iter()
                    .filter_map(|v| v.get(k).cloned())
                    .collect(),
                Step::Index(i) => current
                    .into_iter()
                    .filter_map(|v| v.get(i).cloned())
                    .collect(),
                Step::Iter => current
                    .into_iter()
                    .flat_map(|v| match v {
                        serde_json::Value::Array(arr) => arr,
                        serde_json::Value::Object(map) => map.into_values().collect(),
                        other => vec![other],
                    })
                    .collect(),
            };
        }
        current
    }

    let steps = tokenize(filter)?;
    let results = apply_steps(vec![root], &steps);

    if results.len() == 1 {
        serde_json::to_string_pretty(&results[0]).ok()
    } else {
        Some(
            results
                .iter()
                .filter_map(|v| serde_json::to_string_pretty(v).ok())
                .collect::<Vec<_>>()
                .join("\n"),
        )
    }
}

impl HttpStat {
    /// Returns a semantic exit code based on the error type:
    /// - 0: Success
    /// - 1: General/unknown error
    /// - 2: DNS resolution failure
    /// - 3: TCP connection failure
    /// - 4: TLS/SSL error
    /// - 5: Timeout
    /// - 6: HTTP 4xx client error
    /// - 7: HTTP 5xx server error
    pub fn exit_code(&self) -> i32 {
        if self.is_success() {
            return 0;
        }
        // HTTP status errors (no connection error, but bad status)
        if self.error.is_none() {
            if let Some(status) = &self.status {
                let code = status.as_u16();
                if code >= 500 {
                    return 7;
                }
                if code >= 400 {
                    return 6;
                }
            }
            return 1;
        }
        let err = self.error.as_deref().unwrap_or_default().to_lowercase();
        // Timeout (check before phase-based detection since timeout can happen in any phase)
        if err.contains("timeout") || err.contains("elapsed") {
            return 5;
        }
        // DNS failure: dns_lookup phase never completed
        if self.dns_lookup.is_none() {
            return 2;
        }
        // TCP failure: tcp/quic connection phase never completed
        if self.tcp_connect.is_none() && self.quic_connect.is_none() {
            return 3;
        }
        // TLS failure
        if err.contains("rustls")
            || err.contains("tls")
            || err.contains("certificate")
            || err.contains("invalid dns name")
        {
            return 4;
        }
        1
    }

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

    /// Render a waterfall bar chart to `f`.
    /// Each phase is one row; bars are horizontally positioned by cumulative offset.
    fn fmt_waterfall(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let total = match self.total {
            Some(t) if t.as_nanos() > 0 => t,
            _ => return Ok(()),
        };

        const BAR_WIDTH: usize = 50;
        const LABEL_W: usize = 15;

        let phases: &[(&str, Option<Duration>)] = &[
            ("DNS Lookup", self.dns_lookup),
            ("TCP Connect", self.tcp_connect),
            ("TLS Handshake", self.tls_handshake),
            ("QUIC Connect", self.quic_connect),
            ("Server Process", self.server_processing),
            ("Content Xfer", self.content_transfer),
        ];

        let total_ns = total.as_nanos() as f64;
        let mut elapsed = Duration::ZERO;
        let mut col_cursor: usize = 0;

        for (name, dur_opt) in phases {
            let Some(dur) = dur_opt else { continue };

            let start_col = col_cursor;
            elapsed += *dur;
            let ideal_end = ((elapsed.as_nanos() as f64 / total_ns * BAR_WIDTH as f64).round()
                as usize)
                .min(BAR_WIDTH);
            let end_col = ideal_end.min(BAR_WIDTH);
            if end_col > start_col {
                col_cursor = end_col;
            }

            let bar: String = (0..BAR_WIDTH)
                .map(|i| {
                    if i >= start_col && i < end_col {
                        '█'
                    } else {
                        '░'
                    }
                })
                .collect();

            writeln!(
                f,
                " {:<LABEL_W$} [{}]  {}",
                name,
                LightCyan.paint(bar),
                LightCyan.paint(format_duration(*dur))
            )?;
        }

        writeln!(f)?;
        writeln!(
            f,
            " {:LABEL_W$}  {:BAR_WIDTH$}  Total: {}",
            "",
            "",
            LightCyan.paint(format_duration(total))
        )?;
        writeln!(f)
    }

    pub fn to_json(&self) -> Value {
        let dur_us = |d: Option<Duration>| -> Value {
            d.map_or(Value::Null, |d| json!(d.as_micros() as u64))
        };

        let mut obj = Map::new();

        // Timing (microseconds)
        let mut timing = Map::new();
        timing.insert("dns_lookup_us".into(), dur_us(self.dns_lookup));
        timing.insert("tcp_connect_us".into(), dur_us(self.tcp_connect));
        timing.insert("tls_handshake_us".into(), dur_us(self.tls_handshake));
        timing.insert("quic_connect_us".into(), dur_us(self.quic_connect));
        timing.insert(
            "server_processing_us".into(),
            dur_us(self.server_processing),
        );
        timing.insert("content_transfer_us".into(), dur_us(self.content_transfer));
        timing.insert("total_us".into(), dur_us(self.total));
        obj.insert("timing".into(), Value::Object(timing));

        // Connection
        obj.insert(
            "addr".into(),
            self.addr.as_deref().map_or(Value::Null, |s| json!(s)),
        );
        obj.insert(
            "status".into(),
            self.status.map_or(Value::Null, |s| json!(s.as_u16())),
        );
        obj.insert(
            "alpn".into(),
            self.alpn.as_deref().map_or(Value::Null, |s| json!(s)),
        );

        // TLS
        if self.tls.is_some() {
            let mut tls = Map::new();
            tls.insert(
                "version".into(),
                self.tls.as_deref().map_or(Value::Null, |s| json!(s)),
            );
            tls.insert(
                "cipher".into(),
                self.cert_cipher
                    .as_deref()
                    .map_or(Value::Null, |s| json!(s)),
            );
            tls.insert(
                "subject".into(),
                self.subject.as_deref().map_or(Value::Null, |s| json!(s)),
            );
            tls.insert(
                "issuer".into(),
                self.issuer.as_deref().map_or(Value::Null, |s| json!(s)),
            );
            tls.insert(
                "not_before".into(),
                self.cert_not_before
                    .as_deref()
                    .map_or(Value::Null, |s| json!(s)),
            );
            tls.insert(
                "not_after".into(),
                self.cert_not_after
                    .as_deref()
                    .map_or(Value::Null, |s| json!(s)),
            );
            tls.insert(
                "domains".into(),
                self.cert_domains.as_ref().map_or(Value::Null, |d| json!(d)),
            );
            obj.insert("tls".into(), Value::Object(tls));
        }

        // Headers
        if let Some(headers) = &self.headers {
            let mut hdr_map = Map::new();
            for (key, value) in headers.iter() {
                let v = value.to_str().unwrap_or_default().to_string();
                hdr_map.insert(key.to_string(), json!(v));
            }
            obj.insert("headers".into(), Value::Object(hdr_map));
        }

        // Body
        obj.insert(
            "body_size".into(),
            self.body_size.map_or(Value::Null, |s| json!(s)),
        );

        // Error
        obj.insert(
            "error".into(),
            self.error.as_deref().map_or(Value::Null, |e| json!(e)),
        );
        obj.insert("exit_code".into(), json!(self.exit_code()));

        Value::Object(obj)
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
                let key_lower = key.as_str();
                let show = if let Some(includes) = &self.include_headers {
                    includes.iter().any(|h| h == key_lower)
                } else if let Some(excludes) = &self.exclude_headers {
                    !excludes.iter().any(|h| h == key_lower)
                } else {
                    true
                };
                if show {
                    writeln!(
                        f,
                        "{}: {}",
                        key.to_string().to_train_case(),
                        LightCyan.paint(value)
                    )?;
                }
            }
            writeln!(f)?;
        }

        if self.waterfall {
            self.fmt_waterfall(f)?;
        } else {
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
        }

        if let Some(body) = &self.body {
            let status = self.status.unwrap_or(StatusCode::OK).as_u16();
            let mut body = std::str::from_utf8(body.as_ref())
                .unwrap_or_default()
                .to_string();
            if let Some(filter) = &self.jq_filter {
                if let Some(filtered) = apply_jq_filter(&body, filter) {
                    body = filtered;
                }
            } else if self.pretty && is_json {
                if let Ok(json_body) = serde_json::from_str::<serde_json::Value>(&body) {
                    if let Ok(value) = serde_json::to_string_pretty(&json_body) {
                        body = value;
                    }
                }
            }
            if self.verbose || self.jq_filter.is_some() || (is_text && body.len() < 4096) {
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
