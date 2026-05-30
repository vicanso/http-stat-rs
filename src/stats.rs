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
use nu_ansi_term::Color::{LightCyan, LightGreen, LightRed, LightYellow};
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
/// * `request_send` - Time to send the request headers and body
/// * `server_processing` - Time from request fully sent to first response byte
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
    /// Cold connect cost (TCP + TLS) to the DNS server. Only populated when
    /// using DoH or DoT — for plain UDP DNS this stays None. When present,
    /// the `dns_lookup` total can be split into `dns_connect` and a derived
    /// `dns_query = dns_lookup - dns_connect`, making it possible to tell
    /// whether DoH/DoT latency comes from TLS handshake or query processing.
    pub dns_connect: Option<Duration>,
    pub quic_connect: Option<Duration>,
    pub tcp_connect: Option<Duration>,
    pub tls_handshake: Option<Duration>,
    pub request_send: Option<Duration>,
    pub server_processing: Option<Duration>,
    pub content_transfer: Option<Duration>,
    pub server_timing: Option<Vec<ServerTiming>>,
    pub total: Option<Duration>,
    pub addr: Option<String>,
    pub grpc_status: Option<String>,
    pub status: Option<StatusCode>,
    pub tls: Option<String>,
    pub tls_resumed: Option<bool>,
    pub tls_early_data_accepted: Option<bool>,
    pub tls_ocsp_stapled: Option<bool>,
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

/// A single entry parsed from the `Server-Timing` response header (RFC 8673 / W3C).
///
/// Format: `name[;dur=<ms>][;desc="<text>"]`, possibly multiple comma-separated entries
/// per header, possibly multiple `Server-Timing` headers.
#[derive(Debug, Clone)]
pub struct ServerTiming {
    pub name: String,
    pub duration: Option<Duration>,
    pub description: Option<String>,
}

/// Parse all `Server-Timing` header values into a flat list of entries.
/// Returns `None` if the input iterator yields no entries.
pub fn parse_server_timing<'a, I>(values: I) -> Option<Vec<ServerTiming>>
where
    I: IntoIterator<Item = &'a str>,
{
    let mut out = Vec::new();
    for raw in values {
        for part in split_top_level_commas(raw) {
            let mut subparts = part.split(';').map(str::trim);
            let name = match subparts.next() {
                Some(n) if !n.is_empty() => n.to_string(),
                _ => continue,
            };
            let mut entry = ServerTiming {
                name,
                duration: None,
                description: None,
            };
            for kv in subparts {
                let Some(eq) = kv.find('=') else { continue };
                let key = kv[..eq].trim().to_ascii_lowercase();
                let mut val = kv[eq + 1..].trim();
                if val.starts_with('"') && val.ends_with('"') && val.len() >= 2 {
                    val = &val[1..val.len() - 1];
                }
                match key.as_str() {
                    "dur" => {
                        if let Ok(ms) = val.parse::<f64>() {
                            if ms.is_finite() && ms >= 0.0 {
                                entry.duration = Some(Duration::from_secs_f64(ms / 1000.0));
                            }
                        }
                    }
                    "desc" => entry.description = Some(val.to_string()),
                    _ => {}
                }
            }
            out.push(entry);
        }
    }
    if out.is_empty() {
        None
    } else {
        Some(out)
    }
}

/// Split on top-level commas, ignoring commas inside double-quoted strings.
fn split_top_level_commas(s: &str) -> Vec<&str> {
    let mut parts = Vec::new();
    let mut start = 0usize;
    let mut in_quotes = false;
    let bytes = s.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'"' => in_quotes = !in_quotes,
            b',' if !in_quotes => {
                parts.push(s[start..i].trim());
                start = i + 1;
            }
            _ => {}
        }
        i += 1;
    }
    parts.push(s[start..].trim());
    parts
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

    /// Derived "DNS Query" phase: the portion of `dns_lookup` not spent on
    /// `dns_connect`. Returns `None` when no DoH/DoT probe was performed.
    /// Clamped to ≥ 0 because the parallel probe can race slightly ahead of
    /// the real resolver in rare cases.
    pub fn dns_query(&self) -> Option<Duration> {
        match (self.dns_lookup, self.dns_connect) {
            (Some(total), Some(connect)) => Some(total.saturating_sub(connect)),
            _ => None,
        }
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

        // When a DoH/DoT probe ran, split the DNS column into Connect + Query.
        let (dns_a, dns_b) = if self.dns_connect.is_some() {
            (
                ("DNS Connect", self.dns_connect),
                ("DNS Query", self.dns_query()),
            )
        } else {
            (("DNS Lookup", self.dns_lookup), ("", None))
        };
        let phases_vec: Vec<(&str, Option<Duration>)> = vec![
            dns_a,
            dns_b,
            ("TCP Connect", self.tcp_connect),
            ("TLS Handshake", self.tls_handshake),
            ("QUIC Connect", self.quic_connect),
            ("Request Send", self.request_send),
            ("Server Process", self.server_processing),
            ("Content Xfer", self.content_transfer),
        ];
        let phases: &[(&str, Option<Duration>)] = &phases_vec;

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
        timing.insert("dns_connect_us".into(), dur_us(self.dns_connect));
        timing.insert("dns_query_us".into(), dur_us(self.dns_query()));
        timing.insert("tcp_connect_us".into(), dur_us(self.tcp_connect));
        timing.insert("tls_handshake_us".into(), dur_us(self.tls_handshake));
        timing.insert("quic_connect_us".into(), dur_us(self.quic_connect));
        timing.insert("request_send_us".into(), dur_us(self.request_send));
        timing.insert(
            "server_processing_us".into(),
            dur_us(self.server_processing),
        );
        timing.insert("content_transfer_us".into(), dur_us(self.content_transfer));
        timing.insert("total_us".into(), dur_us(self.total));
        obj.insert("timing".into(), Value::Object(timing));

        // Server-Timing entries (RFC 8673)
        if let Some(entries) = &self.server_timing {
            let arr: Vec<Value> = entries
                .iter()
                .map(|e| {
                    let mut m = Map::new();
                    m.insert("name".into(), json!(e.name));
                    m.insert(
                        "duration_us".into(),
                        e.duration
                            .map_or(Value::Null, |d| json!(d.as_micros() as u64)),
                    );
                    m.insert(
                        "description".into(),
                        e.description.as_deref().map_or(Value::Null, |s| json!(s)),
                    );
                    Value::Object(m)
                })
                .collect();
            obj.insert("server_timing".into(), Value::Array(arr));
        }

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
                "resumed".into(),
                self.tls_resumed.map_or(Value::Null, |b| json!(b)),
            );
            tls.insert(
                "early_data_accepted".into(),
                self.tls_early_data_accepted
                    .map_or(Value::Null, |b| json!(b)),
            );
            tls.insert(
                "ocsp_stapled".into(),
                self.tls_ocsp_stapled.map_or(Value::Null, |b| json!(b)),
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
            let label = if self.tcp_connect.is_some() || self.quic_connect.is_some() {
                LightGreen.paint("Connected to")
            } else {
                LightYellow.paint("Resolved to")
            };
            let mut text = format!("{} {}", label, LightCyan.paint(addr));
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
                // Surface TLS resumption / 0-RTT inline — most useful in
                // benchmark (-n) output where iterations 2+ may resume.
                if let Some(true) = self.tls_resumed {
                    let tag = if matches!(self.tls_early_data_accepted, Some(true)) {
                        "0-RTT"
                    } else {
                        "Resumed"
                    };
                    text = format!("{text} [{}]", LightYellow.paint(tag));
                }
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
            if let Some(resumed) = self.tls_resumed {
                let label = if resumed { "Resumed" } else { "Full" };
                writeln!(f, "Handshake: {}", LightCyan.paint(label))?;
            }
            if let Some(accepted) = self.tls_early_data_accepted {
                let label = if accepted {
                    "accepted (0-RTT)"
                } else {
                    "not accepted"
                };
                writeln!(f, "Early Data: {}", LightCyan.paint(label))?;
            }
            if let Some(stapled) = self.tls_ocsp_stapled {
                let label = if stapled { "stapled" } else { "not stapled" };
                writeln!(f, "OCSP: {}", LightCyan.paint(label))?;
            }
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

        // Server-Timing breakdown (what the server says happened inside Server Processing).
        // Each row shows: name, a sparkline-style bar sized by share of the reported total,
        // duration, and percent. The header line reconciles the reported sum against the
        // measured Server Processing time so the unaccounted gap (network/queueing) is visible.
        if let Some(entries) = &self.server_timing {
            if !entries.is_empty() {
                const BAR_W: usize = 34;
                let name_w = entries
                    .iter()
                    .map(|e| e.name.chars().count())
                    .max()
                    .unwrap_or(0)
                    .max(4);

                let sum: Duration = entries.iter().filter_map(|e| e.duration).sum();
                let total_ns = (sum.as_nanos() as f64).max(1.0);
                let largest_idx: Option<usize> = entries
                    .iter()
                    .enumerate()
                    .filter_map(|(i, e)| e.duration.filter(|d| !d.is_zero()).map(|d| (i, d)))
                    .max_by_key(|(_, d)| *d)
                    .map(|(i, _)| i);

                let summary = match self.server_processing {
                    Some(sp) if sp > sum => format!(
                        "(\u{03A3} {} of {} Server Processing \u{00B7} {} unaccounted)",
                        format_duration(sum),
                        format_duration(sp),
                        format_duration(sp - sum),
                    ),
                    Some(sp) => format!(
                        "(\u{03A3} {} of {} Server Processing)",
                        format_duration(sum),
                        format_duration(sp),
                    ),
                    None => format!("(\u{03A3} {})", format_duration(sum)),
                };
                writeln!(
                    f,
                    "{} {}",
                    LightGreen.paint("Server-Timing:"),
                    LightCyan.paint(&summary),
                )?;

                // Lay each bar out at its cumulative offset, so the sequence reads
                // left-to-right like a waterfall inside Server Processing.
                let sum_ns_u = sum.as_nanos();
                let mut cum_ns: u128 = 0;
                for (i, entry) in entries.iter().enumerate() {
                    let name_pad = " ".repeat(name_w.saturating_sub(entry.name.chars().count()));
                    let dur_ns = entry.duration.map(|d| d.as_nanos()).unwrap_or(0);

                    let start_col = ((cum_ns as f64 / total_ns) * BAR_W as f64).round() as usize;
                    let start_col = start_col.min(BAR_W);
                    let mut end_col =
                        (((cum_ns + dur_ns) as f64 / total_ns) * BAR_W as f64).round() as usize;
                    end_col = end_col.min(BAR_W);
                    // Non-zero entries should always paint at least one cell so they
                    // don't disappear into rounding.
                    if dur_ns > 0 && end_col <= start_col {
                        end_col = (start_col + 1).min(BAR_W);
                    }

                    let bar: String = (0..BAR_W)
                        .map(|col| {
                            if dur_ns == 0 {
                                let marker = start_col.min(BAR_W - 1);
                                if col == marker {
                                    '\u{00B7}'
                                } else {
                                    '\u{2591}'
                                }
                            } else if col >= start_col && col < end_col {
                                '\u{2588}'
                            } else {
                                '\u{2591}'
                            }
                        })
                        .collect();

                    let (dur_str, pct_str) = if dur_ns > 0 {
                        let pct = if sum_ns_u > 0 {
                            (dur_ns as f64 / sum_ns_u as f64) * 100.0
                        } else {
                            0.0
                        };
                        (
                            format_duration(entry.duration.unwrap_or_default()),
                            format!("{pct:>5.1}%"),
                        )
                    } else {
                        ("\u{2014}".to_string(), "\u{2013}".to_string())
                    };

                    let is_largest = Some(i) == largest_idx;
                    let bar_painted = if is_largest {
                        LightYellow.paint(&bar).to_string()
                    } else {
                        LightCyan.paint(&bar).to_string()
                    };
                    let dur_painted = if is_largest {
                        LightYellow.paint(format!("{dur_str:>8}")).to_string()
                    } else {
                        LightCyan.paint(format!("{dur_str:>8}")).to_string()
                    };
                    let pct_painted = LightCyan.paint(format!("{pct_str:>6}")).to_string();
                    let desc = entry
                        .description
                        .as_deref()
                        .map(|d| format!("  ({d})"))
                        .unwrap_or_default();

                    writeln!(
                        f,
                        "  {}{}  {}  {}  {}{}",
                        LightCyan.paint(&entry.name),
                        name_pad,
                        bar_painted,
                        dur_painted,
                        pct_painted,
                        desc,
                    )?;

                    cum_ns += dur_ns;
                }
                writeln!(f)?;
            }
        }

        if self.waterfall {
            self.fmt_waterfall(f)?;
        } else {
            let width = 20;

            let mut timelines = vec![];
            // When a DoH/DoT probe ran, render DNS as two columns so the user
            // can see whether the cost was the TLS handshake or the query.
            if let Some(connect) = self.dns_connect {
                timelines.push(Timeline {
                    name: "DNS Connect".to_string(),
                    duration: connect,
                });
                if let Some(query) = self.dns_query() {
                    timelines.push(Timeline {
                        name: "DNS Query".to_string(),
                        duration: query,
                    });
                }
            } else if let Some(value) = self.dns_lookup {
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
            if let Some(value) = self.request_send {
                timelines.push(Timeline {
                    name: "Request Send".to_string(),
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

        // When any run used DoH/DoT, render DNS as two columns; otherwise keep
        // the single DNS Lookup column for the existing plain-UDP path.
        let has_dns_connect = self.stats.iter().any(|s| s.dns_connect.is_some());
        let dns_cols: Vec<(&str, Vec<Duration>)> = if has_dns_connect {
            vec![
                ("DNS Connect", self.collect_sorted(|s| s.dns_connect)),
                ("DNS Query", self.collect_sorted(|s| s.dns_query())),
            ]
        } else {
            vec![("DNS Lookup", self.collect_sorted(|s| s.dns_lookup))]
        };
        let phases: Vec<(&str, Vec<Duration>)> = dns_cols
            .into_iter()
            .chain([
                ("TCP Connect", self.collect_sorted(|s| s.tcp_connect)),
                ("TLS Handshake", self.collect_sorted(|s| s.tls_handshake)),
                ("QUIC Connect", self.collect_sorted(|s| s.quic_connect)),
                ("Request Send", self.collect_sorted(|s| s.request_send)),
                (
                    "Server Process",
                    self.collect_sorted(|s| s.server_processing),
                ),
                ("Content Xfer", self.collect_sorted(|s| s.content_transfer)),
                ("Total", self.collect_sorted(|s| s.total)),
            ])
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
