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

#[derive(Default, Debug)]
pub struct HttpStat {
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
    pub cert_not_before: Option<String>,
    pub cert_not_after: Option<String>,
    pub cert_cipher: Option<String>,
    pub cert_domains: Option<Vec<String>>,
    pub body: Option<Bytes>,
    pub headers: Option<HeaderMap<HeaderValue>>,
    pub error: Option<String>,
}

impl fmt::Display for HttpStat {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if let Some(addr) = &self.addr {
            write!(
                f,
                "{} {}\n\n",
                LightGreen.paint("Connected to"),
                LightCyan.paint(addr)
            )?;
        }
        if let Some(error) = &self.error {
            writeln!(f, "Error: {}", LightRed.paint(error))?;
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
            writeln!(f, "{}: {}", "tls".to_train_case(), LightCyan.paint(tls))?;
            writeln!(
                f,
                "{}: {}",
                "cipher".to_train_case(),
                LightCyan.paint(self.cert_cipher.clone().unwrap_or_default())
            )?;
            writeln!(
                f,
                "{}: {}",
                "not before".to_train_case(),
                LightCyan.paint(self.cert_not_before.clone().unwrap_or_default())
            )?;
            writeln!(
                f,
                "{}: {}",
                "not after".to_train_case(),
                LightCyan.paint(self.cert_not_after.clone().unwrap_or_default())
            )?;
            writeln!(f)?;
        }

        if let Some(headers) = &self.headers {
            for (key, value) in headers.iter() {
                writeln!(
                    f,
                    "{}: {}",
                    key.to_string().to_train_case(),
                    LightCyan.paint(value.to_str().unwrap_or_default())
                )?;
            }
            writeln!(f)?;
        }

        if let Some(body) = &self.body {
            let status = self.status.unwrap_or(StatusCode::OK).as_u16();
            if status >= 400 {
                let body = std::str::from_utf8(self.body.as_ref().unwrap()).unwrap_or_default();
                writeln!(f, "Body: {}", LightRed.paint(body))?;
            } else {
                let text = format!("Body discarded {} bytes", body.len());
                writeln!(f, "{}", LightCyan.paint(text))?;
            }
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
            "total:{}",
            LightCyan.paint(format_duration(self.total.unwrap_or_default()))
        )?;

        Ok(())
    }
}
