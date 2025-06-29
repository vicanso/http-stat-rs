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
use super::stats::{HttpStat, ALPN_HTTP1, ALPN_HTTP2};
use bytes::Bytes;
use http::request::Builder;
use http::HeaderValue;
use http::Request;
use http::Uri;
use http::{HeaderMap, Method};
use http_body_util::Full;
use std::net::IpAddr;
use std::str::FromStr;
use std::time::Duration;
use std::time::Instant;

// Version information from Cargo.toml
const VERSION: &str = env!("CARGO_PKG_VERSION");

// Handle request error and update statistics
pub(crate) fn finish_with_error(
    mut stat: HttpStat,
    error: impl ToString,
    start: Instant,
) -> HttpStat {
    stat.error = Some(error.to_string());
    stat.total = Some(start.elapsed());
    stat
}

// HttpRequest struct to hold request configuration
#[derive(Default, Debug, Clone)]
pub struct HttpRequest {
    pub uri: Uri,                                // Target URI
    pub method: Option<String>,                  // HTTP method (GET, POST, etc.)
    pub alpn_protocols: Vec<String>,             // Supported ALPN protocols
    pub resolve: Option<IpAddr>,                 // Custom DNS resolution
    pub headers: Option<HeaderMap<HeaderValue>>, // Custom HTTP headers
    pub ip_version: Option<i32>,                 // IP version (4 for IPv4, 6 for IPv6)
    pub skip_verify: bool,                       // Skip TLS certificate verification
    pub body: Option<Bytes>,                     // Request body
    pub dns_servers: Option<Vec<String>>,        // DNS servers
    pub dns_timeout: Option<Duration>,           // DNS resolution timeout
    pub tcp_timeout: Option<Duration>,           // TCP connection timeout
    pub tls_timeout: Option<Duration>,           // TLS handshake timeout
    pub request_timeout: Option<Duration>,       // HTTP request timeout
    pub quic_timeout: Option<Duration>,          // QUIC connection timeout
}

impl HttpRequest {
    pub fn get_port(&self) -> u16 {
        let schema = if let Some(scheme) = self.uri.scheme() {
            scheme.to_string()
        } else {
            "".to_string()
        };

        let default_port = if ["https", "grpcs"].contains(&schema.as_str()) {
            443
        } else {
            80
        };
        self.uri.port_u16().unwrap_or(default_port)
    }
    // Build HTTP request with proper headers
    pub fn builder(&self, is_http1: bool) -> Builder {
        let uri = &self.uri;
        let method = if let Some(method) = &self.method {
            Method::from_str(method).unwrap_or(Method::GET)
        } else {
            Method::GET
        };
        let mut builder = if is_http1 {
            if let Some(value) = uri.path_and_query() {
                Request::builder().uri(value.to_string())
            } else {
                Request::builder().uri(uri)
            }
        } else {
            Request::builder().uri(uri)
        };
        builder = builder.method(method);
        let mut set_host = false;
        let mut set_user_agent = false;

        // Add custom headers if provided
        if let Some(headers) = &self.headers {
            for (key, value) in headers.iter() {
                builder = builder.header(key, value);
                match key.to_string().to_lowercase().as_str() {
                    "host" => set_host = true,
                    "user-agent" => set_user_agent = true,
                    _ => {}
                }
            }
        }

        // Set default Host header if not provided
        if !set_host {
            if let Some(host) = uri.host() {
                builder = builder.header("Host", host);
            }
        }

        // Set default User-Agent if not provided
        if !set_user_agent {
            builder = builder.header("User-Agent", format!("httpstat.rs/{}", VERSION));
        }
        builder
    }
}

// Convert string URL to HttpRequest
impl TryFrom<&str> for HttpRequest {
    type Error = Error;

    fn try_from(url: &str) -> Result<Self> {
        let prefixes = ["http://", "https://", "grpc://", "grpcs://"];

        let value = if prefixes.iter().any(|prefix| url.starts_with(prefix)) {
            url.to_string()
        } else {
            format!("http://{}", url)
        };
        let uri = value.parse::<Uri>().map_err(|e| Error::Uri { source: e })?;
        Ok(Self {
            uri,
            alpn_protocols: vec![ALPN_HTTP2.to_string(), ALPN_HTTP1.to_string()],
            ..Default::default()
        })
    }
}

// Convert HttpRequest to hyper Request
impl TryFrom<&HttpRequest> for Request<Full<Bytes>> {
    type Error = Error;
    fn try_from(req: &HttpRequest) -> Result<Self> {
        req.builder(true)
            .body(Full::new(req.body.clone().unwrap_or_default()))
            .map_err(|e| Error::Http { source: e })
    }
}

pub(crate) fn build_http_request(
    req: &HttpRequest,
    is_http1: bool,
) -> Result<Request<Full<Bytes>>> {
    req.builder(is_http1)
        .body(Full::new(req.body.clone().unwrap_or_default()))
        .map_err(|e| Error::Http { source: e })
}
