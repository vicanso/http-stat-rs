#!/usr/bin/env cargo run

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
use clap::Parser;
use futures::stream::{FuturesUnordered, StreamExt};
use http::header::{HeaderMap, HeaderName, HeaderValue};
use http::StatusCode;
use http::Uri;
use http_stat::{
    connect, format_duration, proxy_bypassed, request, AltSvcCache, BenchmarkSummary, ConnectTo,
    CookieJar, DnsCache, HttpConnection, HttpRequest, HttpStat, Lang, RedirectHop, ALPN_HTTP1,
    ALPN_HTTP2, ALPN_HTTP3,
};
use std::net::IpAddr;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::Instant;
use tokio::fs;

#[cfg(target_env = "musl")]
#[global_allocator]
static GLOBAL: mimalloc::MiMalloc = mimalloc::MiMalloc;

/// HTTP statistics tool
#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// URL to request (optional, can be provided as the last argument)
    #[arg(short, long)]
    url: Option<String>,

    /// HTTP headers to set (format: "Header-Name: value")
    #[arg(
        short = 'H',
        help = "set HTTP header; repeatable: -H 'Accept: ...' -H 'Range: ...'"
    )]
    headers: Vec<String>,

    /// Force IPv4
    #[arg(short = '4', help = "resolve host to ipv4 only")]
    ipv4: bool,

    /// Force IPv6
    #[arg(short = '6', help = "resolve host to ipv6 only")]
    ipv6: bool,

    /// Skip verify tls certificate
    #[arg(short = 'k', help = "skip verify tls certificate")]
    skip_verify: bool,

    /// Output file
    #[arg(short = 'o', help = "output file")]
    output: Option<String>,

    /// follow 30x redirects
    #[arg(short = 'L', help = "follow 30x redirects")]
    follow_redirect: bool,

    /// Maximum redirects to follow with -L. Zero does not follow.
    #[arg(
        long = "max-redirs",
        help = "max redirects to follow with -L (default 10); 0 does not follow"
    )]
    max_redirs: Option<usize>,

    /// HTTP method to use (default GET)
    #[arg(short = 'X', help = "HTTP method to use (default GET)")]
    method: Option<String>,

    /// Data to send
    #[arg(
        short = 'd',
        long = "data",
        help = "request body; without -X this implies POST; from file use @filename, from stdin use @-"
    )]
    data: Option<String>,

    /// URL as positional argument
    #[arg(help = "url to request")]
    url_arg: Option<String>,

    /// Resolve host to specific IP address (format: HOST:PORT:ADDRESS)
    #[arg(
        long = "resolve",
        help = "resolve the request host to specific ip address (e.g. 1.2.3.4,1.2.3.5)"
    )]
    resolve: Option<String>,

    /// Compressed
    #[arg(
        long = "compressed",
        help = "request compressed response: gzip, br, zstd"
    )]
    compressed: bool,

    /// HTTP/3
    #[arg(long = "http3", help = "use http/3")]
    http3: bool,

    /// HTTP/2
    #[arg(long = "http2", help = "use http/2")]
    http2: bool,

    /// HTTP/1.1
    #[arg(long = "http1", help = "use http/1.1")]
    http1: bool,

    /// Auto-upgrade to HTTP/3 when the response advertises an h3 endpoint via
    /// Alt-Svc (RFC 7838), retrying the request once over h3.
    #[arg(
        long = "alt-svc",
        help = "if the response advertises HTTP/3 via Alt-Svc, retry once over h3"
    )]
    alt_svc: bool,

    /// Silent mode
    #[arg(
        short = 's',
        help = "silent mode, only output the connect address and result"
    )]
    silent: bool,
    /// DNS servers
    #[arg(
        long = "dns-servers",
        help = "dns server address to use, format: 8.8.8.8,8.8.4.4"
    )]
    dns_servers: Option<String>,
    /// Verbose mode
    #[arg(short = 'v', long = "verbose", help = "verbose mode")]
    verbose: bool,

    /// Pretty mode
    #[arg(long = "pretty", help = "pretty mode")]
    pretty: bool,

    /// Waterfall mode — show timing as a horizontal bar chart instead of columns
    #[arg(long = "waterfall", help = "show timing as a waterfall bar chart")]
    waterfall: bool,

    /// Show kernel TCP statistics (RTT, MSS, cwnd, retransmits-during-request)
    /// without needing the full --verbose dump. Linux + macOS only.
    #[arg(
        long = "tcp-info",
        help = "show kernel TCP_INFO stats (RTT, cwnd, retransmits); Linux, macOS, and Windows"
    )]
    tcp_info: bool,

    /// Display language. Accepts `en` / `zh` (case-insensitive). When
    /// omitted, falls back to LC_ALL / LC_MESSAGES / LANG, then English.
    /// JSON output always uses English keys.
    #[arg(long = "lang", help = "display language: en | zh (default: system)")]
    lang: Option<String>,

    /// Timeout
    #[arg(long = "timeout", help = "timeout")]
    timeout: Option<String>,

    /// Connection-phase timeout (DNS + TCP + TLS/QUIC). Overrides --timeout
    /// for the connection phase only; the request/response phase is unaffected.
    #[arg(
        long = "connect-timeout",
        help = "max time for the connection phase only (DNS + TCP + TLS/QUIC), e.g. 5s"
    )]
    connect_timeout: Option<String>,

    /// Overall wall-clock limit for the whole operation, including the
    /// response body and any followed redirects (like curl --max-time).
    #[arg(
        long = "max-time",
        help = "overall time limit for the whole operation, including body, redirects, retries, and Alt-Svc, e.g. 30s"
    )]
    max_time: Option<String>,

    /// Retry the request on transient failures (timeouts, connection errors,
    /// or HTTP 408/429/500/502/503/504). Useful for flaky CI gates.
    #[arg(
        long = "retry",
        help = "retry up to N times on transient failure (timeout, conn error, 408/429/5xx)"
    )]
    retry: Option<usize>,

    /// Fixed delay between retries. When omitted, exponential backoff is used
    /// (1s, 2s, 4s, ... capped at 30s).
    #[arg(
        long = "retry-delay",
        help = "fixed delay between retries (e.g. 2s); default is exponential backoff"
    )]
    retry_delay: Option<String>,

    /// Abort the transfer when the response body exceeds this size. The body
    /// is buffered in memory, so the cap protects against unbounded responses.
    #[arg(
        long = "max-filesize",
        help = "max response body size to buffer, e.g. 100MB (default 1GB); 0 = unlimited"
    )]
    max_filesize: Option<String>,

    /// Number of requests to make for benchmarking
    #[arg(
        short = 'n',
        long = "count",
        help = "number of requests for benchmarking, show min/max/avg/p50/p95/p99 stats"
    )]
    count: Option<usize>,

    /// Reuse connection in benchmark mode
    #[arg(
        short = 'K',
        long = "reuse",
        help = "reuse one connection across -n requests (HTTP/3 included); -c also reuses"
    )]
    reuse: bool,

    /// How many requests may be in flight on one multiplexed connection.
    #[arg(
        short = 'c',
        long = "concurrency",
        help = "in-flight requests on one HTTP/2 or HTTP/3 connection; if -n is omitted, -c N runs N requests"
    )]
    concurrency: Option<usize>,

    /// Cookie
    #[arg(
        short = 'b',
        long = "cookie",
        help = "send cookies: 'name=value; name2=value2' or from file use @filename"
    )]
    cookie: Option<String>,

    /// JSON output
    #[arg(long = "json", help = "output results as JSON for scripting and CI/CD")]
    json: bool,

    /// Connect-to overrides: HOST1:PORT1:HOST2:PORT2
    #[arg(
        long = "connect-to",
        help = "redirect HOST1:PORT1 to HOST2:PORT2 (repeatable); TLS SNI and Host header stay unchanged"
    )]
    connect_to: Vec<String>,

    /// Proxy URL (http://, https://, socks5://)
    #[arg(
        long = "proxy",
        help = "proxy URL: http://host:port, https://host:port, socks5://host:port"
    )]
    proxy: Option<String>,

    /// Client certificate for mTLS (PEM file path)
    #[arg(long = "cert", help = "client certificate for mTLS (PEM file)")]
    cert: Option<String>,

    /// Client private key for mTLS (PEM file path)
    #[arg(long = "key", help = "client private key for mTLS (PEM file)")]
    key: Option<String>,

    /// Bind to a specific local IP address before connecting
    #[arg(
        long = "bind",
        help = "bind to a specific local IP address (e.g. 192.168.1.100 or ::1)"
    )]
    bind: Option<String>,

    /// jq-style filter for JSON response body (e.g. ".items[].name")
    #[arg(
        long = "jq",
        help = "filter JSON response body with a jq-style selector (e.g. \".items[].name\")"
    )]
    jq: Option<String>,

    /// Include only specific response headers
    #[arg(
        long = "include-header",
        help = "only show these response headers (repeatable, case-insensitive)"
    )]
    include_header: Vec<String>,

    /// Exclude specific response headers
    #[arg(
        long = "exclude-header",
        help = "hide these response headers (repeatable, case-insensitive)"
    )]
    exclude_header: Vec<String>,
}

/// Load config from ~/.httpstatrc (JSON object). Silently ignored if absent.
fn load_config() -> serde_json::Map<String, serde_json::Value> {
    let path = std::env::var("HOME")
        .or_else(|_| std::env::var("USERPROFILE"))
        .ok()
        .map(|h| std::path::PathBuf::from(h).join(".httpstatrc"));
    let Some(path) = path else {
        return serde_json::Map::new();
    };
    let content = match std::fs::read_to_string(&path) {
        Ok(c) => c,
        Err(_) => return serde_json::Map::new(),
    };
    match serde_json::from_str::<serde_json::Value>(&content) {
        Ok(serde_json::Value::Object(map)) => map,
        Ok(_) => {
            eprintln!("httpstat: ~/.httpstatrc must be a JSON object, ignoring");
            serde_json::Map::new()
        }
        Err(e) => {
            eprintln!("httpstat: failed to parse ~/.httpstatrc: {e}, ignoring");
            serde_json::Map::new()
        }
    }
}

/// Apply config file defaults to args where CLI did not provide a value.
fn apply_config(args: &mut Args, cfg: &serde_json::Map<String, serde_json::Value>) {
    macro_rules! cfg_bool {
        ($field:ident) => {
            if !args.$field {
                if let Some(true) = cfg.get(stringify!($field)).and_then(|v| v.as_bool()) {
                    args.$field = true;
                }
            }
        };
    }
    macro_rules! cfg_opt_str {
        ($field:ident) => {
            if args.$field.is_none() {
                if let Some(s) = cfg.get(stringify!($field)).and_then(|v| v.as_str()) {
                    args.$field = Some(s.to_string());
                }
            }
        };
    }
    // Booleans: config is applied only when CLI left them false (no negation flags exist)
    cfg_bool!(compressed);
    cfg_bool!(verbose);
    cfg_bool!(pretty);
    cfg_bool!(silent);
    cfg_bool!(follow_redirect);
    cfg_bool!(skip_verify);
    cfg_bool!(http1);
    cfg_bool!(http2);
    cfg_bool!(http3);
    cfg_bool!(json);
    cfg_bool!(alt_svc);
    cfg_bool!(waterfall);
    cfg_bool!(tcp_info);
    cfg_bool!(reuse);
    // Optional strings: config fills in when CLI left them None
    cfg_opt_str!(dns_servers);
    cfg_opt_str!(timeout);
    cfg_opt_str!(connect_timeout);
    cfg_opt_str!(max_time);
    cfg_opt_str!(retry_delay);
    cfg_opt_str!(max_filesize);
    cfg_opt_str!(cookie);
    cfg_opt_str!(output);
    cfg_opt_str!(proxy);
    cfg_opt_str!(bind);
    cfg_opt_str!(lang);
    macro_rules! cfg_opt_usize {
        ($field:ident) => {
            if args.$field.is_none() {
                if let Some(n) = cfg.get(stringify!($field)).and_then(|v| v.as_u64()) {
                    args.$field = Some(n as usize);
                }
            }
        };
    }
    cfg_opt_usize!(concurrency);
    cfg_opt_usize!(max_redirs);
    // Numeric: retry count
    if args.retry.is_none() {
        if let Some(n) = cfg.get("retry").and_then(|v| v.as_u64()) {
            args.retry = Some(n as usize);
        }
    }
    // Vecs: config values are prepended (CLI values take precedence / extend)
    for key in &["headers", "include_header", "exclude_header"] {
        if let Some(arr) = cfg.get(*key).and_then(|v| v.as_array()) {
            let defaults: Vec<String> = arr
                .iter()
                .filter_map(|v| v.as_str())
                .map(|s| s.to_string())
                .collect();
            if !defaults.is_empty() {
                let field = match *key {
                    "headers" => &mut args.headers,
                    "include_header" => &mut args.include_header,
                    _ => &mut args.exclude_header,
                };
                // prepend config defaults; CLI-provided values come after
                let mut merged = defaults;
                merged.append(field);
                *field = merged;
            }
        }
    }
    if let Some(arr) = cfg.get("connect_to").and_then(|v| v.as_array()) {
        let defaults: Vec<String> = arr
            .iter()
            .filter_map(|v| v.as_str())
            .map(|s| s.to_string())
            .collect();
        if !defaults.is_empty() {
            let mut merged = defaults;
            merged.append(&mut args.connect_to);
            args.connect_to = merged;
        }
    }
}

fn with_jar<T>(jar: &Mutex<CookieJar>, f: impl FnOnce(&mut CookieJar) -> T) -> T {
    let mut guard = jar.lock().unwrap_or_else(|e| e.into_inner());
    f(&mut guard)
}

fn apply_jar(req: &mut HttpRequest, jar: &mut CookieJar) {
    if let Some(headers) = req.headers.as_mut() {
        headers.remove(http::header::COOKIE);
    }
    let Some(value) = jar.header_for(&req.uri) else {
        return;
    };
    let Ok(header) = HeaderValue::from_str(&value) else {
        return;
    };
    req.headers
        .get_or_insert_with(HeaderMap::new)
        .insert(http::header::COOKIE, header);
}

fn store_response_cookies(jar: &mut CookieJar, uri: &Uri, stat: &HttpStat) {
    let Some(headers) = &stat.headers else {
        return;
    };
    for value in headers.get_all(http::header::SET_COOKIE) {
        if let Ok(raw) = value.to_str() {
            jar.store_set_cookie(uri, raw);
        }
    }
}

/// Decide whether a redirect with `status` should rewrite the request to GET
/// and drop its body, matching curl/browser behavior:
/// - 303 See Other: switch to GET, except HEAD stays HEAD (RFC 9110 §15.4.4)
/// - 301/302: downgrade POST to GET (de-facto web convention)
/// - 307/308: preserve the method and body verbatim
fn redirect_downgrades_to_get(status: StatusCode, method: &str) -> bool {
    match status {
        StatusCode::SEE_OTHER => !method.eq_ignore_ascii_case("HEAD"),
        StatusCode::MOVED_PERMANENTLY | StatusCode::FOUND => method.eq_ignore_ascii_case("POST"),
        _ => false,
    }
}

/// RFC 3986 §5.2.4. An empty input stays empty so an absolute URL with no
/// path is left alone; a reference that collapses to nothing becomes `/`.
fn remove_dot_segments(path: &str) -> String {
    if path.is_empty() {
        return String::new();
    }
    let mut input = path.to_string();
    let mut output = String::new();
    while !input.is_empty() {
        if let Some(rest) = input.strip_prefix("../") {
            input = rest.to_string();
        } else if let Some(rest) = input.strip_prefix("./") {
            input = rest.to_string();
        } else if let Some(rest) = input.strip_prefix("/./") {
            input = format!("/{rest}");
        } else if input == "/." {
            input = "/".to_string();
        } else if let Some(rest) = input.strip_prefix("/../") {
            input = format!("/{rest}");
            remove_last_segment(&mut output);
        } else if input == "/.." {
            input = "/".to_string();
            remove_last_segment(&mut output);
        } else if input == "." || input == ".." {
            input.clear();
        } else {
            let (seg, rest) = split_first_segment(&input);
            output.push_str(seg);
            input = rest.to_string();
        }
    }
    if output.is_empty() {
        "/".to_string()
    } else {
        output
    }
}

fn remove_last_segment(output: &mut String) {
    match output.rfind('/') {
        Some(i) => output.truncate(i),
        None => output.clear(),
    }
}

/// First path segment, including a leading `/`, up to but not including the
/// next `/`.
fn split_first_segment(input: &str) -> (&str, &str) {
    let start_rest = usize::from(input.starts_with('/'));
    let rest = &input[start_rest..];
    match rest.find('/') {
        Some(i) => {
            let end = start_rest + i;
            (&input[..end], &input[end..])
        }
        None => (input, ""),
    }
}

fn normalize_absolute(uri: Uri) -> Option<Uri> {
    let path = uri.path();
    if !path.contains('.') {
        return Some(uri);
    }
    let normalized = remove_dot_segments(path);
    if normalized == path {
        return Some(uri);
    }
    let query = uri.query().map(str::to_string);
    let mut parts = uri.into_parts();
    let pq = match query {
        Some(q) => format!("{normalized}?{q}"),
        None => normalized,
    };
    parts.path_and_query = Some(pq.parse().ok()?);
    Uri::from_parts(parts).ok()
}

/// Resolve a redirect `Location` against the request's current URI.
/// Covers absolute URLs, scheme-relative (`//host/path`), absolute-path, and
/// relative-path references. Dot segments are removed (RFC 3986 §5.2.4), the
/// query is preserved, and any fragment is dropped.
/// Returns `None` for an empty location or when the base lacks scheme/authority.
fn resolve_redirect(base: &Uri, location: &str) -> Option<Uri> {
    let location = location.trim();
    if location.is_empty() {
        return None;
    }
    let location = location
        .split_once('#')
        .map(|(head, _)| head)
        .unwrap_or(location);
    if location.is_empty() {
        return None;
    }
    if let Ok(uri) = location.parse::<Uri>() {
        if uri.scheme().is_some() && uri.authority().is_some() {
            return normalize_absolute(uri);
        }
    }
    let (path_ref, query) = match location.split_once('?') {
        Some((path, query)) => (path, Some(query)),
        None => (location, None),
    };
    let scheme = base.scheme_str()?;
    let authority = base.authority()?.as_str();
    if let Some(rest) = path_ref.strip_prefix("//") {
        let absolute = match query {
            Some(q) => format!("{scheme}://{rest}?{q}"),
            None => format!("{scheme}://{rest}"),
        };
        return absolute.parse::<Uri>().ok().and_then(normalize_absolute);
    }
    let merged = if path_ref.starts_with('/') {
        remove_dot_segments(path_ref)
    } else {
        let base_path = base.path();
        let dir = if base_path.is_empty() {
            "/"
        } else {
            match base_path.rfind('/') {
                Some(i) => &base_path[..=i],
                None => "/",
            }
        };
        remove_dot_segments(&format!("{dir}{path_ref}"))
    };
    let path = if merged.is_empty() {
        "/"
    } else {
        merged.as_str()
    };
    let full = match query {
        Some(q) => format!("{scheme}://{authority}{path}?{q}"),
        None => format!("{scheme}://{authority}{path}"),
    };
    full.parse().ok()
}

fn is_redirect_status(status: StatusCode) -> bool {
    matches!(
        status,
        StatusCode::MOVED_PERMANENTLY
            | StatusCode::FOUND
            | StatusCode::SEE_OTHER
            | StatusCode::TEMPORARY_REDIRECT
            | StatusCode::PERMANENT_REDIRECT
    )
}

fn method_uri_key(req: &HttpRequest) -> String {
    format!(
        "{} {}",
        req.method.as_deref().unwrap_or("GET").to_ascii_uppercase(),
        req.uri
    )
}

fn redirect_hop(url: &str, stat: &HttpStat) -> RedirectHop {
    RedirectHop {
        url: url.to_string(),
        status: stat.status.map(|s| s.as_u16()).unwrap_or(0),
        dns_lookup: stat.dns_lookup,
        dns_connect: stat.dns_connect,
        tcp_connect: stat.tcp_connect,
        tls_handshake: stat.tls_handshake,
        quic_connect: stat.quic_connect,
        proxy_connect: stat.proxy_connect,
        proxy_handshake: stat.proxy_handshake,
        request_send: stat.request_send,
        server_processing: stat.server_processing,
        content_transfer: stat.content_transfer,
        total: stat.total,
    }
}

async fn do_request(
    mut req: HttpRequest,
    follow_redirect: bool,
    max_redirs: usize,
    jar: &Mutex<CookieJar>,
) -> HttpStat {
    let chain_start = Instant::now();
    let mut seen = std::collections::HashSet::new();
    seen.insert(method_uri_key(&req));
    with_jar(jar, |j| apply_jar(&mut req, j));
    let mut stat = request(req.clone()).await;
    with_jar(jar, |j| store_response_cookies(j, &req.uri, &stat));

    let mut hops = Vec::new();
    if follow_redirect && max_redirs > 0 {
        let mut followed = 0usize;
        while let Some(status) = stat.status {
            if !is_redirect_status(status) {
                break;
            }
            if followed >= max_redirs {
                eprintln!(
                    "httpstat: stopped after {max_redirs} redirect(s); increase --max-redirs to follow further"
                );
                break;
            }
            let location = stat
                .headers
                .as_ref()
                .and_then(|header| header.get(http::header::LOCATION))
                .and_then(|value| value.to_str().ok())
                .unwrap_or("")
                .to_string();
            let Some(new_uri) = resolve_redirect(&req.uri, &location) else {
                break;
            };

            let current_method = req.method.as_deref().unwrap_or("GET");
            if redirect_downgrades_to_get(status, current_method) {
                req.method = Some("GET".to_string());
                req.body = None;
                if let Some(h) = req.headers.as_mut() {
                    h.remove(http::header::CONTENT_TYPE);
                    h.remove(http::header::CONTENT_LENGTH);
                    h.remove(http::header::TRANSFER_ENCODING);
                }
            }

            let same_host = req
                .uri
                .host()
                .unwrap_or_default()
                .eq_ignore_ascii_case(new_uri.host().unwrap_or_default());
            if !same_host {
                if let Some(h) = req.headers.as_mut() {
                    h.remove(http::header::AUTHORIZATION);
                }
                req.resolve = None;
            }

            let hop_url = req.uri.to_string();
            req.uri = new_uri;
            if !seen.insert(method_uri_key(&req)) {
                stat.error = Some(format!(
                    "redirect loop detected for {} {}",
                    req.method.as_deref().unwrap_or("GET"),
                    req.uri
                ));
                break;
            }

            hops.push(redirect_hop(&hop_url, &stat));
            with_jar(jar, |j| apply_jar(&mut req, j));
            stat = request(req.clone()).await;
            with_jar(jar, |j| store_response_cookies(j, &req.uri, &stat));
            followed += 1;
        }
    }
    if !hops.is_empty() {
        stat.redirects = hops;
        stat.chain_total = Some(chain_start.elapsed());
    }
    stat
}

fn benchmark_to_json(stats: &[HttpStat], connect_stat: Option<&HttpStat>) -> serde_json::Value {
    let dur_us = |d: Option<std::time::Duration>| -> serde_json::Value {
        d.map_or(serde_json::Value::Null, |d| {
            serde_json::json!(d.as_micros() as u64)
        })
    };

    let calc = |f: fn(&HttpStat) -> Option<std::time::Duration>| -> Vec<std::time::Duration> {
        let mut v: Vec<std::time::Duration> = stats.iter().filter_map(f).collect();
        v.sort();
        v
    };

    let stat_obj = |sorted: &[std::time::Duration]| -> serde_json::Value {
        if sorted.is_empty() {
            return serde_json::Value::Null;
        }
        let sum: std::time::Duration = sorted.iter().sum();
        let avg = sum / sorted.len() as u32;
        let p = |pct: f64| -> u64 {
            let idx = ((pct * sorted.len() as f64).ceil() as usize)
                .saturating_sub(1)
                .min(sorted.len() - 1);
            sorted[idx].as_micros() as u64
        };
        serde_json::json!({
            "min_us": sorted.first().unwrap().as_micros() as u64,
            "max_us": sorted.last().unwrap().as_micros() as u64,
            "avg_us": avg.as_micros() as u64,
            "p50_us": p(0.5),
            "p95_us": p(0.95),
            "p99_us": p(0.99),
        })
    };

    let success = stats.iter().filter(|s| s.is_success()).count();
    let total = stats.len();

    let mut obj = serde_json::json!({
        "count": total,
        "success": success,
        "timing": {
            "dns_lookup": stat_obj(&calc(|s| s.dns_lookup)),
            "tcp_connect": stat_obj(&calc(|s| s.tcp_connect)),
            "tls_handshake": stat_obj(&calc(|s| s.tls_handshake)),
            "quic_connect": stat_obj(&calc(|s| s.quic_connect)),
            "server_processing": stat_obj(&calc(|s| s.server_processing)),
            "content_transfer": stat_obj(&calc(|s| s.content_transfer)),
            "request_send": stat_obj(&calc(|s| s.request_send)),
            "total": stat_obj(&calc(|s| s.total)),
        },
    });

    let mut rates: Vec<f64> = stats.iter().filter_map(|s| s.throughput_bps()).collect();
    rates.sort_by(|a, b| a.total_cmp(b));
    obj["throughput"] = if rates.is_empty() {
        serde_json::Value::Null
    } else {
        let sum: f64 = rates.iter().sum();
        let avg = sum / rates.len() as f64;
        let at = |pct: f64| -> f64 {
            let idx = ((pct * rates.len() as f64).ceil() as usize)
                .saturating_sub(1)
                .min(rates.len() - 1);
            rates[idx]
        };
        serde_json::json!({
            "bps_total": {
                "min": rates[0],
                "max": rates[rates.len() - 1],
                "avg": avg,
                "p50": at(0.5),
                "p95": at(0.95),
                "p99": at(0.99),
            }
        })
    };

    if let Some(cs) = connect_stat {
        obj["cold_connect"] = serde_json::json!({
            "dns_lookup_us": dur_us(cs.dns_lookup),
            "tcp_connect_us": dur_us(cs.tcp_connect),
            "tls_handshake_us": dur_us(cs.tls_handshake),
            "quic_connect_us": dur_us(cs.quic_connect),
            "total_us": dur_us(cs.total),
        });
    }

    obj
}

async fn handle_output(body: Option<Bytes>, output: Option<String>) {
    let Some(output) = output else {
        return;
    };
    let Some(body) = body else {
        return;
    };
    if let Err(e) = fs::write(output, body).await {
        println!("write output error: {e}");
    }
}

/// Parse a humantime duration (e.g. `5s`, `1m30s`), exiting with a clear
/// message on a malformed value. `name` is the flag name for the error text.
fn parse_dur(name: &str, value: &str) -> std::time::Duration {
    match value.parse::<humantime::Duration>() {
        Ok(d) => d.into(),
        Err(e) => {
            eprintln!("httpstat: invalid {name} '{value}': {e}");
            std::process::exit(1);
        }
    }
}

/// Default response-body cap applied when `--max-filesize` isn't given:
/// generous enough for any diagnostic use, small enough to keep a hostile
/// endless body from OOMing the process.
const DEFAULT_MAX_FILESIZE: u64 = 1024 * 1024 * 1024; // 1 GiB

/// Parse a human byte size (e.g. `100MB`, `1GiB`, `52428800`), exiting with a
/// clear message on a malformed value. `name` is the flag name for the error.
fn parse_size(name: &str, value: &str) -> u64 {
    match value.trim().parse::<bytesize::ByteSize>() {
        Ok(v) => v.as_u64(),
        Err(e) => {
            eprintln!("httpstat: invalid {name} '{value}': {e}");
            std::process::exit(1);
        }
    }
}

/// Resolve `--max-filesize` into the request's body cap: default 1 GiB,
/// explicit `0` disables the limit entirely.
fn resolve_max_filesize(arg: Option<&str>) -> Option<usize> {
    match arg {
        None => Some(DEFAULT_MAX_FILESIZE as usize),
        Some(v) => {
            let n = parse_size("max-filesize", v);
            if n == 0 {
                None
            } else {
                Some(n as usize)
            }
        }
    }
}

/// Synthesize the `HttpStat` returned when `--max-time` is exceeded. The error
/// text contains "timeout" so `exit_code()` maps it to the timeout code (5).
fn max_time_error_stat(d: std::time::Duration) -> HttpStat {
    HttpStat {
        total: Some(d),
        error: Some(format!(
            "timeout: exceeded --max-time of {}",
            format_duration(d)
        )),
        ..Default::default()
    }
}

/// Run `fut` under an optional overall wall-clock deadline. When `max_time`
/// elapses first, the in-flight request is cancelled and a timeout `HttpStat`
/// is returned instead (mirroring curl --max-time).
async fn with_max_time<F>(fut: F, max_time: Option<std::time::Duration>) -> HttpStat
where
    F: std::future::Future<Output = HttpStat>,
{
    match max_time {
        Some(d) => match tokio::time::timeout(d, fut).await {
            Ok(stat) => stat,
            Err(_) => max_time_error_stat(d),
        },
        None => fut.await,
    }
}

/// Whether a result is worth retrying. With an HTTP response we only retry the
/// transient status codes (curl's default set). Without a response we retry
/// transient connection failures — timeouts and TCP errors — but not DNS or
/// TLS/cert failures, where a retry won't help.
fn is_retryable(stat: &HttpStat) -> bool {
    if let Some(status) = stat.status {
        return matches!(status.as_u16(), 408 | 429 | 500 | 502 | 503 | 504);
    }
    if stat.error.is_some() {
        // 1 = generic (e.g. connection reset), 3 = TCP connect, 5 = timeout.
        return matches!(stat.exit_code(), 1 | 3 | 5);
    }
    false
}

/// Exponential backoff for retry attempt `n` (0-based): 1s, 2s, 4s, ...
/// capped at 30s.
fn backoff_delay(n: usize) -> std::time::Duration {
    let secs = (1u64 << n.min(5)).min(30);
    std::time::Duration::from_secs(secs)
}

/// One wall-clock budget for a logical request, including retries, backoff,
/// and an Alt-Svc upgrade. `limit` is the original `--max-time`.
#[derive(Clone, Copy)]
struct TimeBudget {
    deadline: Instant,
    limit: std::time::Duration,
}

fn fresh_budget(max_time: Option<std::time::Duration>) -> Option<TimeBudget> {
    max_time.map(|limit| TimeBudget {
        deadline: Instant::now() + limit,
        limit,
    })
}

fn budget_expired(budget: Option<TimeBudget>) -> Option<HttpStat> {
    let budget = budget?;
    if Instant::now() >= budget.deadline {
        Some(max_time_error_stat(budget.limit))
    } else {
        None
    }
}

/// Sleep `delay`, but not past `budget`. Returns true when the deadline won
/// and the caller should surface a `--max-time` timeout.
async fn sleep_within_budget(delay: std::time::Duration, budget: Option<TimeBudget>) -> bool {
    let Some(budget) = budget else {
        tokio::time::sleep(delay).await;
        return false;
    };
    let now = Instant::now();
    if now >= budget.deadline {
        return true;
    }
    let left = budget.deadline.saturating_duration_since(now);
    if delay >= left {
        tokio::time::sleep(left).await;
        true
    } else {
        tokio::time::sleep(delay).await;
        false
    }
}

/// Run an operation with up to `retries` retries on transient failure. `make`
/// builds a fresh operation future per attempt. `budget`, when set, covers
/// every attempt and the backoff between them.
async fn run_with_retry<F, Fut>(
    mut make: F,
    retries: usize,
    retry_delay: Option<std::time::Duration>,
    budget: Option<TimeBudget>,
) -> HttpStat
where
    F: FnMut() -> Fut,
    Fut: std::future::Future<Output = HttpStat>,
{
    let mut attempt = 0usize;
    loop {
        if let Some(stat) = budget_expired(budget) {
            return stat;
        }
        let fut = make();
        let stat = if let Some(budget) = budget {
            let left = budget.deadline.saturating_duration_since(Instant::now());
            if left.is_zero() {
                return max_time_error_stat(budget.limit);
            }
            match tokio::time::timeout(left, fut).await {
                Ok(stat) => stat,
                Err(_) => return max_time_error_stat(budget.limit),
            }
        } else {
            fut.await
        };
        if attempt >= retries || !is_retryable(&stat) {
            return stat;
        }
        let delay = retry_delay.unwrap_or_else(|| backoff_delay(attempt));
        let reason = stat
            .status
            .map(|s| format!("HTTP {}", s.as_u16()))
            .or_else(|| stat.error.clone())
            .unwrap_or_else(|| "request failed".to_string());
        eprintln!(
            "httpstat: attempt {}/{} failed ({reason}); retrying in {}",
            attempt + 1,
            retries + 1,
            format_duration(delay)
        );
        if sleep_within_budget(delay, budget).await {
            let limit = budget.map(|b| b.limit).unwrap_or(delay);
            return max_time_error_stat(limit);
        }
        attempt += 1;
    }
}

/// Parse an Alt-Svc `authority` (`[host]:port`, host optional) into
/// `(host, port)`. An empty host means "same as the origin".
fn parse_alt_authority(authority: &str) -> Option<(String, u16)> {
    let (host, port_str) = authority.rsplit_once(':')?;
    let port: u16 = port_str.trim().parse().ok()?;
    let host = host.trim().trim_start_matches('[').trim_end_matches(']');
    Some((host.to_string(), port))
}

/// Find an advertised HTTP/3 endpoint in a response's `Alt-Svc` list, if any.
#[cfg_attr(not(test), allow(dead_code))]
fn h3_endpoint(stat: &HttpStat) -> Option<(String, u16)> {
    stat.alt_svc
        .as_ref()?
        .iter()
        .find(|e| e.protocol == "h3")
        .and_then(|e| parse_alt_authority(&e.authority))
}

/// HTTP/3 advertisement plus `ma`. `ma=0` is skipped. A missing `ma` uses the
/// RFC 7838 default of 24 hours so the on-disk cache can still expire.
fn h3_advertisement(stat: &HttpStat) -> Option<(String, u16, u64)> {
    let entry = stat.alt_svc.as_ref()?.iter().find(|e| e.protocol == "h3")?;
    let (host, port) = parse_alt_authority(&entry.authority)?;
    let max_age = match entry.max_age {
        Some(0) => return None,
        Some(ma) => ma,
        None => 24 * 60 * 60,
    };
    Some((host, port, max_age))
}

fn alt_svc_cleared(stat: &HttpStat) -> bool {
    stat.alt_svc.as_ref().is_some_and(|entries| {
        entries
            .iter()
            .any(|e| e.protocol == "h3" && e.max_age == Some(0))
    })
}

/// Format an Alt-Svc endpoint for display (`:443`, `host:443`, `[::1]:443`).
fn fmt_alt_endpoint(host: &str, port: u16) -> String {
    if host.is_empty() {
        format!(":{port}")
    } else if host.contains(':') {
        format!("[{host}]:{port}")
    } else {
        format!("{host}:{port}")
    }
}

/// Rewrite `req` to attempt the advertised HTTP/3 endpoint: force the h3 ALPN
/// and, when the endpoint differs from the origin, add a connect-to override so
/// the TCP/QUIC target changes while TLS SNI and the Host header stay on the
/// origin (the Alt-Svc contract).
fn apply_alt_endpoint(req: &mut HttpRequest, alt_host: &str, alt_port: u16) {
    req.alpn_protocols = vec![ALPN_HTTP3.to_string()];
    let origin_host = req.uri.host().unwrap_or("").to_string();
    let origin_port = req.get_port();
    let target_host = if alt_host.is_empty() {
        origin_host.as_str()
    } else {
        alt_host
    };
    if target_host != origin_host || alt_port != origin_port {
        req.connect_to = vec![format!(
            "{}:{}",
            fmt_alt_endpoint(&origin_host, origin_port),
            fmt_alt_endpoint(target_host, alt_port)
        )];
    }
}

/// Per-invocation options shared by the single-request and `--resolve` paths.
struct RunOpts {
    follow_redirect: bool,
    max_redirs: usize,
    max_time: Option<std::time::Duration>,
    retries: usize,
    retry_delay: Option<std::time::Duration>,
    alt_svc: bool,
    alt_cache: Option<Arc<Mutex<AltSvcCache>>>,
    jar: Arc<Mutex<CookieJar>>,
    concurrency: usize,
}

fn remember_advertised_alt(opts: &RunOpts, origin_host: &str, origin_port: u16, stat: &HttpStat) {
    let Some(cache) = &opts.alt_cache else {
        return;
    };
    let mut cache = cache.lock().unwrap_or_else(|e| e.into_inner());
    if alt_svc_cleared(stat) {
        cache.invalidate(origin_host, origin_port);
        return;
    }
    if let Some((host, port, max_age)) = h3_advertisement(stat) {
        cache.put(origin_host, origin_port, &host, port, max_age);
    }
}

fn invalidate_alt(opts: &RunOpts, origin_host: &str, origin_port: u16) {
    if let Some(cache) = &opts.alt_cache {
        cache
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .invalidate(origin_host, origin_port);
    }
}

fn cached_alt(opts: &RunOpts, origin_host: &str, origin_port: u16) -> Option<(String, u16)> {
    let cache = opts.alt_cache.as_ref()?;
    cache
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .get(origin_host, origin_port)
}

/// Run one request through retry + one shared `--max-time` budget, then
/// optionally upgrade to HTTP/3. The upgrade uses the same deadline.
async fn run_request(mut req: HttpRequest, opts: &RunOpts) -> HttpStat {
    let origin_host = req.uri.host().unwrap_or("").to_string();
    let origin_port = req.get_port();
    let mut forced_h3 = req.alpn_protocols.iter().any(|p| p == ALPN_HTTP3);
    if opts.alt_svc && !forced_h3 {
        if let Some((host, port)) = cached_alt(opts, &origin_host, origin_port) {
            apply_alt_endpoint(&mut req, &host, port);
            forced_h3 = true;
        }
    }

    let budget = fresh_budget(opts.max_time);
    let stat = run_with_retry(
        || {
            with_max_time(
                do_request(
                    req.clone(),
                    opts.follow_redirect,
                    opts.max_redirs,
                    &opts.jar,
                ),
                opts.max_time,
            )
        },
        opts.retries,
        opts.retry_delay,
        budget,
    )
    .await;
    remember_advertised_alt(opts, &origin_host, origin_port, &stat);

    if forced_h3 && stat.error.is_some() {
        invalidate_alt(opts, &origin_host, origin_port);
    }
    if !opts.alt_svc || forced_h3 {
        return stat;
    }
    let Some((host, port, _)) = h3_advertisement(&stat) else {
        return stat;
    };

    let mut h3_req = req;
    apply_alt_endpoint(&mut h3_req, &host, port);
    let h3_stat = run_with_retry(
        || {
            with_max_time(
                do_request(
                    h3_req.clone(),
                    opts.follow_redirect,
                    opts.max_redirs,
                    &opts.jar,
                ),
                opts.max_time,
            )
        },
        opts.retries,
        opts.retry_delay,
        budget,
    )
    .await;

    if h3_stat.error.is_none() {
        eprintln!(
            "alt-svc: upgraded to HTTP/3 via {}",
            fmt_alt_endpoint(&host, port)
        );
        h3_stat
    } else {
        eprintln!(
            "alt-svc: HTTP/3 upgrade to {} failed ({}); showing original result",
            fmt_alt_endpoint(&host, port),
            h3_stat.error.as_deref().unwrap_or("unknown")
        );
        invalidate_alt(opts, &origin_host, origin_port);
        stat
    }
}

fn stamp_reused(stat: &mut HttpStat, connect: &HttpStat) {
    stat.addr.clone_from(&connect.addr);
    stat.alpn.clone_from(&connect.alpn);
    stat.tls_resumed = connect.tls_resumed;
    stat.tls_early_data_accepted = connect.tls_early_data_accepted;
    stat.dns_cached = connect.dns_cached;
}

async fn indexed_multiplex(
    index: usize,
    shared: Arc<Mutex<HttpConnection>>,
    req: HttpRequest,
    max_time: Option<std::time::Duration>,
    retries: usize,
    retry_delay: Option<std::time::Duration>,
    budget: Option<TimeBudget>,
) -> (usize, HttpStat) {
    let stat = run_with_retry(
        || {
            let shared = Arc::clone(&shared);
            let req = req.clone();
            async move {
                let worker = {
                    let guard = shared.lock().unwrap_or_else(|e| e.into_inner());
                    guard.worker()
                };
                match worker {
                    Some(worker) => with_max_time(worker.send(&req), max_time).await,
                    None => HttpStat {
                        error: Some("http connection cannot multiplex".into()),
                        ..Default::default()
                    },
                }
            }
        },
        retries,
        retry_delay,
        budget,
    )
    .await;
    (index, stat)
}

/// One uncounted request so `-K` / `-c` can open HTTP/3 directly when Alt-Svc
/// (or the on-disk cache) already names an endpoint.
async fn learn_alt_svc_for_reuse(req: &mut HttpRequest, opts: &RunOpts) {
    if !opts.alt_svc || req.alpn_protocols.iter().any(|p| p == ALPN_HTTP3) {
        return;
    }
    let origin_host = req.uri.host().unwrap_or("").to_string();
    let origin_port = req.get_port();
    if let Some((host, port)) = cached_alt(opts, &origin_host, origin_port) {
        apply_alt_endpoint(req, &host, port);
        return;
    }
    eprintln!(
        "alt-svc: probing {} once to learn an HTTP/3 endpoint (not counted)",
        req.uri
    );
    let _probe = run_request(req.clone(), opts).await;
    if let Some((host, port)) = cached_alt(opts, &origin_host, origin_port) {
        apply_alt_endpoint(req, &host, port);
    }
}

fn print_cold_connect(connect_stat: &HttpStat, lang: Lang) {
    let mut parts = vec![];
    if let Some(d) = connect_stat.dns_lookup {
        parts.push(format!("DNS {}", format_duration(d)));
    }
    if let Some(d) = connect_stat.tcp_connect {
        parts.push(format!("TCP {}", format_duration(d)));
    }
    if let Some(d) = connect_stat.tls_handshake {
        parts.push(format!("TLS {}", format_duration(d)));
    }
    if let Some(d) = connect_stat.quic_connect {
        parts.push(format!("QUIC {}", format_duration(d)));
    }
    println!(
        "  {}: {} ({})",
        lang.strings().cold_connect,
        format_duration(connect_stat.total.unwrap_or_default()),
        parts.join(" + ")
    );
}

fn print_benchmark(
    stats: Vec<HttpStat>,
    connect_stat: Option<&HttpStat>,
    lang: Lang,
    json_output: bool,
) {
    if json_output {
        let json_val = benchmark_to_json(&stats, connect_stat);
        println!(
            "{}",
            serde_json::to_string_pretty(&json_val).unwrap_or_default()
        );
    } else {
        let summary = BenchmarkSummary { stats, lang };
        println!("{summary}");
        if let Some(connect_stat) = connect_stat {
            print_cold_connect(connect_stat, lang);
        }
    }
}

async fn sequential_reused(
    conn: HttpConnection,
    req: &HttpRequest,
    count: usize,
    opts: &RunOpts,
    connect_stat: &HttpStat,
    lang: Lang,
    json_output: bool,
) -> (Vec<HttpStat>, i32) {
    let shared = Arc::new(tokio::sync::Mutex::new(conn));
    let width = count.to_string().len();
    let mut stats = Vec::with_capacity(count);
    let mut exit_code = 0i32;
    for i in 0..count {
        let budget = fresh_budget(opts.max_time);
        let mut stat = run_with_retry(
            {
                let shared = Arc::clone(&shared);
                let req = req.clone();
                let max_time = opts.max_time;
                move || {
                    let shared = Arc::clone(&shared);
                    let req = req.clone();
                    async move {
                        let mut guard = shared.lock().await;
                        with_max_time(guard.send(&req), max_time).await
                    }
                }
            },
            opts.retries,
            opts.retry_delay,
            budget,
        )
        .await;
        stamp_reused(&mut stat, connect_stat);
        stat.silent = true;
        stat.lang = lang;
        stat.body = None;
        if !json_output {
            print!("[{:>width$}/{count}] {stat}", i + 1);
        }
        if exit_code == 0 {
            exit_code = stat.exit_code();
        }
        stats.push(stat);
    }
    (stats, exit_code)
}

async fn concurrent_reused(
    conn: HttpConnection,
    req: &HttpRequest,
    count: usize,
    opts: &RunOpts,
    connect_stat: &HttpStat,
    lang: Lang,
    json_output: bool,
) -> (Vec<HttpStat>, i32) {
    let shared = Arc::new(Mutex::new(conn));
    let mut pending = FuturesUnordered::new();
    let mut next = 0usize;
    while next < count && pending.len() < opts.concurrency {
        let budget = fresh_budget(opts.max_time);
        pending.push(indexed_multiplex(
            next,
            Arc::clone(&shared),
            req.clone(),
            opts.max_time,
            opts.retries,
            opts.retry_delay,
            budget,
        ));
        next += 1;
    }
    let width = count.to_string().len();
    let mut slots = Vec::with_capacity(count);
    slots.resize_with(count, || None);
    while let Some((idx, mut stat)) = pending.next().await {
        stamp_reused(&mut stat, connect_stat);
        stat.silent = true;
        stat.lang = lang;
        stat.body = None;
        if !json_output {
            print!("[{:>width$}/{count}] {stat}", idx + 1);
        }
        slots[idx] = Some(stat);
        if next < count {
            let budget = fresh_budget(opts.max_time);
            pending.push(indexed_multiplex(
                next,
                Arc::clone(&shared),
                req.clone(),
                opts.max_time,
                opts.retries,
                opts.retry_delay,
                budget,
            ));
            next += 1;
        }
    }
    let mut exit_code = 0i32;
    let mut stats = Vec::with_capacity(count);
    for slot in slots {
        let stat = slot.unwrap_or_default();
        if exit_code == 0 {
            exit_code = stat.exit_code();
        }
        stats.push(stat);
    }
    (stats, exit_code)
}

#[tokio::main(flavor = "current_thread")]
async fn main() {
    let mut args = Args::parse();
    let config = load_config();
    apply_config(&mut args, &config);

    // Resolve the effective display language once. Explicit --lang wins;
    // otherwise we sniff LC_ALL / LC_MESSAGES / LANG and fall back to English.
    let lang = match args.lang.as_deref() {
        Some(v) => Lang::parse_arg(v),
        None => Lang::detect(),
    };

    let Some(url) = args.url.or(args.url_arg) else {
        println!("httpstat: try 'httpstat -h' or 'httpstat --help' for more information");
        std::process::exit(1);
    };

    let mut req: HttpRequest = match url.as_str().try_into() {
        Ok(req) => req,
        Err(e) => {
            eprintln!("httpstat: invalid URL: {e}");
            std::process::exit(1);
        }
    };

    // Set IP version if specified
    if args.ipv4 {
        req.ip_version = Some(4);
    }
    if args.ipv6 {
        req.ip_version = Some(6);
    }
    req.skip_verify = args.skip_verify;

    if let Some(bind_str) = args.bind {
        match bind_str.parse::<std::net::IpAddr>() {
            Ok(ip) => req.bind_addr = Some(ip),
            Err(_) => {
                eprintln!("httpstat: invalid --bind address '{bind_str}'");
                std::process::exit(1);
            }
        }
    }

    if let Some(dns_servers) = args.dns_servers {
        req.dns_servers = Some(dns_servers.split(',').map(|s| s.to_string()).collect());
    }

    // --timeout is the coarse catch-all: it sets every phase timeout.
    if let Some(timeout_str) = args.timeout {
        let timeout = parse_dur("timeout", &timeout_str);
        req.dns_timeout = Some(timeout);
        req.tcp_timeout = Some(timeout);
        req.tls_timeout = Some(timeout);
        req.request_timeout = Some(timeout);
        req.quic_timeout = Some(timeout);
    }
    // --connect-timeout refines the connection phase only (DNS + TCP + TLS/QUIC),
    // overriding whatever --timeout set there; the request phase is untouched.
    if let Some(ct_str) = args.connect_timeout {
        let ct = parse_dur("connect-timeout", &ct_str);
        req.dns_timeout = Some(ct);
        req.tcp_timeout = Some(ct);
        req.tls_timeout = Some(ct);
        req.quic_timeout = Some(ct);
    }
    // Response-body cap: default 1 GiB, --max-filesize 0 lifts it.
    req.max_body_size = resolve_max_filesize(args.max_filesize.as_deref());

    // --max-time is an overall wall-clock cap enforced around each operation.
    let max_time = args.max_time.as_deref().map(|v| parse_dur("max-time", v));
    let retries = args.retry.unwrap_or(0);
    let retry_delay = args
        .retry_delay
        .as_deref()
        .map(|v| parse_dur("retry-delay", v));
    let follow_redirect = args.follow_redirect;
    let max_redirs = args.max_redirs.unwrap_or(10);
    let jar = Arc::new(Mutex::new(CookieJar::new()));

    // Parse headers if provided. Repeated names are kept (`append`), and a
    // missing colon or an illegal name/value is a usage error.
    if !args.headers.is_empty() {
        let mut header_map = HeaderMap::new();
        for header in &args.headers {
            let Some((name, value)) = header.split_once(':') else {
                eprintln!("httpstat: invalid header '{header}': missing ':'");
                std::process::exit(1);
            };
            let name = name.trim();
            let value = value.trim();
            let Ok(header_name) = name.parse::<HeaderName>() else {
                eprintln!("httpstat: invalid header name '{name}'");
                std::process::exit(1);
            };
            let Ok(header_value) = value.parse::<HeaderValue>() else {
                eprintln!("httpstat: invalid header value for '{name}'");
                std::process::exit(1);
            };
            header_map.append(header_name, header_value);
        }
        req.headers = Some(header_map);
    }
    if args.compressed {
        let value = HeaderValue::from_static("gzip, br, zstd");
        if let Some(header_map) = req.headers.as_mut() {
            header_map.insert(http::header::ACCEPT_ENCODING, value);
        } else {
            let mut header_map = HeaderMap::new();
            header_map.insert(http::header::ACCEPT_ENCODING, value);
            req.headers = Some(header_map);
        }
    }

    // Cookies live in the jar so Domain/Path/Secure/Expires are honored on -L.
    // A Cookie header from -H is absorbed first; -b then overrides the same names.
    if let Some(host) = req.uri.host().map(str::to_string) {
        if let Some(headers) = req.headers.as_mut() {
            if let Some(existing) = headers
                .get(http::header::COOKIE)
                .and_then(|v| v.to_str().ok())
                .map(str::to_string)
            {
                headers.remove(http::header::COOKIE);
                jar.lock()
                    .unwrap_or_else(|e| e.into_inner())
                    .load_cookie_header(&host, &existing);
            }
        }
    }
    if let Some(cookie) = args.cookie {
        let cookie_value = if let Some(file_path) = cookie.strip_prefix('@') {
            match fs::read_to_string(file_path).await {
                Ok(content) => content.trim().to_string(),
                Err(e) => {
                    eprintln!("httpstat: failed to read cookie file '{}': {e}", file_path);
                    std::process::exit(1);
                }
            }
        } else {
            cookie
        };
        if cookie_value.parse::<HeaderValue>().is_err() {
            eprintln!("httpstat: invalid cookie header");
            std::process::exit(1);
        }
        if let Some(host) = req.uri.host() {
            jar.lock()
                .unwrap_or_else(|e| e.into_inner())
                .load_cookie_header(host, &cookie_value);
        }
    }

    if args.method.is_none() && args.data.is_some() {
        req.method = Some("POST".to_string());
    } else {
        req.method = args.method.clone();
    }

    if let Some(data) = args.data {
        if let Some(file_path) = data.strip_prefix('@') {
            if file_path == "-" {
                let mut buf = Vec::new();
                if let Err(e) = std::io::Read::read_to_end(&mut std::io::stdin(), &mut buf) {
                    eprintln!("httpstat: failed to read stdin: {e}");
                    std::process::exit(1);
                }
                req.body = Some(Bytes::from(buf));
            } else {
                match fs::read(file_path).await {
                    Ok(content) => req.body = Some(Bytes::from(content)),
                    Err(e) => {
                        eprintln!("httpstat: failed to read file '{}': {e}", file_path);
                        std::process::exit(1);
                    }
                }
            }
        } else {
            req.body = Some(Bytes::from(data));
        }
    }

    // Validate and apply --connect-to entries
    if !args.connect_to.is_empty() {
        for entry in &args.connect_to {
            if ConnectTo::parse(entry).is_none() {
                eprintln!(
                    "httpstat: invalid --connect-to '{}': expected HOST1:PORT1:HOST2:PORT2",
                    entry
                );
                std::process::exit(1);
            }
        }
        req.connect_to = args.connect_to;
    }

    // Proxy: CLI flag takes precedence, then env vars
    let proxy = args.proxy.or_else(|| {
        let scheme = req.uri.scheme_str().unwrap_or("http");
        let from_env = if scheme == "https" {
            std::env::var("HTTPS_PROXY")
                .or_else(|_| std::env::var("https_proxy"))
                .ok()
        } else {
            std::env::var("HTTP_PROXY")
                .or_else(|_| std::env::var("http_proxy"))
                .ok()
        };
        from_env.or_else(|| {
            std::env::var("ALL_PROXY")
                .or_else(|_| std::env::var("all_proxy"))
                .ok()
        })
    });
    req.proxy = proxy;
    if req.proxy.is_some() {
        if let Some(host) = req.uri.host() {
            if proxy_bypassed(host, req.get_port()) {
                req.proxy = None;
            }
        }
    }

    // Load client certificate and key for mTLS
    match (args.cert, args.key) {
        (Some(cert_path), Some(key_path)) => {
            match (std::fs::read(&cert_path), std::fs::read(&key_path)) {
                (Ok(cert), Ok(key)) => {
                    req.client_cert = Some(cert);
                    req.client_key = Some(key);
                }
                (Err(e), _) => {
                    eprintln!("httpstat: failed to read cert file '{}': {e}", cert_path);
                    std::process::exit(1);
                }
                (_, Err(e)) => {
                    eprintln!("httpstat: failed to read key file '{}': {e}", key_path);
                    std::process::exit(1);
                }
            }
        }
        (Some(_), None) => {
            eprintln!("httpstat: --cert requires --key");
            std::process::exit(1);
        }
        (None, Some(_)) => {
            eprintln!("httpstat: --key requires --cert");
            std::process::exit(1);
        }
        (None, None) => {}
    }

    if args.http1 {
        req.alpn_protocols = vec![ALPN_HTTP1.to_string()];
    }
    if args.http2 {
        req.alpn_protocols = vec![ALPN_HTTP2.to_string()];
    }
    if args.http3 {
        req.alpn_protocols = vec![ALPN_HTTP3.to_string()];
    }
    let output = args.output;
    let count_explicit = args.count.is_some();
    let concurrency = args.concurrency.unwrap_or(1).max(1);
    let mut count = args.count.unwrap_or(1).max(1);
    if !count_explicit && concurrency > 1 {
        count = concurrency;
    }
    let reuse_conn = count > 1 && (args.reuse || concurrency > 1);
    if count > 1 {
        req.tls_session_store = Some(http_stat::new_tls_session_store(count.max(8)));
        req.dns_cache = Some(Arc::new(DnsCache::new()));
        req.discard_body = true;
    }
    if output.is_some() && args.jq.is_none() && !args.pretty && count == 1 && concurrency == 1 {
        req.output_path = output.as_ref().map(PathBuf::from);
    }
    let alt_cache = if args.alt_svc {
        Some(Arc::new(Mutex::new(AltSvcCache::load())))
    } else {
        None
    };
    let run_opts = RunOpts {
        follow_redirect,
        max_redirs,
        max_time,
        retries,
        retry_delay,
        alt_svc: args.alt_svc,
        alt_cache,
        jar,
        concurrency,
    };
    let include_headers: Option<Vec<String>> = if args.include_header.is_empty() {
        None
    } else {
        Some(
            args.include_header
                .iter()
                .map(|h| h.to_lowercase())
                .collect(),
        )
    };
    let exclude_headers: Option<Vec<String>> = if args.exclude_header.is_empty() {
        None
    } else {
        Some(
            args.exclude_header
                .iter()
                .map(|h| h.to_lowercase())
                .collect(),
        )
    };
    let json_output = args.json;
    let mut exit_code = 0i32;

    if let Some(resolve) = args.resolve {
        let ips = resolve.split(',').collect::<Vec<&str>>();
        let mut futs = vec![];
        for ip in ips {
            let ip = ip.trim();
            if ip.is_empty() {
                continue;
            }
            let Ok(ip) = ip.parse::<IpAddr>() else {
                eprintln!("httpstat: invalid --resolve IP '{ip}'");
                std::process::exit(1);
            };
            let mut req = req.clone();
            req.resolve = Some(ip);
            futs.push(run_request(req, &run_opts));
        }
        if futs.is_empty() {
            eprintln!("httpstat: --resolve produced no addresses");
            std::process::exit(1);
        }
        let mut stats_list = futures::future::join_all(futs).await;
        // error request last
        stats_list.sort_by(|item1, item2| {
            let value1 = item1.error.is_some();
            let value2 = item2.error.is_some();
            value1.cmp(&value2)
        });
        if json_output {
            let arr: Vec<_> = stats_list.iter().map(|s| s.to_json()).collect();
            println!("{}", serde_json::to_string_pretty(&arr).unwrap_or_default());
            for s in &stats_list {
                let code = s.exit_code();
                if code != 0 && exit_code == 0 {
                    exit_code = code;
                }
            }
        } else {
            for mut stat in stats_list {
                stat.verbose = args.verbose;
                stat.silent = args.silent;
                stat.pretty = args.pretty;
                stat.waterfall = args.waterfall;
                stat.show_tcp_info = args.tcp_info;
                stat.lang = lang;
                stat.jq_filter.clone_from(&args.jq);
                stat.include_headers.clone_from(&include_headers);
                stat.exclude_headers.clone_from(&exclude_headers);
                let body = stat.body.clone();
                handle_output(body, output.clone()).await;
                if output.is_some() {
                    stat.body = None;
                }
                println!("{stat}");
                if exit_code == 0 {
                    exit_code = stat.exit_code();
                }
            }
        }
    } else if reuse_conn {
        learn_alt_svc_for_reuse(&mut req, &run_opts).await;
        let (connect_stat, conn) = connect(&req).await;
        if let Some(conn) = conn {
            let (stats, code) = if concurrency > 1 && conn.multiplexes() {
                concurrent_reused(
                    conn,
                    &req,
                    count,
                    &run_opts,
                    &connect_stat,
                    lang,
                    json_output,
                )
                .await
            } else {
                if concurrency > 1 {
                    eprintln!(
                        "httpstat: HTTP/1.1 cannot multiplex; running -c {concurrency} sequentially"
                    );
                }
                sequential_reused(
                    conn,
                    &req,
                    count,
                    &run_opts,
                    &connect_stat,
                    lang,
                    json_output,
                )
                .await
            };
            if exit_code == 0 {
                exit_code = code;
            }
            print_benchmark(stats, Some(&connect_stat), lang, json_output);
        } else {
            if json_output {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&connect_stat.to_json()).unwrap_or_default()
                );
            } else {
                println!("{connect_stat}");
            }
            exit_code = connect_stat.exit_code();
        }
    } else if count > 1 {
        // Each iteration is a new connection, but it still goes through retry
        // and Alt-Svc. The shared TLS session store and DNS cache live on `req`.
        let width = count.to_string().len();
        let mut stats = Vec::with_capacity(count);
        for i in 0..count {
            let mut stat = run_request(req.clone(), &run_opts).await;
            stat.silent = true;
            stat.lang = lang;
            stat.body = None;
            if !json_output {
                print!("[{:>width$}/{count}] {stat}", i + 1);
            }
            if exit_code == 0 {
                exit_code = stat.exit_code();
            }
            stats.push(stat);
        }
        print_benchmark(stats, None, lang, json_output);
    } else {
        let mut stat = run_request(req, &run_opts).await;
        if json_output {
            println!(
                "{}",
                serde_json::to_string_pretty(&stat.to_json()).unwrap_or_default()
            );
        } else {
            stat.verbose = args.verbose;
            stat.silent = args.silent;
            stat.pretty = args.pretty;
            stat.waterfall = args.waterfall;
            stat.show_tcp_info = args.tcp_info;
            stat.lang = lang;
            stat.jq_filter = args.jq;
            stat.include_headers = include_headers;
            stat.exclude_headers = exclude_headers;
            let body = stat.body.clone();
            handle_output(body, output.clone()).await;
            if output.is_some() {
                stat.body = None;
            }
            println!("{stat}");
        }
        exit_code = stat.exit_code();
    }
    if exit_code != 0 {
        std::process::exit(exit_code);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg_map(v: serde_json::Value) -> serde_json::Map<String, serde_json::Value> {
        v.as_object().unwrap().clone()
    }

    // ---- apply_config ----
    #[test]
    fn apply_config_fills_missing_values() {
        let mut args = Args::parse_from(["httpstat", "http://example.com"]);
        assert!(!args.verbose);
        assert!(args.timeout.is_none());

        let map = cfg_map(serde_json::json!({
            "verbose": true,
            "timeout": "5s",
            "headers": ["X-From-Config: yes"],
        }));
        apply_config(&mut args, &map);

        assert!(args.verbose);
        assert_eq!(args.timeout.as_deref(), Some("5s"));
        assert_eq!(args.headers, vec!["X-From-Config: yes".to_string()]);
    }

    #[test]
    fn apply_config_does_not_override_cli_values() {
        let mut args = Args::parse_from(["httpstat", "--timeout", "1s", "http://example.com"]);
        let map = cfg_map(serde_json::json!({ "timeout": "99s" }));
        apply_config(&mut args, &map);
        // an explicit CLI value wins over config
        assert_eq!(args.timeout.as_deref(), Some("1s"));
    }

    #[test]
    fn apply_config_prepends_header_defaults() {
        let mut args = Args::parse_from(["httpstat", "-H", "X-Cli: 1", "http://example.com"]);
        let map = cfg_map(serde_json::json!({ "headers": ["X-Config: 0"] }));
        apply_config(&mut args, &map);
        // config defaults come first; CLI-provided headers are appended
        assert_eq!(
            args.headers,
            vec!["X-Config: 0".to_string(), "X-Cli: 1".to_string()]
        );
    }

    #[test]
    fn apply_config_accepts_new_keys() {
        let mut args = Args::parse_from(["httpstat", "http://example.com"]);
        let map = cfg_map(serde_json::json!({
            "proxy": "http://proxy.example:8080",
            "bind": "127.0.0.1",
            "connect_to": ["a:1:b:2"],
            "waterfall": true,
            "tcp_info": true,
            "lang": "zh",
            "reuse": true,
            "concurrency": 4,
            "max_redirs": 3
        }));
        apply_config(&mut args, &map);
        assert_eq!(args.proxy.as_deref(), Some("http://proxy.example:8080"));
        assert_eq!(args.bind.as_deref(), Some("127.0.0.1"));
        assert_eq!(args.connect_to, vec!["a:1:b:2".to_string()]);
        assert!(args.waterfall);
        assert!(args.tcp_info);
        assert_eq!(args.lang.as_deref(), Some("zh"));
        assert!(args.reuse);
        assert_eq!(args.concurrency, Some(4));
        assert_eq!(args.max_redirs, Some(3));
    }

    // ---- redirect_downgrades_to_get ----
    #[test]
    fn redirect_303_forces_get_except_head() {
        assert!(redirect_downgrades_to_get(StatusCode::SEE_OTHER, "POST"));
        assert!(redirect_downgrades_to_get(StatusCode::SEE_OTHER, "GET"));
        assert!(redirect_downgrades_to_get(StatusCode::SEE_OTHER, "PUT"));
        // HEAD is preserved across a 303
        assert!(!redirect_downgrades_to_get(StatusCode::SEE_OTHER, "HEAD"));
    }

    #[test]
    fn redirect_301_302_downgrade_only_post() {
        for s in [StatusCode::MOVED_PERMANENTLY, StatusCode::FOUND] {
            assert!(redirect_downgrades_to_get(s, "POST"));
            assert!(!redirect_downgrades_to_get(s, "GET"));
            assert!(!redirect_downgrades_to_get(s, "PUT"));
        }
    }

    #[test]
    fn redirect_307_308_preserve_method() {
        for s in [
            StatusCode::TEMPORARY_REDIRECT,
            StatusCode::PERMANENT_REDIRECT,
        ] {
            assert!(!redirect_downgrades_to_get(s, "POST"));
            assert!(!redirect_downgrades_to_get(s, "GET"));
        }
    }

    // ---- resolve_redirect ----
    #[test]
    fn resolve_redirect_forms() {
        let base: Uri = "http://example.com/a/b".parse().unwrap();
        // absolute URL is used as-is
        assert_eq!(
            resolve_redirect(&base, "https://other.com/x")
                .unwrap()
                .to_string(),
            "https://other.com/x"
        );
        // scheme-relative inherits the base scheme
        assert_eq!(
            resolve_redirect(&base, "//cdn.example.com/y")
                .unwrap()
                .to_string(),
            "http://cdn.example.com/y"
        );
        // absolute path keeps the base authority and carries the query
        assert_eq!(
            resolve_redirect(&base, "/x?q=1").unwrap().to_string(),
            "http://example.com/x?q=1"
        );
        // relative path resolves against the base path's directory
        assert_eq!(
            resolve_redirect(&base, "c").unwrap().to_string(),
            "http://example.com/a/c"
        );
        // empty location is rejected
        assert!(resolve_redirect(&base, "").is_none());
        // dot segments are removed; the query stays and the fragment is dropped
        assert_eq!(
            resolve_redirect(&base, "../c").unwrap().to_string(),
            "http://example.com/c"
        );
        assert_eq!(
            resolve_redirect(&base, "./c").unwrap().to_string(),
            "http://example.com/a/c"
        );
        assert_eq!(
            resolve_redirect(&base, "/a/./b/../c").unwrap().to_string(),
            "http://example.com/a/c"
        );
        assert_eq!(
            resolve_redirect(&base, "/a/./b/../c?q=1#frag")
                .unwrap()
                .to_string(),
            "http://example.com/a/c?q=1"
        );
        assert_eq!(
            resolve_redirect(&base, "https://other.com/a/./b/../c?q=1#f")
                .unwrap()
                .to_string(),
            "https://other.com/a/c?q=1"
        );
    }

    // ---- --max-time handling ----
    #[test]
    fn max_time_error_stat_maps_to_timeout_exit() {
        let s = max_time_error_stat(std::time::Duration::from_secs(2));
        assert!(!s.is_success());
        assert_eq!(s.exit_code(), 5); // timeout
        assert!(s.error.as_deref().unwrap().contains("max-time"));
    }

    #[tokio::test]
    async fn with_max_time_passes_through_fast_result() {
        let fast = async {
            HttpStat {
                status: Some(StatusCode::OK),
                ..Default::default()
            }
        };
        let s = with_max_time(fast, Some(std::time::Duration::from_secs(10))).await;
        assert_eq!(s.exit_code(), 0);
    }

    #[tokio::test]
    async fn with_max_time_cancels_slow_result() {
        let slow = async {
            tokio::time::sleep(std::time::Duration::from_secs(5)).await;
            HttpStat {
                status: Some(StatusCode::OK),
                ..Default::default()
            }
        };
        let s = with_max_time(slow, Some(std::time::Duration::from_millis(10))).await;
        assert_eq!(s.exit_code(), 5); // synthesized timeout
    }

    #[tokio::test]
    async fn with_max_time_none_is_unbounded() {
        let fut = async {
            HttpStat {
                status: Some(StatusCode::OK),
                ..Default::default()
            }
        };
        assert_eq!(with_max_time(fut, None).await.exit_code(), 0);
    }

    // ---- retry logic ----
    #[test]
    fn is_retryable_status_codes() {
        for code in [408u16, 429, 500, 502, 503, 504] {
            let s = HttpStat {
                status: Some(StatusCode::from_u16(code).unwrap()),
                ..Default::default()
            };
            assert!(is_retryable(&s), "expected {code} retryable");
        }
        for code in [200u16, 404, 501, 505] {
            let s = HttpStat {
                status: Some(StatusCode::from_u16(code).unwrap()),
                ..Default::default()
            };
            assert!(!is_retryable(&s), "expected {code} non-retryable");
        }
    }

    #[test]
    fn is_retryable_connection_errors() {
        let ms = std::time::Duration::from_millis(1);
        // timeout (exit 5) and TCP connect failure (exit 3) are transient
        let to = HttpStat {
            error: Some("operation timeout".into()),
            ..Default::default()
        };
        assert!(is_retryable(&to));
        let tcp = HttpStat {
            error: Some("connection refused".into()),
            dns_lookup: Some(ms),
            ..Default::default()
        };
        assert!(is_retryable(&tcp));
        // generic mid-flight error / reset (exit 1) is retried too
        let reset = HttpStat {
            error: Some("connection reset by peer".into()),
            dns_lookup: Some(ms),
            tcp_connect: Some(ms),
            ..Default::default()
        };
        assert!(is_retryable(&reset));
        // DNS (exit 2) and TLS/cert (exit 4) failures are NOT retried
        let dns = HttpStat {
            error: Some("no such host".into()),
            dns_attempted: true,
            ..Default::default()
        };
        assert!(!is_retryable(&dns));
        let tls = HttpStat {
            error: Some("rustls: bad certificate".into()),
            dns_lookup: Some(ms),
            tcp_connect: Some(ms),
            ..Default::default()
        };
        assert!(!is_retryable(&tls));
        // a clean (empty) stat is not retryable
        assert!(!is_retryable(&HttpStat::default()));
    }

    #[test]
    fn backoff_is_exponential_capped() {
        assert_eq!(backoff_delay(0), std::time::Duration::from_secs(1));
        assert_eq!(backoff_delay(1), std::time::Duration::from_secs(2));
        assert_eq!(backoff_delay(2), std::time::Duration::from_secs(4));
        assert_eq!(backoff_delay(4), std::time::Duration::from_secs(16));
        assert_eq!(backoff_delay(5), std::time::Duration::from_secs(30)); // capped
        assert_eq!(backoff_delay(20), std::time::Duration::from_secs(30)); // capped
    }

    #[tokio::test]
    async fn run_with_retry_retries_then_succeeds() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        let calls = AtomicUsize::new(0);
        let make = || {
            let n = calls.fetch_add(1, Ordering::SeqCst);
            async move {
                let status = if n < 2 {
                    StatusCode::SERVICE_UNAVAILABLE
                } else {
                    StatusCode::OK
                };
                HttpStat {
                    status: Some(status),
                    ..Default::default()
                }
            }
        };
        let stat = run_with_retry(make, 5, Some(std::time::Duration::from_millis(1)), None).await;
        assert_eq!(stat.exit_code(), 0);
        assert_eq!(calls.load(Ordering::SeqCst), 3); // 2 failures + 1 success
    }

    #[tokio::test]
    async fn run_with_retry_gives_up_after_n() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        let calls = AtomicUsize::new(0);
        let make = || {
            calls.fetch_add(1, Ordering::SeqCst);
            async {
                HttpStat {
                    status: Some(StatusCode::BAD_GATEWAY),
                    ..Default::default()
                }
            }
        };
        let stat = run_with_retry(make, 2, Some(std::time::Duration::from_millis(1)), None).await;
        assert_eq!(stat.exit_code(), 7); // 502 → 5xx exit code
        assert_eq!(calls.load(Ordering::SeqCst), 3); // initial + 2 retries
    }

    #[tokio::test]
    async fn run_with_retry_does_not_retry_non_transient() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        let calls = AtomicUsize::new(0);
        let make = || {
            calls.fetch_add(1, Ordering::SeqCst);
            async {
                HttpStat {
                    status: Some(StatusCode::NOT_FOUND),
                    ..Default::default()
                }
            }
        };
        let stat = run_with_retry(make, 5, Some(std::time::Duration::from_millis(1)), None).await;
        assert_eq!(stat.exit_code(), 6); // 404 → no retry
        assert_eq!(calls.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn max_time_budget_covers_retry_backoff() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        let calls = AtomicUsize::new(0);
        let make = || {
            calls.fetch_add(1, Ordering::SeqCst);
            async {
                HttpStat {
                    status: Some(StatusCode::BAD_GATEWAY),
                    ..Default::default()
                }
            }
        };
        let start = std::time::Instant::now();
        let budget = TimeBudget {
            deadline: start + std::time::Duration::from_millis(30),
            limit: std::time::Duration::from_millis(30),
        };
        let stat = run_with_retry(
            make,
            5,
            Some(std::time::Duration::from_secs(30)),
            Some(budget),
        )
        .await;
        assert_eq!(stat.exit_code(), 5);
        assert!(start.elapsed() < std::time::Duration::from_secs(2));
        assert_eq!(calls.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn benchmark_json_includes_request_send_and_throughput() {
        let stat = HttpStat {
            request_send: Some(std::time::Duration::from_micros(100)),
            content_transfer: Some(std::time::Duration::from_millis(100)),
            wire_body_size: Some(100_000),
            total: Some(std::time::Duration::from_millis(200)),
            ..Default::default()
        };
        let v = benchmark_to_json(&[stat.clone(), stat.clone()], None);
        assert!(v["timing"]["request_send"]["p50_us"].as_u64().is_some());
        let bps = &v["throughput"]["bps_total"];
        for key in ["min", "max", "avg", "p50", "p95", "p99"] {
            assert!(bps[key].as_f64().is_some(), "{key}");
        }
        let connect = HttpStat {
            quic_connect: Some(std::time::Duration::from_micros(50)),
            total: Some(std::time::Duration::from_micros(80)),
            ..Default::default()
        };
        let with_cold = benchmark_to_json(&[stat.clone(), stat], Some(&connect));
        assert_eq!(
            with_cold["cold_connect"]["quic_connect_us"].as_u64(),
            Some(50)
        );
    }

    #[test]
    fn h3_advertisement_skips_zero_max_age() {
        let stat = HttpStat {
            alt_svc: Some(vec![http_stat::AltSvc {
                protocol: "h3".into(),
                authority: ":443".into(),
                max_age: Some(0),
            }]),
            ..Default::default()
        };
        assert!(h3_advertisement(&stat).is_none());
        assert!(alt_svc_cleared(&stat));
        let kept = HttpStat {
            alt_svc: Some(vec![http_stat::AltSvc {
                protocol: "h3".into(),
                authority: "alt.example:8443".into(),
                max_age: Some(60),
            }]),
            ..Default::default()
        };
        assert_eq!(
            h3_advertisement(&kept),
            Some(("alt.example".to_string(), 8443, 60))
        );
        let missing_ma = HttpStat {
            alt_svc: Some(vec![http_stat::AltSvc {
                protocol: "h3".into(),
                authority: ":443".into(),
                max_age: None,
            }]),
            ..Default::default()
        };
        assert_eq!(
            h3_advertisement(&missing_ma),
            Some((String::new(), 443, 24 * 60 * 60))
        );
    }

    // ---- Alt-Svc auto-upgrade ----
    #[test]
    fn parse_alt_authority_forms() {
        assert_eq!(parse_alt_authority(":443"), Some((String::new(), 443)));
        assert_eq!(
            parse_alt_authority("alt.example.com:8443"),
            Some(("alt.example.com".to_string(), 8443))
        );
        assert_eq!(
            parse_alt_authority("[::1]:443"),
            Some(("::1".to_string(), 443))
        );
        assert!(parse_alt_authority("noport").is_none());
        assert!(parse_alt_authority(":notnum").is_none());
    }

    #[test]
    fn h3_endpoint_picks_h3() {
        let stat = HttpStat {
            alt_svc: Some(vec![
                http_stat::AltSvc {
                    protocol: "h2".into(),
                    authority: ":443".into(),
                    max_age: None,
                },
                http_stat::AltSvc {
                    protocol: "h3".into(),
                    authority: ":8443".into(),
                    max_age: Some(86400),
                },
            ]),
            ..Default::default()
        };
        assert_eq!(h3_endpoint(&stat), Some((String::new(), 8443)));

        let no_h3 = HttpStat {
            alt_svc: Some(vec![http_stat::AltSvc {
                protocol: "h2".into(),
                authority: ":443".into(),
                max_age: None,
            }]),
            ..Default::default()
        };
        assert!(h3_endpoint(&no_h3).is_none());
        assert!(h3_endpoint(&HttpStat::default()).is_none());
    }

    #[test]
    fn fmt_alt_endpoint_forms() {
        assert_eq!(fmt_alt_endpoint("", 443), ":443");
        assert_eq!(fmt_alt_endpoint("h", 8443), "h:8443");
        assert_eq!(fmt_alt_endpoint("::1", 443), "[::1]:443");
    }

    #[test]
    fn apply_alt_endpoint_same_origin_needs_no_connect_to() {
        let mut req = HttpRequest::try_from("https://example.com").unwrap();
        apply_alt_endpoint(&mut req, "", 443); // same host, same default port
        assert_eq!(req.alpn_protocols, vec![ALPN_HTTP3.to_string()]);
        assert!(req.connect_to.is_empty());
    }

    #[test]
    fn apply_alt_endpoint_different_endpoint_uses_connect_to() {
        // different port, same host
        let mut req = HttpRequest::try_from("https://example.com").unwrap();
        apply_alt_endpoint(&mut req, "", 8443);
        assert_eq!(
            req.connect_to,
            vec!["example.com:443:example.com:8443".to_string()]
        );
        // different host
        let mut req2 = HttpRequest::try_from("https://example.com").unwrap();
        apply_alt_endpoint(&mut req2, "alt.example.com", 443);
        assert_eq!(
            req2.connect_to,
            vec!["example.com:443:alt.example.com:443".to_string()]
        );
    }

    #[test]
    fn parse_size_accepts_common_forms() {
        assert_eq!(parse_size("max-filesize", "100MB"), 100_000_000);
        assert_eq!(parse_size("max-filesize", "1MiB"), 1024 * 1024);
        assert_eq!(parse_size("max-filesize", "52428800"), 52_428_800);
        assert_eq!(parse_size("max-filesize", "0"), 0);
    }

    #[test]
    fn resolve_max_filesize_default_and_unlimited() {
        assert_eq!(
            resolve_max_filesize(None),
            Some(DEFAULT_MAX_FILESIZE as usize)
        );
        assert_eq!(resolve_max_filesize(Some("0")), None);
        assert_eq!(resolve_max_filesize(Some("10MB")), Some(10_000_000));
    }
}
