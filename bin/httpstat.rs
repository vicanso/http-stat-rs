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
use http::header::{HeaderMap, HeaderName, HeaderValue};
use http::StatusCode;
use http::Uri;
use http_stat::{
    connect, format_duration, request, BenchmarkSummary, ConnectTo, HttpRequest, HttpStat, Lang,
    ALPN_HTTP1, ALPN_HTTP2, ALPN_HTTP3,
};
use std::net::IpAddr;
use std::sync::Arc;
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

    /// HTTP method to use (default GET)
    #[arg(short = 'X', help = "HTTP method to use (default GET)")]
    method: Option<String>,

    /// Data to send
    #[arg(
        short = 'd',
        long = "data",
        help = "the body of a POST or PUT request; from file use @filename, from stdin use @-"
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
        help = "show kernel TCP_INFO stats (RTT, cwnd, retransmits); Linux + macOS"
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
        help = "overall time limit for the whole operation incl. body and redirects, e.g. 30s"
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
        help = "reuse connection in benchmark mode (requires -n), test warm request performance"
    )]
    reuse: bool,

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
    // Optional strings: config fills in when CLI left them None
    cfg_opt_str!(dns_servers);
    cfg_opt_str!(timeout);
    cfg_opt_str!(connect_timeout);
    cfg_opt_str!(max_time);
    cfg_opt_str!(retry_delay);
    cfg_opt_str!(cookie);
    cfg_opt_str!(output);
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
}

fn collect_cookies(stat: &HttpStat, existing: &str) -> String {
    let mut cookies = std::collections::HashMap::new();
    // Parse existing cookies
    for pair in existing.split(';') {
        let pair = pair.trim();
        if let Some((name, value)) = pair.split_once('=') {
            cookies.insert(name.trim().to_string(), value.trim().to_string());
        }
    }
    // Collect Set-Cookie from response
    if let Some(headers) = &stat.headers {
        for value in headers.get_all(http::header::SET_COOKIE).iter() {
            let value = value.to_str().unwrap_or_default();
            // Only take name=value part (before first ';')
            let cookie_part = value.split(';').next().unwrap_or_default().trim();
            if let Some((name, val)) = cookie_part.split_once('=') {
                cookies.insert(name.trim().to_string(), val.trim().to_string());
            }
        }
    }
    cookies
        .into_iter()
        .map(|(k, v)| format!("{k}={v}"))
        .collect::<Vec<_>>()
        .join("; ")
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

/// Resolve a redirect `Location` against the request's current URI, covering
/// the common RFC 3986 reference forms: absolute URLs, scheme-relative
/// (`//host/path`), absolute-path (`/path`), and relative-path references.
/// Returns `None` for an empty location or when the base lacks scheme/authority.
fn resolve_redirect(base: &Uri, location: &str) -> Option<Uri> {
    let location = location.trim();
    if location.is_empty() {
        return None;
    }
    // Already absolute (has both scheme and authority).
    if let Ok(uri) = location.parse::<Uri>() {
        if uri.scheme().is_some() && uri.authority().is_some() {
            return Some(uri);
        }
    }
    let scheme = base.scheme_str()?;
    let authority = base.authority()?.as_str();
    if let Some(rest) = location.strip_prefix("//") {
        // Scheme-relative: //host/path
        format!("{scheme}://{rest}").parse().ok()
    } else if location.starts_with('/') {
        // Absolute path on the same authority.
        format!("{scheme}://{authority}{location}").parse().ok()
    } else {
        // Relative path: resolve against the base path's directory.
        let base_path = base.path();
        let dir = match base_path.rfind('/') {
            Some(i) => &base_path[..=i],
            None => "/",
        };
        format!("{scheme}://{authority}{dir}{location}")
            .parse()
            .ok()
    }
}

async fn do_request(mut req: HttpRequest, follow_redirect: bool) -> HttpStat {
    let mut stat = request(req.clone()).await;
    if follow_redirect {
        for _ in 0..10 {
            let status = stat.status.unwrap_or(StatusCode::OK);
            if ![
                StatusCode::MOVED_PERMANENTLY,
                StatusCode::FOUND,
                StatusCode::SEE_OTHER,
                StatusCode::TEMPORARY_REDIRECT,
                StatusCode::PERMANENT_REDIRECT,
            ]
            .contains(&status)
            {
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

            // Method/body rewrite per RFC 9110 (see redirect_downgrades_to_get).
            // When downgrading to GET we must also drop the request body and any
            // body-describing headers the user supplied, so we don't send a
            // stale Content-Length / Content-Type with a now-empty GET.
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

            // Drop credentials when the redirect crosses to a different host, so
            // an Authorization header isn't leaked to a third party (curl strips
            // it too unless --location-trusted is given).
            let same_host = req
                .uri
                .host()
                .unwrap_or_default()
                .eq_ignore_ascii_case(new_uri.host().unwrap_or_default());
            if !same_host {
                if let Some(h) = req.headers.as_mut() {
                    h.remove(http::header::AUTHORIZATION);
                }
            }

            // Carry cookies across the redirect (this hop's Set-Cookie merged
            // into the forwarded Cookie header).
            let existing_cookie = req
                .headers
                .as_ref()
                .and_then(|h| h.get(http::header::COOKIE))
                .and_then(|v| v.to_str().ok())
                .unwrap_or_default()
                .to_string();
            let merged = collect_cookies(&stat, &existing_cookie);
            if !merged.is_empty() {
                if let Ok(value) = merged.parse::<HeaderValue>() {
                    let header_map = req.headers.get_or_insert_with(HeaderMap::new);
                    header_map.insert(http::header::COOKIE, value);
                }
            }

            req.uri = new_uri;
            stat = request(req.clone()).await;
        }
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
            "total": stat_obj(&calc(|s| s.total)),
        },
    });

    if let Some(cs) = connect_stat {
        obj["cold_connect"] = serde_json::json!({
            "dns_lookup_us": dur_us(cs.dns_lookup),
            "tcp_connect_us": dur_us(cs.tcp_connect),
            "tls_handshake_us": dur_us(cs.tls_handshake),
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

/// Run an operation with up to `retries` retries on transient failure. `make`
/// builds a fresh operation future per attempt. Between attempts it waits
/// `retry_delay` (fixed) or an exponential backoff, logging each retry to
/// stderr so it never pollutes stdout / JSON output.
async fn run_with_retry<F, Fut>(
    make: F,
    retries: usize,
    retry_delay: Option<std::time::Duration>,
) -> HttpStat
where
    F: Fn() -> Fut,
    Fut: std::future::Future<Output = HttpStat>,
{
    let mut attempt = 0usize;
    loop {
        let stat = make().await;
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
        tokio::time::sleep(delay).await;
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
fn h3_endpoint(stat: &HttpStat) -> Option<(String, u16)> {
    stat.alt_svc
        .as_ref()?
        .iter()
        .find(|e| e.protocol == "h3")
        .and_then(|e| parse_alt_authority(&e.authority))
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
    max_time: Option<std::time::Duration>,
    retries: usize,
    retry_delay: Option<std::time::Duration>,
    alt_svc: bool,
}

/// Run one request through retry + max-time, then optionally upgrade to HTTP/3
/// when `--alt-svc` is set and the response advertised an h3 endpoint. On a
/// failed upgrade the original result is kept (with a note on stderr).
async fn run_request(req: HttpRequest, opts: &RunOpts) -> HttpStat {
    let forced_h3 = req.alpn_protocols.iter().any(|p| p == ALPN_HTTP3);
    let stat = run_with_retry(
        || with_max_time(do_request(req.clone(), opts.follow_redirect), opts.max_time),
        opts.retries,
        opts.retry_delay,
    )
    .await;

    if !opts.alt_svc || forced_h3 {
        return stat;
    }
    let Some((host, port)) = h3_endpoint(&stat) else {
        return stat;
    };

    let mut h3_req = req;
    apply_alt_endpoint(&mut h3_req, &host, port);
    let h3_stat = run_with_retry(
        || {
            with_max_time(
                do_request(h3_req.clone(), opts.follow_redirect),
                opts.max_time,
            )
        },
        opts.retries,
        opts.retry_delay,
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
        stat
    }
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
    // --max-time is an overall wall-clock cap enforced around each operation.
    let max_time = args.max_time.as_deref().map(|v| parse_dur("max-time", v));
    let retries = args.retry.unwrap_or(0);
    let retry_delay = args
        .retry_delay
        .as_deref()
        .map(|v| parse_dur("retry-delay", v));
    let follow_redirect = args.follow_redirect;
    let run_opts = RunOpts {
        follow_redirect,
        max_time,
        retries,
        retry_delay,
        alt_svc: args.alt_svc,
    };

    // Parse headers if provided
    if !args.headers.is_empty() {
        let mut header_map = HeaderMap::new();
        for header in args.headers {
            if let Some((name, value)) = header.split_once(':') {
                let name = name.trim();
                let value = value.trim();
                if let Ok(header_name) = name.parse::<HeaderName>() {
                    if let Ok(header_value) = value.parse::<HeaderValue>() {
                        header_map.insert(header_name, header_value);
                    }
                }
            }
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

    // Parse cookie
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
        if let Ok(value) = cookie_value.parse::<HeaderValue>() {
            let header_map = req.headers.get_or_insert_with(HeaderMap::new);
            header_map.insert(http::header::COOKIE, value);
        }
    }

    req.method = args.method;

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
    let count = args.count.unwrap_or(1).max(1);
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
            let mut req = req.clone();
            let Ok(ip) = ip.parse::<IpAddr>() else {
                continue;
            };
            req.resolve = Some(ip);
            futs.push(run_request(req, &run_opts));
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
    } else if count > 1 && args.reuse {
        // Benchmark with connection reuse
        let (connect_stat, conn) = connect(&req).await;
        if let Some(mut conn) = conn {
            let width = count.to_string().len();
            let mut stats = Vec::with_capacity(count);
            for i in 0..count {
                let mut stat = with_max_time(conn.send(&req), max_time).await;
                stat.addr.clone_from(&connect_stat.addr);
                stat.alpn.clone_from(&connect_stat.alpn);
                stat.silent = true;
                stat.lang = lang;
                if !json_output {
                    print!("[{:>width$}/{count}] {stat}", i + 1);
                }
                if exit_code == 0 {
                    exit_code = stat.exit_code();
                }
                stat.body = None;
                stats.push(stat);
            }
            if json_output {
                let json_val = benchmark_to_json(&stats, Some(&connect_stat));
                println!(
                    "{}",
                    serde_json::to_string_pretty(&json_val).unwrap_or_default()
                );
            } else {
                let summary = BenchmarkSummary { stats, lang };
                println!("{summary}");
                // Show cold connect cost
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
                println!(
                    "  {}: {} ({})",
                    lang.strings().cold_connect,
                    format_duration(connect_stat.total.unwrap_or_default()),
                    parts.join(" + ")
                );
            }
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
        // Benchmark mode (new connection each time). Share a single TLS session
        // store across iterations so runs 2..N can perform a resumed handshake
        // (and attempt 0-RTT) — making the speedup visible in the per-request
        // tls_handshake column and in the reported handshake kind.
        let width = count.to_string().len();
        let session_store = http_stat::new_tls_session_store(count.max(8));
        let mut stats = Vec::with_capacity(count);
        for i in 0..count {
            let mut req = req.clone();
            req.tls_session_store = Some(Arc::clone(&session_store));
            let mut stat = with_max_time(do_request(req, args.follow_redirect), max_time).await;
            stat.silent = true;
            stat.lang = lang;
            if !json_output {
                print!("[{:>width$}/{count}] {stat}", i + 1);
            }
            if exit_code == 0 {
                exit_code = stat.exit_code();
            }
            stat.body = None;
            stats.push(stat);
        }
        if json_output {
            let json_val = benchmark_to_json(&stats, None);
            println!(
                "{}",
                serde_json::to_string_pretty(&json_val).unwrap_or_default()
            );
        } else {
            let summary = BenchmarkSummary { stats, lang };
            println!("{summary}");
        }
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

    // ---- collect_cookies ----
    #[test]
    fn collect_cookies_merges_set_cookie_and_existing() {
        let mut headers = HeaderMap::new();
        headers.append(
            http::header::SET_COOKIE,
            HeaderValue::from_static("a=1; Path=/; HttpOnly"),
        );
        headers.append(http::header::SET_COOKIE, HeaderValue::from_static("b=2"));
        let stat = HttpStat {
            headers: Some(headers),
            ..Default::default()
        };
        let merged = collect_cookies(&stat, "c=3");
        // HashMap ordering is unspecified, so compare as a set
        let set: std::collections::HashSet<&str> = merged.split("; ").collect();
        assert_eq!(set.len(), 3);
        assert!(set.contains("a=1"));
        assert!(set.contains("b=2"));
        assert!(set.contains("c=3"));
    }

    #[test]
    fn collect_cookies_response_overrides_existing() {
        let mut headers = HeaderMap::new();
        headers.append(
            http::header::SET_COOKIE,
            HeaderValue::from_static("session=new"),
        );
        let stat = HttpStat {
            headers: Some(headers),
            ..Default::default()
        };
        assert_eq!(collect_cookies(&stat, "session=old"), "session=new");
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
        let stat = run_with_retry(make, 5, Some(std::time::Duration::from_millis(1))).await;
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
        let stat = run_with_retry(make, 2, Some(std::time::Duration::from_millis(1))).await;
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
        let stat = run_with_retry(make, 5, Some(std::time::Duration::from_millis(1))).await;
        assert_eq!(stat.exit_code(), 6); // 404 → no retry
        assert_eq!(calls.load(Ordering::SeqCst), 1);
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
}
