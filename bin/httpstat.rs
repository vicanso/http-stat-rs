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
    connect, format_duration, request, BenchmarkSummary, ConnectTo, HttpRequest, HttpStat,
    ALPN_HTTP1, ALPN_HTTP2, ALPN_HTTP3,
};
use std::net::IpAddr;
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

    /// Timeout
    #[arg(long = "timeout", help = "timeout")]
    timeout: Option<String>,

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
    // Optional strings: config fills in when CLI left them None
    cfg_opt_str!(dns_servers);
    cfg_opt_str!(timeout);
    cfg_opt_str!(cookie);
    cfg_opt_str!(output);
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
            let redirect_url = stat
                .headers
                .as_ref()
                .and_then(|header| header.get("Location"))
                .map(|value| value.to_str().unwrap_or(""))
                .unwrap_or("");
            if redirect_url.is_empty() {
                break;
            }
            // Carry cookies across redirects
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
            if let Ok(uri) = redirect_url.parse::<Uri>() {
                req.uri = uri;
                stat = request(req.clone()).await;
            }
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
#[tokio::main(flavor = "current_thread")]
async fn main() {
    let mut args = Args::parse();
    let config = load_config();
    apply_config(&mut args, &config);

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

    if let Some(dns_servers) = args.dns_servers {
        req.dns_servers = Some(dns_servers.split(',').map(|s| s.to_string()).collect());
    }

    if let Some(timeout_str) = args.timeout {
        let timeout: std::time::Duration = match timeout_str.parse::<humantime::Duration>() {
            Ok(d) => d.into(),
            Err(e) => {
                eprintln!("httpstat: invalid timeout '{timeout_str}': {e}");
                std::process::exit(1);
            }
        };
        req.dns_timeout = Some(timeout);
        req.tcp_timeout = Some(timeout);
        req.tls_timeout = Some(timeout);
        req.request_timeout = Some(timeout);
        req.quic_timeout = Some(timeout);
    }

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
            futs.push(do_request(req, args.follow_redirect));
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
                let mut stat = conn.send(&req).await;
                stat.addr.clone_from(&connect_stat.addr);
                stat.alpn.clone_from(&connect_stat.alpn);
                stat.silent = true;
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
                let summary = BenchmarkSummary { stats };
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
                    "  Cold connect: {} ({})",
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
        // Benchmark mode (new connection each time)
        let width = count.to_string().len();
        let mut stats = Vec::with_capacity(count);
        for i in 0..count {
            let mut stat = do_request(req.clone(), args.follow_redirect).await;
            stat.silent = true;
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
            let summary = BenchmarkSummary { stats };
            println!("{summary}");
        }
    } else {
        let mut stat = do_request(req, args.follow_redirect).await;
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
