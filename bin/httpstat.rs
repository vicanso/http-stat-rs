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
use http::Method;
use http::StatusCode;
use http::Uri;
use http_stat::{request, HttpRequest, HttpStat, ALPN_HTTP1, ALPN_HTTP2, ALPN_HTTP3};
use std::net::IpAddr;

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
        help = "the body of a POST or PUT request; from file use @filename"
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
            if let Ok(uri) = redirect_url.parse::<Uri>() {
                req.uri = uri;
                stat = request(req.clone()).await;
            }
        }
    }
    stat
}

#[tokio::main]
async fn main() {
    let args = Args::parse();

    let Some(url) = args.url.or(args.url_arg) else {
        println!("url is required, either via --url or as a positional argument");
        return;
    };

    let mut req: HttpRequest = url.as_str().try_into().unwrap();

    // Set IP version if specified
    if args.ipv4 {
        req.ip_version = Some(4);
    }
    if args.ipv6 {
        req.ip_version = Some(6);
    }
    req.skip_verify = args.skip_verify;
    req.output = args.output;

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

    if let Some(method) = args.method {
        req.method = Some(method.parse::<Method>().unwrap_or_default());
    }

    if let Some(data) = args.data {
        req.body = Some(Bytes::from(data));
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
    req.silent = args.silent;

    if let Some(resolve) = args.resolve {
        let ips = resolve.split(',').collect::<Vec<&str>>();
        let mut stats_list = vec![];
        for ip in ips {
            let mut req = req.clone();
            let Ok(ip) = ip.parse::<IpAddr>() else {
                continue;
            };
            req.resolve = Some(ip);
            let stat = do_request(req, args.follow_redirect).await;
            stats_list.push(stat);
        }
        // error request last
        stats_list.sort_by(|item1, item2| {
            let value1 = item1.error.is_some();
            let value2 = item2.error.is_some();
            value1.cmp(&value2)
        });
        for stat in stats_list {
            println!("{}", stat);
        }
    } else {
        let stat = do_request(req, args.follow_redirect).await;
        println!("{}", stat);
    }
}
