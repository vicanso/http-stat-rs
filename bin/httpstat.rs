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

use clap::Parser;
use http::header::{HeaderMap, HeaderName, HeaderValue};
use http::StatusCode;
use http::Uri;
use http_stat::{request, HttpRequest};

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

    /// URL as positional argument
    #[arg(help = "url to request")]
    url_arg: Option<String>,
}

#[tokio::main]
async fn main() {
    let args = Args::parse();

    let url = args
        .url
        .or(args.url_arg)
        .expect("URL is required, either via --url or as a positional argument");

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

    let mut stat = request(req.clone()).await;
    if args.follow_redirect {
        loop {
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
    // while stat.status_code.is_some_and(|code| code >= 300 && code < 400) {
    // let redirect_url = stat.redirect_url;
    // let req = HttpRequest::new(redirect_url);
    // stat = request(req).await;
    // }
    println!("{}", stat);
}
