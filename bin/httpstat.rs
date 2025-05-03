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
use http_stat::{request, HttpRequest};

/// HTTP statistics tool
#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// URL to request (optional, can be provided as the last argument)
    #[arg(short, long)]
    url: Option<String>,

    /// HTTP headers to set (format: "Header-Name: value")
    #[arg(short = 'H', help = "HTTP headers to set")]
    headers: Vec<String>,

    /// URL as positional argument
    #[arg(help = "URL to request")]
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

    let stat = request(req).await;
    println!("{}", stat);
}
