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
use http_stat::request;

/// HTTP statistics tool
#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// URL to request (optional, can be provided as the last argument)
    #[arg(short, long)]
    url: Option<String>,

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

    let stat = request(url.as_str().try_into().unwrap()).await;
    println!("{}", stat);
}
