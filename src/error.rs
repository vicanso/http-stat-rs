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

use snafu::Snafu;
// Error enum for handling various error types in the configuration
#[derive(Debug, Snafu)]
pub enum Error {
    #[snafu(display("uri parse error {source}"))]
    Uri { source: http::uri::InvalidUri },
    #[snafu(display("resolve error {source}"))]
    Resolve {
        source: hickory_resolver::ResolveError,
    },
    #[snafu(display("{category}, {message}"))]
    Common { category: String, message: String },
    #[snafu(display("io error {source}"))]
    Io { source: std::io::Error },
    #[snafu(display("timeout error {source}"))]
    Timeout { source: tokio::time::error::Elapsed },
    #[snafu(display("rustls error {source}"))]
    Rustls { source: tokio_rustls::rustls::Error },
    #[snafu(display("invalid dns name {source}"))]
    InvalidDnsName {
        source: tokio_rustls::rustls::pki_types::InvalidDnsNameError,
    },
    #[snafu(display("hyper error {source}"))]
    Hyper { source: hyper::Error },
    #[snafu(display("http error {source}"))]
    Http { source: http::Error },
}

pub type Result<T> = std::result::Result<T, Error>;
