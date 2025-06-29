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
use brotli_decompressor::Decompressor;
use bytes::Bytes;
use flate2::read::GzDecoder;
use zstd::Decoder;

// Decompress gzip data
fn decompress_gzip(data: &[u8]) -> Result<Bytes> {
    let mut decoder = GzDecoder::new(data);
    let mut decompressed = Vec::new();
    std::io::Read::read_to_end(&mut decoder, &mut decompressed).map_err(|e| Error::Common {
        category: "gzip".to_string(),
        message: format!("Failed to decompress gzip data: {e}"),
    })?;
    Ok(Bytes::from(decompressed))
}

fn decompress_brotli(data: &[u8]) -> Result<Bytes> {
    let mut decompressor = Decompressor::new(data, 4096);
    let mut decompressed = Vec::new();
    std::io::Read::read_to_end(&mut decompressor, &mut decompressed).map_err(|e| {
        Error::Common {
            category: "brotli".to_string(),
            message: format!("Failed to decompress brotli data: {e}"),
        }
    })?;
    Ok(Bytes::from(decompressed))
}

fn decompress_zstd(data: &[u8]) -> Result<Bytes> {
    let mut decompressor = Decoder::new(data).map_err(|e| Error::Common {
        category: "zstd".to_string(),
        message: format!("Failed to create zstd decoder: {e}"),
    })?;
    let mut decompressed = Vec::new();
    std::io::Read::read_to_end(&mut decompressor, &mut decompressed).map_err(|e| {
        Error::Common {
            category: "zstd".to_string(),
            message: format!("Failed to decompress zstd data: {e}"),
        }
    })?;
    Ok(Bytes::from(decompressed))
}

pub fn decompress(encoding: &str, data: &Bytes) -> Result<Bytes> {
    match encoding {
        "gzip" => decompress_gzip(data),
        "br" => decompress_brotli(data),
        "zstd" => decompress_zstd(data),
        _ => Ok(data.clone()),
    }
}
