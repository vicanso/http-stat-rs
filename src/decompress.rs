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
use std::io::Read;
use zstd::Decoder;

/// What a decoder reports when its output passes the body size limit.
pub(crate) fn decoded_too_large(max: usize) -> String {
    format!("decompressed body exceeds the {max} byte limit (--max-filesize, 0 = unlimited)")
}

/// Read `decoder` to its end. `max` bounds the output: a small compressed
/// body can decode to a very large one.
pub(crate) fn read_decoded(decoder: impl Read, max: Option<usize>, name: &str) -> Result<Bytes> {
    // One byte past the limit is enough to know it was exceeded.
    let limit = max.map_or(u64::MAX, |max| (max as u64).saturating_add(1));
    let mut decoded = Vec::new();
    decoder
        .take(limit)
        .read_to_end(&mut decoded)
        .map_err(|e| Error::Common {
            category: name.to_string(),
            message: format!("Failed to decompress {name} data: {e}"),
        })?;
    match max {
        Some(max) if decoded.len() > max => Err(Error::Common {
            category: name.to_string(),
            message: decoded_too_large(max),
        }),
        _ => Ok(Bytes::from(decoded)),
    }
}

/// [`decompress`] with an upper bound on the decoded size.
pub(crate) fn decompress_capped(encoding: &str, data: &Bytes, max: Option<usize>) -> Result<Bytes> {
    match encoding {
        "gzip" => read_decoded(GzDecoder::new(data.as_ref()), max, "gzip"),
        "br" => read_decoded(Decompressor::new(data.as_ref(), 4096), max, "brotli"),
        "zstd" => {
            let decoder = Decoder::new(data.as_ref()).map_err(|e| Error::Common {
                category: "zstd".to_string(),
                message: format!("Failed to create zstd decoder: {e}"),
            })?;
            read_decoded(decoder, max, "zstd")
        }
        _ => Ok(data.clone()),
    }
}

pub fn decompress(encoding: &str, data: &Bytes) -> Result<Bytes> {
    decompress_capped(encoding, data, None)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::Cell;
    use std::io::Write;
    use std::rc::Rc;

    /// A reader that counts the bytes taken from it.
    struct Counted<R> {
        inner: R,
        taken: Rc<Cell<usize>>,
    }

    impl<R: Read> Read for Counted<R> {
        fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
            let n = self.inner.read(buf)?;
            self.taken.set(self.taken.get() + n);
            Ok(n)
        }
    }

    #[test]
    fn read_decoded_stops_one_byte_past_the_limit() {
        let taken = Rc::new(Cell::new(0));
        let decoder = Counted {
            inner: std::io::repeat(0).take(64 * 1024 * 1024),
            taken: taken.clone(),
        };
        let error = read_decoded(decoder, Some(1000), "gzip").unwrap_err();
        assert!(error.to_string().contains("exceeds the 1000 byte limit"));
        // The rest of the output is never produced.
        assert_eq!(taken.get(), 1001);
    }

    #[test]
    fn decompress_capped_bounds_the_decoded_size() {
        let plain = vec![7u8; 10_000];
        let mut encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
        encoder.write_all(&plain).unwrap();
        let gzip = Bytes::from(encoder.finish().unwrap());
        assert!(gzip.len() < 1000);

        assert_eq!(decompress("gzip", &gzip).unwrap(), plain);
        assert_eq!(
            decompress_capped("gzip", &gzip, Some(10_000)).unwrap(),
            plain
        );
        assert!(decompress_capped("gzip", &gzip, Some(9_999)).is_err());
        // An encoding that is not decoded is passed through whatever the limit.
        assert_eq!(decompress_capped("identity", &gzip, Some(1)).unwrap(), gzip);
    }
}
