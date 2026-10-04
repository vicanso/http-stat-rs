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

//! Response-body sink.
//!
//! The whole body is buffered only when the caller still needs it (display,
//! `--jq`, `--pretty`, library consumers). `-o` streams decoded bytes to the
//! file, and benchmark mode counts bytes and drops them.

use crate::decompress::decoded_too_large;
use crate::stats::FIRST_CHUNK_BYTES;
use brotli_decompressor::writer::DecompressorWriter;
use bytes::{Bytes, BytesMut};
use flate2::write::GzDecoder;
use std::fs::File;
use std::io::Write;
use std::path::PathBuf;
use std::time::{Duration, Instant};
use zstd::stream::write::Decoder as ZstdDecoder;

pub(crate) struct DrainedBody {
    pub bytes: Option<Bytes>,
    pub wire_len: usize,
    pub decoded_len: usize,
    pub first_100k: Option<Duration>,
    /// Time spent inside the decoder. Set only when bytes were decoded here
    /// (the streaming `-o` path). In-memory responses are decoded later.
    pub decompress: Option<Duration>,
    pub saved_to: Option<String>,
}

/// The output file behind a decoder. The wire bytes are counted as they
/// arrive; this bounds what they decode to.
struct CappedFile {
    file: File,
    max: Option<usize>,
    written: usize,
}

impl Write for CappedFile {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        if let Some(max) = self.max {
            if self.written.saturating_add(buf.len()) > max {
                return Err(std::io::Error::other(decoded_too_large(max)));
            }
        }
        let n = self.file.write(buf)?;
        self.written += n;
        Ok(n)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.file.flush()
    }
}

/// Concrete file writers so each decoder can run its consuming finish.
/// `Box<dyn Write>` cannot call `GzDecoder::finish` or `into_inner`.
enum FileSink {
    Plain(File),
    Gzip(Box<GzDecoder<CappedFile>>),
    Brotli(Box<DecompressorWriter<CappedFile>>),
    Zstd(Box<ZstdDecoder<'static, CappedFile>>),
}

impl FileSink {
    fn write_all(&mut self, chunk: &[u8]) -> std::io::Result<()> {
        match self {
            Self::Plain(file) => file.write_all(chunk),
            Self::Gzip(dec) => dec.write_all(chunk),
            Self::Brotli(dec) => dec.write_all(chunk),
            Self::Zstd(dec) => dec.write_all(chunk),
        }
    }

    fn finish(self) -> std::io::Result<()> {
        match self {
            Self::Plain(mut file) => file.flush(),
            Self::Gzip(dec) => {
                (*dec).finish()?;
                Ok(())
            }
            Self::Brotli(dec) => {
                let mut file = match (*dec).into_inner() {
                    Ok(file) | Err(file) => file,
                };
                file.flush()
            }
            Self::Zstd(dec) => {
                let mut dec = *dec;
                dec.flush()?;
                let mut file = dec.into_inner();
                file.flush()
            }
        }
    }
}

enum Sink {
    Memory(BytesMut),
    Discard,
    File(FileSink),
}

pub(crate) struct BodyPump {
    sink: Sink,
    wire_len: usize,
    decoded_len: usize,
    first_100k: Option<Duration>,
    decompress: Duration,
    decoded_here: bool,
    max: Option<usize>,
    saved_to: Option<String>,
}

impl BodyPump {
    /// `encoding` is the response `Content-Encoding` (may be empty).
    /// Streaming decode runs only when `output` is set; otherwise the wire
    /// bytes are kept for the caller to decode.
    pub(crate) fn new(
        max: Option<usize>,
        output: Option<&PathBuf>,
        discard: bool,
        encoding: &str,
    ) -> std::result::Result<Self, String> {
        let (sink, decoded_here, saved_to) = if let Some(path) = output {
            let file = File::create(path).map_err(|e| format!("write output error: {e}"))?;
            let saved = path.display().to_string();
            let writer = file_sink(file, encoding, max)?;
            (
                Sink::File(writer),
                !encoding_is_identity(encoding),
                Some(saved),
            )
        } else if discard {
            (Sink::Discard, false, None)
        } else {
            (Sink::Memory(BytesMut::new()), false, None)
        };
        Ok(Self {
            sink,
            wire_len: 0,
            decoded_len: 0,
            first_100k: None,
            decompress: Duration::ZERO,
            decoded_here,
            max,
            saved_to,
        })
    }

    pub(crate) fn push(
        &mut self,
        chunk: &[u8],
        started: Instant,
    ) -> std::result::Result<(), String> {
        if chunk.is_empty() {
            return Ok(());
        }
        if let Some(max) = self.max {
            if self.wire_len.saturating_add(chunk.len()) > max {
                return Err(format!(
                    "response body exceeds the {max} byte limit (--max-filesize, 0 = unlimited)"
                ));
            }
        }
        self.wire_len += chunk.len();
        if self.first_100k.is_none() && self.wire_len >= FIRST_CHUNK_BYTES {
            self.first_100k = Some(started.elapsed());
        }
        match &mut self.sink {
            Sink::Memory(buf) => buf.extend_from_slice(chunk),
            Sink::Discard => {}
            Sink::File(writer) => {
                let t0 = Instant::now();
                writer
                    .write_all(chunk)
                    .map_err(|e| format!("write output error: {e}"))?;
                if self.decoded_here {
                    self.decompress += t0.elapsed();
                }
            }
        }
        Ok(())
    }

    pub(crate) fn finish(mut self) -> std::result::Result<DrainedBody, String> {
        let bytes = match self.sink {
            Sink::Memory(buf) => {
                self.decoded_len = buf.len();
                Some(buf.freeze())
            }
            Sink::Discard => {
                self.decoded_len = self.wire_len;
                None
            }
            Sink::File(writer) => {
                let t0 = Instant::now();
                writer
                    .finish()
                    .map_err(|e| format!("write output error: {e}"))?;
                if self.decoded_here {
                    self.decompress += t0.elapsed();
                }
                // Decoder CPU is `decompress`. The file length is the decoded
                // size, measured after the consuming finish has flushed.
                self.decoded_len = self.saved_to.as_deref().and_then(file_len).unwrap_or(0);
                None
            }
        };
        Ok(DrainedBody {
            bytes,
            wire_len: self.wire_len,
            decoded_len: self.decoded_len,
            first_100k: self.first_100k,
            decompress: if self.decoded_here {
                Some(self.decompress)
            } else {
                None
            },
            saved_to: self.saved_to,
        })
    }
}

fn file_len(path: &str) -> Option<usize> {
    std::fs::metadata(path).ok().map(|m| m.len() as usize)
}

fn encoding_is_identity(encoding: &str) -> bool {
    let enc = encoding.trim();
    enc.is_empty() || enc.eq_ignore_ascii_case("identity")
}

fn file_sink(
    file: File,
    encoding: &str,
    max: Option<usize>,
) -> std::result::Result<FileSink, String> {
    let enc = encoding.split(',').next().unwrap_or("").trim();
    if encoding_is_identity(enc) {
        return Ok(FileSink::Plain(file));
    }
    let file = CappedFile {
        file,
        max,
        written: 0,
    };
    match enc {
        "gzip" | "x-gzip" => Ok(FileSink::Gzip(Box::new(GzDecoder::new(file)))),
        "br" => Ok(FileSink::Brotli(Box::new(DecompressorWriter::new(
            file, 4096,
        )))),
        "zstd" => ZstdDecoder::new(file)
            .map(|dec| FileSink::Zstd(Box::new(dec)))
            .map_err(|e| format!("zstd decoder: {e}")),
        other => Err(format!("unsupported content-encoding '{other}'")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use flate2::write::GzEncoder;
    use flate2::Compression;

    #[test]
    fn gzip_stream_finish_writes_decoded_bytes() {
        let mut enc = GzEncoder::new(Vec::new(), Compression::default());
        enc.write_all(b"hello httpstat").unwrap();
        let gz = enc.finish().unwrap();
        let path = std::env::temp_dir().join(format!("httpstat-body-{}.txt", std::process::id()));
        let mut pump = BodyPump::new(None, Some(&path), false, "gzip").unwrap();
        pump.push(&gz, Instant::now()).unwrap();
        let drained = pump.finish().unwrap();
        let text = std::fs::read_to_string(&path).unwrap();
        assert_eq!(text, "hello httpstat");
        assert_eq!(drained.decoded_len, text.len());
        assert!(drained.decompress.is_some());
        assert_eq!(drained.saved_to.as_deref(), Some(path.to_str().unwrap()));
        let _ = std::fs::remove_file(&path);
    }
}
