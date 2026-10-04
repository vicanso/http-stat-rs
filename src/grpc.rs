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

use crate::decompress::{decompress_capped, read_decoded};
use crate::proxy::percent_decode;
use crate::{HttpRequest, HttpStat, ALPN_HTTP2};
use bytes::{Bytes, BytesMut};
use http::header::{HeaderMap, HeaderValue};
use http::uri::{PathAndQuery, Uri};

const HEALTH_CHECK_PATH: &str = "/grpc.health.v1.Health/Check";
/// Message encodings `--compressed` offers the server, in `grpc-accept-encoding`.
const ACCEPTED_ENCODINGS: &str = "gzip,deflate,zstd";

fn is_health_path(path: &str) -> bool {
    path.is_empty() || path == "/" || path.contains("grpc.health.v1.Health/Check")
}

fn header_value(map: &HeaderMap, name: &str) -> Option<String> {
    map.get(name)
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string())
}

/// Decompress one message with the response's `grpc-encoding`, to at most
/// `max` bytes.
fn decompress_message(encoding: &str, data: &[u8], max: Option<usize>) -> Option<Bytes> {
    match encoding {
        "gzip" | "zstd" => decompress_capped(encoding, &Bytes::copy_from_slice(data), max).ok(),
        // gRPC's `deflate` is the zlib format.
        "deflate" => read_decoded(flate2::read::ZlibDecoder::new(data), max, encoding).ok(),
        _ => None,
    }
}

/// Concatenate gRPC length-prefixed messages, decompressing those flagged
/// as compressed with `encoding`. A truncated frame, or a compressed one
/// that cannot be decoded or passes `max` bytes, leaves the body as it
/// arrived.
fn unframe_grpc(bytes: &[u8], encoding: Option<&str>, max: Option<usize>) -> Option<Bytes> {
    if bytes.is_empty() {
        return Some(Bytes::new());
    }
    let mut i = 0;
    let mut out = BytesMut::new();
    while i < bytes.len() {
        if i + 5 > bytes.len() {
            return None;
        }
        let flag = bytes[i];
        let len =
            u32::from_be_bytes([bytes[i + 1], bytes[i + 2], bytes[i + 3], bytes[i + 4]]) as usize;
        i += 5;
        if i + len > bytes.len() {
            return None;
        }
        let message = &bytes[i..i + len];
        match flag {
            0 => out.extend_from_slice(message),
            1 => out.extend_from_slice(&decompress_message(encoding?, message, max)?),
            _ => return None,
        }
        if max.is_some_and(|max| out.len() > max) {
            return None;
        }
        i += len;
    }
    Some(out.freeze())
}

/// A gRPC trailer such as `grpc-status`. A Trailers-Only response carries
/// it in the headers instead.
fn grpc_trailer(stat: &HttpStat, name: &str) -> Option<String> {
    stat.trailers
        .as_ref()
        .and_then(|h| header_value(h, name))
        .or_else(|| stat.headers.as_ref().and_then(|h| header_value(h, name)))
}

fn apply_grpc_status(stat: &mut HttpStat) {
    stat.grpc_status = grpc_trailer(stat, "grpc-status");
}

/// Which RPC a `grpc://` / `grpcs://` request stands for.
pub(crate) enum GrpcCall {
    /// A raw unary RPC to the method in the URL path.
    Unary,
    /// `grpc.health.v1.Health/Check`.
    HealthCheck,
}

pub(crate) fn is_grpc(http_req: &HttpRequest) -> bool {
    matches!(http_req.uri.scheme_str(), Some("grpc" | "grpcs"))
}

/// The `service` query parameter of a health check URL, percent-decoded,
/// or `""` for the server as a whole.
fn health_service(query: Option<&str>) -> String {
    query
        .into_iter()
        .flat_map(|q| q.split('&'))
        .find_map(|pair| pair.strip_prefix("service="))
        .map(percent_decode)
        .unwrap_or_default()
}

/// A `grpc.health.v1.HealthCheckRequest`: `service` is field 1. Proto3
/// leaves out an empty string.
fn health_check_request(service: &str) -> Bytes {
    let mut msg = Vec::new();
    if !service.is_empty() {
        msg.push(0x0a);
        write_varint(&mut msg, service.len() as u64);
        msg.extend_from_slice(service.as_bytes());
    }
    Bytes::from(msg)
}

/// Turn a `grpc://` / `grpcs://` request into the HTTP/2 request that
/// carries it. Cleartext `grpc://` uses h2c prior knowledge; `--http2
/// http://` is unchanged.
pub(crate) fn prepare(mut http_req: HttpRequest) -> (HttpRequest, GrpcCall) {
    let call = if is_health_path(http_req.uri.path()) {
        GrpcCall::HealthCheck
    } else {
        GrpcCall::Unary
    };
    let cleartext = http_req.uri.scheme_str() == Some("grpc");
    let mut parts = http_req.uri.clone().into_parts();
    parts.scheme = Some(if cleartext {
        http::uri::Scheme::HTTP
    } else {
        http::uri::Scheme::HTTPS
    });
    match call {
        GrpcCall::HealthCheck => {
            http_req.body = Some(health_check_request(&health_service(http_req.uri.query())));
            parts.path_and_query = Some(PathAndQuery::from_static(HEALTH_CHECK_PATH));
            // The verdict is in the response message, so it has to stay in
            // memory.
            http_req.discard_body = false;
            http_req.output_path = None;
        }
        GrpcCall::Unary => {
            if parts.path_and_query.is_none() {
                parts.path_and_query = Some(PathAndQuery::from_static("/"));
            }
        }
    }
    http_req.uri = Uri::from_parts(parts).unwrap_or(http_req.uri);
    http_req.alpn_protocols = vec![ALPN_HTTP2.to_string()];
    http_req.method = Some("POST".to_string());
    http_req.h2_prior_knowledge = cleartext;

    let payload = http_req.body.clone().unwrap_or_default();
    let mut frame = Vec::with_capacity(5 + payload.len());
    frame.push(0);
    frame.extend_from_slice(&(payload.len() as u32).to_be_bytes());
    frame.extend_from_slice(&payload);
    http_req.body = Some(Bytes::from(frame));

    let mut headers = http_req.headers.take().unwrap_or_default();
    // gRPC compresses per message, not at the HTTP level: `--compressed`
    // (an `Accept-Encoding` header) asks for that instead.
    if headers.remove(http::header::ACCEPT_ENCODING).is_some() {
        headers.insert(
            "grpc-accept-encoding",
            HeaderValue::from_static(ACCEPTED_ENCODINGS),
        );
    }
    headers.insert(
        http::header::CONTENT_TYPE,
        HeaderValue::from_static("application/grpc"),
    );
    headers.insert(http::header::TE, HeaderValue::from_static("trailers"));
    http_req.headers = Some(headers);
    (http_req, call)
}

/// Read the gRPC outcome out of the HTTP/2 response to a prepared request.
/// `max_body_size` bounds what compressed messages may decode to.
pub(crate) fn finish(
    mut stat: HttpStat,
    call: &GrpcCall,
    max_body_size: Option<usize>,
) -> HttpStat {
    stat.is_grpc = true;
    let encoding = stat
        .headers
        .as_ref()
        .and_then(|h| header_value(h, "grpc-encoding"));
    if let Some(body) = stat.body.clone() {
        if let Some(unframed) = unframe_grpc(&body, encoding.as_deref(), max_body_size) {
            stat.body_size = Some(unframed.len());
            stat.body = Some(unframed);
        }
    }
    apply_grpc_status(&mut stat);
    if let GrpcCall::HealthCheck = call {
        finish_health_check(&mut stat);
    }
    stat
}

pub(crate) async fn grpc_request(http_req: HttpRequest) -> HttpStat {
    let (http_req, call) = prepare(http_req);
    let max_body_size = http_req.max_body_size;
    // Boxed so the grpc:// → request() → grpc_request cycle stays a finite
    // future. `prepare` rewrote the scheme, so this call takes the HTTP path.
    let stat = Box::pin(crate::request::request(http_req)).await;
    finish(stat, &call, max_body_size)
}

fn write_varint(buf: &mut Vec<u8>, mut value: u64) {
    while value >= 0x80 {
        buf.push(value as u8 | 0x80);
        value >>= 7;
    }
    buf.push(value as u8);
}

fn read_varint(buf: &mut &[u8]) -> Option<u64> {
    let mut value = 0u64;
    for shift in (0..64).step_by(7) {
        let (&byte, rest) = buf.split_first()?;
        *buf = rest;
        value |= u64::from(byte & 0x7f) << shift;
        if byte & 0x80 == 0 {
            return Some(value);
        }
    }
    None
}

/// `status` (field 1) of a `grpc.health.v1.HealthCheckResponse`. Proto3
/// omits a zero value, so an empty message is `UNKNOWN`. `None` when the
/// bytes are not a protobuf message.
fn health_status(mut msg: &[u8]) -> Option<u64> {
    let mut status = 0;
    while !msg.is_empty() {
        let key = read_varint(&mut msg)?;
        let field = key >> 3;
        if field == 0 {
            return None;
        }
        match key & 7 {
            0 => {
                let value = read_varint(&mut msg)?;
                if field == 1 {
                    status = value;
                }
            }
            1 => msg = msg.get(8..)?,
            2 => {
                let len = usize::try_from(read_varint(&mut msg)?).ok()?;
                msg = msg.get(len..)?;
            }
            5 => msg = msg.get(4..)?,
            _ => return None,
        }
    }
    Some(status)
}

/// `grpc.health.v1.HealthCheckResponse.ServingStatus.SERVING`.
const SERVING: u64 = 1;

fn serving_status_name(status: u64) -> String {
    match status {
        0 => "Unknown".to_string(),
        SERVING => "Serving".to_string(),
        2 => "NotServing".to_string(),
        3 => "ServiceUnknown".to_string(),
        other => other.to_string(),
    }
}

fn grpc_code_name(code: &str) -> Option<&'static str> {
    const NAMES: [&str; 17] = [
        "OK",
        "CANCELLED",
        "UNKNOWN",
        "INVALID_ARGUMENT",
        "DEADLINE_EXCEEDED",
        "NOT_FOUND",
        "ALREADY_EXISTS",
        "PERMISSION_DENIED",
        "RESOURCE_EXHAUSTED",
        "FAILED_PRECONDITION",
        "ABORTED",
        "OUT_OF_RANGE",
        "UNIMPLEMENTED",
        "INTERNAL",
        "UNAVAILABLE",
        "DATA_LOSS",
        "UNAUTHENTICATED",
    ];
    NAMES.get(code.parse::<usize>().ok()?).copied()
}

/// Why a health check RPC that got an HTTP response still failed, or `None`
/// when `grpc-status` is `0`.
fn health_rpc_error(stat: &HttpStat) -> Option<String> {
    let Some(code) = stat.grpc_status.as_deref() else {
        let status = stat.status.map(|s| s.as_u16()).unwrap_or_default();
        return Some(format!("grpc-status missing (HTTP {status})"));
    };
    if code == "0" {
        return None;
    }
    let mut error = format!("grpc-status {code}");
    if let Some(name) = grpc_code_name(code) {
        error.push_str(&format!(" ({name})"));
    }
    // `grpc-message` is percent-encoded on the wire.
    if let Some(message) = grpc_trailer(stat, "grpc-message").filter(|m| !m.is_empty()) {
        error.push_str(&format!(": {}", percent_decode(&message)));
    }
    Some(error)
}

/// Turn the response to `grpc.health.v1.Health/Check` into a verdict.
fn finish_health_check(stat: &mut HttpStat) {
    // One metadata block, so `grpc-status` stays readable from the headers.
    if let Some(trailers) = stat.trailers.take() {
        stat.headers
            .get_or_insert_with(HeaderMap::new)
            .extend(trailers);
    }
    if stat.error.is_some() {
        return;
    }
    if let Some(error) = health_rpc_error(stat) {
        stat.error = Some(error);
        return;
    }
    let Some(status) = stat.body.as_deref().and_then(health_status) else {
        stat.error = Some("invalid health check response".to_string());
        return;
    };
    stat.body = Some(
        format!(
            "HealthCheckResponse {{ status: {} }}",
            serving_status_name(status)
        )
        .into(),
    );
    stat.body_is_text = true;
    if status != SERVING {
        stat.error = Some("service not serving".to_string());
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn health_status_reads_field_one() {
        // Proto3 leaves out a zero value.
        assert_eq!(health_status(&[]), Some(0));
        assert_eq!(health_status(&[0x08, 0x01]), Some(1));
        assert_eq!(health_status(&[0x08, 0x02]), Some(2));
        assert_eq!(health_status(&[0x08, 0x81, 0x01]), Some(129));
    }

    #[test]
    fn health_status_skips_unknown_fields() {
        // field 2 (bytes), field 3 (fixed32), field 4 (fixed64), then status.
        let msg = [
            0x12, 0x02, b'h', b'i', 0x1d, 1, 2, 3, 4, 0x21, 1, 2, 3, 4, 5, 6, 7, 8, 0x08, 0x01,
        ];
        assert_eq!(health_status(&msg), Some(1));
    }

    #[test]
    fn health_status_rejects_malformed_messages() {
        // Truncated varint, length past the end, and an unsupported wire type.
        assert_eq!(health_status(&[0x08]), None);
        assert_eq!(health_status(&[0x08, 0x80]), None);
        assert_eq!(health_status(&[0x12, 0x05, b'h']), None);
        assert_eq!(health_status(&[0x0b]), None);
        assert_eq!(health_status(&[0x08; 12].map(|b| b | 0x80)), None);
        // A gRPC frame that was not unframed (compressed or truncated) starts
        // with a flag byte, which decodes as field number 0.
        assert_eq!(health_status(&[0, 0, 0, 0, 2, 0x08, 0x01]), None);
        assert_eq!(health_status(&[1, 0, 0, 0, 2, 0x08, 0x01]), None);
    }

    #[test]
    fn serving_status_names_match_the_proto_enum() {
        assert_eq!(serving_status_name(0), "Unknown");
        assert_eq!(serving_status_name(1), "Serving");
        assert_eq!(serving_status_name(2), "NotServing");
        assert_eq!(serving_status_name(3), "ServiceUnknown");
        assert_eq!(serving_status_name(7), "7");
    }

    #[test]
    fn health_rpc_error_explains_the_status() {
        let stat = |code: Option<&str>| HttpStat {
            status: Some(http::StatusCode::OK),
            grpc_status: code.map(String::from),
            ..Default::default()
        };
        assert_eq!(health_rpc_error(&stat(Some("0"))), None);
        assert_eq!(
            health_rpc_error(&stat(Some("12"))).as_deref(),
            Some("grpc-status 12 (UNIMPLEMENTED)")
        );
        assert_eq!(
            health_rpc_error(&stat(Some("99"))).as_deref(),
            Some("grpc-status 99")
        );
        assert_eq!(
            health_rpc_error(&stat(None)).as_deref(),
            Some("grpc-status missing (HTTP 200)")
        );

        let mut with_message = stat(Some("5"));
        let mut trailers = HeaderMap::new();
        trailers.insert(
            "grpc-message",
            HeaderValue::from_static("service%20not%20registered"),
        );
        with_message.trailers = Some(trailers);
        assert_eq!(
            health_rpc_error(&with_message).as_deref(),
            Some("grpc-status 5 (NOT_FOUND): service not registered")
        );
    }

    #[test]
    fn health_service_comes_from_the_query() {
        assert_eq!(health_service(None), "");
        assert_eq!(health_service(Some("")), "");
        assert_eq!(health_service(Some("service=pkg.Svc")), "pkg.Svc");
        assert_eq!(health_service(Some("a=1&service=pkg.Svc&b=2")), "pkg.Svc");
        assert_eq!(health_service(Some("myservice=x")), "");
        assert_eq!(
            health_service(Some("service=my%2Epkg.Svc%20v2")),
            "my.pkg.Svc v2"
        );
    }

    #[test]
    fn health_check_request_encodes_the_service_name() {
        assert!(health_check_request("").is_empty());
        assert_eq!(
            health_check_request("ab").as_ref(),
            [0x0a, 0x02, b'a', b'b']
        );
        // A length past 127 needs a two-byte varint.
        let long = "x".repeat(200);
        let msg = health_check_request(&long);
        assert_eq!(&msg[..3], [0x0a, 0xc8, 0x01]);
        assert_eq!(msg.len(), 3 + 200);
    }

    #[test]
    fn prepare_builds_a_health_check() {
        let mut req = HttpRequest::try_from("grpc://svc.local:50051/?service=pkg.Svc").unwrap();
        req.body = Some(Bytes::from_static(b"ignored"));
        req.discard_body = true;
        req.proxy = Some("http://proxy.local:8080".to_string());
        let mut headers = HeaderMap::new();
        headers.insert(
            http::header::ACCEPT_ENCODING,
            HeaderValue::from_static("gzip, br, zstd"),
        );
        req.headers = Some(headers);
        let (wire, call) = prepare(req);
        assert!(matches!(call, GrpcCall::HealthCheck));
        assert_eq!(
            wire.uri.to_string(),
            "http://svc.local:50051/grpc.health.v1.Health/Check"
        );
        assert_eq!(wire.method.as_deref(), Some("POST"));
        assert!(wire.h2_prior_knowledge);
        assert!(!wire.discard_body);
        // A health check goes through the proxy like any other call.
        assert_eq!(wire.proxy.as_deref(), Some("http://proxy.local:8080"));
        // --compressed becomes per-message compression.
        let headers = wire.headers.as_ref().unwrap();
        assert!(headers.get(http::header::ACCEPT_ENCODING).is_none());
        assert_eq!(
            headers.get("grpc-accept-encoding").unwrap(),
            ACCEPTED_ENCODINGS
        );
        // 5-byte gRPC frame header, then the HealthCheckRequest.
        let mut expected = vec![0, 0, 0, 0, 9, 0x0a, 7];
        expected.extend_from_slice(b"pkg.Svc");
        assert_eq!(wire.body.as_deref(), Some(expected.as_slice()));
    }

    #[test]
    fn prepare_keeps_a_unary_call_as_written() {
        let mut req = HttpRequest::try_from("grpcs://svc.local/pkg.Svc/Method").unwrap();
        req.body = Some(Bytes::from_static(&[0x08, 0x01]));
        req.discard_body = true;
        let (wire, call) = prepare(req);
        assert!(matches!(call, GrpcCall::Unary));
        assert_eq!(wire.uri.to_string(), "https://svc.local/pkg.Svc/Method");
        assert!(!wire.h2_prior_knowledge);
        assert!(wire.discard_body);
        assert!(wire
            .headers
            .as_ref()
            .unwrap()
            .get("grpc-accept-encoding")
            .is_none());
        assert_eq!(wire.alpn_protocols, [ALPN_HTTP2]);
        assert_eq!(
            wire.body.as_deref(),
            Some([0, 0, 0, 0, 2, 0x08, 0x01].as_slice())
        );
    }

    #[test]
    fn finish_reads_the_health_verdict() {
        let response = |message: &'static [u8]| {
            let mut headers = HeaderMap::new();
            headers.insert("content-type", HeaderValue::from_static("application/grpc"));
            let mut trailers = HeaderMap::new();
            trailers.insert("grpc-status", HeaderValue::from_static("0"));
            HttpStat {
                status: Some(http::StatusCode::OK),
                headers: Some(headers),
                trailers: Some(trailers),
                body: Some(Bytes::from_static(message)),
                ..Default::default()
            }
        };
        let serving = finish(
            response(&[0, 0, 0, 0, 2, 0x08, 0x01]),
            &GrpcCall::HealthCheck,
            None,
        );
        assert!(serving.is_success());
        assert!(serving.body_is_text);
        assert_eq!(
            serving.body.as_deref(),
            Some(b"HealthCheckResponse { status: Serving }".as_slice())
        );
        // Trailers are folded into the headers for a health check.
        assert!(serving.trailers.is_none());
        assert_eq!(serving.headers.unwrap().get("grpc-status").unwrap(), "0");

        let down = finish(
            response(&[0, 0, 0, 0, 2, 0x08, 0x02]),
            &GrpcCall::HealthCheck,
            None,
        );
        assert_eq!(down.error.as_deref(), Some("service not serving"));

        // A raw unary call keeps the message bytes and its trailers.
        let unary = finish(
            response(&[0, 0, 0, 0, 2, 0x08, 0x01]),
            &GrpcCall::Unary,
            None,
        );
        assert!(unary.is_success());
        assert!(!unary.body_is_text);
        assert_eq!(unary.body.as_deref(), Some([0x08, 0x01].as_slice()));
        assert!(unary.trailers.is_some());
    }

    fn frame(flag: u8, message: &[u8]) -> Vec<u8> {
        let mut frame = vec![flag];
        frame.extend_from_slice(&(message.len() as u32).to_be_bytes());
        frame.extend_from_slice(message);
        frame
    }

    #[test]
    fn unframe_joins_plain_messages() {
        assert_eq!(
            unframe_grpc(&[], None, None).as_deref(),
            Some([].as_slice())
        );
        let mut body = frame(0, b"one");
        body.extend(frame(0, b"two"));
        assert_eq!(
            unframe_grpc(&body, None, None).as_deref(),
            Some(b"onetwo".as_slice())
        );
        // A frame cut short leaves the body alone.
        assert_eq!(unframe_grpc(&body[..body.len() - 1], None, None), None);
    }

    #[test]
    fn unframe_decompresses_flagged_messages() {
        use std::io::Write;
        let message = b"a compressed gRPC message, a compressed gRPC message";

        let mut gzip = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
        gzip.write_all(message).unwrap();
        let gzip = gzip.finish().unwrap();

        let mut zlib = flate2::write::ZlibEncoder::new(Vec::new(), flate2::Compression::default());
        zlib.write_all(message).unwrap();
        let zlib = zlib.finish().unwrap();

        let zstd = zstd::encode_all(message.as_slice(), 0).unwrap();

        for (encoding, compressed) in [("gzip", gzip), ("deflate", zlib), ("zstd", zstd)] {
            // A compressed message followed by a plain one.
            let mut body = frame(1, &compressed);
            body.extend(frame(0, b"!"));
            let mut expected = message.to_vec();
            expected.push(b'!');
            assert_eq!(
                unframe_grpc(&body, Some(encoding), None).as_deref(),
                Some(expected.as_slice()),
                "{encoding}"
            );
            // Without a usable `grpc-encoding` the body is left alone.
            assert_eq!(unframe_grpc(&body, None, None), None, "{encoding}");
            assert_eq!(
                unframe_grpc(&body, Some("snappy"), None),
                None,
                "{encoding}"
            );
        }
        // The flag is set but the bytes are not what the encoding says.
        assert_eq!(unframe_grpc(&frame(1, b"plain"), Some("gzip"), None), None);
    }
}
