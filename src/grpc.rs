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

use crate::{HttpRequest, HttpStat, ALPN_HTTP2};
use bytes::{Bytes, BytesMut};
use http::header::{HeaderMap, HeaderValue};
use http::uri::{PathAndQuery, Uri};

const HEALTH_CHECK_PATH: &str = "/grpc.health.v1.Health/Check";

fn is_health_path(path: &str) -> bool {
    path.is_empty() || path == "/" || path.contains("grpc.health.v1.Health/Check")
}

fn header_value(map: &HeaderMap, name: &str) -> Option<String> {
    map.get(name)
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string())
}

/// Concatenate uncompressed gRPC length-prefixed messages. A compressed flag
/// or a truncated frame leaves the body as it arrived.
fn unframe_grpc(bytes: &[u8]) -> Option<Bytes> {
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
        if flag != 0 {
            return None;
        }
        out.extend_from_slice(&bytes[i..i + len]);
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

/// Raw unary RPC. The scheme is rewritten before `request()` so this does not
/// recurse. Cleartext `grpc://` uses h2c prior knowledge; `--http2 http://`
/// is unchanged.
async fn raw_unary(mut http_req: HttpRequest) -> HttpStat {
    let cleartext = http_req.uri.scheme_str() == Some("grpc");
    let mut parts = http_req.uri.clone().into_parts();
    parts.scheme = Some(if cleartext {
        http::uri::Scheme::HTTP
    } else {
        http::uri::Scheme::HTTPS
    });
    if parts.path_and_query.is_none() {
        parts.path_and_query = Some(http::uri::PathAndQuery::from_static("/"));
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
    headers.insert(
        http::header::CONTENT_TYPE,
        HeaderValue::from_static("application/grpc"),
    );
    headers.insert(http::header::TE, HeaderValue::from_static("trailers"));
    http_req.headers = Some(headers);

    // Boxed so the grpc:// → request() → raw_unary cycle stays a finite future.
    // The scheme was rewritten above, so this call takes the HTTP path.
    let mut stat = Box::pin(crate::request::request(http_req)).await;
    stat.is_grpc = true;
    if let Some(body) = stat.body.clone() {
        if let Some(unframed) = unframe_grpc(&body) {
            stat.body_size = Some(unframed.len());
            stat.body = Some(unframed);
        }
    }
    apply_grpc_status(&mut stat);
    stat
}

pub(crate) async fn grpc_request(http_req: HttpRequest) -> HttpStat {
    if !is_health_path(http_req.uri.path()) {
        return raw_unary(http_req).await;
    }
    health_request(http_req).await
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
    if let Some(message) = grpc_trailer(stat, "grpc-message").filter(|m| !m.is_empty()) {
        error.push_str(&format!(": {message}"));
    }
    Some(error)
}

/// `grpc.health.v1.Health/Check` for the server as a whole. It is sent as a
/// raw unary RPC, so it shares the HTTP/2 path and its timings.
async fn health_request(mut http_req: HttpRequest) -> HttpStat {
    let mut parts = http_req.uri.clone().into_parts();
    parts.path_and_query = Some(PathAndQuery::from_static(HEALTH_CHECK_PATH));
    http_req.uri = Uri::from_parts(parts).unwrap_or(http_req.uri);
    // An empty HealthCheckRequest names no service.
    http_req.body = None;
    // The verdict is in the response message, so it has to stay in memory.
    http_req.discard_body = false;
    http_req.output_path = None;
    // The check dials the target directly.
    http_req.proxy = None;

    let mut stat = raw_unary(http_req).await;
    // One metadata block, so `grpc-status` stays readable from the headers.
    if let Some(trailers) = stat.trailers.take() {
        stat.headers
            .get_or_insert_with(HeaderMap::new)
            .extend(trailers);
    }
    if stat.error.is_some() {
        return stat;
    }
    if let Some(error) = health_rpc_error(&stat) {
        stat.error = Some(error);
        return stat;
    }
    let Some(status) = stat.body.as_deref().and_then(health_status) else {
        stat.error = Some("invalid health check response".to_string());
        return stat;
    };
    stat.body = Some(
        format!(
            "HealthCheckResponse {{ status: {} }}",
            serving_status_name(status)
        )
        .into(),
    );
    if status != SERVING {
        stat.error = Some("service not serving".to_string());
    }
    stat
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
        trailers.insert("grpc-message", HeaderValue::from_static("no such service"));
        with_message.trailers = Some(trailers);
        assert_eq!(
            health_rpc_error(&with_message).as_deref(),
            Some("grpc-status 5 (NOT_FOUND): no such service")
        );
    }
}
