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

use crate::{
    dns_resolve, finish_with_error, tcp_connect, tls_handshake, Error, HttpRequest, HttpStat,
    ALPN_HTTP2,
};
use bytes::{Bytes, BytesMut};
use http::header::{HeaderMap, HeaderValue};
use http::uri::Uri;
use hyper_util::rt::TokioIo;
use std::future::Future;
use std::io;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Instant;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::TcpStream;
use tokio::sync::Mutex;
use tokio_rustls::client::TlsStream;
use tonic_health::pb::health_client::HealthClient;
use tonic_health::{pb::HealthCheckRequest, ServingStatus};
use tower_service::Service;

// Version information from Cargo.toml
const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Transport handed to tonic: plain TCP for `grpc://`, rustls-wrapped TCP
/// for `grpcs://`.
pub(crate) enum GrpcStream {
    Plain(TcpStream),
    Tls(Box<TlsStream<TcpStream>>),
}

impl AsyncRead for GrpcStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        match self.get_mut() {
            GrpcStream::Plain(s) => Pin::new(s).poll_read(cx, buf),
            GrpcStream::Tls(s) => Pin::new(s.as_mut()).poll_read(cx, buf),
        }
    }
}

impl AsyncWrite for GrpcStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        match self.get_mut() {
            GrpcStream::Plain(s) => Pin::new(s).poll_write(cx, buf),
            GrpcStream::Tls(s) => Pin::new(s.as_mut()).poll_write(cx, buf),
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self.get_mut() {
            GrpcStream::Plain(s) => Pin::new(s).poll_flush(cx),
            GrpcStream::Tls(s) => Pin::new(s.as_mut()).poll_flush(cx),
        }
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self.get_mut() {
            GrpcStream::Plain(s) => Pin::new(s).poll_shutdown(cx),
            GrpcStream::Tls(s) => Pin::new(s.as_mut()).poll_shutdown(cx),
        }
    }
}

struct CustomHttpConnector {
    http_req: HttpRequest,
    stat: Arc<Mutex<HttpStat>>,
}

impl Service<Uri> for CustomHttpConnector {
    type Response = TokioIo<GrpcStream>;
    type Error = Error;
    type Future = ConnectorConnecting;

    fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, _: Uri) -> Self::Future {
        let http_req = self.http_req.clone();
        let stat = Arc::clone(&self.stat);
        let fut = async move {
            let mut stat = stat.lock().await;
            let resolved = dns_resolve(&http_req, &mut stat).await?;
            // gRPC uses tonic's high-level client; we can't reliably sample
            // post-transfer TCP_INFO, so drop the probe. The post-connect
            // baseline is already populated by tcp_connect.
            let (tcp_stream, _tcp_probe, winner) = tcp_connect(
                resolved.addrs,
                http_req.tcp_timeout,
                http_req.bind_addr,
                &mut stat,
            )
            .await?;
            http_req.note_dns_winner(&resolved.cache_host, resolved.cache_port, winner);
            // grpcs:// = gRPC over TLS: run the rustls handshake (honoring
            // --skip-verify and mTLS) with h2 as the only ALPN offer, since
            // gRPC requires HTTP/2.
            if http_req.uri.scheme_str() == Some("grpcs") {
                let mut tls_req = http_req.clone();
                tls_req.alpn_protocols = vec![ALPN_HTTP2.to_string()];
                let (tls_stream, _) =
                    tls_handshake(resolved.host, tcp_stream, &tls_req, &mut stat).await?;
                Ok(TokioIo::new(GrpcStream::Tls(Box::new(tls_stream))))
            } else {
                Ok(TokioIo::new(GrpcStream::Plain(tcp_stream)))
            }
        };
        ConnectorConnecting {
            inner: Box::pin(fut),
        }
    }
}

type ConnectResult = Result<TokioIo<GrpcStream>, Error>;

pub(crate) struct ConnectorConnecting {
    inner: Pin<Box<dyn Future<Output = ConnectResult> + Send>>,
}

impl Future for ConnectorConnecting {
    type Output = ConnectResult;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        self.get_mut().inner.as_mut().poll(cx)
    }
}

/// The `:scheme` pseudo-header tonic sends comes from the endpoint URI.
/// `grpc`/`grpcs` are not valid HTTP schemes and strict servers reset the
/// stream with PROTOCOL_ERROR, so normalize to `http`/`https` here; the
/// connector keeps looking at the original request URI for TLS routing.
fn endpoint_uri(uri: &Uri) -> Uri {
    let mut parts = uri.clone().into_parts();
    parts.scheme = Some(if uri.scheme_str() == Some("grpcs") {
        http::uri::Scheme::HTTPS
    } else {
        http::uri::Scheme::HTTP
    });
    if parts.path_and_query.is_none() {
        parts.path_and_query = Some(http::uri::PathAndQuery::from_static("/"));
    }
    Uri::from_parts(parts).unwrap_or_else(|_| uri.clone())
}

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

fn apply_grpc_status(stat: &mut HttpStat) {
    stat.grpc_status = stat
        .trailers
        .as_ref()
        .and_then(|h| header_value(h, "grpc-status"))
        .or_else(|| {
            stat.headers
                .as_ref()
                .and_then(|h| header_value(h, "grpc-status"))
        });
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

async fn health_request(http_req: HttpRequest) -> HttpStat {
    let start = Instant::now();
    let stat = Arc::new(Mutex::new(HttpStat {
        is_grpc: true,
        ..Default::default()
    }));
    let endpoint = tonic::transport::Endpoint::from(endpoint_uri(&http_req.uri));
    let endpoint = match endpoint.user_agent(format!("httpstat.rs/{VERSION}")) {
        Ok(endpoint) => endpoint,
        Err(e) => {
            let stat = stat.lock().await;
            return finish_with_error(stat.clone(), e, start);
        }
    };

    let conn = match endpoint
        .connect_with_connector(CustomHttpConnector {
            http_req,
            stat: Arc::clone(&stat),
        })
        .await
    {
        Ok(conn) => conn,
        Err(e) => {
            let stat = stat.lock().await;
            return finish_with_error(stat.clone(), e, start);
        }
    };
    let mut client = HealthClient::new(conn);
    let server_processing_start = Instant::now();
    let resp = match client.check(HealthCheckRequest::default()).await {
        Ok(resp) => resp,
        Err(e) => {
            let stat = stat.lock().await;
            return finish_with_error(stat.clone(), e, start);
        }
    };

    let mut stat = {
        let mut guard = stat.lock().await;
        guard.server_processing = Some(server_processing_start.elapsed());
        guard.clone()
    };
    if resp.get_ref().status() != ServingStatus::Serving.into() {
        return finish_with_error(stat, "service not serving", start);
    }
    let (meta, message, _) = resp.into_parts();
    if let Some(grpc_status) = meta.get("grpc-status") {
        stat.grpc_status = Some(grpc_status.to_str().unwrap_or_default().to_string());
    }
    // tonic omits grpc-status on a successful Check. Success requires "0".
    if stat.grpc_status.is_none() {
        stat.grpc_status = Some("0".to_string());
    }
    stat.headers = Some(meta.into_headers());
    stat.body = Some(format!("{message:?}").into());
    stat.total = Some(start.elapsed());
    stat
}
