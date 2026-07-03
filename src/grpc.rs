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
            let (addr, host) = dns_resolve(&http_req, &mut stat).await?;
            // gRPC uses tonic's high-level client; we can't reliably sample
            // post-transfer TCP_INFO, so drop the probe. The post-connect
            // baseline is already populated by tcp_connect.
            let (tcp_stream, _tcp_probe) =
                tcp_connect(addr, http_req.tcp_timeout, http_req.bind_addr, &mut stat).await?;
            // grpcs:// = gRPC over TLS: run the rustls handshake (honoring
            // --skip-verify and mTLS) with h2 as the only ALPN offer, since
            // gRPC requires HTTP/2.
            if http_req.uri.scheme_str() == Some("grpcs") {
                let mut tls_req = http_req.clone();
                tls_req.alpn_protocols = vec![ALPN_HTTP2.to_string()];
                let (tls_stream, _) = tls_handshake(host, tcp_stream, &tls_req, &mut stat).await?;
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

pub(crate) async fn grpc_request(http_req: HttpRequest) -> HttpStat {
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
    stat.headers = Some(meta.into_headers());
    stat.body = Some(format!("{message:?}").into());
    stat.total = Some(start.elapsed());
    stat
}
