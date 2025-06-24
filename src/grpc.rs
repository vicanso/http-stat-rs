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

use crate::{dns_resolve, finish_with_error, tcp_connect, Error, HttpRequest, HttpStat};
use http::uri::Uri;
use hyper_util::rt::TokioIo;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Instant;
use tokio::net::TcpStream;
use tokio::sync::Mutex;
use tonic::codegen::GrpcMethod;
use tonic::IntoRequest;
use tonic_health::{
    pb::{HealthCheckRequest, HealthCheckResponse},
    ServingStatus,
};
use tower_service::Service;

// Version information from Cargo.toml
const VERSION: &str = env!("CARGO_PKG_VERSION");

struct CustomHttpConnector {
    http_req: HttpRequest,
    stat: Arc<Mutex<HttpStat>>,
}

impl Service<Uri> for CustomHttpConnector {
    type Response = TokioIo<TcpStream>;
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
            let (addr, _host) = dns_resolve(&http_req, &mut stat).await?;
            let tcp_stream = tcp_connect(addr, http_req.tcp_timeout, &mut stat).await?;
            Ok(TokioIo::new(tcp_stream))
        };
        ConnectorConnecting {
            inner: Box::pin(fut),
        }
    }
}

type ConnectResult = Result<TokioIo<TcpStream>, Error>;

pub(crate) struct ConnectorConnecting {
    inner: Pin<Box<dyn Future<Output = ConnectResult> + Send>>,
}

impl Future for ConnectorConnecting {
    type Output = ConnectResult;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        self.get_mut().inner.as_mut().poll(cx)
    }
}

pub(crate) async fn grpc_request(http_req: HttpRequest) -> HttpStat {
    let start = Instant::now();
    let stat = Arc::new(Mutex::new(HttpStat {
        is_grpc: true,
        ..Default::default()
    }));
    let endpoint = tonic::transport::Endpoint::from(http_req.uri.clone());
    let endpoint = match endpoint.user_agent(format!("httpstat.rs/{}", VERSION)) {
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

    let mut grpc = tonic::client::Grpc::new(conn);
    match grpc.ready().await {
        Ok(_) => {}
        Err(e) => {
            let stat = stat.lock().await;
            return finish_with_error(stat.clone(), e, start);
        }
    }

    let server_processing_start = Instant::now();
    let codec = tonic::codec::ProstCodec::<HealthCheckRequest, HealthCheckResponse>::default();
    let path = http::uri::PathAndQuery::from_static("/grpc.health.v1.Health/Check");
    let mut req = HealthCheckRequest::default().into_request();
    req.extensions_mut()
        .insert(GrpcMethod::new("grpc.health.v1.Health", "Check"));
    let resp = match grpc.unary(req, path, codec).await {
        Ok(resp) => resp,
        Err(e) => {
            let stat = stat.lock().await;
            return finish_with_error(stat.clone(), e, start);
        }
    };

    stat.lock().await.server_processing = Some(server_processing_start.elapsed());
    let mut stat = stat.lock().await.clone();
    if resp.get_ref().status() != ServingStatus::Serving.into() {
        return finish_with_error(stat, "service not serving", start);
    }
    let (meta, message, _) = resp.into_parts();
    if let Some(grpc_status) = meta.get("grpc-status") {
        stat.grpc_status = Some(grpc_status.to_str().unwrap_or_default().to_string());
    }
    stat.headers = Some(meta.into_headers());
    stat.body = Some(format!("{:?}", message).into());
    stat.total = Some(start.elapsed());
    stat
}
