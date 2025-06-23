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

use crate::{finish_with_error, HttpRequest, HttpStat};
use hyper_util::client::legacy::connect::HttpConnector;
use std::time::{Duration, Instant};
use tonic_health::{
    pb::{health_client::HealthClient, HealthCheckRequest},
    ServingStatus,
};

pub(crate) async fn grpc_request(http_req: HttpRequest) -> HttpStat {
    let start = Instant::now();
    let mut stat = HttpStat {
        ..Default::default()
    };
    let endpoint = tonic::transport::Endpoint::from(http_req.uri);
    let mut http = HttpConnector::new();
    // let mut http = HttpConnector::new_with_resolver(resolver);
    http.enforce_http(false);
    http.set_connect_timeout(Some(Duration::from_secs(30)));

    let conn = match endpoint.connect_with_connector(http).await {
        Ok(conn) => conn,
        Err(e) => {
            return finish_with_error(stat, e, start);
        }
    };
    let resp = match HealthClient::new(conn)
        .check(HealthCheckRequest::default())
        .await
    {
        Ok(resp) => resp,
        Err(e) => {
            return finish_with_error(stat, e, start);
        }
    };
    if resp.get_ref().status() != ServingStatus::Serving.into() {
        return finish_with_error(stat, "service not serving", start);
    }
    stat.total = Some(start.elapsed());
    stat
}
