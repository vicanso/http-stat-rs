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

// HTTP/1.1, HTTP/2, and HTTP/3 request execution.

use super::body_io::{BodyPump, DrainedBody};
use super::decompress::decompress;
use super::error::{Error, Result};
use super::finish_with_error;
use super::grpc::grpc_request;
use super::net::{
    capture_quic_certs, dns_resolve, quic_connect, tcp_connect, tls_connect_stream, tls_handshake,
    QuicConnect,
};
use super::proxy::{basic_auth_header, http_connect, socks5_connect, ProxyConfig, ProxyKind};
use super::quic_info::QuicInfo;
use super::stats::{parse_alt_svc, parse_hsts, parse_server_timing, HttpStat, ALPN_HTTP3};
use super::HttpRequest;
use bytes::{Buf, Bytes};
use http::Request;
use http::Response;
use http::Version;
use http_body::{Body, Frame, SizeHint};
use http_body_util::BodyExt;
use hyper::body::Incoming;
use hyper_util::rt::TokioExecutor;
use hyper_util::rt::TokioIo;
use std::io;
use std::pin::Pin;
use std::sync::{Arc, Once, OnceLock};
use std::task::{Context, Poll};
use std::time::Duration;
use std::time::Instant;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::TcpStream;
use tokio::sync::oneshot;
use tokio::time::timeout;
use tokio_rustls::client::TlsStream;

/// Returned when `--http3` is combined with a proxy that was not bypassed.
pub(crate) const H3_PROXY_REFUSAL: &str =
    "HTTP/3 does not support proxies; refusing to bypass --proxy";

type H3Send = h3::client::SendRequest<h3_quinn::OpenStreams, Bytes>;

/// Direct TCP, or a TLS session to an HTTPS proxy after CONNECT.
/// One type so the origin handshake can wrap either path.
enum BoxedIo {
    Plain(TcpStream),
    ProxyTls(Box<TlsStream<TcpStream>>),
}

impl AsyncRead for BoxedIo {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        match self.get_mut() {
            BoxedIo::Plain(s) => Pin::new(s).poll_read(cx, buf),
            BoxedIo::ProxyTls(s) => Pin::new(s.as_mut()).poll_read(cx, buf),
        }
    }
}

impl AsyncWrite for BoxedIo {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        match self.get_mut() {
            BoxedIo::Plain(s) => Pin::new(s).poll_write(cx, buf),
            BoxedIo::ProxyTls(s) => Pin::new(s.as_mut()).poll_write(cx, buf),
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self.get_mut() {
            BoxedIo::Plain(s) => Pin::new(s).poll_flush(cx),
            BoxedIo::ProxyTls(s) => Pin::new(s.as_mut()).poll_flush(cx),
        }
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self.get_mut() {
            BoxedIo::Plain(s) => Pin::new(s).poll_shutdown(cx),
            BoxedIo::ProxyTls(s) => Pin::new(s.as_mut()).poll_shutdown(cx),
        }
    }
}

/// Request body that records the `Instant` at which hyper finished consuming it.
pub(crate) struct TrackedBody {
    data: Option<Bytes>,
    done: Arc<OnceLock<Instant>>,
}

impl TrackedBody {
    pub(crate) fn new(data: Bytes) -> (Self, Arc<OnceLock<Instant>>) {
        let done = Arc::new(OnceLock::new());
        (
            Self {
                data: Some(data),
                done: done.clone(),
            },
            done,
        )
    }
}

impl Body for TrackedBody {
    type Data = Bytes;
    type Error = std::convert::Infallible;

    fn poll_frame(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
    ) -> Poll<Option<std::result::Result<Frame<Self::Data>, Self::Error>>> {
        let this = self.get_mut();
        if let Some(bytes) = this.data.take() {
            Poll::Ready(Some(Ok(Frame::data(bytes))))
        } else {
            let _ = this.done.set(Instant::now());
            Poll::Ready(None)
        }
    }

    fn is_end_stream(&self) -> bool {
        false
    }

    fn size_hint(&self) -> SizeHint {
        match &self.data {
            Some(b) => SizeHint::with_exact(b.len() as u64),
            None => SizeHint::with_exact(0),
        }
    }
}

fn build_tracked_request(
    req: &HttpRequest,
    is_http1: bool,
) -> Result<(Request<TrackedBody>, Arc<OnceLock<Instant>>)> {
    let body = req.body.clone().unwrap_or_default();
    let (tracked, done) = TrackedBody::new(body);
    let request = req
        .builder(is_http1)
        .body(tracked)
        .map_err(|e| Error::Http { source: e })?;
    Ok((request, done))
}

fn record_send_split(
    stat: &mut HttpStat,
    send_start: Instant,
    response_at: Instant,
    done: &Arc<OnceLock<Instant>>,
) {
    match done.get().copied() {
        Some(done_at) if done_at >= send_start && done_at <= response_at => {
            stat.request_send = Some(done_at.duration_since(send_start));
            stat.server_processing = Some(response_at.duration_since(done_at));
        }
        _ => {
            stat.server_processing = Some(response_at.duration_since(send_start));
        }
    }
}

fn capture_server_timing(stat: &mut HttpStat, headers: &http::HeaderMap) {
    let values: Vec<&str> = headers
        .get_all("server-timing")
        .iter()
        .filter_map(|v| v.to_str().ok())
        .collect();
    if !values.is_empty() {
        stat.server_timing = parse_server_timing(values.iter().copied());
    }
}

fn capture_protocol_advertisements(stat: &mut HttpStat, headers: &http::HeaderMap) {
    let alt_svc_values: Vec<&str> = headers
        .get_all("alt-svc")
        .iter()
        .filter_map(|v| v.to_str().ok())
        .collect();
    if !alt_svc_values.is_empty() {
        stat.alt_svc = parse_alt_svc(alt_svc_values.iter().copied());
    }
    if let Some(v) = headers
        .get("strict-transport-security")
        .and_then(|v| v.to_str().ok())
    {
        stat.hsts = parse_hsts(v);
    }
}

fn content_encoding(headers: &http::HeaderMap) -> String {
    headers
        .get(http::header::CONTENT_ENCODING)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_string()
}

fn pump_for(req: &HttpRequest, headers: &http::HeaderMap) -> std::result::Result<BodyPump, String> {
    // Decode inside the pump only for the streaming `-o` path. Memory and
    // discard keep the wire bytes; in-memory decode is timed after `total`.
    let encoding = if req.output_path.is_some() {
        content_encoding(headers)
    } else {
        String::new()
    };
    BodyPump::new(
        req.max_body_size,
        req.output_path.as_ref(),
        req.discard_body,
        &encoding,
    )
}

async fn drain_incoming(
    mut body: Incoming,
    mut pump: BodyPump,
    started: Instant,
) -> std::result::Result<(DrainedBody, Option<http::HeaderMap>), String> {
    let mut trailers = None;
    while let Some(frame) = body.frame().await {
        let frame = frame.map_err(|e| format!("Failed to read response body: {e}"))?;
        let frame = match frame.into_data() {
            Ok(data) => {
                pump.push(&data, started)?;
                continue;
            }
            Err(frame) => frame,
        };
        if let Ok(t) = frame.into_trailers() {
            trailers = Some(t);
        }
    }
    Ok((pump.finish()?, trailers))
}

/// In-memory decode runs after `total` is recorded. Streaming decode already
/// stored its CPU time on `drained` and is not subtracted from
/// `content_transfer`.
fn finalize_body(stat: &mut HttpStat, drained: DrainedBody, encoding: &str) {
    stat.wire_body_size = Some(drained.wire_len);
    stat.time_to_first_100k = drained.first_100k;
    if stat.output_saved.is_none() {
        stat.output_saved = drained.saved_to.clone();
    }
    if let Some(d) = drained.decompress {
        stat.decompress = Some(d);
    }
    match drained.bytes {
        Some(bytes) => {
            let enc = encoding.split(',').next().unwrap_or("").trim();
            let enc = if enc.eq_ignore_ascii_case("x-gzip") {
                "gzip"
            } else {
                enc
            };
            if enc.is_empty() || enc.eq_ignore_ascii_case("identity") {
                stat.body_size = Some(bytes.len());
                stat.body = Some(bytes);
            } else {
                let t0 = Instant::now();
                match decompress(enc, &bytes) {
                    Ok(data) => {
                        stat.decompress = Some(t0.elapsed());
                        stat.body_size = Some(data.len());
                        stat.body = Some(data);
                    }
                    Err(e) => {
                        if stat.error.is_none() {
                            stat.error = Some(e.to_string());
                        }
                        stat.body_size = Some(drained.wire_len);
                        stat.body = Some(bytes);
                    }
                }
            }
        }
        None if drained.saved_to.is_some() => {
            stat.body = None;
            stat.body_size = Some(drained.decoded_len);
        }
        None => {
            stat.body = None;
            stat.body_size = Some(drained.wire_len);
        }
    }
}

const DEFAULT_REQUEST_TIMEOUT: Duration = Duration::from_secs(30);

fn phase_timeout(req: &HttpRequest) -> Duration {
    req.request_timeout.unwrap_or(DEFAULT_REQUEST_TIMEOUT)
}

static INIT: Once = Once::new();

fn ensure_crypto_provider() {
    INIT.call_once(|| {
        let _ = tokio_rustls::rustls::crypto::ring::default_provider().install_default();
    });
}

async fn send_http1_request<S>(
    req: Request<TrackedBody>,
    done: Arc<OnceLock<Instant>>,
    stream: S,
    request_timeout: Option<Duration>,
    tx: oneshot::Sender<String>,
    stat: &mut HttpStat,
) -> Result<Response<Incoming>>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let (mut sender, conn) = timeout(
        request_timeout.unwrap_or(DEFAULT_REQUEST_TIMEOUT),
        hyper::client::conn::http1::handshake(TokioIo::new(stream)),
    )
    .await
    .map_err(|e| Error::Timeout { source: e })?
    .map_err(|e| Error::Hyper { source: e })?;

    tokio::spawn(async move {
        if let Err(e) = conn.await {
            let _ = tx.send(e.to_string());
        }
    });

    let send_start = Instant::now();
    let resp = timeout(
        request_timeout.unwrap_or(DEFAULT_REQUEST_TIMEOUT),
        sender.send_request(req),
    )
    .await
    .map_err(|e| Error::Timeout { source: e })?
    .map_err(|e| Error::Hyper { source: e })?;
    record_send_split(stat, send_start, Instant::now(), &done);
    Ok(resp)
}

async fn send_http2_request<S>(
    req: Request<TrackedBody>,
    done: Arc<OnceLock<Instant>>,
    stream: S,
    request_timeout: Option<Duration>,
    tx: oneshot::Sender<String>,
    stat: &mut HttpStat,
) -> Result<Response<Incoming>>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let (mut sender, conn) = timeout(
        request_timeout.unwrap_or(DEFAULT_REQUEST_TIMEOUT),
        hyper::client::conn::http2::handshake(TokioExecutor::new(), TokioIo::new(stream)),
    )
    .await
    .map_err(|e| Error::Timeout { source: e })?
    .map_err(|e| Error::Hyper { source: e })?;

    tokio::spawn(async move {
        if let Err(e) = conn.await {
            let _ = tx.send(e.to_string());
        }
    });

    let mut req = req;
    *req.version_mut() = Version::HTTP_2;
    req.headers_mut().remove("Host");

    let send_start = Instant::now();
    let resp = timeout(
        request_timeout.unwrap_or(DEFAULT_REQUEST_TIMEOUT),
        sender.send_request(req),
    )
    .await
    .map_err(|e| Error::Timeout { source: e })?
    .map_err(|e| Error::Hyper { source: e })?;
    record_send_split(stat, send_start, Instant::now(), &done);
    Ok(resp)
}

async fn wait_udp_flush(conn: &quinn::Connection, before: u64) {
    // `finish` only queues FIN. Yield until the driver writes UDP, capped so
    // a peer that never ACKs cannot hold `request_send` open.
    let deadline = Instant::now() + Duration::from_millis(200);
    while conn.stats().udp_tx.bytes <= before && Instant::now() < deadline {
        tokio::task::yield_now().await;
    }
}

async fn settle_early(
    early: Option<quinn::ZeroRttAccepted>,
    conn: &quinn::Connection,
    stat: &mut HttpStat,
) {
    let Some(early) = early else {
        return;
    };
    let accepted = timeout(Duration::from_millis(50), early).await;
    stat.tls_early_data_accepted = Some(matches!(accepted, Ok(true)));
    capture_quic_certs(conn, stat);
}

async fn h3_exchange(
    send: &mut H3Send,
    conn: &quinn::Connection,
    http_req: &HttpRequest,
    stat: &mut HttpStat,
) -> std::result::Result<DrainedBody, String> {
    let mut req = http_req
        .builder(false)
        .body(())
        .map_err(|e| e.to_string())?;
    *req.version_mut() = Version::HTTP_3;
    stat.request_headers = req.headers().clone();
    let body = http_req.body.clone().unwrap_or_default();
    let before = conn.stats().udp_tx.bytes;
    let send_start = Instant::now();
    let mut stream = send.send_request(req).await.map_err(|e| e.to_string())?;
    stream.send_data(body).await.map_err(|e| e.to_string())?;
    stream.finish().await.map_err(|e| e.to_string())?;
    wait_udp_flush(conn, before).await;
    stat.request_send = Some(send_start.elapsed());

    let server_start = Instant::now();
    let resp = stream.recv_response().await.map_err(|e| {
        if e.is_h3_no_error() {
            "h3 stream closed".to_string()
        } else {
            e.to_string()
        }
    })?;
    stat.server_processing = Some(server_start.elapsed());
    stat.status = Some(resp.status());
    stat.headers = Some(resp.headers().clone());
    stat.version = Some(format!("{:?}", resp.version()));
    capture_server_timing(stat, resp.headers());
    capture_protocol_advertisements(stat, resp.headers());

    let pump = pump_for(http_req, resp.headers())?;
    let ct = Instant::now();
    let mut pump = pump;
    loop {
        match stream.recv_data().await {
            Ok(Some(mut chunk)) => {
                let bytes = chunk.copy_to_bytes(chunk.remaining());
                if let Err(e) = pump.push(&bytes, ct) {
                    stat.error = Some(e);
                    break;
                }
            }
            Ok(None) => break,
            Err(e) if e.is_h3_no_error() => break,
            Err(e) => return Err(e.to_string()),
        }
    }
    match stream.recv_trailers().await {
        Ok(t) => stat.trailers = t,
        Err(e) if e.is_h3_no_error() || stat.error.is_some() => {}
        Err(e) => return Err(e.to_string()),
    }
    stat.content_transfer = Some(ct.elapsed());
    pump.finish()
}

struct TcpReady {
    io: BoxedIo,
    host: String,
    is_http_forward: bool,
    probe: Option<crate::tcp_info::TcpInfoProbe>,
}

async fn tcp_via_proxy(http_req: &HttpRequest, stat: &mut HttpStat) -> Result<TcpReady> {
    let uri = &http_req.uri;
    let is_https = uri.scheme() == Some(&http::uri::Scheme::HTTPS);
    let target_host = uri.host().unwrap_or_default().to_string();
    let target_port = http_req.get_port();

    if let Some(proxy) = http_req.proxy.as_deref().and_then(ProxyConfig::parse) {
        let proxy_addr = format!("{}:{}", proxy.host, proxy.port);
        let tcp_start = Instant::now();
        let proxy_stream = timeout(
            http_req.tcp_timeout.unwrap_or(Duration::from_secs(5)),
            tokio::net::TcpStream::connect(&proxy_addr),
        )
        .await
        .map_err(|e| Error::Timeout { source: e })?
        .map_err(|e| Error::Io { source: e })?;
        stat.proxy_connect = Some(tcp_start.elapsed());
        if let Ok(peer) = proxy_stream.peer_addr() {
            stat.addr = Some(peer.to_string());
        }
        let (baseline, probe) = crate::tcp_info::TcpInfoProbe::capture(&proxy_stream);
        stat.tcp_info_post_connect = baseline;

        let auth = proxy
            .username
            .as_deref()
            .map(|user| basic_auth_header(user, proxy.password.as_deref().unwrap_or("")));
        let user = proxy.username.as_deref();
        let pass = proxy.password.as_deref();
        let handshake_start = Instant::now();
        // `https://` proxy is TLS to the proxy, then CONNECT. Plain HTTP to
        // an `http://` proxy stays a forward request (absolute URI, no tunnel).
        let is_http_forward = !proxy.tls && !is_https && matches!(proxy.kind, ProxyKind::Http);
        let io: BoxedIo = if proxy.tls {
            let tls = tls_connect_stream(
                &proxy.host,
                proxy_stream,
                vec![b"http/1.1".to_vec()],
                http_req.skip_verify,
                http_req.tls_timeout,
            )
            .await?;
            let tunneled = http_connect(tls, &target_host, target_port, auth.as_deref()).await?;
            stat.proxy_handshake = Some(handshake_start.elapsed());
            BoxedIo::ProxyTls(Box::new(tunneled))
        } else if is_http_forward {
            BoxedIo::Plain(proxy_stream)
        } else {
            match proxy.kind {
                ProxyKind::Socks5 => {
                    let tunneled =
                        socks5_connect(proxy_stream, &target_host, target_port, user, pass).await?;
                    stat.proxy_handshake = Some(handshake_start.elapsed());
                    BoxedIo::Plain(tunneled)
                }
                ProxyKind::Http => {
                    let tunneled =
                        http_connect(proxy_stream, &target_host, target_port, auth.as_deref())
                            .await?;
                    stat.proxy_handshake = Some(handshake_start.elapsed());
                    BoxedIo::Plain(tunneled)
                }
            }
        };
        stat.tcp_connect =
            Some(stat.proxy_connect.unwrap_or_default() + stat.proxy_handshake.unwrap_or_default());
        Ok(TcpReady {
            io,
            host: target_host,
            is_http_forward,
            probe,
        })
    } else {
        let resolved = dns_resolve(http_req, stat).await?;
        let (stream, probe, winner) = tcp_connect(
            resolved.addrs,
            http_req.tcp_timeout,
            http_req.bind_addr,
            stat,
        )
        .await?;
        http_req.note_dns_winner(&resolved.cache_host, resolved.cache_port, winner);
        Ok(TcpReady {
            io: BoxedIo::Plain(stream),
            host: resolved.host,
            is_http_forward: false,
            probe,
        })
    }
}

async fn consume_response(
    resp: Response<Incoming>,
    http_req: &HttpRequest,
    mut stat: HttpStat,
    start: Instant,
    probe: Option<&crate::tcp_info::TcpInfoProbe>,
) -> HttpStat {
    stat.status = Some(resp.status());
    let encoding = content_encoding(resp.headers());
    stat.headers = Some(resp.headers().clone());
    stat.version = Some(format!("{:?}", resp.version()));
    capture_server_timing(&mut stat, resp.headers());
    capture_protocol_advertisements(&mut stat, resp.headers());
    let pump = match pump_for(http_req, resp.headers()) {
        Ok(p) => p,
        Err(e) => return finish_with_error(stat, e, start),
    };
    let ct = Instant::now();
    let drained = timeout(
        phase_timeout(http_req),
        drain_incoming(resp.into_body(), pump, ct),
    )
    .await;
    let (drained, trailers) = match drained {
        Ok(Ok(pair)) => pair,
        Ok(Err(e)) => return finish_with_error(stat, e, start),
        Err(e) => return finish_with_error(stat, Error::Timeout { source: e }, start),
    };
    stat.content_transfer = Some(ct.elapsed());
    stat.trailers = trailers;
    if let Some(probe) = probe {
        stat.tcp_info_final = probe.sample();
    }
    stat.total = Some(start.elapsed());
    finalize_body(&mut stat, drained, &encoding);
    stat
}

async fn http3_request(http_req: HttpRequest) -> HttpStat {
    let start = Instant::now();
    let mut stat = HttpStat {
        alpn: Some(ALPN_HTTP3.to_string()),
        ..Default::default()
    };
    if http_req.proxy.is_some() {
        return finish_with_error(stat, H3_PROXY_REFUSAL, start);
    }

    let resolved = match dns_resolve(&http_req, &mut stat).await {
        Ok(v) => v,
        Err(e) => return finish_with_error(stat, e, start),
    };
    let QuicConnect {
        endpoint,
        conn,
        early,
    } = match quic_connect(resolved.host, resolved.addrs, &http_req, &mut stat).await {
        Ok(v) => v,
        Err(e) => return finish_with_error(stat, e, start),
    };
    http_req.note_dns_winner(
        &resolved.cache_host,
        resolved.cache_port,
        conn.remote_address(),
    );
    stat.quic_info_post_connect = Some(QuicInfo::from_conn(&conn));
    let conn_stats = conn.clone();

    let h3_conn = h3_quinn::Connection::new(conn);
    let (mut driver, mut send_request) =
        match timeout(phase_timeout(&http_req), h3::client::new(h3_conn)).await {
            Ok(Ok(v)) => v,
            Ok(Err(e)) => return finish_with_error(stat, e, start),
            Err(e) => return finish_with_error(stat, e, start),
        };

    let req_for_exchange = http_req.clone();
    let request = async move {
        let mut sub = HttpStat::default();
        let drained =
            h3_exchange(&mut send_request, &conn_stats, &req_for_exchange, &mut sub).await?;
        sub.quic_info_final = Some(QuicInfo::from_conn(&conn_stats));
        Ok::<_, String>((sub, drained, conn_stats))
    };
    let drive = async move { driver.wait_idle().await };
    let (req_res, drive_res) = tokio::join!(timeout(phase_timeout(&http_req), request), drive);

    match req_res {
        Ok(Ok((sub, drained, conn_stats))) => {
            stat.request_headers = sub.request_headers;
            stat.request_send = sub.request_send;
            stat.server_processing = sub.server_processing;
            stat.content_transfer = sub.content_transfer;
            stat.status = sub.status;
            stat.headers = sub.headers;
            stat.version = sub.version;
            stat.server_timing = sub.server_timing;
            stat.alt_svc = sub.alt_svc;
            stat.hsts = sub.hsts;
            stat.trailers = sub.trailers;
            stat.error = sub.error;
            stat.quic_info_final = sub.quic_info_final;
            stat.total = Some(start.elapsed());
            settle_early(early, &conn_stats, &mut stat).await;
            let encoding = stat
                .headers
                .as_ref()
                .map(content_encoding)
                .unwrap_or_default();
            finalize_body(&mut stat, drained, &encoding);
        }
        Ok(Err(err)) => {
            stat.error = Some(err);
            stat.total = Some(start.elapsed());
        }
        Err(e) => {
            stat.error = Some(format!("request timeout: {e}"));
            stat.total = Some(start.elapsed());
        }
    }
    if stat.status.is_none() && stat.error.is_none() && !drive_res.is_h3_no_error() {
        stat.error = Some(drive_res.to_string());
    }
    endpoint.close(0u32.into(), b"done");
    stat
}

async fn http1_2_request(mut http_req: HttpRequest) -> HttpStat {
    let start = Instant::now();
    let mut stat = HttpStat::default();
    let is_https = http_req.uri.scheme() == Some(&http::uri::Scheme::HTTPS);

    let ready = match tcp_via_proxy(&http_req, &mut stat).await {
        Ok(r) => r,
        Err(e) => return finish_with_error(stat, e, start),
    };
    if ready.is_http_forward {
        http_req.use_absolute_uri = true;
    }
    let (tx, mut rx) = oneshot::channel();
    let resp = if is_https {
        let (tls_stream, is_http2) =
            match tls_handshake(ready.host, ready.io, &http_req, &mut stat).await {
                Ok(v) => v,
                Err(e) => return finish_with_error(stat, e, start),
            };
        if is_http2 {
            let (req, done) = match build_tracked_request(&http_req, false) {
                Ok(r) => r,
                Err(e) => return finish_with_error(stat, e, start),
            };
            stat.request_headers = req.headers().clone();
            match send_http2_request(
                req,
                done,
                tls_stream,
                http_req.request_timeout,
                tx,
                &mut stat,
            )
            .await
            {
                Ok(resp) => resp,
                Err(e) => return finish_with_error(stat, e, start),
            }
        } else {
            let (req, done) = match build_tracked_request(&http_req, true) {
                Ok(r) => r,
                Err(e) => return finish_with_error(stat, e, start),
            };
            stat.request_headers = req.headers().clone();
            match send_http1_request(
                req,
                done,
                tls_stream,
                http_req.request_timeout,
                tx,
                &mut stat,
            )
            .await
            {
                Ok(resp) => resp,
                Err(e) => return finish_with_error(stat, e, start),
            }
        }
    } else if http_req.h2_prior_knowledge {
        let (req, done) = match build_tracked_request(&http_req, false) {
            Ok(r) => r,
            Err(e) => return finish_with_error(stat, e, start),
        };
        stat.request_headers = req.headers().clone();
        match send_http2_request(req, done, ready.io, http_req.request_timeout, tx, &mut stat).await
        {
            Ok(resp) => resp,
            Err(e) => return finish_with_error(stat, e, start),
        }
    } else {
        let (req, done) = match build_tracked_request(&http_req, true) {
            Ok(r) => r,
            Err(e) => return finish_with_error(stat, e, start),
        };
        stat.request_headers = req.headers().clone();
        match send_http1_request(req, done, ready.io, http_req.request_timeout, tx, &mut stat).await
        {
            Ok(resp) => resp,
            Err(e) => return finish_with_error(stat, e, start),
        }
    };

    if let Ok(error) = rx.try_recv() {
        stat.error = Some(error);
    }
    consume_response(resp, &http_req, stat, start, ready.probe.as_ref()).await
}

/// Performs an HTTP request and returns detailed statistics about the request lifecycle.
pub async fn request(http_req: HttpRequest) -> HttpStat {
    ensure_crypto_provider();
    let is_grpc = matches!(http_req.uri.scheme_str().unwrap_or(""), "grpc" | "grpcs");
    if is_grpc {
        grpc_request(http_req).await
    } else if http_req.alpn_protocols.iter().any(|p| p == ALPN_HTTP3) {
        http3_request(http_req).await
    } else {
        http1_2_request(http_req).await
    }
}

enum ConnectionSender {
    Http1(hyper::client::conn::http1::SendRequest<TrackedBody>),
    Http2(hyper::client::conn::http2::SendRequest<TrackedBody>),
    Http3 {
        conn: quinn::Connection,
        send: H3Send,
    },
}

enum WorkerKind {
    Http2(hyper::client::conn::http2::SendRequest<TrackedBody>),
    Http3 {
        conn: quinn::Connection,
        send: H3Send,
    },
}

/// Cloned sender for one in-flight request on a multiplexed connection.
pub struct HttpWorker {
    kind: WorkerKind,
}

/// A reusable HTTP connection. `endpoint` is last so it drops after the
/// QUIC connection: dropping a `quinn::Endpoint` aborts every connection it owns.
pub struct HttpConnection {
    sender: ConnectionSender,
    tcp_probe: Option<crate::tcp_info::TcpInfoProbe>,
    last_tcp_info: Option<crate::TcpInfo>,
    last_quic: Option<QuicInfo>,
    /// Kept so the endpoint drops after the QUIC connection. Dropping an
    /// endpoint aborts every connection it owns.
    #[allow(dead_code)]
    endpoint: Option<quinn::Endpoint>,
}

impl HttpConnection {
    /// HTTP/2 and HTTP/3 can have several requests in flight. HTTP/1.1 cannot.
    pub fn multiplexes(&self) -> bool {
        matches!(
            self.sender,
            ConnectionSender::Http2(_) | ConnectionSender::Http3 { .. }
        )
    }

    /// Clone a sender for a concurrent request. `None` for HTTP/1.1.
    /// The parent keeps its own sender so the last drop does not close HTTP/3.
    pub fn worker(&self) -> Option<HttpWorker> {
        match &self.sender {
            ConnectionSender::Http2(send) => Some(HttpWorker {
                kind: WorkerKind::Http2(send.clone()),
            }),
            ConnectionSender::Http3 { conn, send } => Some(HttpWorker {
                kind: WorkerKind::Http3 {
                    conn: conn.clone(),
                    send: send.clone(),
                },
            }),
            ConnectionSender::Http1(_) => None,
        }
    }
}

async fn establish_http1<S>(
    stream: S,
    handshake_timeout: Duration,
    mut stat: HttpStat,
    tcp_probe: Option<crate::tcp_info::TcpInfoProbe>,
    start: Instant,
) -> (HttpStat, Option<HttpConnection>)
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    match timeout(
        handshake_timeout,
        hyper::client::conn::http1::handshake(TokioIo::new(stream)),
    )
    .await
    {
        Ok(Ok((sender, conn))) => {
            tokio::spawn(async move {
                let _ = conn.await;
            });
            stat.total = Some(start.elapsed());
            let last_tcp_info = stat.tcp_info_post_connect.clone();
            (
                stat,
                Some(HttpConnection {
                    sender: ConnectionSender::Http1(sender),
                    tcp_probe,
                    last_tcp_info,
                    last_quic: None,
                    endpoint: None,
                }),
            )
        }
        Ok(Err(e)) => (
            finish_with_error(stat, Error::Hyper { source: e }, start),
            None,
        ),
        Err(e) => (
            finish_with_error(stat, Error::Timeout { source: e }, start),
            None,
        ),
    }
}

async fn establish_http2<S>(
    stream: S,
    handshake_timeout: Duration,
    mut stat: HttpStat,
    tcp_probe: Option<crate::tcp_info::TcpInfoProbe>,
    start: Instant,
) -> (HttpStat, Option<HttpConnection>)
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    match timeout(
        handshake_timeout,
        hyper::client::conn::http2::handshake(TokioExecutor::new(), TokioIo::new(stream)),
    )
    .await
    {
        Ok(Ok((sender, conn))) => {
            tokio::spawn(async move {
                let _ = conn.await;
            });
            stat.total = Some(start.elapsed());
            let last_tcp_info = stat.tcp_info_post_connect.clone();
            (
                stat,
                Some(HttpConnection {
                    sender: ConnectionSender::Http2(sender),
                    tcp_probe,
                    last_tcp_info,
                    last_quic: None,
                    endpoint: None,
                }),
            )
        }
        Ok(Err(e)) => (
            finish_with_error(stat, Error::Hyper { source: e }, start),
            None,
        ),
        Err(e) => (
            finish_with_error(stat, Error::Timeout { source: e }, start),
            None,
        ),
    }
}

async fn connect_h3(http_req: &HttpRequest) -> (HttpStat, Option<HttpConnection>) {
    let start = Instant::now();
    let mut stat = HttpStat {
        alpn: Some(ALPN_HTTP3.to_string()),
        ..Default::default()
    };
    if http_req.proxy.is_some() {
        return (finish_with_error(stat, H3_PROXY_REFUSAL, start), None);
    }
    let resolved = match dns_resolve(http_req, &mut stat).await {
        Ok(v) => v,
        Err(e) => return (finish_with_error(stat, e, start), None),
    };
    let QuicConnect {
        endpoint,
        conn,
        early,
    } = match quic_connect(resolved.host, resolved.addrs, http_req, &mut stat).await {
        Ok(v) => v,
        Err(e) => return (finish_with_error(stat, e, start), None),
    };
    http_req.note_dns_winner(
        &resolved.cache_host,
        resolved.cache_port,
        conn.remote_address(),
    );
    stat.quic_info_post_connect = Some(QuicInfo::from_conn(&conn));
    let h3_conn = h3_quinn::Connection::new(conn.clone());
    let (mut driver, send) = match timeout(phase_timeout(http_req), h3::client::new(h3_conn)).await
    {
        Ok(Ok(v)) => v,
        Ok(Err(e)) => return (finish_with_error(stat, e, start), None),
        Err(e) => return (finish_with_error(stat, e, start), None),
    };
    // The driver must outlive every cloned sender. It finishes when the last
    // SendRequest is dropped. Spawn it; joining would wait for that drop.
    tokio::spawn(async move {
        let _ = driver.wait_idle().await;
    });
    stat.total = Some(start.elapsed());
    settle_early(early, &conn, &mut stat).await;
    let last_quic = stat.quic_info_post_connect.clone();
    (
        stat,
        Some(HttpConnection {
            sender: ConnectionSender::Http3 { conn, send },
            tcp_probe: None,
            last_tcp_info: None,
            last_quic,
            endpoint: Some(endpoint),
        }),
    )
}

/// Establish a connection and return a reusable handle.
///
/// HTTP/3 keeps the `quinn::Endpoint` alive for the handle's lifetime.
pub async fn connect(http_req: &HttpRequest) -> (HttpStat, Option<HttpConnection>) {
    ensure_crypto_provider();
    if http_req.alpn_protocols.iter().any(|p| p == ALPN_HTTP3) {
        return connect_h3(http_req).await;
    }
    let start = Instant::now();
    let mut stat = HttpStat::default();
    let is_https = http_req.uri.scheme() == Some(&http::uri::Scheme::HTTPS);
    let ready = match tcp_via_proxy(http_req, &mut stat).await {
        Ok(r) => r,
        Err(e) => return (finish_with_error(stat, e, start), None),
    };
    let handshake_timeout = phase_timeout(http_req);
    if is_https {
        let (tls_stream, is_h2) =
            match tls_handshake(ready.host, ready.io, http_req, &mut stat).await {
                Ok(r) => r,
                Err(e) => return (finish_with_error(stat, e, start), None),
            };
        if is_h2 {
            establish_http2(tls_stream, handshake_timeout, stat, ready.probe, start).await
        } else {
            establish_http1(tls_stream, handshake_timeout, stat, ready.probe, start).await
        }
    } else if http_req.h2_prior_knowledge {
        establish_http2(ready.io, handshake_timeout, stat, ready.probe, start).await
    } else {
        establish_http1(ready.io, handshake_timeout, stat, ready.probe, start).await
    }
}

async fn exchange_h2(
    sender: &mut hyper::client::conn::http2::SendRequest<TrackedBody>,
    http_req: &HttpRequest,
    mut stat: HttpStat,
    start: Instant,
    probe: Option<&crate::tcp_info::TcpInfoProbe>,
) -> HttpStat {
    if let Err(e) = sender.ready().await {
        return finish_with_error(stat, Error::Hyper { source: e }, start);
    }
    let (req, done) = match build_tracked_request(http_req, false) {
        Ok(r) => r,
        Err(e) => return finish_with_error(stat, e, start),
    };
    stat.request_headers = req.headers().clone();
    let mut req = req;
    *req.version_mut() = Version::HTTP_2;
    req.headers_mut().remove("Host");
    let send_start = Instant::now();
    let resp = timeout(phase_timeout(http_req), sender.send_request(req)).await;
    let resp = match resp {
        Ok(Ok(resp)) => resp,
        Ok(Err(e)) => return finish_with_error(stat, Error::Hyper { source: e }, start),
        Err(e) => return finish_with_error(stat, Error::Timeout { source: e }, start),
    };
    record_send_split(&mut stat, send_start, Instant::now(), &done);
    consume_response(resp, http_req, stat, start, probe).await
}

async fn exchange_h1(
    sender: &mut hyper::client::conn::http1::SendRequest<TrackedBody>,
    http_req: &HttpRequest,
    mut stat: HttpStat,
    start: Instant,
    probe: Option<&crate::tcp_info::TcpInfoProbe>,
) -> HttpStat {
    if let Err(e) = sender.ready().await {
        return finish_with_error(stat, Error::Hyper { source: e }, start);
    }
    let (req, done) = match build_tracked_request(http_req, true) {
        Ok(r) => r,
        Err(e) => return finish_with_error(stat, e, start),
    };
    stat.request_headers = req.headers().clone();
    let send_start = Instant::now();
    let resp = timeout(phase_timeout(http_req), sender.send_request(req)).await;
    let resp = match resp {
        Ok(Ok(resp)) => resp,
        Ok(Err(e)) => return finish_with_error(stat, Error::Hyper { source: e }, start),
        Err(e) => return finish_with_error(stat, Error::Timeout { source: e }, start),
    };
    record_send_split(&mut stat, send_start, Instant::now(), &done);
    consume_response(resp, http_req, stat, start, probe).await
}

async fn exchange_h3(
    send: &mut H3Send,
    conn: &quinn::Connection,
    http_req: &HttpRequest,
    mut stat: HttpStat,
    start: Instant,
    sample_quic: bool,
    quic_baseline: Option<QuicInfo>,
) -> HttpStat {
    if sample_quic {
        stat.quic_info_post_connect = quic_baseline;
    }
    let drained = match timeout(
        phase_timeout(http_req),
        h3_exchange(send, conn, http_req, &mut stat),
    )
    .await
    {
        Ok(Ok(d)) => d,
        Ok(Err(e)) => return finish_with_error(stat, e, start),
        Err(e) => return finish_with_error(stat, Error::Timeout { source: e }, start),
    };
    if sample_quic {
        stat.quic_info_final = Some(QuicInfo::from_conn(conn));
    }
    stat.total = Some(start.elapsed());
    let encoding = stat
        .headers
        .as_ref()
        .map(content_encoding)
        .unwrap_or_default();
    finalize_body(&mut stat, drained, &encoding);
    stat
}

impl HttpConnection {
    /// Send a request on the existing connection.
    pub async fn send(&mut self, http_req: &HttpRequest) -> HttpStat {
        let start = Instant::now();
        let stat = HttpStat {
            tcp_info_post_connect: self.last_tcp_info.clone(),
            ..HttpStat::default()
        };
        let baseline_quic = self.last_quic.clone();
        // Take the probe so the sender can be borrowed for the duration of the
        // request. The duplicate fd stays valid across that await.
        let probe = self.tcp_probe.take();
        let stat = match &mut self.sender {
            ConnectionSender::Http1(sender) => {
                exchange_h1(sender, http_req, stat, start, probe.as_ref()).await
            }
            ConnectionSender::Http2(sender) => {
                exchange_h2(sender, http_req, stat, start, probe.as_ref()).await
            }
            ConnectionSender::Http3 { conn, send } => {
                exchange_h3(send, conn, http_req, stat, start, true, baseline_quic).await
            }
        };
        self.tcp_probe = probe;
        if stat.tcp_info_final.is_some() {
            self.last_tcp_info = stat.tcp_info_final.clone();
        }
        if stat.quic_info_final.is_some() {
            self.last_quic = stat.quic_info_final.clone();
        }
        stat
    }
}

impl HttpWorker {
    /// One request on a cloned sender. Skips TCP/QUIC path deltas: those
    /// counters are connection-wide and race when several workers send.
    pub async fn send(mut self, http_req: &HttpRequest) -> HttpStat {
        let start = Instant::now();
        let stat = HttpStat::default();
        match &mut self.kind {
            WorkerKind::Http2(sender) => exchange_h2(sender, http_req, stat, start, None).await,
            WorkerKind::Http3 { conn, send } => {
                exchange_h3(send, conn, http_req, stat, start, false, None).await
            }
        }
    }
}
