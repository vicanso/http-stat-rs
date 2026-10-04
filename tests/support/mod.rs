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

//! Local servers and a runner for the `httpstat` binary. Every server
//! listens on an ephemeral 127.0.0.1 port, so the tests can run in parallel
//! and need no network access.

use bytes::Bytes;
use http::{HeaderMap, HeaderValue, Request, Response, StatusCode};
use http_body_util::combinators::BoxBody;
use http_body_util::{BodyExt, Full};
use hyper::body::Incoming;
use hyper::service::service_fn;
use hyper_util::rt::{TokioExecutor, TokioIo};
use hyper_util::server::conn::auto;
use rustls_pki_types::{CertificateDer, PrivateKeyDer};
use std::convert::Infallible;
use std::io::Write;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, OnceLock};
use std::time::{Duration, Instant};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::runtime::Runtime;
use tokio_rustls::TlsAcceptor;

/// Body served at `/`.
pub const HELLO: &str = "hello from the test server\n";
/// Decoded size of the body at `/bomb`, which is a few kilobytes of gzip.
pub const BOMB_SIZE: usize = 8 * 1024 * 1024;
/// How long `/slow-upload` waits before it reads the request body.
pub const UPLOAD_DELAY: Duration = Duration::from_millis(400);
/// How long `/slow-dns` takes to answer one query.
pub const DNS_DELAY: Duration = Duration::from_millis(500);
/// Body served at `/binary`: not valid UTF-8.
pub const BINARY: &[u8] = &[0xff, 0xfe, 0x00, 0x01, 0x80, 0x7f];
/// Hostnames under this suffix resolve to 127.0.0.1 on the test resolvers.
pub const RESOLVABLE: &str = "origin.test";

/// The runtime every test server runs on.
pub fn runtime() -> &'static Runtime {
    static RUNTIME: OnceLock<Runtime> = OnceLock::new();
    RUNTIME.get_or_init(|| {
        let _ = rustls::crypto::ring::default_provider().install_default();
        tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()
            .expect("test runtime")
    })
}

fn scratch_dir() -> PathBuf {
    let dir =
        PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join(format!("e2e-{}", std::process::id()));
    std::fs::create_dir_all(&dir).expect("scratch dir");
    dir
}

/// A throwaway CA and a `localhost` / `127.0.0.1` certificate signed by it.
pub struct TestCa {
    /// PEM file with the CA certificate, for `SSL_CERT_FILE`.
    pub ca_file: PathBuf,
    pub cert_pem: String,
    pub key_pem: String,
    chain: Vec<CertificateDer<'static>>,
    key: PrivateKeyDer<'static>,
}

impl TestCa {
    pub fn server_config(&self, alpn: &[&str]) -> Arc<rustls::ServerConfig> {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let mut config = rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(self.chain.clone(), self.key.clone_key())
            .expect("server certificate");
        config.alpn_protocols = alpn.iter().map(|p| p.as_bytes().to_vec()).collect();
        Arc::new(config)
    }
}

pub fn ca() -> &'static TestCa {
    static CA: OnceLock<TestCa> = OnceLock::new();
    CA.get_or_init(|| {
        let ca_key = rcgen::KeyPair::generate().expect("ca key");
        let mut ca_params = rcgen::CertificateParams::new(Vec::<String>::new()).expect("ca params");
        ca_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        ca_params
            .distinguished_name
            .push(rcgen::DnType::CommonName, "httpstat test CA");
        ca_params.key_usages = vec![
            rcgen::KeyUsagePurpose::KeyCertSign,
            rcgen::KeyUsagePurpose::CrlSign,
        ];
        let ca_cert = ca_params.self_signed(&ca_key).expect("ca certificate");
        let issuer = rcgen::Issuer::from_params(&ca_params, &ca_key);

        let key = rcgen::KeyPair::generate().expect("server key");
        let mut params =
            rcgen::CertificateParams::new(vec!["localhost".to_string(), "127.0.0.1".to_string()])
                .expect("server params");
        params
            .distinguished_name
            .push(rcgen::DnType::CommonName, "localhost");
        let cert = params.signed_by(&key, &issuer).expect("server certificate");

        let ca_file = scratch_dir().join("ca.pem");
        std::fs::write(&ca_file, ca_cert.pem()).expect("write ca file");
        TestCa {
            ca_file,
            cert_pem: cert.pem(),
            key_pem: key.serialize_pem(),
            chain: vec![cert.der().clone()],
            key: PrivateKeyDer::try_from(key.serialize_der()).expect("server key der"),
        }
    })
}

/// What one run of the binary produced.
pub struct Run {
    pub code: i32,
    pub stdout: String,
    pub stderr: String,
}

impl Run {
    /// The `--json` document.
    pub fn json(&self) -> serde_json::Value {
        serde_json::from_str(&self.stdout).unwrap_or_else(|e| {
            panic!(
                "stdout is not JSON ({e}):\n{}\nstderr:\n{}",
                self.stdout, self.stderr
            )
        })
    }
}

fn run(args: &[&str], trust_test_ca: bool, env: &[(&str, &str)]) -> Run {
    let home = scratch_dir().join("home");
    std::fs::create_dir_all(&home).expect("home dir");
    let mut command = Command::new(env!("CARGO_BIN_EXE_httpstat"));
    command
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        // Keep the developer's config, proxy settings and locale out of it.
        .env("HOME", &home)
        .env("USERPROFILE", &home)
        .env("LANG", "en_US.UTF-8")
        .env_remove("LC_ALL")
        .env_remove("LC_MESSAGES")
        .env_remove("SSL_CERT_FILE")
        .env_remove("SSL_CERT_DIR");
    for name in ["HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "NO_PROXY"] {
        command.env_remove(name).env_remove(name.to_lowercase());
    }
    if trust_test_ca {
        command.env("SSL_CERT_FILE", &ca().ca_file);
    }
    command.envs(env.iter().copied());
    let mut child = command.spawn().expect("spawn httpstat");
    // A hung request must fail the test, not the whole CI job.
    let deadline = Instant::now() + Duration::from_secs(60);
    loop {
        match child.try_wait().expect("wait for httpstat") {
            Some(_) => break,
            None if Instant::now() > deadline => {
                let _ = child.kill();
                panic!("httpstat {args:?} did not finish within 60s");
            }
            None => std::thread::sleep(Duration::from_millis(10)),
        }
    }
    let output = child.wait_with_output().expect("httpstat output");
    Run {
        code: output.status.code().unwrap_or(-1),
        stdout: String::from_utf8_lossy(&output.stdout).into_owned(),
        stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
    }
}

/// Run the binary with the test CA as its only trust anchor.
pub fn httpstat(args: &[&str]) -> Run {
    run(args, true, &[])
}

/// Like [`httpstat`], with extra environment variables.
pub fn httpstat_env(args: &[&str], env: &[(&str, &str)]) -> Run {
    run(args, true, env)
}

/// Run the binary with the platform trust store, which does not know the
/// test CA.
pub fn httpstat_untrusting(args: &[&str]) -> Run {
    run(args, false, &[])
}

fn bind() -> (TcpListener, SocketAddr) {
    let listener = runtime()
        .block_on(TcpListener::bind("127.0.0.1:0"))
        .expect("bind test listener");
    let addr = listener.local_addr().expect("listener address");
    (listener, addr)
}

type Body = BoxBody<Bytes, Infallible>;

fn full(data: impl Into<Bytes>) -> Body {
    Full::new(data.into()).boxed()
}

fn respond(status: StatusCode, content_type: &'static str, body: Body) -> Response<Body> {
    let mut response = Response::new(body);
    *response.status_mut() = status;
    response.headers_mut().insert(
        http::header::CONTENT_TYPE,
        HeaderValue::from_static(content_type),
    );
    response
}

/// A `grpc-status: 0` response that sends `message` back, framed.
fn grpc_echo(message: Bytes) -> Response<Body> {
    let mut trailers = HeaderMap::new();
    trailers.insert("grpc-status", HeaderValue::from_static("0"));
    let body = Full::new(message)
        .with_trailers(async move { Some(Ok::<_, Infallible>(trailers)) })
        .boxed();
    respond(StatusCode::OK, "application/grpc", body)
}

fn gzip(data: &[u8]) -> Vec<u8> {
    let mut encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
    encoder.write_all(data).expect("gzip");
    encoder.finish().expect("gzip")
}

async fn handle(request: Request<Incoming>) -> Result<Response<Body>, Infallible> {
    let path = request.uri().path().to_string();
    // HTTP/2 carries the host in `:authority`, HTTP/1.1 in `Host`.
    let seen_host = request
        .uri()
        .authority()
        .map(|a| a.to_string())
        .or_else(|| {
            request
                .headers()
                .get(http::header::HOST)
                .and_then(|v| v.to_str().ok())
                .map(String::from)
        })
        .unwrap_or_default();
    let method = request.method().clone();
    let is_dns_message = request
        .headers()
        .get(http::header::CONTENT_TYPE)
        .is_some_and(|v| v == "application/dns-message");
    if path == "/slow-upload" {
        // Leave the body in the socket for a while: the client's upload
        // stalls once the kernel buffers are full.
        tokio::time::sleep(UPLOAD_DELAY).await;
    }
    let body = request
        .into_body()
        .collect()
        .await
        .map(|b| b.to_bytes())
        .unwrap_or_default();

    let mut response = match (method.as_str(), path.as_str()) {
        (_, "/") => respond(StatusCode::OK, "text/plain", full(HELLO)),
        (_, "/redirect") => {
            let mut response = respond(StatusCode::FOUND, "text/plain", full(""));
            response
                .headers_mut()
                .insert(http::header::LOCATION, HeaderValue::from_static("/"));
            response
        }
        (_, "/binary") => respond(StatusCode::OK, "application/octet-stream", full(BINARY)),
        (_, "/empty") => respond(StatusCode::OK, "application/octet-stream", full("")),
        (_, "/redirect-unicode") => {
            // A `Location` whose host is raw UTF-8, on this server's port.
            let port = seen_host.rsplit(':').next().unwrap_or_default();
            let location = format!("http://bücher.test:{port}/");
            let mut response = respond(StatusCode::FOUND, "text/plain", full(""));
            response.headers_mut().insert(
                http::header::LOCATION,
                HeaderValue::from_bytes(location.as_bytes()).expect("location"),
            );
            response
        }
        (_, "/slow-upload") => respond(StatusCode::OK, "text/plain", full(body.len().to_string())),
        (_, "/bomb") => {
            static BOMB: OnceLock<Vec<u8>> = OnceLock::new();
            let bomb = BOMB.get_or_init(|| gzip(&vec![0u8; BOMB_SIZE]));
            let mut response = respond(
                StatusCode::OK,
                "application/octet-stream",
                full(bomb.clone()),
            );
            response.headers_mut().insert(
                http::header::CONTENT_ENCODING,
                HeaderValue::from_static("gzip"),
            );
            response
        }
        ("POST", "/slow-dns") if is_dns_message => {
            tokio::time::sleep(DNS_DELAY).await;
            respond(
                StatusCode::OK,
                "application/dns-message",
                full(dns_answer(&body)),
            )
        }
        (_, "/gzip") => {
            let mut response = respond(StatusCode::OK, "text/plain", full(gzip(HELLO.as_bytes())));
            response.headers_mut().insert(
                http::header::CONTENT_ENCODING,
                HeaderValue::from_static("gzip"),
            );
            response
        }
        (_, "/hang") => {
            tokio::time::sleep(Duration::from_secs(60)).await;
            respond(StatusCode::OK, "text/plain", full(""))
        }
        ("POST", "/test.Echo/Unary") => grpc_echo(body),
        ("POST", "/dns-query" | "/custom/dns") if is_dns_message => respond(
            StatusCode::OK,
            "application/dns-message",
            full(dns_answer(&body)),
        ),
        (_, other) => match other
            .strip_prefix("/status/")
            .and_then(|c| c.parse::<u16>().ok())
        {
            Some(code) => respond(
                StatusCode::from_u16(code).unwrap_or(StatusCode::BAD_REQUEST),
                "text/plain",
                full(""),
            ),
            None => respond(StatusCode::NOT_FOUND, "text/plain", full("not found\n")),
        },
    };
    if let Ok(value) = HeaderValue::from_str(&seen_host) {
        response.headers_mut().insert("x-seen-host", value);
    }
    Ok(response)
}

async fn serve_http<S>(stream: S)
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let _ = auto::Builder::new(TokioExecutor::new())
        .serve_connection(TokioIo::new(stream), service_fn(handle))
        .await;
}

/// An HTTP server. `None` is cleartext (HTTP/1.1 and h2c prior knowledge);
/// `Some(alpn)` is TLS offering those protocols. It also answers DoH on
/// `/dns-query` and `/custom/dns`, and a gRPC echo on `/test.Echo/Unary`.
pub fn http_server(tls: Option<&[&str]>) -> SocketAddr {
    let (listener, addr) = bind();
    let acceptor = tls.map(|alpn| TlsAcceptor::from(ca().server_config(alpn)));
    runtime().spawn(async move {
        while let Ok((stream, _)) = listener.accept().await {
            let acceptor = acceptor.clone();
            tokio::spawn(async move {
                match acceptor {
                    Some(acceptor) => {
                        if let Ok(stream) = acceptor.accept(stream).await {
                            serve_http(stream).await;
                        }
                    }
                    None => serve_http(stream).await,
                }
            });
        }
    });
    addr
}

/// An HTTP/3 server that answers every request with [`HELLO`].
pub fn http3_server() -> SocketAddr {
    let tls = ca().server_config(&["h3"]);
    let crypto = quinn::crypto::rustls::QuicServerConfig::try_from(tls.as_ref().clone())
        .expect("quic server config");
    let config = quinn::ServerConfig::with_crypto(Arc::new(crypto));
    let _guard = runtime().enter();
    let endpoint =
        quinn::Endpoint::server(config, "127.0.0.1:0".parse().unwrap()).expect("quic endpoint");
    let addr = endpoint.local_addr().expect("quic address");
    runtime().spawn(async move {
        while let Some(incoming) = endpoint.accept().await {
            tokio::spawn(async move {
                let Ok(conn) = incoming.await else { return };
                let Ok(mut h3) =
                    h3::server::Connection::<_, Bytes>::new(h3_quinn::Connection::new(conn)).await
                else {
                    return;
                };
                while let Ok(Some(resolver)) = h3.accept().await {
                    let Ok((_request, mut stream)) = resolver.resolve_request().await else {
                        continue;
                    };
                    let response = Response::builder()
                        .status(StatusCode::OK)
                        .header(http::header::CONTENT_TYPE, "text/plain")
                        .body(())
                        .expect("h3 response");
                    let _ = stream.send_response(response).await;
                    let _ = stream.send_data(Bytes::from_static(HELLO.as_bytes())).await;
                    let _ = stream.finish().await;
                }
            });
        }
    });
    addr
}

/// A proxy and how many tunnels it has opened.
pub struct Proxy {
    pub addr: SocketAddr,
    tunnels: Arc<AtomicUsize>,
}

impl Proxy {
    pub fn tunnels(&self) -> usize {
        self.tunnels.load(Ordering::SeqCst)
    }
}

async fn read_until_blank_line<S: AsyncRead + Unpin>(stream: &mut S) -> Option<String> {
    let mut head = Vec::new();
    let mut byte = [0u8; 1];
    while !head.ends_with(b"\r\n\r\n") {
        if stream.read(&mut byte).await.ok()? == 0 || head.len() > 8192 {
            return None;
        }
        head.push(byte[0]);
    }
    String::from_utf8(head).ok()
}

async fn http_connect_tunnel<S>(mut client: S, tunnels: Arc<AtomicUsize>)
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let Some(head) = read_until_blank_line(&mut client).await else {
        return;
    };
    let mut request_line = head.lines().next().unwrap_or_default().split(' ');
    let (Some("CONNECT"), Some(target)) = (request_line.next(), request_line.next()) else {
        let _ = client
            .write_all(b"HTTP/1.1 405 Method Not Allowed\r\ncontent-length: 0\r\n\r\n")
            .await;
        return;
    };
    let Ok(mut upstream) = TcpStream::connect(target).await else {
        let _ = client
            .write_all(b"HTTP/1.1 502 Bad Gateway\r\ncontent-length: 0\r\n\r\n")
            .await;
        return;
    };
    if client
        .write_all(b"HTTP/1.1 200 Connection established\r\n\r\n")
        .await
        .is_err()
    {
        return;
    }
    tunnels.fetch_add(1, Ordering::SeqCst);
    let _ = tokio::io::copy_bidirectional(&mut client, &mut upstream).await;
}

/// An HTTP `CONNECT` proxy, reached over TLS when `tls` is set.
pub fn connect_proxy(tls: bool) -> Proxy {
    let (listener, addr) = bind();
    let acceptor = tls.then(|| TlsAcceptor::from(ca().server_config(&["http/1.1"])));
    let tunnels = Arc::new(AtomicUsize::new(0));
    let counter = tunnels.clone();
    runtime().spawn(async move {
        while let Ok((stream, _)) = listener.accept().await {
            let acceptor = acceptor.clone();
            let counter = counter.clone();
            tokio::spawn(async move {
                match acceptor {
                    Some(acceptor) => {
                        if let Ok(stream) = acceptor.accept(stream).await {
                            http_connect_tunnel(stream, counter).await;
                        }
                    }
                    None => http_connect_tunnel(stream, counter).await,
                }
            });
        }
    });
    Proxy { addr, tunnels }
}

async fn socks5_tunnel(mut client: TcpStream, tunnels: Arc<AtomicUsize>) -> Option<()> {
    // Greeting: version, method count, methods. Only "no authentication".
    let mut greeting = [0u8; 2];
    client.read_exact(&mut greeting).await.ok()?;
    let mut methods = vec![0u8; greeting[1] as usize];
    client.read_exact(&mut methods).await.ok()?;
    client.write_all(&[5, 0]).await.ok()?;

    // Request: version, CONNECT, reserved, address type, address, port.
    let mut request = [0u8; 4];
    client.read_exact(&mut request).await.ok()?;
    let host = match request[3] {
        1 => {
            let mut ip = [0u8; 4];
            client.read_exact(&mut ip).await.ok()?;
            std::net::Ipv4Addr::from(ip).to_string()
        }
        3 => {
            let mut len = [0u8; 1];
            client.read_exact(&mut len).await.ok()?;
            let mut name = vec![0u8; len[0] as usize];
            client.read_exact(&mut name).await.ok()?;
            String::from_utf8(name).ok()?
        }
        _ => return None,
    };
    let mut port = [0u8; 2];
    client.read_exact(&mut port).await.ok()?;
    let mut upstream = TcpStream::connect((host.as_str(), u16::from_be_bytes(port)))
        .await
        .ok()?;
    client
        .write_all(&[5, 0, 0, 1, 0, 0, 0, 0, 0, 0])
        .await
        .ok()?;
    tunnels.fetch_add(1, Ordering::SeqCst);
    let _ = tokio::io::copy_bidirectional(&mut client, &mut upstream).await;
    Some(())
}

/// A SOCKS5 proxy without authentication.
pub fn socks5_proxy() -> Proxy {
    let (listener, addr) = bind();
    let tunnels = Arc::new(AtomicUsize::new(0));
    let counter = tunnels.clone();
    runtime().spawn(async move {
        while let Ok((stream, _)) = listener.accept().await {
            tokio::spawn(socks5_tunnel(stream, counter.clone()));
        }
    });
    Proxy { addr, tunnels }
}

/// Answer a DNS query: an A record of 127.0.0.1 for names under
/// [`RESOLVABLE`], no AAAA record for them, and NXDOMAIN for anything else.
fn dns_answer(query: &[u8]) -> Vec<u8> {
    let mut end = 12;
    let mut name = String::new();
    while let Some(&len) = query.get(end) {
        end += 1;
        if len == 0 {
            break;
        }
        let label = query.get(end..end + len as usize).unwrap_or_default();
        name.push_str(&String::from_utf8_lossy(label).to_ascii_lowercase());
        name.push('.');
        end += len as usize;
    }
    let qtype = u16::from_be_bytes([
        query.get(end).copied().unwrap_or_default(),
        query.get(end + 1).copied().unwrap_or_default(),
    ]);
    end += 4;
    let known = name.ends_with(&format!("{RESOLVABLE}."));
    let answers = u16::from(known && qtype == 1);
    // Response, recursion desired and available; rcode 3 is NXDOMAIN.
    let flags: u16 = if known { 0x8180 } else { 0x8183 };

    let mut message = query.get(..2).unwrap_or(&[0, 0]).to_vec();
    message.extend_from_slice(&flags.to_be_bytes());
    message.extend_from_slice(&1u16.to_be_bytes());
    message.extend_from_slice(&answers.to_be_bytes());
    message.extend_from_slice(&[0, 0, 0, 0]);
    message.extend_from_slice(query.get(12..end).unwrap_or_default());
    if answers == 1 {
        // Pointer to the question name, type A, class IN, TTL 60, 4 bytes.
        message.extend_from_slice(&[0xc0, 0x0c, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4, 127, 0, 0, 1]);
    }
    message
}

#[cfg(feature = "doh")]
async fn serve_dot<S: AsyncRead + AsyncWrite + Unpin>(mut stream: S) -> Option<()> {
    loop {
        let mut len = [0u8; 2];
        stream.read_exact(&mut len).await.ok()?;
        let mut query = vec![0u8; u16::from_be_bytes(len) as usize];
        stream.read_exact(&mut query).await.ok()?;
        let answer = dns_answer(&query);
        stream
            .write_all(&(answer.len() as u16).to_be_bytes())
            .await
            .ok()?;
        stream.write_all(&answer).await.ok()?;
    }
}

/// A DNS-over-TLS resolver.
#[cfg(feature = "doh")]
pub fn dot_server() -> SocketAddr {
    let (listener, addr) = bind();
    let acceptor = TlsAcceptor::from(ca().server_config(&["dot"]));
    runtime().spawn(async move {
        while let Ok((stream, _)) = listener.accept().await {
            let acceptor = acceptor.clone();
            tokio::spawn(async move {
                if let Ok(stream) = acceptor.accept(stream).await {
                    serve_dot(stream).await;
                }
            });
        }
    });
    addr
}

/// A gRPC server built on tonic.
pub struct Grpc<'a> {
    pub tls: bool,
    /// Register `grpc.health.v1.Health`; without it every call is
    /// UNIMPLEMENTED.
    pub health: bool,
    /// Whether the server as a whole reports SERVING.
    pub serving: bool,
    /// Named services and whether each one is SERVING.
    pub services: &'a [(&'a str, bool)],
    /// Compress responses with gzip for clients that accept it.
    pub gzip: bool,
}

impl Default for Grpc<'_> {
    fn default() -> Self {
        Self {
            tls: false,
            health: true,
            serving: true,
            services: &[],
            gzip: false,
        }
    }
}

impl Grpc<'_> {
    pub fn start(self) -> SocketAddr {
        use tonic::transport::server::TcpIncoming;
        use tonic::transport::{Identity, Server, ServerTlsConfig};
        use tonic_health::ServingStatus;

        let status = |serving| {
            if serving {
                ServingStatus::Serving
            } else {
                ServingStatus::NotServing
            }
        };
        let (listener, addr) = bind();
        let mut statuses = vec![(String::new(), status(self.serving))];
        statuses.extend(
            self.services
                .iter()
                .map(|(name, serving)| (name.to_string(), status(*serving))),
        );
        let (tls, health, gzip) = (self.tls, self.health, self.gzip);
        runtime().spawn(async move {
            let mut server = Server::builder();
            if tls {
                let identity = Identity::from_pem(&ca().cert_pem, &ca().key_pem);
                server = server
                    .tls_config(ServerTlsConfig::new().identity(identity))
                    .expect("grpc tls config");
            }
            let incoming = TcpIncoming::from(listener);
            let served = if health {
                let (reporter, mut service) = tonic_health::server::health_reporter();
                for (name, status) in statuses {
                    reporter.set_service_status(name, status).await;
                }
                if gzip {
                    service = service.send_compressed(tonic::codec::CompressionEncoding::Gzip);
                }
                server
                    .add_service(service)
                    .serve_with_incoming(incoming)
                    .await
            } else {
                server
                    .add_routes(tonic::service::Routes::default())
                    .serve_with_incoming(incoming)
                    .await
            };
            served.expect("grpc server");
        });
        addr
    }
}
