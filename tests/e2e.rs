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

//! End-to-end tests: the `httpstat` binary against local servers.

mod support;

use serde_json::Value;
use std::net::SocketAddr;
use support::*;

const H2_AND_H1: &[&str] = &["h2", "http/1.1"];
/// TCP port 1 (tcpmux): nothing listens there, so connections are refused.
/// An ephemeral port that was just released could be handed to another test.
const REFUSED_PORT: u16 = 1;

/// The single result of a run, also when `--resolve` wraps it in an array.
fn single(value: Value) -> Value {
    match value {
        Value::Array(mut items) => items.remove(0),
        other => other,
    }
}

fn is_duration(value: &Value) -> bool {
    value.as_u64().is_some()
}

fn error_of(value: &Value) -> &str {
    value["error"].as_str().unwrap_or_default()
}

fn strip_ansi(text: &str) -> String {
    let mut out = String::new();
    let mut chars = text.chars();
    while let Some(c) = chars.next() {
        if c == '\u{1b}' {
            // Skip the escape sequence up to its final letter.
            for c in chars.by_ref() {
                if c.is_ascii_alphabetic() {
                    break;
                }
            }
        } else {
            out.push(c);
        }
    }
    out
}

// ---- CLI ----

#[test]
fn help_points_scripts_at_json_output() {
    let run = httpstat(&["--help"]);
    assert_eq!(run.code, 0, "{}", run.stderr);
    assert!(run.stdout.contains("add --json"), "{}", run.stdout);
    assert!(run.stdout.contains("JSON_SCHEMA.md"), "{}", run.stdout);
}

// ---- HTTP ----

#[test]
fn plain_http_reports_status_and_timings() {
    let origin = http_server(None);
    let run = httpstat(&["--json", &format!("http://{origin}/")]);
    let stat = run.json();
    assert_eq!(run.code, 0, "{}", run.stderr);
    assert_eq!(stat["status"], 200);
    assert_eq!(stat["exit_code"], 0);
    assert_eq!(stat["addr"], origin.to_string());
    assert_eq!(stat["body_size"], HELLO.len());
    assert!(stat["error"].is_null());
    assert!(stat.get("tls").is_none());
    assert!(is_duration(&stat["timing"]["tcp_connect_us"]));
    assert!(is_duration(&stat["timing"]["total_us"]));
    assert!(stat["timing"]["tls_handshake_us"].is_null());
}

#[test]
fn https_negotiates_the_protocol_and_verifies_the_certificate() {
    let origin = http_server(Some(H2_AND_H1));
    // The certificate is checked against the name; --resolve keeps the
    // system resolver out of the test.
    let url = format!("https://localhost:{}/", origin.port());
    let pinned = ["--json", "--resolve", "127.0.0.1"];

    let run = httpstat(&[&pinned[..], &[url.as_str()]].concat());
    let stat = single(run.json());
    assert_eq!(run.code, 0, "{}", run.stderr);
    assert_eq!(stat["status"], 200);
    assert_eq!(stat["alpn"], "h2");
    assert_eq!(stat["tls"]["version"], "tls v1.3");
    assert_eq!(stat["tls"]["subject"], "CN=localhost");
    assert!(is_duration(&stat["timing"]["tls_handshake_us"]));

    let run = httpstat(&[&pinned[..], &["--http1", url.as_str()]].concat());
    let stat = single(run.json());
    assert_eq!(stat["status"], 200);
    assert_eq!(stat["alpn"], "http/1.1");
}

#[test]
fn untrusted_certificate_is_a_tls_failure_unless_skipped() {
    let origin = http_server(Some(H2_AND_H1));
    let url = format!("https://127.0.0.1:{}/", origin.port());

    let run = httpstat_untrusting(&["--json", &url]);
    assert_eq!(run.code, 4, "{}", run.stdout);
    assert!(error_of(&run.json()).contains("certificate"));

    let run = httpstat_untrusting(&["--json", "-k", &url]);
    assert_eq!(run.code, 0, "{}", run.stdout);
    assert_eq!(run.json()["status"], 200);
}

#[test]
fn failures_map_to_their_exit_codes() {
    let origin = http_server(None);
    let exit_code = |args: &[&str]| httpstat(args).code;

    assert_eq!(
        exit_code(&["--json", &format!("http://{origin}/status/404")]),
        6
    );
    assert_eq!(
        exit_code(&["--json", &format!("http://{origin}/status/503")]),
        7
    );
    assert_eq!(
        exit_code(&["--json", &format!("http://127.0.0.1:{REFUSED_PORT}/")]),
        3
    );
    assert_eq!(
        exit_code(&[
            "--json",
            "--timeout",
            "1s",
            &format!("http://{origin}/hang")
        ]),
        5
    );
}

#[test]
fn max_time_keeps_the_phases_that_finished() {
    let origin = http_server(None);
    let run = httpstat(&[
        "--json",
        "--max-time",
        "1s",
        &format!("http://{origin}/hang"),
    ]);
    let stat = run.json();
    assert_eq!(run.code, 5, "{}", run.stdout);
    assert!(error_of(&stat).contains("--max-time"), "{}", run.stdout);
    // The connection was up before the server stopped answering.
    assert_eq!(stat["addr"], origin.to_string());
    assert!(is_duration(&stat["timing"]["tcp_connect_us"]));
    assert!(stat["timing"]["server_processing_us"].is_null());
}

#[test]
fn header_filters_apply_to_json() {
    let origin = http_server(None);
    let url = format!("http://{origin}/");

    let stat = httpstat(&["--json", "--include-header", "content-type", &url]).json();
    let names: Vec<&String> = stat["headers"].as_object().unwrap().keys().collect();
    assert_eq!(names, ["content-type"]);

    let stat = httpstat(&["--json", "--exclude-header", "x-seen-host", &url]).json();
    let headers = stat["headers"].as_object().unwrap();
    assert!(!headers.contains_key("x-seen-host"));
    assert!(headers.contains_key("content-type"));
}

#[test]
fn resolve_with_count_repeats_for_each_address() {
    let origin = http_server(None);
    let url = format!("http://name.test:{}/", origin.port());

    for extra in [&[][..], &["-K"][..]] {
        let args = [
            &["--json", "--resolve", "127.0.0.1,127.0.0.1", "-n", "3"][..],
            extra,
            &[url.as_str()][..],
        ]
        .concat();
        let run = httpstat(&args);
        let summaries = run.json();
        assert_eq!(run.code, 0, "{}", run.stdout);
        let summaries = summaries.as_array().expect("one summary per address");
        assert_eq!(summaries.len(), 2);
        for summary in summaries {
            assert_eq!(summary["addr"], origin.to_string());
            assert_eq!(summary["count"], 3);
            assert_eq!(summary["success"], 3);
            assert!(is_duration(&summary["timing"]["total"]["p50_us"]));
        }
    }
}

#[test]
fn benchmark_summary_reports_failures() {
    let origin = http_server(None);

    // A response with a failing status is a completed request: it is timed.
    let run = httpstat(&["--json", "-n", "3", &format!("http://{origin}/status/503")]);
    let summary = run.json();
    assert_eq!(run.code, 7, "{}", run.stdout);
    assert_eq!(summary["count"], 3);
    assert_eq!(summary["success"], 0);
    assert_eq!(summary["failed"], 3);
    assert_eq!(summary["exit_code"], 7);
    assert_eq!(summary["errors"]["HTTP 503"], 3);
    assert!(is_duration(&summary["timing"]["total"]["max_us"]));

    // A request that never got a response is counted, but not timed.
    let run = httpstat(&[
        "--json",
        "-n",
        "2",
        &format!("http://127.0.0.1:{REFUSED_PORT}/"),
    ]);
    let summary = run.json();
    assert_eq!(run.code, 3, "{}", run.stdout);
    assert_eq!(summary["failed"], 2);
    assert_eq!(summary["exit_code"], 3);
    assert_eq!(summary["errors"].as_object().map(|e| e.len()), Some(1));
    assert!(summary["timing"]["total"].is_null());

    // Nothing failed: no `errors` block.
    let summary = httpstat(&["--json", "-n", "2", &format!("http://{origin}/")]).json();
    assert_eq!(summary["failed"], 0);
    assert_eq!(summary["exit_code"], 0);
    assert!(summary.get("errors").is_none());
}

#[test]
fn redirects_are_followed_only_with_dash_l() {
    let origin = http_server(None);
    let url = format!("http://{origin}/redirect");

    let stat = httpstat(&["--json", &url]).json();
    assert_eq!(stat["status"], 302);
    assert!(stat.get("redirects").is_none());

    let run = httpstat(&["--json", "-L", &url]);
    let stat = run.json();
    assert_eq!(run.code, 0, "{}", run.stderr);
    assert_eq!(stat["status"], 200);
    assert_eq!(stat["redirects"].as_array().map(Vec::len), Some(1));
}

#[test]
fn http1_upload_time_is_reported_as_request_send() {
    let origin = http_server(None);

    // Even a request without a body has a send phase.
    let stat = httpstat(&["--json", &format!("http://{origin}/")]).json();
    assert!(is_duration(&stat["timing"]["request_send_us"]));

    // Larger than the loopback socket buffers, so the upload cannot finish
    // before the server starts reading.
    let upload = std::path::Path::new(env!("CARGO_TARGET_TMPDIR"))
        .join(format!("upload-{}.bin", std::process::id()));
    std::fs::write(&upload, vec![0u8; 32 * 1024 * 1024]).expect("upload file");
    let run = httpstat(&[
        "--json",
        "-d",
        &format!("@{}", upload.display()),
        &format!("http://{origin}/slow-upload"),
    ]);
    let _ = std::fs::remove_file(&upload);
    let stat = run.json();
    assert_eq!(run.code, 0, "{}", run.stdout);
    let request_send = stat["timing"]["request_send_us"].as_u64().unwrap_or(0);
    let server_processing = stat["timing"]["server_processing_us"].as_u64().unwrap_or(0);
    let floor = UPLOAD_DELAY.as_micros() as u64 * 3 / 4;
    assert!(request_send >= floor, "request_send {request_send}us");
    // The stalled upload is not billed to the server.
    assert!(
        server_processing < floor,
        "server_processing {server_processing}us"
    );
}

#[test]
fn decoded_body_is_capped_by_max_filesize() {
    let origin = http_server(None);
    let url = format!("http://{origin}/bomb");

    // Within the default limit the body is decoded in full.
    let stat = httpstat(&["--json", &url]).json();
    assert_eq!(stat["status"], 200);
    assert_eq!(stat["body_size"], BOMB_SIZE);

    // The compressed bytes fit in 1MB; what they decode to does not.
    let run = httpstat(&["--json", "--max-filesize", "1MB", &url]);
    assert_ne!(run.code, 0, "{}", run.stdout);
    assert!(error_of(&run.json()).contains("decompressed body exceeds"));

    // The same holds when the body is streamed to a file.
    let output = std::path::Path::new(env!("CARGO_TARGET_TMPDIR"))
        .join(format!("bomb-{}.out", std::process::id()));
    let run = httpstat(&[
        "--json",
        "--max-filesize",
        "1MB",
        "-o",
        &output.display().to_string(),
        &url,
    ]);
    let saved = std::fs::metadata(&output).map(|m| m.len()).unwrap_or(0);
    let _ = std::fs::remove_file(&output);
    assert_ne!(run.code, 0, "{}", run.stdout);
    assert!(error_of(&run.json()).contains("decompressed body exceeds"));
    assert!(saved <= 1_000_000, "{saved} bytes were written");
}

#[test]
fn redirect_to_a_unicode_host_is_followed() {
    let origin = http_server(None);
    let port = origin.port();
    let run = httpstat(&[
        "--json",
        "-L",
        "--connect-to",
        &format!("xn--bcher-kva.test:{port}:127.0.0.1:{port}"),
        &format!("http://{origin}/redirect-unicode"),
    ]);
    let stat = run.json();
    assert_eq!(run.code, 0, "{}", run.stdout);
    assert_eq!(stat["status"], 200);
    assert_eq!(stat["redirects"].as_array().map(Vec::len), Some(1));
    assert_eq!(
        stat["headers"]["x-seen-host"],
        format!("xn--bcher-kva.test:{port}")
    );
}

#[test]
fn compressed_body_is_decoded() {
    let origin = http_server(None);
    let stat = httpstat(&["--json", "--compressed", &format!("http://{origin}/gzip")]).json();
    assert_eq!(stat["status"], 200);
    assert_eq!(stat["headers"]["content-encoding"], "gzip");
    assert_eq!(stat["body_size"], HELLO.len());
}

/// The path after `saved to: ` in text output, if a body was saved.
fn saved_path(text: &str) -> Option<String> {
    text.split_once("saved to: ")
        .map(|(_, rest)| rest.lines().next().unwrap_or_default().trim().to_string())
}

#[test]
fn binary_body_is_saved_to_a_file_as_received() {
    let origin = http_server(None);
    let text = strip_ansi(&httpstat(&[&format!("http://{origin}/binary")]).stdout);
    let path = saved_path(&text).unwrap_or_else(|| panic!("no saved file in:\n{text}"));
    let saved = std::fs::read(&path).expect("saved body");
    let _ = std::fs::remove_file(&path);
    assert_eq!(saved, BINARY);
}

#[test]
fn empty_body_is_not_saved_to_a_file() {
    let origin = http_server(None);
    let text = strip_ansi(&httpstat(&[&format!("http://{origin}/empty")]).stdout);
    assert!(text.contains("Body size: 0 B"), "{text}");
    if let Some(path) = saved_path(&text) {
        let _ = std::fs::remove_file(&path);
        panic!("an empty body was saved to {path}");
    }
}

#[test]
fn unicode_host_is_sent_as_punycode() {
    let origin = http_server(None);
    let run = httpstat(&[
        "--json",
        "--resolve",
        "127.0.0.1",
        &format!("http://bücher.test:{}/", origin.port()),
    ]);
    let stat = single(run.json());
    assert_eq!(run.code, 0, "{}", run.stderr);
    assert_eq!(
        stat["headers"]["x-seen-host"],
        format!("xn--bcher-kva.test:{}", origin.port())
    );
}

// ---- HTTP/3 ----

#[test]
fn http3_request_and_connection_reuse() {
    let origin = http3_server();
    let url = format!("https://127.0.0.1:{}/", origin.port());

    let run = httpstat(&["--json", "--http3", &url]);
    let stat = run.json();
    assert_eq!(run.code, 0, "{}", run.stdout);
    assert_eq!(stat["status"], 200);
    assert_eq!(stat["alpn"], "h3");
    // The same spelling as over TCP.
    assert_eq!(stat["tls"]["version"], "tls v1.3");
    assert_eq!(stat["body_size"], HELLO.len());
    assert!(is_duration(&stat["timing"]["quic_connect_us"]));
    assert!(stat["timing"]["tcp_connect_us"].is_null());

    let run = httpstat(&["--json", "--http3", "-K", "-n", "3", &url]);
    let summary = run.json();
    assert_eq!(run.code, 0, "{}", run.stdout);
    assert_eq!(summary["count"], 3);
    assert_eq!(summary["success"], 3);
}

// ---- Proxies ----

fn assert_tunneled(proxy_url: &str, proxy: &Proxy, origin: SocketAddr) {
    let run = httpstat(&[
        "--json",
        "--proxy",
        proxy_url,
        &format!("https://127.0.0.1:{}/", origin.port()),
    ]);
    let stat = run.json();
    assert_eq!(run.code, 0, "{proxy_url}: {}", run.stdout);
    assert_eq!(stat["status"], 200);
    assert_eq!(stat["alpn"], "h2");
    assert_eq!(stat["tls"]["subject"], "CN=localhost");
    assert!(is_duration(&stat["timing"]["proxy_connect_us"]));
    assert_eq!(proxy.tunnels(), 1, "{proxy_url} was bypassed");
}

#[test]
fn https_through_an_http_proxy() {
    let proxy = connect_proxy(false);
    assert_tunneled(
        &format!("http://{}", proxy.addr),
        &proxy,
        http_server(Some(H2_AND_H1)),
    );
}

#[test]
fn https_through_an_https_proxy() {
    let proxy = connect_proxy(true);
    assert_tunneled(
        &format!("https://{}", proxy.addr),
        &proxy,
        http_server(Some(H2_AND_H1)),
    );
}

#[test]
fn https_through_a_socks5_proxy() {
    let proxy = socks5_proxy();
    assert_tunneled(
        &format!("socks5://{}", proxy.addr),
        &proxy,
        http_server(Some(H2_AND_H1)),
    );
}

#[test]
fn unreachable_proxy_is_a_connection_failure() {
    let origin = http_server(Some(H2_AND_H1));
    let run = httpstat(&[
        "--json",
        "--proxy",
        &format!("http://127.0.0.1:{REFUSED_PORT}"),
        &format!("https://127.0.0.1:{}/", origin.port()),
    ]);
    assert_eq!(run.code, 3, "{}", run.stdout);
}

// ---- DoH / DoT ----

/// Resolve [`RESOLVABLE`] through `dns_server` and fetch `/` from `origin`.
#[cfg(feature = "doh")]
fn fetch_via(dns_server: &str, origin: SocketAddr) -> Run {
    httpstat(&[
        "--json",
        "--dns-servers",
        dns_server,
        &format!("http://www.{RESOLVABLE}:{}/", origin.port()),
    ])
}

#[cfg(feature = "doh")]
fn assert_resolved(dns_server: &str) {
    let origin = http_server(None);
    let run = fetch_via(dns_server, origin);
    let stat = run.json();
    assert_eq!(run.code, 0, "{dns_server}: {}", run.stdout);
    assert_eq!(stat["status"], 200);
    assert_eq!(stat["addr"], origin.to_string());
    assert!(is_duration(&stat["timing"]["dns_connect_us"]));
    assert!(is_duration(&stat["timing"]["dns_lookup_us"]));
}

#[cfg(feature = "doh")]
#[test]
fn doh_resolver_over_http2() {
    // Some resolvers speak nothing but HTTP/2.
    let resolver = http_server(Some(&["h2"]));
    assert_resolved(&format!("https://127.0.0.1:{}/dns-query", resolver.port()));
    // The path defaults to /dns-query, and the host may be a name.
    assert_resolved(&format!("https://localhost:{}", resolver.port()));
}

#[cfg(feature = "doh")]
#[test]
fn doh_queries_run_concurrently_over_http2() {
    // Each of the A and AAAA queries takes DNS_DELAY to answer.
    let resolver = http_server(Some(&["h2"]));
    let origin = http_server(None);
    let run = fetch_via(
        &format!("https://127.0.0.1:{}/slow-dns", resolver.port()),
        origin,
    );
    let stat = run.json();
    assert_eq!(run.code, 0, "{}", run.stdout);
    let lookup = stat["timing"]["dns_lookup_us"].as_u64().unwrap_or(u64::MAX);
    let one_at_a_time = 2 * DNS_DELAY.as_micros() as u64;
    assert!(
        lookup < one_at_a_time * 9 / 10,
        "dns lookup took {lookup}us"
    );
}

#[cfg(feature = "doh")]
#[test]
fn doh_resolver_over_http1() {
    let resolver = http_server(Some(&["http/1.1"]));
    assert_resolved(&format!("https://127.0.0.1:{}/dns-query", resolver.port()));
}

#[cfg(feature = "doh")]
#[test]
fn doh_resolver_on_a_custom_path() {
    let resolver = http_server(Some(H2_AND_H1));
    assert_resolved(&format!("https://127.0.0.1:{}/custom/dns", resolver.port()));

    let run = fetch_via(
        &format!("https://127.0.0.1:{}/nope", resolver.port()),
        http_server(None),
    );
    assert_eq!(run.code, 2, "{}", run.stdout);
    assert!(error_of(&run.json()).contains("doh status 404"));
}

#[cfg(feature = "doh")]
#[test]
fn dot_resolver() {
    let resolver = dot_server();
    assert_resolved(&format!("tls://{resolver}"));
    assert_resolved(&format!("tls://localhost:{}", resolver.port()));
}

#[cfg(feature = "doh")]
#[test]
fn secure_dns_failures_are_dns_failures() {
    let resolver = http_server(Some(H2_AND_H1));
    let dns_server = format!("https://127.0.0.1:{}/dns-query", resolver.port());
    let origin = http_server(None);

    // NXDOMAIN from the resolver.
    let run = httpstat(&[
        "--json",
        "--dns-servers",
        &dns_server,
        &format!("http://missing.invalid:{}/", origin.port()),
    ]);
    assert_eq!(run.code, 2, "{}", run.stdout);

    // Written as a DoH URL, but not one: no silent fallback to another resolver.
    let run = fetch_via("https://", origin);
    assert_eq!(run.code, 2, "{}", run.stdout);
    assert!(error_of(&run.json()).contains("invalid dns server"));

    // The resolver's certificate is verified...
    let url = format!("http://www.{RESOLVABLE}:{}/", origin.port());
    let run = httpstat_untrusting(&["--json", "--dns-servers", &dns_server, &url]);
    assert_eq!(run.code, 2, "{}", run.stdout);
    assert!(error_of(&run.json()).contains("certificate"));

    // ...unless -k says otherwise.
    let run = httpstat_untrusting(&["--json", "-k", "--dns-servers", &dns_server, &url]);
    assert_eq!(run.code, 0, "{}", run.stdout);
    assert_eq!(run.json()["status"], 200);
}

#[cfg(feature = "doh")]
#[test]
fn lookup_without_an_address_is_a_dns_failure() {
    // The test resolver has an A record for the name, but no AAAA.
    let resolver = http_server(Some(H2_AND_H1));
    let run = httpstat(&[
        "--json",
        "-6",
        "--dns-servers",
        &format!("https://127.0.0.1:{}", resolver.port()),
        &format!("http://www.{RESOLVABLE}:{}/", http_server(None).port()),
    ]);
    assert_eq!(run.code, 2, "{}", run.stdout);
}

#[cfg(feature = "doh")]
#[test]
fn connect_to_pins_the_resolver_address() {
    let resolver = http_server(Some(H2_AND_H1));
    let origin = http_server(None);
    // Nothing answers on the port in the URL.
    let dns_server = format!("https://localhost:{REFUSED_PORT}/dns-query");
    let url = format!("http://www.{RESOLVABLE}:{}/", origin.port());

    let run = httpstat(&["--json", "--dns-servers", &dns_server, &url]);
    assert_eq!(run.code, 2, "{}", run.stdout);

    let run = httpstat(&[
        "--json",
        "--dns-servers",
        &dns_server,
        "--connect-to",
        &format!("localhost:{REFUSED_PORT}:127.0.0.1:{}", resolver.port()),
        &url,
    ]);
    let stat = run.json();
    assert_eq!(run.code, 0, "{}", run.stdout);
    assert_eq!(stat["status"], 200);
    assert_eq!(stat["addr"], origin.to_string());
}

// ---- gRPC ----

#[test]
fn grpc_health_check_reports_serving() {
    let server = Grpc::default().start();
    for url in [
        format!("grpc://{server}"),
        format!("grpc://{server}/grpc.health.v1.Health/Check"),
    ] {
        let run = httpstat(&["--json", &url]);
        let stat = run.json();
        assert_eq!(run.code, 0, "{url}: {}", run.stdout);
        assert_eq!(stat["status"], 200);
        assert_eq!(stat["headers"]["grpc-status"], "0");
        assert!(stat["error"].is_null());
    }
}

#[test]
fn grpc_health_check_reports_not_serving() {
    let server = Grpc {
        serving: false,
        ..Default::default()
    }
    .start();
    let run = httpstat(&["--json", &format!("grpc://{server}")]);
    assert_eq!(run.code, 1, "{}", run.stdout);
    assert_eq!(error_of(&run.json()), "service not serving");
}

#[test]
fn grpc_health_check_for_one_service() {
    let server = Grpc {
        services: &[("pkg.Up", true), ("pkg.Down", false)],
        ..Default::default()
    }
    .start();
    let check =
        |service: &str| httpstat(&["--json", &format!("grpc://{server}/?service={service}")]);

    let run = check("pkg.Up");
    assert_eq!(run.code, 0, "{}", run.stdout);

    let run = check("pkg.Down");
    assert_eq!(run.code, 1, "{}", run.stdout);
    assert_eq!(error_of(&run.json()), "service not serving");

    let run = check("pkg.Missing");
    assert_eq!(run.code, 1, "{}", run.stdout);
    assert!(error_of(&run.json()).starts_with("grpc-status 5 (NOT_FOUND)"));
}

#[test]
fn grpc_server_without_the_health_service_is_unimplemented() {
    let server = Grpc {
        health: false,
        ..Default::default()
    }
    .start();
    let run = httpstat(&["--json", &format!("grpc://{server}")]);
    assert_eq!(run.code, 1, "{}", run.stdout);
    assert_eq!(error_of(&run.json()), "grpc-status 12 (UNIMPLEMENTED)");
}

#[test]
fn grpcs_health_check_runs_over_tls() {
    let server = Grpc {
        tls: true,
        ..Default::default()
    }
    .start();
    let url = format!("grpcs://127.0.0.1:{}", server.port());

    let run = httpstat(&["--json", &url]);
    let stat = run.json();
    assert_eq!(run.code, 0, "{}", run.stdout);
    assert_eq!(stat["alpn"], "h2");
    assert_eq!(stat["tls"]["subject"], "CN=localhost");

    assert_eq!(httpstat_untrusting(&["--json", &url]).code, 4);
}

#[test]
fn grpc_health_check_over_a_reused_connection() {
    let server = Grpc::default().start();
    let url = format!("grpc://{server}");

    let run = httpstat(&["--json", "-K", "-n", "3", &url]);
    let summary = run.json();
    assert_eq!(run.code, 0, "{}", run.stdout);
    assert_eq!(summary["count"], 3);
    assert_eq!(summary["success"], 3);

    let run = httpstat(&["--json", "-c", "2", "-n", "4", &url]);
    let summary = run.json();
    assert_eq!(run.code, 0, "{}", run.stdout);
    assert_eq!(summary["count"], 4);
    assert_eq!(summary["success"], 4);

    // A failed check on a reused connection is not reported as a TCP failure.
    let down = Grpc {
        serving: false,
        ..Default::default()
    }
    .start();
    let run = httpstat(&["--json", "-K", "-n", "2", &format!("grpc://{down}")]);
    assert_eq!(run.code, 1, "{}", run.stdout);
}

#[test]
fn grpc_goes_through_a_proxy() {
    // Cleartext gRPC is tunneled with CONNECT, health check included.
    let proxy = connect_proxy(false);
    let server = Grpc::default().start();
    let run = httpstat(&[
        "--json",
        "--proxy",
        &format!("http://{}", proxy.addr),
        &format!("grpc://{server}"),
    ]);
    assert_eq!(run.code, 0, "{}", run.stdout);
    assert_eq!(proxy.tunnels(), 1);

    // grpcs:// picks its proxy up from HTTPS_PROXY.
    let proxy = connect_proxy(false);
    let server = Grpc {
        tls: true,
        ..Default::default()
    }
    .start();
    let run = httpstat_env(
        &["--json", &format!("grpcs://127.0.0.1:{}", server.port())],
        &[("HTTPS_PROXY", &format!("http://{}", proxy.addr))],
    );
    assert_eq!(run.code, 0, "{}", run.stdout);
    assert_eq!(proxy.tunnels(), 1);
}

#[test]
fn grpc_compressed_response_is_decoded() {
    let server = Grpc {
        gzip: true,
        ..Default::default()
    }
    .start();
    let url = format!("grpc://{server}");

    // The server compresses only for a client that accepts it.
    let run = httpstat(&["--json", &url]);
    assert_eq!(run.code, 0, "{}", run.stdout);
    assert!(run.json()["headers"].get("grpc-encoding").is_none());

    let run = httpstat(&["--json", "--compressed", &url]);
    let stat = run.json();
    assert_eq!(run.code, 0, "{}", run.stdout);
    assert_eq!(stat["headers"]["grpc-encoding"], "gzip");
    assert!(stat["error"].is_null());
}

#[test]
fn grpc_raw_unary_call_returns_the_message_and_trailers() {
    let server = http_server(None);
    let url = format!("grpc://{server}/test.Echo/Unary");

    let run = httpstat(&["--json", "-d", "ping", &url]);
    let stat = run.json();
    assert_eq!(run.code, 0, "{}", run.stdout);
    assert_eq!(stat["status"], 200);
    assert_eq!(stat["trailers"]["grpc-status"], "0");
    assert_eq!(stat["body_size"], "ping".len());

    let text = strip_ansi(&httpstat(&["-d", "ping", &url]).stdout);
    assert!(text.contains("H2 200 OK"), "{text}");
    assert!(text.contains("Trailers:\nGrpc-Status: 0"), "{text}");

    let run = httpstat(&["--json", "-K", "-n", "3", "-d", "ping", &url]);
    assert_eq!(run.code, 0, "{}", run.stdout);
    assert_eq!(run.json()["success"], 3);
}

#[test]
fn grpc_unknown_method_fails_without_an_error() {
    let server = Grpc::default().start();
    let run = httpstat(&["--json", &format!("grpc://{server}/pkg.Nothing/Here")]);
    let stat = run.json();
    assert_eq!(run.code, 1, "{}", run.stdout);
    assert_eq!(stat["headers"]["grpc-status"], "12");
    assert!(stat["error"].is_null());
}
