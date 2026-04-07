# http-stat-rs

Imitation is the sincerest form of flattery.

A **zero-dependency, single-binary** HTTP diagnostics tool written in pure Rust. Visualizes the full request lifecycle — DNS, TCP, TLS, server processing, content transfer — in one clear timeline. Inspired by [httpstat](https://github.com/davecheney/httpstat).

[中文](./README_zh.md)

![screenshot](./screenshot.png)

## Highlights

- **HTTP/1.1, HTTP/2 & HTTP/3 (QUIC)** — first-class support for all modern protocols, switch with a single flag
- **gRPC health check** — use `grpc://` or `grpcs://` scheme to probe gRPC services
- **Benchmark mode** — `-n 10` repeats N times with min/max/avg/p50/p95/p99; add `-K` to reuse the connection and compare cold vs warm latency
- **Multi-IP concurrent testing** — `--resolve` tests multiple IPs in parallel, results sorted by success
- **Transparent decompression** — auto-decodes `gzip`, `br`, `zstd` responses with `--compressed`
- **Custom DNS** — specify DNS servers by IP or use built-in presets: `google`, `cloudflare`, `quad9`; DoH/DoT presets: `google-doh`, `cloudflare-doh`, `quad9-doh`, `google-dot`, `cloudflare-dot`, `quad9-dot`
- **JSON output** — `--json` for scripting, CI/CD pipelines, and monitoring integration
- **TLS inspection** — verbose mode shows full certificate chain, cipher suite, SAN domains, and validity
- **Cookie support** — `-b 'k=v'` or `-b @file`, auto-carried across `-L` redirects with `Set-Cookie` merging
- **ALPN negotiation display** — every response line shows the final protocol agreed between client and server (`HTTP/1.1`, `H2`, `H3`), so you always know which version was actually used
- **JSON field selector** — `--jq '.items[].name'` extracts fields directly from the response body; no need to pipe through `jq`
- **Pretty JSON** — `--pretty` formats the response body in-place; combine with `--jq` for focused, readable output
- **Response header filtering** — `--include-header` shows only the headers you care about; `--exclude-header` hides the noisy ones
- **curl-like UX** — familiar flags (`-H`, `-X`, `-d`, `-L`, `-k`, `-o`, `-4`/`-6`) for a smooth transition
- **Waterfall chart** — `--waterfall` renders each phase as a horizontal bar, making bottlenecks instantly visible (like Chrome DevTools Network panel)
- **`--connect-to`** — redirect `HOST1:PORT1` to `HOST2:PORT2` at the TCP level; TLS SNI and `Host` header stay unchanged, like curl's `--connect-to`
- **Proxy support** — `--proxy` for HTTP/HTTPS/SOCKS5 proxies; also reads `HTTP_PROXY`, `HTTPS_PROXY`, `ALL_PROXY` environment variables
- **Source IP binding** — `--bind <IP>` pins outbound connections to a specific local address; essential for multi-NIC hosts, policy routing, or validating which interface reaches a target
- **mTLS (mutual TLS)** — `--cert`/`--key` sends a client certificate for zero-trust and service mesh authentication
- **Config file** — `~/.httpstatrc` sets persistent defaults (DNS, timeout, headers, etc.); CLI flags always win
- **Semantic exit codes** — distinct codes for DNS, TCP, TLS, timeout, 4xx, 5xx failures for easy scripting
- **Tiny binary** — release build uses LTO + `opt-level=z` + strip, typically < 5 MB
- **Truly zero system dependencies** — statically linked, no libcurl, no OpenSSL, no libc on musl builds; drop the binary directly into a `scratch` or `alpine` Docker image for production diagnostics

## Installation

### Pre-built binaries

[Pre-built binaries](https://github.com/vicanso/http-stat-rs/releases) for Windows, macOS and Linux.

```bash
# Linux
curl -L https://github.com/vicanso/http-stat-rs/releases/latest/download/httpstat-linux-musl-$(uname -m).tar.gz | tar -xzf -
sudo mv httpstat /usr/local/bin/

# macOS
curl -L https://github.com/vicanso/http-stat-rs/releases/latest/download/httpstat-darwin-$(uname -m).tar.gz | tar -xzf -
sudo mv httpstat /usr/local/bin/
```

### From source

```bash
cargo install http-stat
```

## Request Lifecycle

Every HTTP request goes through up to five sequential phases. httpstat measures each one independently:

```
  DNS Lookup   TCP Connect  TLS Handshake  Server Processing  Content Transfer
[────────────][────────────][──────────────][──────────────────][───────────────]
      │              │              │                │                  │
  hostname       3-way SYN      TLS/SSL          waiting for       downloading
   → IP          handshake    negotiation        first byte         response
                                 (HTTPS)
                                                                         ▲
                                                              Total = all phases
```

| Phase | What it measures |
|---|---|
| DNS Lookup | Time to resolve the hostname to an IP address |
| TCP Connect | Time for the 3-way TCP handshake |
| TLS Handshake | Time to negotiate the TLS session (HTTPS/HTTP2/HTTP3 only) |
| Server Processing | Time from the last request byte sent to the first response byte received — pure server latency |
| Content Transfer | Time to download the complete response body |

> For HTTP/3, **QUIC Connect** replaces both TCP Connect and TLS Handshake (QUIC combines transport and crypto in a single handshake).

## Usage

```bash
# Basic — auto-negotiates HTTP/2 via ALPN
httpstat https://www.cloudflare.com/

# HTTP/3 (QUIC) with compressed response
httpstat --http3 --compressed https://cloudflare-quic.com/

# Test multiple IPs concurrently in silent mode
httpstat --resolve=183.240.99.169,2409:8c54:870:310:0:ff:b0ed:40ac -s https://www.baidu.com/

# POST with request body from file
httpstat -X POST -d @payload.json -H 'Content-Type: application/json' https://httpbin.org/post

# POST with request body from stdin
echo '{"key":"value"}' | httpstat -X POST -d @- -H 'Content-Type: application/json' https://httpbin.org/post

# gRPC health check
httpstat grpc://localhost:50051

# Verbose mode — full cert chain + request headers
httpstat -v https://github.com

# JSON output for scripting
httpstat --json https://example.com

# JSON benchmark output (pipe to jq, etc.)
httpstat --json -n 5 https://example.com

# Send cookies
httpstat -b 'session=abc123; lang=en' https://httpbin.org/cookies

# Custom DNS server (plain UDP)
httpstat --dns-servers=cloudflare https://example.com

# DNS-over-HTTPS
httpstat --dns-servers=cloudflare-doh https://example.com

# DNS-over-TLS
httpstat --dns-servers=google-dot https://example.com

# Pretty-print JSON response
httpstat --pretty https://httpbin.org/get

# Benchmark — repeat 10 times, show percentile stats
httpstat -n 10 https://example.com

# Benchmark with connection reuse — measure warm request latency
httpstat -n 10 -K https://example.com

# Only show specific response headers
httpstat --include-header content-type --include-header server https://example.com

# Hide noisy response headers
httpstat --exclude-header date --exclude-header via https://example.com

# Set timeout
httpstat --timeout 5s https://example.com

# mTLS — send client certificate
httpstat --cert client.crt --key client.key https://mtls.example.com

# Waterfall bar chart — spot bottlenecks at a glance
httpstat --waterfall https://example.com

# Connect-to: test a specific backend without changing DNS or Host header
httpstat --connect-to example.com:443:staging.internal:443 https://example.com

# Repeatable for multiple overrides
httpstat --connect-to api.example.com:443:192.168.1.10:8443 https://api.example.com

# HTTP proxy
httpstat --proxy http://proxy.corp:8080 https://example.com

# SOCKS5 proxy
httpstat --proxy socks5://127.0.0.1:1080 https://example.com

# Proxy from environment variable
HTTPS_PROXY=http://proxy.corp:8080 httpstat https://example.com

# Bind to a specific local IP (multi-NIC / policy routing)
httpstat --bind 192.168.1.100 https://example.com
```

## Options

```
httpstat visualizes curl(1) statistics in a way of beauty and clarity.

Usage: httpstat [OPTIONS] [URL_ARG]

Arguments:
  [URL_ARG]  url to request

Options:
  -u, --url <URL>                  URL to request (optional, can be provided as the last argument)
  -H <HEADERS>                     set HTTP header; repeatable: -H 'Accept: ...' -H 'Range: ...'
  -4                               resolve host to ipv4 only
  -6                               resolve host to ipv6 only
  -k                               skip verify tls certificate
  -o <OUTPUT>                      output file
  -L                               follow 30x redirects
  -X <METHOD>                      HTTP method to use (default GET)
  -d, --data <DATA>                the body of a POST or PUT request; from file use @filename, from stdin use @-
      --resolve <RESOLVE>          resolve the request host to specific ip address (e.g. 1.2.3.4,1.2.3.5)
      --compressed                 request compressed response: gzip, br, zstd
      --http3                      use http/3
      --http2                      use http/2
      --http1                      use http/1.1
  -s                               silent mode, only output the connect address and result
      --dns-servers <DNS_SERVERS>  dns server address to use, format: 8.8.8.8,8.8.4.4; presets: google, cloudflare, quad9, google-doh, cloudflare-doh, quad9-doh, google-dot, cloudflare-dot, quad9-dot
  -v, --verbose                    verbose mode
      --pretty                     pretty mode
      --timeout <TIMEOUT>          timeout
  -n, --count <COUNT>              number of requests for benchmarking, show min/max/avg/p50/p95/p99 stats
  -K, --reuse                      reuse connection in benchmark mode (requires -n), test warm request performance
  -b, --cookie <COOKIE>            send cookies: 'name=value; name2=value2' or from file use @filename
      --json                       output results as JSON for scripting and CI/CD
      --include-header <HEADER>    only show these response headers (repeatable, case-insensitive)
      --exclude-header <HEADER>    hide these response headers (repeatable, case-insensitive)
      --waterfall                  show timing as a waterfall bar chart
      --connect-to <CONNECT_TO>    redirect HOST1:PORT1 to HOST2:PORT2 (repeatable, IPv6 uses [addr])
      --proxy <PROXY>              proxy URL: http://host:port, https://host:port, socks5://host:port
      --cert <CERT>                client certificate for mTLS (PEM file)
      --key <KEY>                  client private key for mTLS (PEM file)
  -h, --help                       Print help
  -V, --version                    Print version
```

## Config File (`~/.httpstatrc`)

Set persistent defaults so you don't have to repeat flags on every invocation.

Create `~/.httpstatrc` as a JSON object — any field can be omitted. CLI flags always override config values.

```json
{
  "compressed": true,
  "dns_servers": "cloudflare",
  "timeout": "10s",
  "verbose": false,
  "pretty": false,
  "silent": false,
  "follow_redirect": false,
  "skip_verify": false,
  "http1": false,
  "http2": false,
  "http3": false,
  "json": false,
  "headers": ["Accept: application/json"],
  "include_header": [],
  "exclude_header": ["date", "via"]
}
```

## Exit Codes

| Code | Meaning |
|------|---------|
| 0 | Success |
| 1 | General / unknown error |
| 2 | DNS resolution failure |
| 3 | TCP connection failure |
| 4 | TLS / SSL error |
| 5 | Timeout |
| 6 | HTTP 4xx client error |
| 7 | HTTP 5xx server error |

## License

http-stat-rs is provided under the MIT license. See [LICENSE](LICENSE).
