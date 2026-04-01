# http-stat-rs

Imitation is the sincerest form of flattery.

A **zero-dependency, single-binary** HTTP diagnostics tool written in pure Rust. Visualizes the full request lifecycle — DNS, TCP, TLS, server processing, content transfer — in one clear timeline. Inspired by [httpstat](https://github.com/davecheney/httpstat).

[中文](./README_zh.md)

![screenshot](./screenshot.png)

## Highlights

- **HTTP/1.1, HTTP/2 & HTTP/3 (QUIC)** — first-class support for all modern protocols, switch with a single flag
- **gRPC health check** — use `grpc://` or `grpcs://` scheme to probe gRPC services
- **Multi-IP concurrent testing** — `--resolve` tests multiple IPs in parallel, results sorted by success
- **Transparent decompression** — auto-decodes `gzip`, `br`, `zstd` responses with `--compressed`
- **Custom DNS** — specify DNS servers by IP or use built-in presets: `google`, `cloudflare`, `quad9`
- **TLS inspection** — verbose mode shows full certificate chain, cipher suite, SAN domains, and validity
- **curl-like UX** — familiar flags (`-H`, `-X`, `-d`, `-L`, `-k`, `-o`, `-4`/`-6`) for a smooth transition
- **Tiny binary** — release build uses LTO + `opt-level=z` + strip, typically < 5 MB

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

# gRPC health check
httpstat grpc://localhost:50051

# Verbose mode — full cert chain + request headers
httpstat -v https://github.com

# Custom DNS server
httpstat --dns-servers=cloudflare https://example.com

# Pretty-print JSON response
httpstat --pretty https://httpbin.org/get

# Set timeout
httpstat --timeout 5s https://example.com
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
  -d, --data <DATA>                the body of a POST or PUT request; from file use @filename
      --resolve <RESOLVE>          resolve the request host to specific ip address (e.g. 1.2.3.4,1.2.3.5)
      --compressed                 request compressed response: gzip, br, zstd
      --http3                      use http/3
      --http2                      use http/2
      --http1                      use http/1.1
  -s                               silent mode, only output the connect address and result
      --dns-servers <DNS_SERVERS>  dns server address to use, format: 8.8.8.8,8.8.4.4
  -v, --verbose                    verbose mode
      --pretty                     pretty mode
      --timeout <TIMEOUT>          timeout
  -h, --help                       Print help
  -V, --version                    Print version
```

## License

http-stat-rs is provided under the MIT license. See [LICENSE](LICENSE).
