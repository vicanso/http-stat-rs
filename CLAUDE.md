# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

A pure Rust CLI tool (`httpstat`) that visualizes HTTP request statistics (timing for DNS, TCP, TLS, server processing, content transfer). Inspired by [davecheney/httpstat](https://github.com/davecheney/httpstat). Supports HTTP/1.1, HTTP/2, HTTP/3 (QUIC), and gRPC. Binary name is `httpstat`, crate name is `http-stat`.

## Build & Development Commands

- **Build release**: `cargo build --release` (or `make release`)
- **Run dev**: `cargo run --bin httpstat -- <url>` (or `make dev`)
- **Run tests**: `cargo test` (or `make test`)
- **Lint**: `make lint` (runs `typos` + `cargo clippy --all-targets --all -- --deny=warnings`)
- **Check outdated deps**: `cargo outdated`
- **Check MSRV**: `cargo msrv list` (minimum Rust version: 1.82)

## Architecture

The binary entrypoint is `bin/httpstat.rs` which uses `clap` for CLI argument parsing and calls into the library.

The library (`src/lib.rs`) exposes the public API through re-exports:

- **`request::request(HttpRequest) -> HttpStat`** - Main entry point. Routes to `http1_2_request`, `http3_request`, or `grpc_request` based on ALPN/scheme. Handles response body decompression automatically.
- **`http_request::HttpRequest`** - Request configuration struct (URI, method, headers, timeouts, ALPN protocols, DNS/IP settings). Implements `TryFrom<&str>` for URL parsing. Default ALPN is `[h2, http/1.1]`.
- **`stats::HttpStat`** - Result struct with per-phase timing (`dns_lookup`, `tcp_connect`, `tls_handshake`, `quic_connect`, `server_processing`, `content_transfer`, `total`), response data, TLS/cert info, and errors. Implements `Display` for the colorized terminal output visualization.
- **`net`** (crate-internal) - Network primitives: `dns_resolve`, `tcp_connect`, `tls_handshake`, `quic_connect`. Uses `hickory-resolver` for DNS, `tokio-rustls` for TLS, `quinn`/`h3-quinn` for QUIC.
- **`error`** - Error types using `snafu`. All network/protocol errors unified under `Error` enum.
- **`decompress`** - Handles gzip, brotli, and zstd decompression.
- **`grpc`** - gRPC health check support via `tonic`.
- **`skip_verifier`** - Custom TLS certificate verifier for `-k` flag.

## Key Design Details

- Uses single-threaded tokio runtime (`#[tokio::main(flavor = "current_thread")]`).
- Release profile is optimized for binary size: `opt-level = "z"`, LTO, strip, panic=abort.
- The `--resolve` flag tests multiple IPs simultaneously, sorting results so errors appear last.
- Redirect following (`-L`) is implemented manually with a max of 10 redirects.
- URL schemes `grpc://` and `grpcs://` route to gRPC health check path.
