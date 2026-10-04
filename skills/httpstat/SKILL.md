---
name: httpstat
description: Diagnose HTTP endpoints with the `httpstat` CLI - where a request spends its time (DNS, TCP, TLS, request upload, server processing, download), why it fails, which protocol and certificate the server negotiates, and how latency is distributed over repeated requests. Use this whenever the user asks why a URL, API or website is slow, timing out or failing, wants DNS / TLS / TTFB numbers, wants a TLS certificate or its expiry checked, asks whether a server speaks HTTP/2 or HTTP/3, needs a gRPC health check, wants to compare IPs or CDN nodes, test through a proxy or a specific DNS resolver, or benchmark an endpoint - even when they do not mention httpstat. Prefer it over hand-rolled `curl -w` timing.
---

# httpstat

`httpstat` makes one HTTP request and times every phase of it. It speaks HTTP/1.1, HTTP/2, HTTP/3 and gRPC, and its flags follow curl (`-H`, `-X`, `-d`, `-L`, `-k`, `-o`).

## Run it for a machine

Always pass `--json`. The default output is drawn for a terminal: it carries color codes even when piped, and it saves any non-text body to a temp file. `--json` prints one document and nothing else.

```bash
httpstat --json --max-time 30s https://example.com/api | jq '{status, alpn, addr, error, exit_code, timing}'
```

- The response headers make the document long. Project what you need with `jq`, as above, or name the headers to keep with `--include-header`.
- The JSON never contains the body. Add `-o FILE` to keep it; the path comes back as `saved_to`.
- `--max-time` is the safety net against a server that never answers (with `-n` it applies to each request). On a timeout the phases that finished are still reported, so the first `null` phase is where it hung. `--timeout 5s` limits each phase instead. With neither flag, DNS, TCP and TLS each give up after 5 s, and QUIC and the response after 30 s.
- Branch on the exit code, which the document also reports as `exit_code`. `error` holds the reason in words: quote it to the user rather than matching on it.

| Code | Meaning | Code | Meaning |
|---|---|---|---|
| 0 | success | 4 | TLS error |
| 1 | other error | 5 | timeout |
| 2 | DNS failure | 6 | HTTP 4xx |
| 3 | TCP connection failure | 7 | HTTP 5xx |

On 6 and 7 the request completed, so the timings are still valid.

## Read the timings

Everything under `timing` is in microseconds; report milliseconds to the user. `null` means the phase did not run.

| Field | What a large value points to |
|---|---|
| `dns_lookup_us` | the resolver. With DoH/DoT it splits into `dns_connect_us` and `dns_query_us` |
| `tcp_connect_us` | network distance: normally one round trip to the server |
| `tls_handshake_us` | TLS. For HTTP/3, `quic_connect_us` replaces both TCP and TLS |
| `request_send_us` | a slow upload of the request body |
| `server_processing_us` | the wait for the first response byte: the server's own time plus at least one round trip |
| `content_transfer_us` | body download: size, bandwidth, or a server that streams slowly |
| `total_us` | the whole request |

Also useful: `status`, `alpn` (`h2`, `http/1.1`, `h3`), `addr` (the IP that answered), `alt_svc`, `error`, and `tls` with `subject`, `issuer`, `domains`, `not_after`.

Before drawing a conclusion:

- **One run is a cold run.** It pays for DNS, TCP and TLS, and its DNS figure is this tool's own uncached lookup, which an application with a warm cache does not pay. Say so, and repeat with `-n` before calling anything slow.
- **Network or server?** Run `-n 10 -K`. On a reused connection `timing.server_processing.min_us` is one round trip plus the server's own time, so compare it with the round trip.
- **Take the round trip from `tcp_connect_us`, unless it is under a millisecond for a remote host.** Then a local proxy or VPN is answering the TCP handshake and the figure says nothing about the server. Use `quic_info.final.rtt_us` from an `--http3` run if the server has HTTP/3, or tell the user the two cannot be separated from this machine.
- **A `tcp_connect_us` near 250 ms on a host with both IPv4 and IPv6** can be an IPv6 attempt being given up. Rerun with `-4` and `-6` to check.

## The document changes shape

- One request: an object.
- `--resolve IP1,IP2`: an array, one object per IP, requested at the same time. With `-n` it is one summary per IP, each with its `addr`, run one IP after another.
- `-n N`: a summary with `count`, `success`, `failed`, `exit_code`, and `timing.<phase>` holding `min_us`, `avg_us`, `p50_us`, `p95_us`, `p99_us`, `max_us`. Phase names drop the `_us` suffix here (`timing.total.p95_us`).
  - When something failed, `errors` maps each reason to a count. Only requests that got a response are timed.
  - Only the first request looks the name up, so `dns_lookup` is 0 for the rest.
  - With 10 samples p95 and p99 are simply the slowest one. Raise N before quoting a tail.
- `-n N -K`: the same summary for requests on one reused connection, plus `cold_connect` for the one-off setup. `timing.dns_lookup`, `tcp_connect` and `tls_handshake` are `null` and `timing.total` covers the request alone.
- `-L`: adds `redirects`, one entry per hop with its own timings, and `timing.chain_total_us`.

## Recipes

```bash
# Latency distribution over 20 fresh connections
httpstat --json -n 20 https://example.com/

# Warm latency on one reused connection (-c 4 keeps 4 requests in flight on HTTP/2 or HTTP/3)
httpstat --json -n 20 -K https://example.com/

# Certificate: who issued it, for which names, until when.
# not_after is local time; not_after_unix is the one to do arithmetic on
httpstat --json https://example.com/ | jq .tls

# A certificate that fails verification is exit 4 with no tls block. -k shows what was presented
httpstat --json -k https://expired.badssl.com/ | jq .tls

# HTTP/3: --http3 forces QUIC with no fallback, so a server without it is exit 5.
# Look for h3 in alt_svc on a normal request first, and keep the probe short
httpstat --json --timeout 5s --http3 https://example.com/

# Compare the IPs behind one hostname; add -n 20 for a distribution per IP
httpstat --json --resolve 1.1.1.1,1.0.0.1 https://one.one.one.one/

# Reach a specific backend or a staging host; SNI and Host stay as in the URL
httpstat --json --connect-to example.com:443:10.0.0.5:8443 https://example.com/

# Pick the resolver: an IP, a preset (cloudflare, google, quad9, or with -doh / -dot), or a DoH / DoT address
httpstat --json --dns-servers cloudflare-doh https://example.com/

# Through a proxy (http://, https:// or socks5://)
httpstat --json --proxy http://proxy.corp:8080 https://example.com/

# POST a body from a file
httpstat --json -X POST -H 'Content-Type: application/json' -d @body.json https://example.com/api

# Follow redirects and time every hop
httpstat --json -L http://example.com/

# gRPC health check, whole server or one service
httpstat --json grpc://localhost:50051
httpstat --json 'grpc://localhost:50051/?service=my.pkg.Service'
```

## When something is missing

- Every flag: `httpstat --help`. Every JSON field, including `tcp_info`, `quic_info` and `throughput`: <https://github.com/vicanso/http-stat-rs/blob/main/JSON_SCHEMA.md>.
- Not installed: ask before installing. `cargo install http-stat`, or `curl -fsSL https://raw.githubusercontent.com/vicanso/http-stat-rs/main/install.sh | sh`.
- This page describes 0.9.0; check `httpstat --version`. An older version ignores a DoH / DoT address and `-n` with `--resolve` without any error, loses the phase timings when `--max-time` fires, and has no `failed` / `exit_code` / `errors` in the `-n` summary.
