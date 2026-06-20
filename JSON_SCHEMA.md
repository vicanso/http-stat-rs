# `httpstat --json` Output Schema

Stable contract for the JSON document emitted by `httpstat --json <url>`.
Use this to wire `httpstat` into CI checks, dashboards, alerting, or any
other system that consumes machine-readable measurements.

The shape described here is **the stable surface** — fields may be added
in future versions, but existing fields will not be renamed or change
semantics within the `0.x` series unless explicitly noted in the
release notes. JSON output is always English; the `--lang` flag affects
the terminal renderer only.

## Conventions

| Convention | Notes |
| --- | --- |
| Durations | All time fields end in `_us` and are integer microseconds. Divide by 1000 for ms, 1_000_000 for seconds. |
| Throughput | Fields prefixed `bps_` are bytes per second, floating point. |
| Sizes | Byte counts (`wire_body_size`, `body_size`) are integers in bytes. |
| Optional fields | Any field may be `null` when the value was not measured (e.g. `tls_handshake_us` is `null` for plain HTTP). |
| Optional blocks | Whole objects (`tcp_info`, `tls`, `throughput`, `hsts`, etc.) are omitted entirely from the output when not applicable. |
| Case | All field names are lower `snake_case`. |
| Encoding | UTF-8. Output is always a single root JSON object terminated by a newline. |

## Top-level object

```jsonc
{
  "timing":        { /* always present */ },
  "throughput":    { /* present if body was received with measurable transfer */ },
  "tcp_info":      { /* present on Linux/macOS when at least one sample was taken */ },
  "server_timing": [ /* present if the server sent any Server-Timing entries */ ],
  "alt_svc":       [ /* present if the server sent any Alt-Svc entries */ ],
  "hsts":          { /* present if the server sent Strict-Transport-Security */ },
  "addr":          "host:port | null",
  "status":        200,
  "alpn":          "h2 | http/1.1 | h3 | null",
  "tls":           { /* present whenever the connection used TLS */ },
  "headers":       { /* response headers as a flat string->string map */ },
  "body_size":     12345,
  "error":         "string | null",
  "exit_code":     0
}
```

## `timing` (always present)

All units microseconds. `null` means the phase did not run (e.g. no TLS,
or the request failed before reaching that phase).

| Field | Meaning |
| --- | --- |
| `dns_lookup_us` | Total DNS resolution wall-time. |
| `dns_connect_us` | Cold TCP+TLS connect to the DoH/DoT server. Only populated when `--dns-servers=cloudflare-doh` (or similar) is used. |
| `dns_query_us` | Derived: `dns_lookup_us - dns_connect_us`. Only populated when `dns_connect_us` is populated. |
| `tcp_connect_us` | Time for the TCP three-way handshake. `null` for HTTP/3. |
| `tls_handshake_us` | TLS handshake duration. `null` for plain HTTP and for HTTP/3 (folded into `quic_connect_us`). |
| `quic_connect_us` | Full QUIC connection establishment for HTTP/3 (includes the embedded TLS 1.3 handshake). |
| `request_send_us` | Time from "send request" to "request fully written on wire". |
| `server_processing_us` | Time from request fully sent to first response byte received (server-side TTFB). |
| `content_transfer_us` | Time from first response byte to last response byte. |
| `time_to_first_100k_us` | Time from start of `content_transfer` until the first 100 KiB of body has arrived. Only populated for bodies larger than the threshold. Diagnostic for "slow start vs steady state". |
| `total_us` | End-to-end wall-time from request start to response fully consumed. |

## `throughput` (present when a body was received)

Numerator is **wire bytes** (pre-decompression). Use these for true
network throughput, not decoded-byte throughput.

| Field | Type | Meaning |
| --- | --- | --- |
| `wire_body_size` | integer | Bytes received over the wire, before any `gzip`/`brotli`/`zstd` decoding. |
| `bps_total` | float | Steady-state throughput across the full `content_transfer` window. |
| `bps_first_100k` | float \| null | Throughput over the first 100 KiB. Slow-start dominated. |
| `bps_tail` | float \| null | Throughput over the remainder after 100 KiB. Steady-state. |

## `tcp_info` (Linux + macOS only)

Populated whenever `getsockopt(TCP_INFO)` succeeded against the socket.
Renders the kernel's view of the connection at two points and the diff.

```jsonc
{
  "post_connect": { /* TcpInfoSample, sampled right after connect(2) */ },
  "final":        { /* TcpInfoSample, sampled after body fully received */ },
  "delta":        { "retransmits_during": 0, "rtt_final_us": 18034, "cwnd_final": 42 }
}
```

A `TcpInfoSample` has:

| Field | Type | Meaning |
| --- | --- | --- |
| `rtt_us` | integer \| null | Smoothed RTT, microseconds. |
| `rttvar_us` | integer \| null | RTT variance, microseconds. |
| `retransmits` | integer \| null | Cumulative retransmit count for the connection. |
| `cwnd` | integer \| null | Current congestion window in segments. |
| `snd_mss` | integer \| null | Outbound MSS. |

The `delta.retransmits_during` field is the diagnostic gold - it isolates
packet loss to **this request's transfer window**, not the connection
lifetime.

## `server_timing` (array, RFC 8673)

Present only when the server sent at least one `Server-Timing` header.

```jsonc
[
  { "name": "cfEdge",   "duration_us": 9000,   "description": null },
  { "name": "cfOrigin", "duration_us": 0,      "description": null },
  { "name": "cfWorker", "duration_us": 372000, "description": "render-fragment" }
]
```

| Field | Type | Meaning |
| --- | --- | --- |
| `name` | string | Server-provided metric name. |
| `duration_us` | integer \| null | The `dur=` value, converted to microseconds. `null` when the entry has no `dur`. |
| `description` | string \| null | The `desc=` value, with surrounding quotes stripped. |

## `alt_svc` (array, RFC 7838)

Present when the server advertised alternative services. The special
`Alt-Svc: clear` value resets accumulation during parsing - it never
appears in output.

```jsonc
[
  { "protocol": "h3", "authority": ":443", "max_age_seconds": 86400 }
]
```

| Field | Type | Meaning |
| --- | --- | --- |
| `protocol` | string | ALPN-style identifier (`h3`, `h2`, ...). |
| `authority` | string | Authority part (`":443"`, `"alt.example.com:8443"`, ...). |
| `max_age_seconds` | integer \| null | The `ma=` value if present. |

## `hsts` (RFC 6797)

Present when the server sent a `Strict-Transport-Security` header with a
parseable `max-age`.

| Field | Type | Meaning |
| --- | --- | --- |
| `max_age_seconds` | integer | The `max-age=` value (required for the header to be considered valid). |
| `include_subdomains` | boolean | Whether the `includeSubDomains` directive was present. |
| `preload` | boolean | Whether the `preload` directive was present. |

## `tls` (present whenever the connection used TLS)

| Field | Type | Meaning |
| --- | --- | --- |
| `version` | string \| null | Negotiated TLS version (`"tls v1.2"`, `"tls v1.3"`). |
| `cipher` | string \| null | Negotiated cipher suite. |
| `resumed` | boolean \| null | `true` when the session was resumed (PSK / session ticket). `null` when the protocol does not surface this state. |
| `early_data_accepted` | boolean \| null | `true` when the server accepted 0-RTT early data. `null` when no early data was offered. |
| `ocsp_stapled` | boolean \| null | `true` when the server returned an OCSP response in the handshake. |
| `subject` | string \| null | Subject of the leaf certificate. |
| `issuer` | string \| null | Issuer of the leaf certificate. |
| `not_before` | string \| null | Leaf cert validity start (local time zone). |
| `not_after` | string \| null | Leaf cert validity end. |
| `domains` | array of strings \| null | Subject Alternative Names. |

## Top-level scalars

| Field | Type | Meaning |
| --- | --- | --- |
| `addr` | string \| null | Resolved `ip:port` (or `[ipv6]:port`). `null` if DNS failed. |
| `status` | integer \| null | HTTP status code, or `null` if no response. |
| `alpn` | string \| null | ALPN-selected protocol (`"h2"`, `"http/1.1"`, `"h3"`). |
| `headers` | object \| null | Response headers as a flat `{string: string}` map. Multi-value headers are joined per `http::HeaderMap` semantics. |
| `body_size` | integer \| null | Decoded body size in bytes (after `gzip`/`brotli`/`zstd`). |
| `error` | string \| null | Human-readable error string when the request failed. |
| `exit_code` | integer | Process exit code (see table below). Always present. |

## Exit codes

The `exit_code` field mirrors the value the process exits with. The
table below is the **canonical taxonomy** - downstream consumers can
classify failures without parsing the `error` string.

| Code | Meaning | When |
| --- | --- | --- |
| `0` | Success | HTTP 1xx/2xx/3xx (>= 400 is treated as failure). |
| `1` | Generic error | Unclassified failure. |
| `2` | DNS failure | `dns_lookup` phase never completed. |
| `3` | TCP/QUIC failure | Connect phase never completed. |
| `4` | TLS failure | Handshake / cert / SNI error. |
| `5` | Timeout | A per-phase timeout or the overall `--max-time` deadline was exceeded. |
| `6` | HTTP 4xx | Successful transport, client-error status. |
| `7` | HTTP 5xx | Successful transport, server-error status. |

## Sample: HTTP/2 success

```json
{
  "timing": {
    "dns_lookup_us": 950,
    "dns_connect_us": null,
    "dns_query_us": null,
    "tcp_connect_us": 332,
    "tls_handshake_us": 951000,
    "quic_connect_us": null,
    "request_send_us": 71,
    "server_processing_us": 712000,
    "content_transfer_us": 1260000,
    "time_to_first_100k_us": 18000,
    "total_us": 2930000
  },
  "throughput": {
    "wire_body_size": 1258291,
    "bps_total": 998644.4,
    "bps_first_100k": 5688888.9,
    "bps_tail": 935912.1
  },
  "server_timing": [
    { "name": "cfEdge",   "duration_us": 6000,   "description": null },
    { "name": "cfOrigin", "duration_us": 0,      "description": null },
    { "name": "cfWorker", "duration_us": 177000, "description": null }
  ],
  "alt_svc": [
    { "protocol": "h3", "authority": ":443", "max_age_seconds": 86400 }
  ],
  "hsts": {
    "max_age_seconds": 31536000,
    "include_subdomains": true,
    "preload": false
  },
  "addr": "[::ffff:198.18.1.163]:443",
  "status": 200,
  "alpn": "h2",
  "tls": {
    "version": "tls v1.3",
    "cipher": "AES_256_GCM_SHA384",
    "resumed": false,
    "early_data_accepted": null,
    "ocsp_stapled": true,
    "subject": "CN=www.cloudflare.com",
    "issuer": "CN=Cloudflare Inc ECC CA-3",
    "not_before": "2026-05-08 00:54:23 +08:00",
    "not_after": "2026-08-06 01:54:15 +08:00",
    "domains": ["www.cloudflare.com", "cloudflare.com"]
  },
  "headers": {
    "content-type": "text/html; charset=utf-8",
    "server": "cloudflare"
  },
  "body_size": 1258291,
  "error": null,
  "exit_code": 0
}
```

## Sample: DNS failure

```json
{
  "timing": {
    "dns_lookup_us": null,
    "dns_connect_us": null,
    "dns_query_us": null,
    "tcp_connect_us": null,
    "tls_handshake_us": null,
    "quic_connect_us": null,
    "request_send_us": null,
    "server_processing_us": null,
    "content_transfer_us": null,
    "time_to_first_100k_us": null,
    "total_us": 5023000
  },
  "addr": null,
  "status": null,
  "alpn": null,
  "body_size": null,
  "error": "resolve error proto error: no record found",
  "exit_code": 2
}
```

## Recipes

### CI gate: fail if TTFB exceeds 500 ms

```bash
httpstat --json "$URL" \
  | jq -e '.timing.server_processing_us < 500000'
```

### Alert on packet loss

```bash
httpstat --json "$URL" \
  | jq -e '(.tcp_info.delta.retransmits_during // 0) == 0'
```

### Extract a single phase

```bash
httpstat --json "$URL" | jq -r '.timing.tls_handshake_us / 1000 | "tls: \(.)ms"'
```

### Diff two runs

```bash
diff <(httpstat --json "$URL_A" | jq .timing) \
     <(httpstat --json "$URL_B" | jq .timing)
```

## Stability

- Within `0.x`: new fields may be added; existing fields will not be
  renamed or change semantics. New optional blocks may appear at the
  top level.
- A field may transition from "always emitted as `null`" to "populated"
  if measurement support is added on more platforms (for example,
  `tcp_info` on Windows).
- Breaking changes are reserved for `1.0` and will be called out
  explicitly in release notes.

If a field you depend on is missing in a future release, file an issue -
that is a regression, not an intended change.
