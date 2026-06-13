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

//! Tiny i18n layer for the terminal renderer.
//!
//! Two locales are wired up — English (default, fallback) and Simplified
//! Chinese. The CLI flag `--lang` overrides; otherwise we sniff the standard
//! POSIX locale environment variables. JSON output stays in English keys —
//! the contract for machine consumers must not move with the user's locale.

use std::env;

/// Supported display languages.
#[derive(Default, Debug, Clone, Copy, PartialEq, Eq)]
pub enum Lang {
    #[default]
    En,
    Zh,
}

impl Lang {
    /// Detect the locale from `LC_ALL`, then `LC_MESSAGES`, then `LANG`.
    /// A value starting with `zh` (case-insensitive, e.g. `zh_CN.UTF-8`,
    /// `zh-Hans`, `zh_TW`) maps to [`Lang::Zh`]. Everything else falls back
    /// to English.
    pub fn detect() -> Self {
        for key in ["LC_ALL", "LC_MESSAGES", "LANG"] {
            if let Ok(v) = env::var(key) {
                let v = v.trim().to_ascii_lowercase();
                if v.starts_with("zh") {
                    return Lang::Zh;
                }
                if !v.is_empty() {
                    return Lang::En;
                }
            }
        }
        Lang::En
    }

    /// Parse the value passed via `--lang`. Accepts `en`, `english`, `zh`,
    /// `zh-cn`, `zh_cn`, `cn`, `chinese` (case-insensitive). Unknown values
    /// fall back to [`Lang::En`] — the user's intent is "show me something",
    /// not "abort because of a typo".
    pub fn parse_arg(s: &str) -> Self {
        let s = s.trim().to_ascii_lowercase();
        if s.starts_with("zh") || s == "cn" || s == "chinese" {
            Lang::Zh
        } else {
            Lang::En
        }
    }

    /// Return the static label table for this language.
    pub fn strings(self) -> &'static Strings {
        match self {
            Lang::En => &EN,
            Lang::Zh => &ZH,
        }
    }
}

/// All translatable labels. Each field is a single `&'static str`; nothing
/// here uses `format!` arguments, so adding a new locale is mechanical.
///
/// Technical jargon that has no good Chinese equivalent (`cwnd`, `MSS`,
/// `0-RTT`, `OCSP`, ALPN strings like `H2`/`HTTP/1.1`, status codes,
/// duration formatting) intentionally stays in the original form.
#[derive(Debug)]
pub struct Strings {
    // Connection line
    pub connected_to: &'static str,
    pub resolved_to: &'static str,
    pub error_label: &'static str,
    pub fail: &'static str,
    pub grpc_ok: &'static str,

    // Phases (timeline columns + waterfall rows)
    pub dns_lookup: &'static str,
    pub dns_connect: &'static str,
    pub dns_query: &'static str,
    pub tcp_connect: &'static str,
    pub tls_handshake: &'static str,
    pub quic_connect: &'static str,
    pub request_send: &'static str,
    pub server_processing: &'static str,
    pub server_processing_short: &'static str,
    pub content_transfer: &'static str,
    pub content_transfer_short: &'static str,
    pub total: &'static str,

    // TLS block
    pub tls_label: &'static str,
    pub cipher: &'static str,
    pub handshake: &'static str,
    pub handshake_full: &'static str,
    pub handshake_resumed: &'static str,
    pub early_data: &'static str,
    pub early_data_accepted: &'static str,
    pub early_data_not_accepted: &'static str,
    pub ocsp: &'static str,
    pub ocsp_stapled: &'static str,
    pub ocsp_not_stapled: &'static str,
    pub not_before: &'static str,
    pub not_after: &'static str,
    pub subject: &'static str,
    pub issuer: &'static str,
    pub cert_domains: &'static str,
    pub cert_chain: &'static str,

    // Server-Timing summary line
    pub server_timing_heading: &'static str,
    pub st_sum_of: &'static str,
    pub st_unaccounted: &'static str,

    // Protocol advertisements (Alt-Svc / HSTS)
    pub protocol_adv_heading: &'static str,
    pub alt_svc_label: &'static str,
    pub hsts_label: &'static str,

    // Kernel TCP block
    pub kernel_tcp_heading: &'static str,
    pub tcp_post_connect_row: &'static str,
    pub tcp_final_row: &'static str,
    pub tcp_during: &'static str,
    pub tcp_retransmit_word: &'static str,

    // Body & throughput
    pub body_size: &'static str,
    pub body_discarded: &'static str,
    pub saved_to: &'static str,
    pub throughput: &'static str,
    pub throughput_first_100k: &'static str,
    pub throughput_then: &'static str,

    // Benchmark summary
    pub benchmark_results_prefix: &'static str,
    pub benchmark_results_requests: &'static str,
    pub success: &'static str,
    pub cold_connect: &'static str,
    pub min: &'static str,
    pub max: &'static str,
    pub avg: &'static str,
}

pub const EN: Strings = Strings {
    connected_to: "Connected to",
    resolved_to: "Resolved to",
    error_label: "Error",
    fail: "FAIL",
    grpc_ok: "GRPC OK",

    dns_lookup: "DNS Lookup",
    dns_connect: "DNS Connect",
    dns_query: "DNS Query",
    tcp_connect: "TCP Connect",
    tls_handshake: "TLS Handshake",
    quic_connect: "QUIC Connect",
    request_send: "Request Send",
    server_processing: "Server Processing",
    server_processing_short: "Server Process",
    content_transfer: "Content Transfer",
    content_transfer_short: "Content Xfer",
    total: "Total",

    tls_label: "Tls",
    cipher: "Cipher",
    handshake: "Handshake",
    handshake_full: "Full",
    handshake_resumed: "Resumed",
    early_data: "Early Data",
    early_data_accepted: "accepted (0-RTT)",
    early_data_not_accepted: "not accepted",
    ocsp: "OCSP",
    ocsp_stapled: "stapled",
    ocsp_not_stapled: "not stapled",
    not_before: "Not Before",
    not_after: "Not After",
    subject: "Subject",
    issuer: "Issuer",
    cert_domains: "Certificate Domains",
    cert_chain: "Certificate Chain",

    server_timing_heading: "Server-Timing:",
    st_sum_of: "of",
    st_unaccounted: "unaccounted",

    protocol_adv_heading: "Server Advertisements:",
    alt_svc_label: "Alt-Svc:",
    hsts_label: "HSTS:   ",

    kernel_tcp_heading: "Kernel TCP:",
    tcp_post_connect_row: "post-connect:",
    tcp_final_row: "final:",
    tcp_during: "during request:",
    tcp_retransmit_word: "retransmit(s)",

    body_size: "Body size",
    body_discarded: "Body discarded",
    saved_to: "saved to",
    throughput: "Throughput:",
    throughput_first_100k: "first 100KB:",
    throughput_then: "then:",

    benchmark_results_prefix: "--- Benchmark Results",
    benchmark_results_requests: "requests",
    success: "Success",
    cold_connect: "Cold connect",
    min: "min",
    max: "max",
    avg: "avg",
};

pub const ZH: Strings = Strings {
    connected_to: "已连接到",
    resolved_to: "已解析到",
    error_label: "错误",
    fail: "失败",
    grpc_ok: "gRPC 正常",

    dns_lookup: "DNS 解析",
    dns_connect: "DNS 连接",
    dns_query: "DNS 查询",
    tcp_connect: "TCP 连接",
    tls_handshake: "TLS 握手",
    quic_connect: "QUIC 连接",
    request_send: "请求发送",
    server_processing: "服务端处理",
    server_processing_short: "服务端处理",
    content_transfer: "内容传输",
    content_transfer_short: "内容传输",
    total: "总耗时",

    tls_label: "TLS",
    cipher: "加密套件",
    handshake: "握手",
    handshake_full: "完整",
    handshake_resumed: "复用",
    early_data: "早期数据",
    early_data_accepted: "已接受 (0-RTT)",
    early_data_not_accepted: "未接受",
    ocsp: "OCSP",
    ocsp_stapled: "已 staple",
    ocsp_not_stapled: "未 staple",
    not_before: "生效时间",
    not_after: "到期时间",
    subject: "主体",
    issuer: "颁发者",
    cert_domains: "证书域名",
    cert_chain: "证书链",

    server_timing_heading: "Server-Timing：",
    st_sum_of: "占",
    st_unaccounted: "未统计",

    protocol_adv_heading: "服务器声明：",
    alt_svc_label: "Alt-Svc：",
    hsts_label: "HSTS：   ",

    kernel_tcp_heading: "内核 TCP：",
    tcp_post_connect_row: "连接后：",
    tcp_final_row: "完成时：",
    tcp_during: "本次请求：",
    tcp_retransmit_word: "次重传",

    body_size: "响应体大小",
    body_discarded: "响应体已丢弃",
    saved_to: "已保存到",
    throughput: "吞吐：",
    throughput_first_100k: "首 100KB：",
    throughput_then: "之后：",

    benchmark_results_prefix: "--- 基准测试结果",
    benchmark_results_requests: "次请求",
    success: "成功",
    cold_connect: "冷连接",
    min: "最小",
    max: "最大",
    avg: "均值",
};
