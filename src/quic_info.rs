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

//! QUIC path statistics, the HTTP/3 counterpart of [`crate::tcp_info::TcpInfo`].
//!
//! Sampled from `quinn::Connection::stats()` once the handshake finishes and
//! again after the body is read. The delta isolates packet loss to this
//! request instead of the whole connection lifetime.

use std::time::Duration;

/// One snapshot of the QUIC path.
#[derive(Default, Debug, Clone)]
pub struct QuicInfo {
    pub rtt: Duration,
    pub cwnd: u64,
    pub lost_packets: u64,
    pub sent_packets: u64,
}

impl QuicInfo {
    pub fn from_conn(conn: &quinn::Connection) -> Self {
        let stats = conn.stats();
        Self {
            rtt: conn.rtt(),
            cwnd: stats.path.cwnd,
            lost_packets: stats.path.lost_packets,
            sent_packets: stats.path.sent_packets,
        }
    }
}

/// Loss and the final RTT between two QUIC snapshots.
#[derive(Default, Debug, Clone)]
pub struct QuicInfoDelta {
    pub lost_during: u64,
    pub rtt_final: Duration,
    pub cwnd_final: u64,
}

impl QuicInfoDelta {
    pub fn compute(post: Option<&QuicInfo>, final_: Option<&QuicInfo>) -> Option<Self> {
        let end = final_?;
        let start_lost = post.map(|p| p.lost_packets).unwrap_or(0);
        Some(Self {
            lost_during: end.lost_packets.saturating_sub(start_lost),
            rtt_final: end.rtt,
            cwnd_final: end.cwnd,
        })
    }
}
