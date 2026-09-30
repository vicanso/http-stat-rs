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

//! Kernel TCP statistics snapshot.
//!
//! Wraps platform `getsockopt(TCP_INFO)` / `getsockopt(TCP_CONNECTION_INFO)`
//! behind a portable [`TcpInfo`] struct. A baseline sample taken right after
//! `connect(2)` plus a final sample taken after the response body has been
//! fully received together reveal whether "Content Transfer slow" came from
//! packet loss / cwnd movement, rather than the application layer.
//!
//! Supported targets: Linux (`tcp_info`), macOS (`tcp_connection_info`), and
//! Windows (`SIO_TCP_INFO` / `TCP_INFO_v0`). Everything else returns `None`
//! from sampling — the call sites stay cross-platform via [`TcpInfoProbe`].

use std::time::Duration;
use tokio::net::TcpStream;

/// Portable subset of `getsockopt(TCP_INFO)` exposed in the user-facing API.
///
/// Anything unmeasurable on the current OS / libc binding stays `None`. The
/// diff between a baseline and a final sample is more informative than any
/// single value: it isolates retransmits and cwnd movement caused by *this*
/// request.
#[derive(Default, Debug, Clone)]
pub struct TcpInfo {
    /// Smoothed round-trip time estimate.
    pub rtt: Option<Duration>,
    /// RTT variance.
    pub rttvar: Option<Duration>,
    /// Cumulative retransmission counter observed on this connection.
    /// Linux: locally-emitted retransmits (`tcpi_total_retrans`), in segments.
    /// macOS: inbound segments seen as retransmits (`tcpi_rxretransmitpackets`).
    /// Windows: `BytesRetrans` from `TCP_INFO_v0` — bytes, not segments.
    /// Different perspectives, all surface "this connection had loss".
    pub retransmits: Option<u32>,
    /// Congestion window in segments.
    pub cwnd: Option<u32>,
    /// Sender-side MSS in bytes.
    pub snd_mss: Option<u32>,
}

/// Captured socket handle that allows a TCP_INFO sample to be taken later,
/// after the original [`TcpStream`] has been moved into the HTTP stack.
///
/// On Unix this holds a `dup(2)`'d file descriptor pointing at the same
/// kernel socket — counters are shared. On Windows it holds a
/// `DuplicateHandle` of the SOCKET. Dropping the probe closes only the
/// duplicate; the original socket lifetime is unchanged. On other targets
/// this is a zero-sized placeholder and `sample()` always returns `None`.
#[cfg(unix)]
pub struct TcpInfoProbe(std::os::unix::io::OwnedFd);
#[cfg(windows)]
pub struct TcpInfoProbe(std::os::windows::io::OwnedSocket);
#[cfg(not(any(unix, windows)))]
pub struct TcpInfoProbe;

impl TcpInfoProbe {
    /// Take an immediate sample on the original stream (no `dup` needed), and
    /// return a probe that can be sampled again later.
    pub fn capture(stream: &TcpStream) -> (Option<TcpInfo>, Option<Self>) {
        #[cfg(unix)]
        {
            use std::os::unix::io::AsRawFd;
            let raw = stream.as_raw_fd();
            let now = sample_fd(raw);
            // SAFETY: dup returns a fresh FD; FromRawFd takes ownership.
            let dup_fd = unsafe { libc::dup(raw) };
            let probe = if dup_fd >= 0 {
                use std::os::unix::io::FromRawFd;
                Some(TcpInfoProbe(unsafe {
                    std::os::unix::io::OwnedFd::from_raw_fd(dup_fd)
                }))
            } else {
                None
            };
            (now, probe)
        }
        #[cfg(windows)]
        {
            use std::os::windows::io::AsRawSocket;
            let raw = stream.as_raw_socket();
            let now = sample_socket(raw);
            let probe = duplicate_socket(raw).map(TcpInfoProbe);
            (now, probe)
        }
        #[cfg(not(any(unix, windows)))]
        {
            let _ = stream;
            (None, None)
        }
    }

    /// Sample the kernel TCP statistics for the held socket.
    #[allow(clippy::unused_self)]
    pub fn sample(&self) -> Option<TcpInfo> {
        #[cfg(unix)]
        {
            use std::os::unix::io::AsRawFd;
            sample_fd(self.0.as_raw_fd())
        }
        #[cfg(windows)]
        {
            use std::os::windows::io::AsRawSocket;
            sample_socket(self.0.as_raw_socket())
        }
        #[cfg(not(any(unix, windows)))]
        {
            None
        }
    }
}

#[cfg(target_os = "linux")]
fn sample_fd(fd: std::os::unix::io::RawFd) -> Option<TcpInfo> {
    // SAFETY: getsockopt fills a tcp_info buffer; we only read scalar fields.
    unsafe {
        let mut info: libc::tcp_info = std::mem::zeroed();
        let mut len = std::mem::size_of::<libc::tcp_info>() as libc::socklen_t;
        let r = libc::getsockopt(
            fd,
            libc::IPPROTO_TCP,
            libc::TCP_INFO,
            &mut info as *mut _ as *mut libc::c_void,
            &mut len,
        );
        if r != 0 {
            return None;
        }
        Some(TcpInfo {
            // tcpi_rtt / tcpi_rttvar are in microseconds on Linux.
            rtt: Some(Duration::from_micros(info.tcpi_rtt as u64)),
            rttvar: Some(Duration::from_micros(info.tcpi_rttvar as u64)),
            retransmits: Some(info.tcpi_total_retrans),
            cwnd: Some(info.tcpi_snd_cwnd),
            snd_mss: Some(info.tcpi_snd_mss),
        })
    }
}

#[cfg(target_os = "macos")]
fn sample_fd(fd: std::os::unix::io::RawFd) -> Option<TcpInfo> {
    // SAFETY: macOS exposes TCP statistics via TCP_CONNECTION_INFO with a
    // tcp_connection_info struct. Layout matches XNU's <netinet/tcp.h>.
    unsafe {
        let mut info: libc::tcp_connection_info = std::mem::zeroed();
        let mut len = std::mem::size_of::<libc::tcp_connection_info>() as libc::socklen_t;
        let r = libc::getsockopt(
            fd,
            libc::IPPROTO_TCP,
            libc::TCP_CONNECTION_INFO,
            &mut info as *mut _ as *mut libc::c_void,
            &mut len,
        );
        if r != 0 {
            return None;
        }
        Some(TcpInfo {
            // tcpi_srtt / tcpi_rttvar are in *milliseconds* on macOS, while
            // tcpi_rttcur is the latest single sample. Use srtt to match
            // Linux's "smoothed estimate" semantics.
            rtt: Some(Duration::from_millis(info.tcpi_srtt as u64)),
            rttvar: Some(Duration::from_millis(info.tcpi_rttvar as u64)),
            retransmits: Some(info.tcpi_rxretransmitpackets as u32),
            cwnd: Some(info.tcpi_snd_cwnd),
            snd_mss: Some(info.tcpi_maxseg),
        })
    }
}

#[cfg(all(unix, not(any(target_os = "linux", target_os = "macos"))))]
fn sample_fd(_fd: std::os::unix::io::RawFd) -> Option<TcpInfo> {
    None
}

/// `SIO_TCP_INFO` (Windows Vista+). Input is a `ULONG` version; version 0
/// fills `TCP_INFO_v0`.
#[cfg(windows)]
const SIO_TCP_INFO: u32 = 0xD8000027;
#[cfg(windows)]
const DUPLICATE_SAME_ACCESS: u32 = 2;

/// Layout of `TCP_INFO_v0` from `<mstcpip.h>`.
/// `BytesRetrans` counts bytes, not segments. Unused fields stay so the
/// ioctl output lines up; only RTT, cwnd, MSS, and BytesRetrans are read.
#[cfg(windows)]
#[allow(dead_code)]
#[repr(C)]
struct TcpInfoV0 {
    state: u32,
    mss: u32,
    connection_time_ms: u64,
    timestamps_enabled: u8,
    _pad: [u8; 3],
    rtt_us: u32,
    min_rtt_us: u32,
    bytes_in_flight: u32,
    cwnd: u32,
    snd_wnd: u32,
    rcv_wnd: u32,
    rcv_buf: u32,
    bytes_out: u64,
    bytes_in: u64,
    bytes_retrans: u32,
    fast_retrans: u32,
    dup_acks_in: u32,
    timeout_episodes: u32,
    syn_retrans: u8,
}

#[cfg(windows)]
#[link(name = "ws2_32")]
extern "system" {
    fn WSAIoctl(
        s: usize,
        dw_io_control_code: u32,
        lpv_in_buffer: *const std::ffi::c_void,
        cb_in_buffer: u32,
        lpv_out_buffer: *mut std::ffi::c_void,
        cb_out_buffer: u32,
        lpcb_bytes_returned: *mut u32,
        lp_overlapped: *mut std::ffi::c_void,
        lp_completion_routine: *mut std::ffi::c_void,
    ) -> i32;
}

#[cfg(windows)]
#[link(name = "kernel32")]
extern "system" {
    fn GetCurrentProcess() -> *mut std::ffi::c_void;
    fn DuplicateHandle(
        source_process: *mut std::ffi::c_void,
        source: *mut std::ffi::c_void,
        target_process: *mut std::ffi::c_void,
        target: *mut *mut std::ffi::c_void,
        desired_access: u32,
        inherit: i32,
        options: u32,
    ) -> i32;
}

#[cfg(windows)]
fn socket_ptr(raw: std::os::windows::io::RawSocket) -> *mut std::ffi::c_void {
    // `RawSocket` is `u32` or `u64` (pointer-sized SOCKET), not `usize`.
    raw as usize as *mut std::ffi::c_void
}

#[cfg(windows)]
fn sample_socket(raw: std::os::windows::io::RawSocket) -> Option<TcpInfo> {
    // SAFETY: WSAIoctl writes a TCP_INFO_v0 into `info`. We only read scalars.
    unsafe {
        let version: u32 = 0;
        let mut info: TcpInfoV0 = std::mem::zeroed();
        let mut returned: u32 = 0;
        let r = WSAIoctl(
            raw as usize,
            SIO_TCP_INFO,
            &version as *const u32 as *const std::ffi::c_void,
            std::mem::size_of::<u32>() as u32,
            &mut info as *mut TcpInfoV0 as *mut std::ffi::c_void,
            std::mem::size_of::<TcpInfoV0>() as u32,
            &mut returned,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
        );
        if r != 0 {
            return None;
        }
        Some(TcpInfo {
            rtt: Some(Duration::from_micros(info.rtt_us as u64)),
            rttvar: None,
            // BytesRetrans is a byte count, not a segment count.
            retransmits: Some(info.bytes_retrans),
            cwnd: Some(info.cwnd),
            snd_mss: Some(info.mss),
        })
    }
}

#[cfg(windows)]
fn duplicate_socket(
    raw: std::os::windows::io::RawSocket,
) -> Option<std::os::windows::io::OwnedSocket> {
    use std::os::windows::io::FromRawSocket;
    // SAFETY: DuplicateHandle yields a new SOCKET we own via OwnedSocket.
    unsafe {
        let process = GetCurrentProcess();
        let mut duplicated: *mut std::ffi::c_void = std::ptr::null_mut();
        let ok = DuplicateHandle(
            process,
            socket_ptr(raw),
            process,
            &mut duplicated,
            0,
            0,
            DUPLICATE_SAME_ACCESS,
        );
        if ok == 0 || duplicated.is_null() {
            return None;
        }
        Some(std::os::windows::io::OwnedSocket::from_raw_socket(
            duplicated as usize as std::os::windows::io::RawSocket,
        ))
    }
}

/// Delta between two TCP_INFO samples — most useful: how many retransmits
/// occurred *during* the request, plus the final RTT / cwnd seen by the kernel.
#[derive(Default, Debug, Clone)]
pub struct TcpInfoDelta {
    pub retransmits_during: Option<u32>,
    pub rtt_final: Option<Duration>,
    pub cwnd_final: Option<u32>,
}

impl TcpInfoDelta {
    pub fn compute(post_connect: Option<&TcpInfo>, final_: Option<&TcpInfo>) -> Option<Self> {
        let f = final_?;
        let retransmits_during = match (post_connect.and_then(|p| p.retransmits), f.retransmits) {
            (Some(start), Some(end)) => Some(end.saturating_sub(start)),
            _ => None,
        };
        Some(Self {
            retransmits_during,
            rtt_final: f.rtt,
            cwnd_final: f.cwnd,
        })
    }
}
