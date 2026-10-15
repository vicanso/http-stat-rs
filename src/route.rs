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

//! Hop-by-hop trace of the address a request actually used.
//!
//! The probe runs after timings are recorded, and its RTTs stay out of
//! `tcp_connect`, `quic_connect`, and `total`. Linux reads ICMP Time
//! Exceeded via `IP_RECVERR` on an ordinary TCP or UDP socket. macOS sends
//! ICMP echo with a rising TTL on an unprivileged datagram socket. Other
//! platforms report [`ROUTE_UNAVAILABLE`] instead of inventing a path.

use std::fmt;
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::time::Duration;

/// Shown when this OS cannot read hop ICMP replies.
pub const ROUTE_UNAVAILABLE: &str = "route trace is unavailable on this operating system";

/// Shown when macOS refuses the unprivileged ICMP socket.
pub const ROUTE_MACOS_DENIED: &str =
    "route trace on macOS could not open an ICMP socket; re-run this command with sudo";

/// Shown when the request never produced an address to trace.
pub const ROUTE_NO_ADDR: &str = "route trace needs a connected or resolved address";

#[cfg(any(target_os = "linux", target_os = "macos"))]
const MAX_TTL: u8 = 30;
#[cfg(any(target_os = "linux", target_os = "macos"))]
const PROBE_TIMEOUT: Duration = Duration::from_secs(1);

#[cfg(any(test, target_os = "linux"))]
const ORIGIN_ICMP: u8 = 2;
#[cfg(any(test, target_os = "linux"))]
const ORIGIN_ICMP6: u8 = 3;
#[cfg(any(test, target_os = "linux"))]
const ICMP_DEST_UNREACH: u8 = 3;
#[cfg(any(test, target_os = "linux"))]
const ICMP_PORT_UNREACH: u8 = 3;
#[cfg(any(test, target_os = "linux"))]
const ICMP_TIME_EXCEEDED: u8 = 11;
#[cfg(any(test, target_os = "linux"))]
const ICMPV6_DEST_UNREACH: u8 = 1;
#[cfg(any(test, target_os = "linux"))]
const ICMPV6_TIME_EXCEED: u8 = 3;
#[cfg(any(test, target_os = "linux"))]
const ICMPV6_PORT_UNREACH: u8 = 4;

/// One router, or a hop that did not answer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RouteHop {
    pub ttl: u8,
    /// Router address. `None` when the hop timed out or the ICMP source was empty.
    pub addr: Option<String>,
    pub rtt: Option<Duration>,
    pub timeout: bool,
    /// This probe reached the destination host.
    pub reached: bool,
}

/// TCP for HTTP/1.1 and HTTP/2. UDP for HTTP/3, so the path matches QUIC.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RouteProto {
    Tcp,
    Udp,
}

#[derive(Debug)]
pub enum RouteError {
    Unavailable(&'static str),
    Probe(io::Error),
}

impl fmt::Display for RouteError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            RouteError::Unavailable(msg) => f.write_str(msg),
            RouteError::Probe(err) => write!(f, "route trace failed: {err}"),
        }
    }
}

impl std::error::Error for RouteError {}

#[cfg(any(test, target_os = "linux"))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum IcmpClass {
    TimeExceeded,
    Reached,
    Unreachable,
    Other,
}

/// Classify an ICMP error from `IP_RECVERR` / `IPV6_RECVERR`.
#[cfg(any(test, target_os = "linux"))]
fn classify_icmp(origin: u8, ty: u8, code: u8) -> IcmpClass {
    match origin {
        ORIGIN_ICMP => match (ty, code) {
            (ICMP_TIME_EXCEEDED, _) => IcmpClass::TimeExceeded,
            (ICMP_DEST_UNREACH, ICMP_PORT_UNREACH) => IcmpClass::Reached,
            (ICMP_DEST_UNREACH, _) => IcmpClass::Unreachable,
            _ => IcmpClass::Other,
        },
        ORIGIN_ICMP6 => match (ty, code) {
            (ICMPV6_TIME_EXCEED, _) => IcmpClass::TimeExceeded,
            (ICMPV6_DEST_UNREACH, ICMPV6_PORT_UNREACH) => IcmpClass::Reached,
            (ICMPV6_DEST_UNREACH, _) => IcmpClass::Unreachable,
            _ => IcmpClass::Other,
        },
        _ => IcmpClass::Other,
    }
}

/// Trace `dest` after the request has finished.
///
/// `bind` is the same local address as `--bind`, when it matches `dest`'s family.
pub async fn trace_route(
    dest: SocketAddr,
    bind: Option<IpAddr>,
    proto: RouteProto,
) -> Result<Vec<RouteHop>, RouteError> {
    #[cfg(target_os = "linux")]
    {
        tokio::task::spawn_blocking(move || linux::trace_blocking(dest, bind, proto))
            .await
            .unwrap_or_else(|err| Err(RouteError::Probe(io::Error::other(err.to_string()))))
    }
    #[cfg(target_os = "macos")]
    {
        tokio::task::spawn_blocking(move || macos::trace_blocking(dest, bind, proto))
            .await
            .unwrap_or_else(|err| Err(RouteError::Probe(io::Error::other(err.to_string()))))
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    {
        let _ = (dest, bind, proto);
        Err(RouteError::Unavailable(ROUTE_UNAVAILABLE))
    }
}

#[cfg(target_os = "linux")]
mod linux {
    use super::{
        classify_icmp, IcmpClass, RouteError, RouteHop, RouteProto, MAX_TTL, PROBE_TIMEOUT,
    };
    use std::io;
    use std::mem;
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
    use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
    use std::ptr;
    use std::time::{Duration, Instant};

    #[repr(C)]
    struct SockExtendedErr {
        ee_errno: u32,
        ee_origin: u8,
        ee_type: u8,
        ee_code: u8,
        ee_pad: u8,
        ee_info: u32,
        ee_data: u32,
    }

    struct IcmpReply {
        origin: u8,
        ty: u8,
        code: u8,
        from: Option<IpAddr>,
    }

    enum ProbeOut {
        Hop { addr: Option<IpAddr>, rtt: Duration },
        Reached { rtt: Duration },
        Unreachable { addr: Option<IpAddr>, rtt: Duration },
        Timeout,
        Fatal(io::Error),
    }

    pub(super) fn trace_blocking(
        dest: SocketAddr,
        bind: Option<IpAddr>,
        proto: RouteProto,
    ) -> Result<Vec<RouteHop>, RouteError> {
        let mut hops = Vec::new();
        for ttl in 1..=MAX_TTL {
            match probe_once(dest, bind, ttl, proto) {
                ProbeOut::Fatal(err) if hops.is_empty() => return Err(RouteError::Probe(err)),
                ProbeOut::Fatal(_) => break,
                ProbeOut::Timeout => hops.push(hop(ttl, None, None, true, false)),
                ProbeOut::Hop { addr, rtt } => hops.push(hop(ttl, addr, Some(rtt), false, false)),
                ProbeOut::Unreachable { addr, rtt } => {
                    hops.push(hop(ttl, addr, Some(rtt), false, false));
                    break;
                }
                ProbeOut::Reached { rtt } => {
                    hops.push(hop(ttl, Some(dest.ip()), Some(rtt), false, true));
                    break;
                }
            }
        }
        Ok(hops)
    }

    fn hop(
        ttl: u8,
        addr: Option<IpAddr>,
        rtt: Option<Duration>,
        timeout: bool,
        reached: bool,
    ) -> RouteHop {
        RouteHop {
            ttl,
            addr: addr.map(|ip| ip.to_string()),
            rtt,
            timeout,
            reached,
        }
    }

    fn probe_once(dest: SocketAddr, bind: Option<IpAddr>, ttl: u8, proto: RouteProto) -> ProbeOut {
        let fd = match open_socket(dest, bind, i32::from(ttl), proto) {
            Ok(fd) => fd,
            Err(err) => return ProbeOut::Fatal(err),
        };
        let start = Instant::now();
        if let Err(err) = kick(&fd, dest, proto) {
            return match err.raw_os_error() {
                Some(libc::ECONNREFUSED) | Some(libc::ECONNRESET) => ProbeOut::Reached {
                    rtt: start.elapsed(),
                },
                _ => {
                    if let Some(reply) = recv_icmp(fd.as_raw_fd()) {
                        map_icmp(reply, dest, start.elapsed())
                    } else {
                        ProbeOut::Fatal(err)
                    }
                }
            };
        }
        let deadline = start + PROBE_TIMEOUT;
        let mut spins = 0u8;
        loop {
            let left = deadline.saturating_duration_since(Instant::now());
            if left.is_zero() {
                return ProbeOut::Timeout;
            }
            let mut pfd = libc::pollfd {
                fd: fd.as_raw_fd(),
                events: libc::POLLIN | libc::POLLERR | libc::POLLOUT,
                revents: 0,
            };
            let ms = i32::try_from(left.as_millis()).unwrap_or(i32::MAX).max(1);
            let rc = unsafe { libc::poll(&mut pfd, 1, ms) };
            if rc < 0 {
                let err = io::Error::last_os_error();
                if err.kind() == io::ErrorKind::Interrupted {
                    continue;
                }
                return ProbeOut::Fatal(err);
            }
            if rc == 0 {
                return ProbeOut::Timeout;
            }
            if let Some(reply) = recv_icmp(fd.as_raw_fd()) {
                return map_icmp(reply, dest, start.elapsed());
            }
            if proto == RouteProto::Tcp {
                match so_error(fd.as_raw_fd()) {
                    Ok(0) | Ok(libc::ECONNREFUSED) | Ok(libc::ECONNRESET) => {
                        return ProbeOut::Reached {
                            rtt: start.elapsed(),
                        };
                    }
                    Ok(libc::EHOSTUNREACH) | Ok(libc::ENETUNREACH) => {
                        return ProbeOut::Unreachable {
                            addr: None,
                            rtt: start.elapsed(),
                        };
                    }
                    Ok(_) => {}
                    Err(err) => return ProbeOut::Fatal(err),
                }
            } else if pfd.revents & libc::POLLIN != 0 {
                if let Some(src) = recv_udp(fd.as_raw_fd()) {
                    if src == dest.ip() {
                        return ProbeOut::Reached {
                            rtt: start.elapsed(),
                        };
                    }
                }
            }
            spins = spins.saturating_add(1);
            if spins > 3 {
                std::thread::sleep(Duration::from_millis(10));
            }
        }
    }

    fn map_icmp(reply: IcmpReply, dest: SocketAddr, rtt: Duration) -> ProbeOut {
        match classify_icmp(reply.origin, reply.ty, reply.code) {
            IcmpClass::TimeExceeded => ProbeOut::Hop {
                addr: reply.from,
                rtt,
            },
            IcmpClass::Reached => ProbeOut::Reached { rtt },
            IcmpClass::Unreachable => ProbeOut::Unreachable {
                addr: reply.from,
                rtt,
            },
            IcmpClass::Other => {
                if reply.from == Some(dest.ip()) {
                    ProbeOut::Reached { rtt }
                } else {
                    ProbeOut::Hop {
                        addr: reply.from,
                        rtt,
                    }
                }
            }
        }
    }

    fn open_socket(
        dest: SocketAddr,
        bind: Option<IpAddr>,
        ttl: i32,
        proto: RouteProto,
    ) -> io::Result<OwnedFd> {
        let domain = if dest.is_ipv4() {
            libc::AF_INET
        } else {
            libc::AF_INET6
        };
        let (kind, ipproto) = match proto {
            RouteProto::Tcp => (libc::SOCK_STREAM, libc::IPPROTO_TCP),
            RouteProto::Udp => (libc::SOCK_DGRAM, libc::IPPROTO_UDP),
        };
        let raw = unsafe {
            libc::socket(
                domain,
                kind | libc::SOCK_NONBLOCK | libc::SOCK_CLOEXEC,
                ipproto,
            )
        };
        if raw < 0 {
            return Err(io::Error::last_os_error());
        }
        let fd = unsafe { OwnedFd::from_raw_fd(raw) };
        if dest.is_ipv4() {
            set_int(fd.as_raw_fd(), libc::IPPROTO_IP, libc::IP_TTL, ttl)?;
            set_int(fd.as_raw_fd(), libc::IPPROTO_IP, libc::IP_RECVERR, 1)?;
        } else {
            set_int(
                fd.as_raw_fd(),
                libc::IPPROTO_IPV6,
                libc::IPV6_UNICAST_HOPS,
                ttl,
            )?;
            set_int(fd.as_raw_fd(), libc::IPPROTO_IPV6, libc::IPV6_RECVERR, 1)?;
        }
        if let Some(ip) = bind {
            if ip.is_ipv4() == dest.is_ipv4() {
                let (storage, len) = socket_addr(SocketAddr::new(ip, 0));
                let rc = unsafe {
                    libc::bind(
                        fd.as_raw_fd(),
                        &storage as *const libc::sockaddr_storage as *const libc::sockaddr,
                        len,
                    )
                };
                if rc < 0 {
                    return Err(io::Error::last_os_error());
                }
            }
        }
        Ok(fd)
    }

    fn kick(fd: &OwnedFd, dest: SocketAddr, proto: RouteProto) -> io::Result<()> {
        let (storage, len) = socket_addr(dest);
        let rc = unsafe {
            libc::connect(
                fd.as_raw_fd(),
                &storage as *const libc::sockaddr_storage as *const libc::sockaddr,
                len,
            )
        };
        if rc < 0 {
            let err = io::Error::last_os_error();
            // Nonblocking connect reports EINPROGRESS. UDP connect is usually immediate.
            let pending = err.kind() == io::ErrorKind::WouldBlock
                || err.raw_os_error() == Some(libc::EINPROGRESS);
            if !pending {
                return Err(err);
            }
        }
        if proto == RouteProto::Udp {
            let byte = [0u8; 1];
            let n = unsafe { libc::send(fd.as_raw_fd(), byte.as_ptr().cast(), 1, 0) };
            if n < 0 {
                let err = io::Error::last_os_error();
                if err.kind() != io::ErrorKind::WouldBlock {
                    return Err(err);
                }
            }
        }
        Ok(())
    }

    fn set_int(fd: i32, level: i32, name: i32, value: i32) -> io::Result<()> {
        let rc = unsafe {
            libc::setsockopt(
                fd,
                level,
                name,
                &value as *const i32 as *const libc::c_void,
                mem::size_of::<i32>() as libc::socklen_t,
            )
        };
        if rc == 0 {
            Ok(())
        } else {
            Err(io::Error::last_os_error())
        }
    }

    fn so_error(fd: i32) -> io::Result<i32> {
        let mut err = 0i32;
        let mut len = mem::size_of::<i32>() as libc::socklen_t;
        let rc = unsafe {
            libc::getsockopt(
                fd,
                libc::SOL_SOCKET,
                libc::SO_ERROR,
                &mut err as *mut i32 as *mut libc::c_void,
                &mut len,
            )
        };
        if rc == 0 {
            Ok(err)
        } else {
            Err(io::Error::last_os_error())
        }
    }

    fn socket_addr(addr: SocketAddr) -> (libc::sockaddr_storage, libc::socklen_t) {
        let mut storage: libc::sockaddr_storage = unsafe { mem::zeroed() };
        let len = match addr {
            SocketAddr::V4(v4) => {
                let sa = unsafe {
                    &mut *(&mut storage as *mut libc::sockaddr_storage).cast::<libc::sockaddr_in>()
                };
                sa.sin_family = libc::AF_INET as libc::sa_family_t;
                sa.sin_port = v4.port().to_be();
                sa.sin_addr = libc::in_addr {
                    s_addr: u32::from(*v4.ip()).to_be(),
                };
                mem::size_of::<libc::sockaddr_in>() as libc::socklen_t
            }
            SocketAddr::V6(v6) => {
                let sa = unsafe {
                    &mut *(&mut storage as *mut libc::sockaddr_storage).cast::<libc::sockaddr_in6>()
                };
                sa.sin6_family = libc::AF_INET6 as libc::sa_family_t;
                sa.sin6_port = v6.port().to_be();
                sa.sin6_flowinfo = v6.flowinfo();
                sa.sin6_addr = libc::in6_addr {
                    s6_addr: v6.ip().octets(),
                };
                sa.sin6_scope_id = v6.scope_id();
                mem::size_of::<libc::sockaddr_in6>() as libc::socklen_t
            }
        };
        (storage, len)
    }

    fn recv_icmp(fd: i32) -> Option<IcmpReply> {
        let mut data = [0u8; 256];
        let mut name = [0u8; 128];
        let mut cbuf = [0u64; 32];
        let mut iov = libc::iovec {
            iov_base: data.as_mut_ptr().cast(),
            iov_len: data.len(),
        };
        let mut msg: libc::msghdr = unsafe { mem::zeroed() };
        msg.msg_name = name.as_mut_ptr().cast();
        msg.msg_namelen = name.len() as libc::socklen_t;
        msg.msg_iov = &mut iov;
        msg.msg_iovlen = 1;
        msg.msg_control = cbuf.as_mut_ptr().cast();
        // glibc uses `size_t`; musl uses `socklen_t`.
        msg.msg_controllen = mem::size_of_val(&cbuf) as _;
        let n = unsafe { libc::recvmsg(fd, &mut msg, libc::MSG_ERRQUEUE) };
        if n < 0 {
            return None;
        }
        let len = (msg.msg_controllen as usize).min(mem::size_of_val(&cbuf));
        let bytes = unsafe { std::slice::from_raw_parts(cbuf.as_ptr().cast::<u8>(), len) };
        parse_control(bytes)
    }

    fn recv_udp(fd: i32) -> Option<IpAddr> {
        let mut data = [0u8; 256];
        let mut name = [0u8; 128];
        let n = unsafe {
            libc::recvfrom(
                fd,
                data.as_mut_ptr().cast(),
                data.len(),
                0,
                name.as_mut_ptr().cast(),
                &mut (name.len() as libc::socklen_t),
            )
        };
        if n < 0 {
            return None;
        }
        parse_offender(&name)
    }

    fn align(n: usize) -> usize {
        let a = mem::align_of::<usize>();
        n.wrapping_add(a - 1) & !(a - 1)
    }

    fn parse_control(buf: &[u8]) -> Option<IcmpReply> {
        let hdr_size = mem::size_of::<libc::cmsghdr>();
        let mut off = 0usize;
        while off + hdr_size <= buf.len() {
            let hdr = unsafe { ptr::read_unaligned(buf.as_ptr().add(off).cast::<libc::cmsghdr>()) };
            // musl's `cmsg_len` is `socklen_t`, glibc's is `size_t`.
            let cmsg_len = hdr.cmsg_len as usize;
            if cmsg_len < hdr_size {
                break;
            }
            let data = off + align(hdr_size);
            let ee_end = data + mem::size_of::<SockExtendedErr>();
            let msg_end = off + cmsg_len;
            let is_err = (hdr.cmsg_level == libc::IPPROTO_IP && hdr.cmsg_type == libc::IP_RECVERR)
                || (hdr.cmsg_level == libc::IPPROTO_IPV6 && hdr.cmsg_type == libc::IPV6_RECVERR);
            if is_err && ee_end <= buf.len() && ee_end <= msg_end {
                let ee = unsafe {
                    ptr::read_unaligned(buf.as_ptr().add(data).cast::<SockExtendedErr>())
                };
                let tail = msg_end.min(buf.len());
                return Some(IcmpReply {
                    origin: ee.ee_origin,
                    ty: ee.ee_type,
                    code: ee.ee_code,
                    from: parse_offender(&buf[ee_end..tail]),
                });
            }
            let next = align(msg_end);
            if next <= off {
                break;
            }
            off = next;
        }
        None
    }

    fn parse_offender(buf: &[u8]) -> Option<IpAddr> {
        if buf.len() < 2 {
            return None;
        }
        let family = u16::from_ne_bytes([buf[0], buf[1]]);
        if family == libc::AF_INET as u16 && buf.len() >= 8 {
            let ip = Ipv4Addr::new(buf[4], buf[5], buf[6], buf[7]);
            if ip.is_unspecified() {
                None
            } else {
                Some(IpAddr::V4(ip))
            }
        } else if family == libc::AF_INET6 as u16 && buf.len() >= 24 {
            let mut oct = [0u8; 16];
            oct.copy_from_slice(&buf[8..24]);
            let ip = Ipv6Addr::from(oct);
            if ip.is_unspecified() {
                None
            } else {
                Some(IpAddr::V6(ip))
            }
        } else {
            None
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn parse_control_reads_time_exceeded_offender() {
            let ee = SockExtendedErr {
                ee_errno: libc::EHOSTUNREACH as u32,
                ee_origin: 2,
                ee_type: 11,
                ee_code: 0,
                ee_pad: 0,
                ee_info: 0,
                ee_data: 0,
            };
            let mut offender = [0u8; 16];
            let family = (libc::AF_INET as u16).to_ne_bytes();
            offender[0] = family[0];
            offender[1] = family[1];
            offender[4] = 192;
            offender[5] = 0;
            offender[6] = 2;
            offender[7] = 1;
            let data_len = mem::size_of::<SockExtendedErr>() + offender.len();
            let hdr_size = mem::size_of::<libc::cmsghdr>();
            let cmsg_len = hdr_size + data_len;
            let mut buf = vec![0u8; align(cmsg_len)];
            let mut hdr: libc::cmsghdr = unsafe { mem::zeroed() };
            hdr.cmsg_len = cmsg_len as _;
            hdr.cmsg_level = libc::IPPROTO_IP;
            hdr.cmsg_type = libc::IP_RECVERR;
            unsafe {
                ptr::write_unaligned(buf.as_mut_ptr().cast::<libc::cmsghdr>(), hdr);
                ptr::write_unaligned(
                    buf.as_mut_ptr()
                        .add(align(hdr_size))
                        .cast::<SockExtendedErr>(),
                    ee,
                );
                ptr::copy_nonoverlapping(
                    offender.as_ptr(),
                    buf.as_mut_ptr()
                        .add(align(hdr_size) + mem::size_of::<SockExtendedErr>()),
                    offender.len(),
                );
            }
            let reply = parse_control(&buf).expect("icmp");
            assert_eq!(reply.origin, 2);
            assert_eq!(reply.ty, 11);
            assert_eq!(reply.from, Some(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1))));
        }
    }
}

#[cfg(target_os = "macos")]
mod macos {
    use super::{RouteError, RouteHop, RouteProto, MAX_TTL, PROBE_TIMEOUT, ROUTE_MACOS_DENIED};
    use std::io;
    use std::mem;
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
    use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
    use std::time::Instant;

    const ICMP_ECHO_REPLY: u8 = 0;
    const ICMP_DEST_UNREACH: u8 = 3;
    const ICMP_ECHO: u8 = 8;
    const ICMP_TIME_EXCEEDED: u8 = 11;
    const ICMPV6_DEST_UNREACH: u8 = 1;
    const ICMPV6_TIME_EXCEED: u8 = 3;
    const ICMPV6_ECHO_REPLY: u8 = 129;
    const ICMPV6_ECHO_REQUEST: u8 = 128;

    enum ProbeOut {
        Hop {
            addr: Option<IpAddr>,
            rtt: std::time::Duration,
        },
        Reached {
            rtt: std::time::Duration,
        },
        Unreachable {
            addr: Option<IpAddr>,
            rtt: std::time::Duration,
        },
        Timeout,
        Denied,
        Fatal(io::Error),
    }

    pub(super) fn trace_blocking(
        dest: SocketAddr,
        bind: Option<IpAddr>,
        proto: RouteProto,
    ) -> Result<Vec<RouteHop>, RouteError> {
        // macOS will not deliver another socket's ICMP errors. Echo probes
        // reach the same address; TCP versus UDP is a Linux distinction.
        let _ = proto;
        // `::ffff:a.b.c.d` is an IPv4 peer. ICMPv6 sendto rejects it with EINVAL.
        let dest = ipv4_mapped(dest);
        let mut hops = Vec::new();
        for ttl in 1..=MAX_TTL {
            match probe_once(dest, bind, ttl) {
                ProbeOut::Denied if hops.is_empty() => {
                    return Err(RouteError::Unavailable(ROUTE_MACOS_DENIED));
                }
                ProbeOut::Denied => break,
                ProbeOut::Fatal(err) if hops.is_empty() => return Err(RouteError::Probe(err)),
                ProbeOut::Fatal(_) => break,
                ProbeOut::Timeout => hops.push(hop(ttl, None, None, true, false)),
                ProbeOut::Hop { addr, rtt } => hops.push(hop(ttl, addr, Some(rtt), false, false)),
                ProbeOut::Unreachable { addr, rtt } => {
                    hops.push(hop(ttl, addr, Some(rtt), false, false));
                    break;
                }
                ProbeOut::Reached { rtt } => {
                    hops.push(hop(ttl, Some(dest.ip()), Some(rtt), false, true));
                    break;
                }
            }
        }
        Ok(hops)
    }

    fn hop(
        ttl: u8,
        addr: Option<IpAddr>,
        rtt: Option<std::time::Duration>,
        timeout: bool,
        reached: bool,
    ) -> RouteHop {
        RouteHop {
            ttl,
            addr: addr.map(|ip| ip.to_string()),
            rtt,
            timeout,
            reached,
        }
    }

    fn probe_once(dest: SocketAddr, bind: Option<IpAddr>, ttl: u8) -> ProbeOut {
        let fd = match open_socket(dest, bind, i32::from(ttl)) {
            Ok(fd) => fd,
            Err(err) if is_denied(&err) => return ProbeOut::Denied,
            Err(err) => return ProbeOut::Fatal(err),
        };
        let start = Instant::now();
        let packet = echo_packet(dest, ttl);
        let (storage, len) = socket_addr(SocketAddr::new(dest.ip(), 0));
        let sent = unsafe {
            libc::sendto(
                fd.as_raw_fd(),
                packet.as_ptr().cast(),
                packet.len(),
                0,
                &storage as *const libc::sockaddr_storage as *const libc::sockaddr,
                len,
            )
        };
        if sent < 0 {
            return ProbeOut::Fatal(io::Error::last_os_error());
        }
        let deadline = start + PROBE_TIMEOUT;
        loop {
            let left = deadline.saturating_duration_since(Instant::now());
            if left.is_zero() {
                return ProbeOut::Timeout;
            }
            let mut pfd = libc::pollfd {
                fd: fd.as_raw_fd(),
                events: libc::POLLIN,
                revents: 0,
            };
            let ms = i32::try_from(left.as_millis()).unwrap_or(i32::MAX).max(1);
            let rc = unsafe { libc::poll(&mut pfd, 1, ms) };
            if rc < 0 {
                let err = io::Error::last_os_error();
                if err.kind() == io::ErrorKind::Interrupted {
                    continue;
                }
                return ProbeOut::Fatal(err);
            }
            if rc == 0 {
                return ProbeOut::Timeout;
            }
            if let Some((from, ty)) = recv_icmp(fd.as_raw_fd()) {
                let rtt = start.elapsed();
                if ty == time_exceeded(dest) {
                    return ProbeOut::Hop {
                        addr: Some(from),
                        rtt,
                    };
                }
                if ty == echo_reply(dest) && from == dest.ip() {
                    return ProbeOut::Reached { rtt };
                }
                if ty == dest_unreach(dest) {
                    return ProbeOut::Unreachable {
                        addr: Some(from),
                        rtt,
                    };
                }
            }
        }
    }

    fn ipv4_mapped(dest: SocketAddr) -> SocketAddr {
        match dest.ip() {
            IpAddr::V6(ip) => match ip.to_ipv4_mapped() {
                Some(v4) => SocketAddr::new(IpAddr::V4(v4), dest.port()),
                None => dest,
            },
            IpAddr::V4(_) => dest,
        }
    }

    fn is_denied(err: &io::Error) -> bool {
        matches!(err.raw_os_error(), Some(libc::EPERM) | Some(libc::EACCES))
    }

    fn time_exceeded(dest: SocketAddr) -> u8 {
        if dest.is_ipv4() {
            ICMP_TIME_EXCEEDED
        } else {
            ICMPV6_TIME_EXCEED
        }
    }

    fn echo_reply(dest: SocketAddr) -> u8 {
        if dest.is_ipv4() {
            ICMP_ECHO_REPLY
        } else {
            ICMPV6_ECHO_REPLY
        }
    }

    fn dest_unreach(dest: SocketAddr) -> u8 {
        if dest.is_ipv4() {
            ICMP_DEST_UNREACH
        } else {
            ICMPV6_DEST_UNREACH
        }
    }

    fn echo_packet(dest: SocketAddr, ttl: u8) -> [u8; 16] {
        let mut pkt = [0u8; 16];
        pkt[0] = if dest.is_ipv4() {
            ICMP_ECHO
        } else {
            ICMPV6_ECHO_REQUEST
        };
        let id = (std::process::id() as u16).to_be_bytes();
        pkt[4] = id[0];
        pkt[5] = id[1];
        pkt[7] = ttl;
        if dest.is_ipv4() {
            let sum = internet_checksum(&pkt).to_be_bytes();
            pkt[2] = sum[0];
            pkt[3] = sum[1];
        }
        pkt
    }

    fn internet_checksum(data: &[u8]) -> u16 {
        let mut sum = 0u32;
        let mut i = 0;
        while i + 1 < data.len() {
            sum += u16::from_be_bytes([data[i], data[i + 1]]) as u32;
            i += 2;
        }
        if i < data.len() {
            sum += u16::from_be_bytes([data[i], 0]) as u32;
        }
        while sum >> 16 != 0 {
            sum = (sum & 0xffff) + (sum >> 16);
        }
        !(sum as u16)
    }

    fn open_socket(dest: SocketAddr, bind: Option<IpAddr>, ttl: i32) -> io::Result<OwnedFd> {
        let (domain, proto, level, opt) = if dest.is_ipv4() {
            (
                libc::AF_INET,
                libc::IPPROTO_ICMP,
                libc::IPPROTO_IP,
                libc::IP_TTL,
            )
        } else {
            (
                libc::AF_INET6,
                libc::IPPROTO_ICMPV6,
                libc::IPPROTO_IPV6,
                libc::IPV6_UNICAST_HOPS,
            )
        };
        let raw = unsafe { libc::socket(domain, libc::SOCK_DGRAM, proto) };
        if raw < 0 {
            return Err(io::Error::last_os_error());
        }
        let fd = unsafe { OwnedFd::from_raw_fd(raw) };
        set_nonblock_cloexec(fd.as_raw_fd())?;
        set_int(fd.as_raw_fd(), level, opt, ttl)?;
        if let Some(ip) = bind {
            if ip.is_ipv4() == dest.is_ipv4() {
                let (storage, len) = socket_addr(SocketAddr::new(ip, 0));
                let rc = unsafe {
                    libc::bind(
                        fd.as_raw_fd(),
                        &storage as *const libc::sockaddr_storage as *const libc::sockaddr,
                        len,
                    )
                };
                if rc < 0 {
                    return Err(io::Error::last_os_error());
                }
            }
        }
        Ok(fd)
    }

    fn set_nonblock_cloexec(fd: i32) -> io::Result<()> {
        let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
        if flags < 0 {
            return Err(io::Error::last_os_error());
        }
        if unsafe { libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) } < 0 {
            return Err(io::Error::last_os_error());
        }
        let fdflags = unsafe { libc::fcntl(fd, libc::F_GETFD) };
        if fdflags < 0 {
            return Err(io::Error::last_os_error());
        }
        if unsafe { libc::fcntl(fd, libc::F_SETFD, fdflags | libc::FD_CLOEXEC) } < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }

    fn set_int(fd: i32, level: i32, name: i32, value: i32) -> io::Result<()> {
        let rc = unsafe {
            libc::setsockopt(
                fd,
                level,
                name,
                &value as *const i32 as *const libc::c_void,
                mem::size_of::<i32>() as libc::socklen_t,
            )
        };
        if rc == 0 {
            Ok(())
        } else {
            Err(io::Error::last_os_error())
        }
    }

    fn socket_addr(addr: SocketAddr) -> (libc::sockaddr_storage, libc::socklen_t) {
        let mut storage: libc::sockaddr_storage = unsafe { mem::zeroed() };
        let len = match addr {
            SocketAddr::V4(v4) => {
                let sa = unsafe {
                    &mut *(&mut storage as *mut libc::sockaddr_storage).cast::<libc::sockaddr_in>()
                };
                sa.sin_len = mem::size_of::<libc::sockaddr_in>() as u8;
                sa.sin_family = libc::AF_INET as libc::sa_family_t;
                sa.sin_port = v4.port().to_be();
                sa.sin_addr = libc::in_addr {
                    s_addr: u32::from_ne_bytes(v4.ip().octets()),
                };
                mem::size_of::<libc::sockaddr_in>() as libc::socklen_t
            }
            SocketAddr::V6(v6) => {
                let sa = unsafe {
                    &mut *(&mut storage as *mut libc::sockaddr_storage).cast::<libc::sockaddr_in6>()
                };
                sa.sin6_len = mem::size_of::<libc::sockaddr_in6>() as u8;
                sa.sin6_family = libc::AF_INET6 as libc::sa_family_t;
                sa.sin6_port = v6.port().to_be();
                sa.sin6_flowinfo = v6.flowinfo();
                sa.sin6_addr = libc::in6_addr {
                    s6_addr: v6.ip().octets(),
                };
                sa.sin6_scope_id = v6.scope_id();
                mem::size_of::<libc::sockaddr_in6>() as libc::socklen_t
            }
        };
        (storage, len)
    }

    fn recv_icmp(fd: i32) -> Option<(IpAddr, u8)> {
        let mut buf = [0u8; 512];
        let mut name = [0u8; 128];
        let mut namelen = name.len() as libc::socklen_t;
        let n = unsafe {
            libc::recvfrom(
                fd,
                buf.as_mut_ptr().cast(),
                buf.len(),
                0,
                name.as_mut_ptr().cast(),
                &mut namelen,
            )
        };
        if n < 1 {
            return None;
        }
        let from = parse_src(&name[..namelen as usize])?;
        let ty = icmp_type(&buf[..n as usize])?;
        Some((from, ty))
    }

    /// macOS delivers the IPv4 header in front of the ICMP message (`0x45…`).
    fn icmp_type(buf: &[u8]) -> Option<u8> {
        let off = if buf.len() >= 20 && buf[0] >> 4 == 4 {
            usize::from(buf[0] & 0x0f) * 4
        } else if buf.len() >= 40 && buf[0] >> 4 == 6 {
            40
        } else {
            0
        };
        buf.get(off).copied()
    }

    fn parse_src(buf: &[u8]) -> Option<IpAddr> {
        if buf.len() < 2 {
            return None;
        }
        let family = i32::from(buf[1]);
        if family == libc::AF_INET && buf.len() >= 8 {
            Some(IpAddr::V4(Ipv4Addr::new(buf[4], buf[5], buf[6], buf[7])))
        } else if family == libc::AF_INET6 && buf.len() >= 24 {
            let mut oct = [0u8; 16];
            oct.copy_from_slice(&buf[8..24]);
            Some(IpAddr::V6(Ipv6Addr::from(oct)))
        } else {
            None
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn echo_checksum_matches_the_header() {
            let pkt = echo_packet("127.0.0.1:80".parse().unwrap(), 1);
            assert_eq!(pkt[0], ICMP_ECHO);
            assert_eq!(internet_checksum(&pkt), 0);
        }

        #[test]
        fn parse_src_reads_bsd_sockaddr() {
            let (storage, len) = socket_addr("10.49.81.1:0".parse().unwrap());
            let bytes = unsafe {
                std::slice::from_raw_parts(
                    (&storage as *const libc::sockaddr_storage).cast::<u8>(),
                    len as usize,
                )
            };
            assert_eq!(
                parse_src(bytes),
                Some(IpAddr::V4(Ipv4Addr::new(10, 49, 81, 1)))
            );
            let (storage, len) = socket_addr("[::1]:0".parse().unwrap());
            let bytes = unsafe {
                std::slice::from_raw_parts(
                    (&storage as *const libc::sockaddr_storage).cast::<u8>(),
                    len as usize,
                )
            };
            assert_eq!(parse_src(bytes), Some(IpAddr::V6(Ipv6Addr::LOCALHOST)));
        }

        #[test]
        fn icmp_type_skips_the_ipv4_header() {
            let mut buf = vec![0x45, 0, 0, 0];
            buf.resize(20, 0);
            buf.push(ICMP_TIME_EXCEEDED);
            assert_eq!(icmp_type(&buf), Some(ICMP_TIME_EXCEEDED));
            assert_eq!(icmp_type(&[ICMP_ECHO_REPLY, 0]), Some(ICMP_ECHO_REPLY));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classify_icmp_kinds() {
        assert_eq!(
            classify_icmp(ORIGIN_ICMP, ICMP_TIME_EXCEEDED, 0),
            IcmpClass::TimeExceeded
        );
        assert_eq!(
            classify_icmp(ORIGIN_ICMP, ICMP_DEST_UNREACH, ICMP_PORT_UNREACH),
            IcmpClass::Reached
        );
        assert_eq!(
            classify_icmp(ORIGIN_ICMP, ICMP_DEST_UNREACH, 1),
            IcmpClass::Unreachable
        );
        assert_eq!(
            classify_icmp(ORIGIN_ICMP6, ICMPV6_TIME_EXCEED, 0),
            IcmpClass::TimeExceeded
        );
        assert_eq!(
            classify_icmp(ORIGIN_ICMP6, ICMPV6_DEST_UNREACH, ICMPV6_PORT_UNREACH),
            IcmpClass::Reached
        );
        assert_eq!(classify_icmp(0, ICMP_TIME_EXCEEDED, 0), IcmpClass::Other);
    }

    #[tokio::test]
    async fn unsupported_platform_names_the_reason() {
        if cfg!(any(target_os = "linux", target_os = "macos")) {
            return;
        }
        let err = trace_route("127.0.0.1:80".parse().unwrap(), None, RouteProto::Tcp)
            .await
            .unwrap_err();
        assert_eq!(err.to_string(), ROUTE_UNAVAILABLE);
    }

    #[cfg(target_os = "macos")]
    #[tokio::test]
    async fn macos_localhost_reaches_on_the_first_hop() {
        let hops = trace_route("127.0.0.1:80".parse().unwrap(), None, RouteProto::Tcp)
            .await
            .unwrap();
        let last = hops.last().expect("hop");
        assert!(last.reached);
        assert_eq!(last.addr.as_deref(), Some("127.0.0.1"));
    }

    #[cfg(target_os = "macos")]
    #[tokio::test]
    async fn macos_ipv4_mapped_address_is_traced() {
        let hops = trace_route(
            "[::ffff:127.0.0.1]:80".parse().unwrap(),
            None,
            RouteProto::Tcp,
        )
        .await
        .unwrap();
        let last = hops.last().expect("hop");
        assert!(last.reached);
        assert_eq!(last.addr.as_deref(), Some("127.0.0.1"));
    }
}
