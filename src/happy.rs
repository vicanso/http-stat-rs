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

//! Happy Eyeballs (RFC 8305) connection racing.
//!
//! Addresses are interleaved by family, preferred family first (whatever the
//! resolver returned first). The first attempt starts immediately; the next
//! starts 250 ms later if nothing has connected yet. The first success wins.

use futures::stream::{FuturesUnordered, StreamExt};
use std::collections::VecDeque;
use std::net::{IpAddr, SocketAddr};
use std::time::Duration;
use tokio::net::{TcpSocket, TcpStream};
use tokio::time::timeout;

const STAGGER: Duration = Duration::from_millis(250);

/// Interleave address families. The family of `addrs[0]` is preferred.
pub(crate) fn interleave(addrs: Vec<SocketAddr>) -> Vec<SocketAddr> {
    if addrs.len() <= 1 {
        return addrs;
    }
    let v6_first = addrs[0].is_ipv6();
    let mut v4 = VecDeque::new();
    let mut v6 = VecDeque::new();
    for addr in addrs {
        if addr.is_ipv6() {
            v6.push_back(addr);
        } else {
            v4.push_back(addr);
        }
    }
    let (mut primary, mut secondary) = if v6_first { (v6, v4) } else { (v4, v6) };
    let mut out = Vec::with_capacity(primary.len() + secondary.len());
    while !primary.is_empty() || !secondary.is_empty() {
        if let Some(addr) = primary.pop_front() {
            out.push(addr);
        }
        if let Some(addr) = secondary.pop_front() {
            out.push(addr);
        }
    }
    out
}

/// Race TCP connects. The outer `timeout` covers the whole race.
#[cfg_attr(not(test), allow(dead_code))]
pub(crate) async fn race_tcp(
    addrs: Vec<SocketAddr>,
    overall: Duration,
    bind_addr: Option<IpAddr>,
) -> std::io::Result<(SocketAddr, TcpStream)> {
    timeout(overall, race_tcp_inner(addrs, bind_addr))
        .await
        .map_err(|_| std::io::Error::new(std::io::ErrorKind::TimedOut, "tcp connect timed out"))?
}

pub(crate) async fn race_tcp_inner(
    addrs: Vec<SocketAddr>,
    bind_addr: Option<IpAddr>,
) -> std::io::Result<(SocketAddr, TcpStream)> {
    let mut pending: VecDeque<SocketAddr> = interleave(addrs).into();
    let Some(first) = pending.pop_front() else {
        return Err(std::io::Error::new(
            std::io::ErrorKind::NotFound,
            "dns lookup returned no address",
        ));
    };
    let mut inflight = FuturesUnordered::new();
    inflight.push(connect_one(first, bind_addr));
    let mut stagger = Box::pin(tokio::time::sleep(STAGGER));
    let mut last_err =
        std::io::Error::new(std::io::ErrorKind::ConnectionRefused, "tcp connect failed");

    loop {
        tokio::select! {
            _ = &mut stagger, if !pending.is_empty() => {
                if let Some(addr) = pending.pop_front() {
                    inflight.push(connect_one(addr, bind_addr));
                }
                stagger = Box::pin(tokio::time::sleep(STAGGER));
            }
            done = inflight.next(), if !inflight.is_empty() => {
                match done {
                    Some(Ok(pair)) => return Ok(pair),
                    Some(Err(err)) => {
                        last_err = err;
                        if inflight.is_empty() && pending.is_empty() {
                            return Err(last_err);
                        }
                    }
                    None => return Err(last_err),
                }
            }
        }
    }
}

async fn connect_one(
    addr: SocketAddr,
    bind_addr: Option<IpAddr>,
) -> std::io::Result<(SocketAddr, TcpStream)> {
    let stream = if let Some(src) = bind_addr {
        let socket = if src.is_ipv6() {
            TcpSocket::new_v6()
        } else {
            TcpSocket::new_v4()
        }?;
        socket.bind(SocketAddr::new(src, 0))?;
        socket.connect(addr).await?
    } else {
        TcpStream::connect(addr).await?
    };
    Ok((addr, stream))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr};

    fn v4(o: u8) -> SocketAddr {
        SocketAddr::new(IpAddr::V4(Ipv4Addr::new(1, 2, 3, o)), 443)
    }
    fn v6(o: u16) -> SocketAddr {
        SocketAddr::new(
            IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, o)),
            443,
        )
    }

    #[test]
    fn interleave_prefers_first_family() {
        let out = interleave(vec![v6(1), v6(2), v4(1), v4(2)]);
        assert_eq!(out, vec![v6(1), v4(1), v6(2), v4(2)]);

        let out = interleave(vec![v4(9), v6(1)]);
        assert_eq!(out, vec![v4(9), v6(1)]);
    }

    #[tokio::test]
    async fn race_skips_a_refused_port() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let open = listener.local_addr().unwrap();
        let refused_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let refused = refused_listener.local_addr().unwrap();
        drop(refused_listener);

        let (winner, _stream) = race_tcp(vec![refused, open], Duration::from_secs(2), None)
            .await
            .unwrap();
        assert_eq!(winner, open);
    }
}
