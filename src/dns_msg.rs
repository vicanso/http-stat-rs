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

#![cfg_attr(not(feature = "doh"), allow(dead_code))]
//! Tiny DNS wire codec for the DoH/DoT presets.
//!
//! The preset path opens one TLS session and speaks DNS on it, so the
//! connect time and the query time belong to the same connection. Only A and
//! AAAA answers are kept.

use std::net::IpAddr;

pub(crate) const QTYPE_A: u16 = 1;
pub(crate) const QTYPE_AAAA: u16 = 28;

#[derive(Debug, Clone)]
pub(crate) struct DnsRecord {
    pub addr: IpAddr,
    pub ttl: u32,
}

pub(crate) fn encode_query(id: u16, name: &str, qtype: u16) -> Vec<u8> {
    let mut buf = Vec::with_capacity(64);
    buf.extend_from_slice(&id.to_be_bytes());
    buf.extend_from_slice(&0x0100u16.to_be_bytes()); // recursion desired
    buf.extend_from_slice(&1u16.to_be_bytes());
    buf.extend_from_slice(&[0, 0, 0, 0, 0, 0]);
    write_name(&mut buf, name);
    buf.extend_from_slice(&qtype.to_be_bytes());
    buf.extend_from_slice(&1u16.to_be_bytes()); // IN
    buf
}

pub(crate) fn parse_records(msg: &[u8]) -> std::result::Result<Vec<DnsRecord>, String> {
    if msg.len() < 12 {
        return Err("short dns message".to_string());
    }
    let flags = u16::from_be_bytes([msg[2], msg[3]]);
    let rcode = flags & 0x000f;
    if rcode != 0 {
        return Err(format!("dns rcode {rcode}"));
    }
    let qd = u16::from_be_bytes([msg[4], msg[5]]) as usize;
    let an = u16::from_be_bytes([msg[6], msg[7]]) as usize;
    let mut i = 12usize;
    for _ in 0..qd {
        skip_name(msg, &mut i)?;
        if i + 4 > msg.len() {
            return Err("short dns question".to_string());
        }
        i += 4;
    }
    let mut out = Vec::new();
    for _ in 0..an {
        skip_name(msg, &mut i)?;
        if i + 10 > msg.len() {
            return Err("short dns record".to_string());
        }
        let typ = u16::from_be_bytes([msg[i], msg[i + 1]]);
        let ttl = u32::from_be_bytes([msg[i + 4], msg[i + 5], msg[i + 6], msg[i + 7]]);
        let rdlen = u16::from_be_bytes([msg[i + 8], msg[i + 9]]) as usize;
        i += 10;
        if i + rdlen > msg.len() {
            return Err("short dns rdata".to_string());
        }
        let rdata = &msg[i..i + rdlen];
        i += rdlen;
        if typ == QTYPE_A && rdata.len() == 4 {
            out.push(DnsRecord {
                addr: IpAddr::from([rdata[0], rdata[1], rdata[2], rdata[3]]),
                ttl,
            });
        } else if typ == QTYPE_AAAA && rdata.len() == 16 {
            let mut octets = [0u8; 16];
            octets.copy_from_slice(rdata);
            out.push(DnsRecord {
                addr: IpAddr::from(octets),
                ttl,
            });
        }
    }
    Ok(out)
}

fn write_name(buf: &mut Vec<u8>, name: &str) {
    for label in name.trim_end_matches('.').split('.') {
        if label.is_empty() {
            continue;
        }
        let bytes = label.as_bytes();
        buf.push(bytes.len() as u8);
        buf.extend_from_slice(bytes);
    }
    buf.push(0);
}

fn skip_name(msg: &[u8], i: &mut usize) -> std::result::Result<(), String> {
    let mut guard = 0;
    loop {
        if *i >= msg.len() {
            return Err("short dns name".to_string());
        }
        let len = msg[*i];
        if len == 0 {
            *i += 1;
            return Ok(());
        }
        if len & 0xc0 == 0xc0 {
            if *i + 1 >= msg.len() {
                return Err("short dns pointer".to_string());
            }
            *i += 2;
            return Ok(());
        }
        if len & 0xc0 != 0 {
            return Err("bad dns name".to_string());
        }
        *i += 1 + len as usize;
        guard += 1;
        if guard > 128 {
            return Err("dns name too long".to_string());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    #[test]
    fn roundtrip_a_record_with_compression_pointer() {
        let query = encode_query(0x1234, "example.com", QTYPE_A);
        // Response: copy the question, then an answer whose name is a pointer
        // back at the question name (offset 12).
        let mut msg = query.clone();
        // flags: response + RD + RA
        msg[2] = 0x81;
        msg[3] = 0x80;
        msg[6] = 0;
        msg[7] = 1; // ANCOUNT
        msg.extend_from_slice(&[0xc0, 0x0c]); // pointer to offset 12
        msg.extend_from_slice(&QTYPE_A.to_be_bytes());
        msg.extend_from_slice(&1u16.to_be_bytes());
        msg.extend_from_slice(&60u32.to_be_bytes());
        msg.extend_from_slice(&4u16.to_be_bytes());
        msg.extend_from_slice(&[1, 2, 3, 4]);

        let recs = parse_records(&msg).unwrap();
        assert_eq!(recs.len(), 1);
        assert_eq!(recs[0].addr, IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4)));
        assert_eq!(recs[0].ttl, 60);
    }

    #[test]
    fn rcode_is_an_error() {
        let mut msg = encode_query(1, "example.com", QTYPE_A);
        msg[3] = 3; // NXDOMAIN
        assert!(parse_records(&msg).is_err());
    }
}
