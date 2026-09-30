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

//! Process-local DNS cache for benchmark repeats.
//!
//! A single `httpstat` invocation rebuilds the resolver on every request, so
//! `-n` measures resolver startup over and over. The cache stores the answer
//! until the record TTL and is installed only for repeated runs. A one-shot
//! request leaves it unset and always resolves for real.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Mutex;
use std::time::Instant;

#[derive(Hash, Eq, PartialEq, Clone)]
struct Key {
    host: String,
    port: u16,
    /// DNS server list joined, so a different `--dns-servers` does not collide.
    servers: String,
    ip_version: i32,
}

struct Entry {
    addrs: Vec<SocketAddr>,
    valid_until: Instant,
}

/// Shared DNS answer cache. Cheap to clone via `Arc`.
#[derive(Default)]
pub struct DnsCache {
    inner: Mutex<HashMap<Key, Entry>>,
}

impl std::fmt::Debug for DnsCache {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let n = self.inner.lock().map(|g| g.len()).unwrap_or(0);
        f.debug_struct("DnsCache").field("entries", &n).finish()
    }
}

impl DnsCache {
    pub fn new() -> Self {
        Self {
            inner: Mutex::new(HashMap::new()),
        }
    }

    pub fn get(
        &self,
        host: &str,
        port: u16,
        servers: &str,
        ip_version: i32,
    ) -> Option<Vec<SocketAddr>> {
        let key = Key {
            host: host.to_ascii_lowercase(),
            port,
            servers: servers.to_string(),
            ip_version,
        };
        let mut guard = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        let entry = guard.get(&key)?;
        if Instant::now() >= entry.valid_until {
            guard.remove(&key);
            return None;
        }
        Some(entry.addrs.clone())
    }

    pub fn put(
        &self,
        host: &str,
        port: u16,
        servers: &str,
        ip_version: i32,
        addrs: Vec<SocketAddr>,
        valid_until: Instant,
    ) {
        if addrs.is_empty() || valid_until <= Instant::now() {
            return;
        }
        let key = Key {
            host: host.to_ascii_lowercase(),
            port,
            servers: servers.to_string(),
            ip_version,
        };
        let mut guard = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        guard.insert(key, Entry { addrs, valid_until });
    }

    /// Move `winner` to the front of a cached answer so the next repeat
    /// connects to the address Happy Eyeballs already picked.
    pub fn prefer(
        &self,
        host: &str,
        port: u16,
        servers: &str,
        ip_version: i32,
        winner: SocketAddr,
    ) {
        let key = Key {
            host: host.to_ascii_lowercase(),
            port,
            servers: servers.to_string(),
            ip_version,
        };
        let mut guard = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        let Some(entry) = guard.get_mut(&key) else {
            return;
        };
        if let Some(pos) = entry.addrs.iter().position(|a| *a == winner) {
            entry.addrs.swap(0, pos);
        }
    }
}
