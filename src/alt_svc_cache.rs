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

//! Persistent Alt-Svc memory so a later `httpstat --alt-svc` run can open
//! HTTP/3 directly instead of paying for an HTTP/1.1 or HTTP/2 probe first.
//!
//! The file lives at `~/.httpstat/alt-svc.json`. Entries expire with the
//! `ma=` value the server advertised. A failed upgrade drops the entry.

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Debug, Clone)]
struct Entry {
    host: String,
    port: u16,
    expires_unix: u64,
}

/// On-disk Alt-Svc table. Methods take `&self` and rewrite the file so the
/// CLI can share one instance across benchmark iterations.
#[derive(Debug, Clone)]
pub struct AltSvcCache {
    path: PathBuf,
    entries: BTreeMap<String, Entry>,
}

impl AltSvcCache {
    /// Load the user cache. A missing or corrupt file starts empty.
    pub fn load() -> Self {
        let path = default_path();
        Self::load_from(path)
    }

    pub fn load_from(path: PathBuf) -> Self {
        let entries = fs::read_to_string(&path)
            .ok()
            .and_then(|text| serde_json::from_str::<serde_json::Value>(&text).ok())
            .and_then(|v| v.as_object().cloned())
            .map(|map| {
                map.into_iter()
                    .filter_map(|(k, v)| {
                        let obj = v.as_object()?;
                        let host = obj.get("host")?.as_str()?.to_string();
                        let port = obj.get("port")?.as_u64()? as u16;
                        let expires_unix = obj.get("expires_unix")?.as_u64()?;
                        Some((
                            k,
                            Entry {
                                host,
                                port,
                                expires_unix,
                            },
                        ))
                    })
                    .collect()
            })
            .unwrap_or_default();
        Self { path, entries }
    }

    /// Advertised HTTP/3 endpoint for `host:port`, if it has not expired.
    /// An empty host means "same origin".
    pub fn get(&mut self, host: &str, port: u16) -> Option<(String, u16)> {
        let key = origin_key(host, port);
        let now = now_unix();
        let fresh = self
            .entries
            .get(&key)
            .filter(|e| e.expires_unix > now)
            .map(|e| (e.host.clone(), e.port));
        if fresh.is_none() && self.entries.remove(&key).is_some() {
            self.store();
        }
        fresh
    }

    pub fn put(&mut self, host: &str, port: u16, alt_host: &str, alt_port: u16, max_age: u64) {
        if max_age == 0 {
            self.invalidate(host, port);
            return;
        }
        let key = origin_key(host, port);
        self.entries.insert(
            key,
            Entry {
                host: alt_host.to_string(),
                port: alt_port,
                expires_unix: now_unix().saturating_add(max_age),
            },
        );
        self.store();
    }

    pub fn invalidate(&mut self, host: &str, port: u16) {
        if self.entries.remove(&origin_key(host, port)).is_some() {
            self.store();
        }
    }

    fn store(&self) {
        if let Some(dir) = self.path.parent() {
            let _ = fs::create_dir_all(dir);
        }
        let mut obj = serde_json::Map::new();
        for (k, e) in &self.entries {
            obj.insert(
                k.clone(),
                serde_json::json!({
                    "host": e.host,
                    "port": e.port,
                    "expires_unix": e.expires_unix,
                }),
            );
        }
        if let Ok(text) = serde_json::to_string_pretty(&obj) {
            let _ = fs::write(&self.path, text);
        }
    }
}

fn origin_key(host: &str, port: u16) -> String {
    format!("{}:{port}", host.trim().to_ascii_lowercase())
}

fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn default_path() -> PathBuf {
    let home = std::env::var("HOME")
        .or_else(|_| std::env::var("USERPROFILE"))
        .unwrap_or_else(|_| ".".into());
    Path::new(&home).join(".httpstat").join("alt-svc.json")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_respects_max_age() {
        let path = std::env::temp_dir().join(format!(
            "httpstat-alt-svc-{}-{}.json",
            std::process::id(),
            now_unix()
        ));
        let _ = fs::remove_file(&path);
        let mut cache = AltSvcCache::load_from(path.clone());
        cache.put("Example.com", 443, "", 443, 60);
        let mut again = AltSvcCache::load_from(path.clone());
        assert_eq!(again.get("example.com", 443), Some((String::new(), 443)));
        again.invalidate("example.com", 443);
        assert!(again.get("example.com", 443).is_none());
        let _ = fs::remove_file(&path);
    }
}
