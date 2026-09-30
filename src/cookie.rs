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

//! Minimal RFC 6265 cookie jar.
//!
//! Enough for `-b` and `Set-Cookie` across `-L`: `Domain`, `Path`, `Secure`,
//! `Max-Age` and `Expires` are honored. A cookie is attached to a request only
//! when the host, path and scheme all match, so a cross-host redirect does not
//! carry the previous host's session along.

use http::Uri;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use time::format_description::well_known::Rfc2822;
use time::OffsetDateTime;

#[derive(Debug, Clone)]
struct StoredCookie {
    name: String,
    value: String,
    /// Registrable host this cookie is bound to. Lowercase, no leading dot.
    domain: String,
    host_only: bool,
    path: String,
    secure: bool,
    /// `None` means a session cookie (lives for this process only).
    expires: Option<SystemTime>,
}

/// Process-local cookie jar used while following redirects.
#[derive(Debug, Default, Clone)]
pub struct CookieJar {
    cookies: Vec<StoredCookie>,
}

impl CookieJar {
    pub fn new() -> Self {
        Self {
            cookies: Vec::new(),
        }
    }

    /// Load a `Cookie` request header (`a=1; b=2`) as host-only cookies for `host`.
    pub fn load_cookie_header(&mut self, host: &str, header: &str) {
        let host = host.trim().trim_end_matches('.').to_ascii_lowercase();
        if host.is_empty() {
            return;
        }
        for pair in header.split(';') {
            let pair = pair.trim();
            let Some((name, value)) = pair.split_once('=') else {
                continue;
            };
            let name = name.trim();
            if name.is_empty() {
                continue;
            }
            self.upsert(StoredCookie {
                name: name.to_string(),
                value: value.trim().to_string(),
                domain: host.clone(),
                host_only: true,
                path: "/".to_string(),
                secure: false,
                expires: None,
            });
        }
    }

    /// Store one `Set-Cookie` value received while requesting `uri`.
    pub fn store_set_cookie(&mut self, uri: &Uri, set_cookie: &str) {
        let Some(host) = uri.host() else {
            return;
        };
        let host = host.trim_end_matches('.').to_ascii_lowercase();
        let mut parts = set_cookie.split(';');
        let Some(nv) = parts.next() else {
            return;
        };
        let Some((name, value)) = nv.split_once('=') else {
            return;
        };
        let name = name.trim();
        if name.is_empty() {
            return;
        }

        let mut domain = host.clone();
        let mut host_only = true;
        let mut path = default_path(uri.path());
        let mut secure = false;
        let mut expires: Option<SystemTime> = None;
        let mut delete = false;

        for attr in parts {
            let attr = attr.trim();
            if attr.is_empty() {
                continue;
            }
            let (key, raw_val) = attr
                .split_once('=')
                .map(|(k, v)| (k.trim(), v.trim()))
                .unwrap_or((attr, ""));
            match key.to_ascii_lowercase().as_str() {
                "domain" => {
                    let d = raw_val
                        .trim_start_matches('.')
                        .trim_end_matches('.')
                        .to_ascii_lowercase();
                    // A Domain attribute must domain-match the request host.
                    // A single label ("com") is rejected: it is never a host
                    // we just talked to, and it would leak the cookie widely.
                    if d.is_empty() || !domain_matches(&host, &d) || !d.contains('.') && d != host {
                        return;
                    }
                    domain = d;
                    host_only = false;
                }
                "path" => {
                    if raw_val.starts_with('/') {
                        path = raw_val.to_string();
                    }
                }
                "secure" => secure = true,
                "max-age" => match raw_val.parse::<i64>() {
                    Ok(secs) if secs <= 0 => delete = true,
                    Ok(secs) => {
                        expires = Some(SystemTime::now() + Duration::from_secs(secs as u64));
                    }
                    Err(_) => {}
                },
                "expires" if expires.is_none() => {
                    if let Some(when) = parse_http_date(raw_val) {
                        if when <= SystemTime::now() {
                            delete = true;
                        } else {
                            expires = Some(when);
                        }
                    }
                }
                _ => {}
            }
        }

        if delete {
            self.cookies
                .retain(|c| !(c.name == name && c.domain == domain && c.path == path));
            return;
        }

        self.upsert(StoredCookie {
            name: name.to_string(),
            value: value.trim().to_string(),
            domain,
            host_only,
            path,
            secure,
            expires,
        });
    }

    /// `Cookie` header value for `uri`, or `None` when nothing matches.
    pub fn header_for(&mut self, uri: &Uri) -> Option<String> {
        let host = uri.host()?.trim_end_matches('.').to_ascii_lowercase();
        let secure_ok = matches!(uri.scheme_str(), Some("https" | "grpcs" | "wss"));
        let path = if uri.path().is_empty() {
            "/"
        } else {
            uri.path()
        };
        let now = SystemTime::now();
        self.cookies.retain(|c| match c.expires {
            Some(exp) => exp > now,
            None => true,
        });

        let mut matched: Vec<&StoredCookie> = self
            .cookies
            .iter()
            .filter(|c| {
                if c.secure && !secure_ok {
                    return false;
                }
                if c.host_only {
                    if c.domain != host {
                        return false;
                    }
                } else if !domain_matches(&host, &c.domain) {
                    return false;
                }
                path_matches(&c.path, path)
            })
            .collect();
        // Longer paths win when two cookies share a name; name order is stable.
        matched.sort_by(|a, b| {
            b.path
                .len()
                .cmp(&a.path.len())
                .then_with(|| a.name.cmp(&b.name))
        });
        // One name, most specific path.
        let mut seen = std::collections::HashSet::new();
        let mut pairs = Vec::new();
        for c in matched {
            if seen.insert(c.name.as_str()) {
                pairs.push(format!("{}={}", c.name, c.value));
            }
        }
        if pairs.is_empty() {
            None
        } else {
            Some(pairs.join("; "))
        }
    }

    fn upsert(&mut self, cookie: StoredCookie) {
        if let Some(existing) = self
            .cookies
            .iter_mut()
            .find(|c| c.name == cookie.name && c.domain == cookie.domain && c.path == cookie.path)
        {
            *existing = cookie;
        } else {
            self.cookies.push(cookie);
        }
    }
}

fn domain_matches(host: &str, domain: &str) -> bool {
    host == domain
        || (host.len() > domain.len()
            && host.as_bytes()[host.len() - domain.len() - 1] == b'.'
            && host[host.len() - domain.len()..].eq_ignore_ascii_case(domain))
}

fn path_matches(cookie_path: &str, request_path: &str) -> bool {
    if request_path == cookie_path {
        return true;
    }
    if !request_path.starts_with(cookie_path) {
        return false;
    }
    cookie_path.ends_with('/') || request_path.as_bytes().get(cookie_path.len()) == Some(&b'/')
}

fn default_path(request_path: &str) -> String {
    if !request_path.starts_with('/') {
        return "/".to_string();
    }
    match request_path.rfind('/') {
        Some(0) | None => "/".to_string(),
        Some(i) => request_path[..=i].trim_end_matches('/').to_string() + "/",
    }
}

fn parse_http_date(value: &str) -> Option<SystemTime> {
    let dt = OffsetDateTime::parse(value, &Rfc2822).ok()?;
    let secs = dt.unix_timestamp();
    if secs < 0 {
        return None;
    }
    Some(UNIX_EPOCH + Duration::from_secs(secs as u64))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn uri(s: &str) -> Uri {
        s.parse().unwrap()
    }

    #[test]
    fn host_only_cookie_does_not_leak() {
        let mut jar = CookieJar::new();
        jar.load_cookie_header("example.com", "session=abc");
        assert_eq!(
            jar.header_for(&uri("https://example.com/")).as_deref(),
            Some("session=abc")
        );
        assert!(jar.header_for(&uri("https://other.example.com/")).is_none());
        assert!(jar.header_for(&uri("https://evil.com/")).is_none());
    }

    #[test]
    fn domain_path_and_secure_are_honored() {
        let mut jar = CookieJar::new();
        let origin = uri("https://www.example.com/app/index");
        jar.store_set_cookie(&origin, "a=1; Domain=example.com; Path=/app");
        jar.store_set_cookie(&origin, "b=2; Secure; Path=/");
        jar.store_set_cookie(&origin, "c=3; Domain=com");

        assert_eq!(
            jar.header_for(&uri("https://api.example.com/app/x"))
                .as_deref(),
            Some("a=1")
        );
        let both = jar.header_for(&uri("https://www.example.com/app")).unwrap();
        assert!(both.contains("a=1"));
        assert!(both.contains("b=2"));
        assert!(!both.contains("c=3"));

        // Secure cookie stays off cleartext, including the host-only one.
        let http = jar.header_for(&uri("http://www.example.com/app")).unwrap();
        assert!(http.contains("a=1"));
        assert!(!http.contains("b=2"));

        assert!(jar
            .header_for(&uri("https://www.example.com/other"))
            .unwrap()
            .contains("b=2"));
        assert!(!jar
            .header_for(&uri("https://www.example.com/other"))
            .unwrap()
            .contains("a=1"));
    }

    #[test]
    fn max_age_zero_deletes() {
        let mut jar = CookieJar::new();
        let origin = uri("https://example.com/");
        jar.store_set_cookie(&origin, "a=1; Path=/");
        assert!(jar.header_for(&origin).is_some());
        jar.store_set_cookie(&origin, "a=1; Path=/; Max-Age=0");
        assert!(jar.header_for(&origin).is_none());
    }
}
