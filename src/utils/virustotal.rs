//! VirusTotal v3 file reputation lookups by SHA-256 (no file is ever
//! uploaded), modelled after Procexp-Mac's `VirusTotalClient`:
//!
//! - results are cached by hash, in memory and on disk,
//! - requests are rate limited (the free API allows 4 per minute),
//! - unknown files (HTTP 404) are a normal answer, not an error.
//!
//! The API key is not handled here, see [`crate::utils::secrets`].

use std::cell::RefCell;
use std::collections::{HashMap, VecDeque};
use std::path::{Path, PathBuf};
use std::rc::Rc;
use std::time::{Duration, Instant};

use gtk::glib::{self, translate::IntoGlib};
use log::{debug, warn};
use serde_json::{Value, json};
use soup::prelude::*;

use crate::utils::i18n::{i18n, i18n_f};

/// Environment variable that replaces the API base URL, for testing against a
/// local server.
pub const API_URL_ENV: &str = "RESOURCES_VIRUSTOTAL_API_URL";
const DEFAULT_API_URL: &str = "https://www.virustotal.com/api/v3";
const REPORT_URL: &str = "https://www.virustotal.com/gui/file";

/// The free API tier allows 4 requests per minute
const MAX_REQUESTS_PER_MINUTE: usize = 4;
const WINDOW: Duration = Duration::from_secs(60);
const REQUEST_TIMEOUT_SECS: u32 = 20;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Reputation {
    /// engines that flagged the file as malicious or suspicious
    pub positives: u32,
    /// engines that looked at the file
    pub total: u32,
    pub permalink: String,
    /// Unix time of the check
    pub checked_at: i64,
}

impl Reputation {
    /// e.g. `3 / 72`
    pub fn summary(&self) -> String {
        format!("{} / {}", self.positives, self.total)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Lookup {
    Found(Reputation),
    /// VirusTotal has never seen this file
    Unknown,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VtError {
    InvalidKey,
    RateLimited,
    Http(u16),
    Network(String),
    Parse(String),
}

impl VtError {
    pub fn message(&self) -> String {
        match self {
            Self::InvalidKey => i18n("VirusTotal rejected the API key"),
            Self::RateLimited => i18n("VirusTotal rate limit reached, try again in a minute"),
            Self::Http(status) => i18n_f("VirusTotal returned HTTP {}", &[&status.to_string()]),
            Self::Network(error) => i18n_f("Could not reach VirusTotal: {}", &[error]),
            Self::Parse(error) => i18n_f("Unexpected answer from VirusTotal: {}", &[error]),
        }
    }
}

pub fn report_url(sha256: &str) -> String {
    format!("{REPORT_URL}/{sha256}")
}

/// 64 hexadecimal digits. Hashes end up in a URL, so they are validated.
pub fn is_valid_sha256(hash: &str) -> bool {
    hash.len() == 64 && hash.bytes().all(|byte| byte.is_ascii_hexdigit())
}

/// Parses the body of `GET /files/<sha256>`.
pub fn parse_response(sha256: &str, body: &[u8], now: i64) -> Result<Reputation, VtError> {
    let json: Value = serde_json::from_slice(body).map_err(|e| VtError::Parse(e.to_string()))?;
    let stats = json
        .pointer("/data/attributes/last_analysis_stats")
        .and_then(Value::as_object)
        .ok_or_else(|| VtError::Parse("no analysis statistics".into()))?;

    let mut total: u32 = 0;
    for count in stats.values() {
        let count = count
            .as_u64()
            .and_then(|count| u32::try_from(count).ok())
            .ok_or_else(|| VtError::Parse("invalid engine count".into()))?;
        total = total
            .checked_add(count)
            .ok_or_else(|| VtError::Parse("engine counts out of range".into()))?;
    }
    let count_of = |key: &str| {
        stats
            .get(key)
            .and_then(Value::as_u64)
            .and_then(|count| u32::try_from(count).ok())
            .unwrap_or(0)
    };

    Ok(Reputation {
        positives: count_of("malicious") + count_of("suspicious"),
        total,
        permalink: report_url(sha256),
        checked_at: now,
    })
}

/// Sliding window rate limiter. Time is passed in so that it can be tested.
#[derive(Debug)]
pub struct RateLimiter {
    max: usize,
    window: Duration,
    /// when requests were (or will be) made
    slots: VecDeque<Instant>,
}

impl RateLimiter {
    pub fn new(max: usize, window: Duration) -> Self {
        Self {
            max: max.max(1),
            window,
            slots: VecDeque::new(),
        }
    }

    /// Reserves the next free slot and returns how long to wait for it
    /// (zero if it's free now).
    pub fn reserve(&mut self, now: Instant) -> Duration {
        while self
            .slots
            .front()
            .is_some_and(|slot| now.saturating_duration_since(*slot) >= self.window)
        {
            self.slots.pop_front();
        }

        let at = if self.slots.len() < self.max {
            now
        } else {
            // the oldest slot of the last `max` ones has to age out first
            let oldest_relevant = self.slots[self.slots.len() - self.max];
            (oldest_relevant + self.window).max(now)
        };
        self.slots.push_back(at);
        at.saturating_duration_since(now)
    }
}

/// Persistent cache of reputations by hash.
#[derive(Debug, Default)]
pub struct Cache {
    entries: HashMap<String, Reputation>,
}

impl Cache {
    pub fn get(&self, sha256: &str) -> Option<&Reputation> {
        self.entries.get(sha256)
    }

    pub fn insert(&mut self, sha256: &str, reputation: Reputation) {
        self.entries.insert(sha256.to_string(), reputation);
    }

    /// Loads a cache file; a missing or damaged file gives an empty cache and
    /// entries with impossible counts are dropped.
    pub fn load(path: &Path) -> Self {
        let mut cache = Self::default();
        let Ok(content) = std::fs::read(path) else {
            return cache;
        };
        let Ok(Value::Object(entries)) = serde_json::from_slice::<Value>(&content) else {
            warn!("Ignoring unreadable VirusTotal cache {}", path.display());
            return cache;
        };

        for (hash, entry) in entries {
            let number = |key: &str| {
                entry
                    .get(key)
                    .and_then(Value::as_u64)
                    .and_then(|n| u32::try_from(n).ok())
            };
            let (Some(positives), Some(total), Some(checked_at)) = (
                number("positives"),
                number("total"),
                entry.get("checked_at").and_then(Value::as_i64),
            ) else {
                continue;
            };
            if !is_valid_sha256(&hash) || positives > total {
                continue;
            }
            cache.entries.insert(
                hash.clone(),
                Reputation {
                    positives,
                    total,
                    permalink: report_url(&hash),
                    checked_at,
                },
            );
        }
        cache
    }

    pub fn save(&self, path: &Path) {
        let entries: serde_json::Map<String, Value> = self
            .entries
            .iter()
            .map(|(hash, reputation)| {
                (
                    hash.clone(),
                    json!({
                        "positives": reputation.positives,
                        "total": reputation.total,
                        "checked_at": reputation.checked_at,
                    }),
                )
            })
            .collect();

        if let Some(parent) = path.parent() {
            let _ = std::fs::create_dir_all(parent);
        }
        if let Err(error) = std::fs::write(path, Value::Object(entries).to_string()) {
            warn!("Could not save VirusTotal cache: {error}");
        }
    }
}

fn cache_path() -> PathBuf {
    glib::user_cache_dir()
        .join("resources")
        .join("virustotal-cache.json")
}

fn now_unix() -> i64 {
    glib::real_time() / 1_000_000
}

struct State {
    cache: Cache,
    limiter: RateLimiter,
}

struct Inner {
    base_url: String,
    cache_path: Option<PathBuf>,
    state: RefCell<State>,
    session: soup::Session,
}

/// Client with its own cache and rate limiter; clones share them. Use
/// [`check`] for the one of the application.
#[derive(Clone)]
pub struct Client {
    inner: Rc<Inner>,
}

impl Client {
    pub fn new(base_url: &str, cache_path: Option<PathBuf>, limiter: RateLimiter) -> Self {
        let cache = cache_path.as_deref().map(Cache::load).unwrap_or_default();
        Self {
            inner: Rc::new(Inner {
                base_url: base_url.trim_end_matches('/').to_string(),
                cache_path,
                state: RefCell::new(State { cache, limiter }),
                session: soup::Session::builder()
                    .timeout(REQUEST_TIMEOUT_SECS)
                    .user_agent("Resources")
                    .build(),
            }),
        }
    }

    /// Looks a hash up, using the cache when possible.
    pub async fn check(&self, sha256: &str, api_key: &str) -> Result<Lookup, VtError> {
        let inner = &self.inner;
        let sha256 = sha256.to_ascii_lowercase();
        if !is_valid_sha256(&sha256) {
            return Err(VtError::Parse("not a SHA-256 hash".into()));
        }

        if let Some(cached) = inner.state.borrow().cache.get(&sha256) {
            debug!("VirusTotal cache hit for {sha256}");
            return Ok(Lookup::Found(cached.clone()));
        }

        let wait = inner.state.borrow_mut().limiter.reserve(Instant::now());
        if !wait.is_zero() {
            debug!("Waiting {wait:?} for a free VirusTotal request slot");
            glib::timeout_future(wait).await;
        }

        let message = soup::Message::new("GET", &format!("{}/files/{sha256}", inner.base_url))
            .map_err(|e| VtError::Network(e.to_string()))?;
        if let Some(headers) = message.request_headers() {
            headers.append("x-apikey", api_key);
            headers.append("accept", "application/json");
        }

        let body = inner
            .session
            .send_and_read_future(&message, glib::Priority::DEFAULT)
            .await
            .map_err(|e| VtError::Network(e.to_string()))?;

        let status = message.status().into_glib() as u16;
        match status {
            200 => {}
            404 => return Ok(Lookup::Unknown),
            401 | 403 => return Err(VtError::InvalidKey),
            429 => return Err(VtError::RateLimited),
            other => return Err(VtError::Http(other)),
        }

        let reputation = parse_response(&sha256, body.as_ref(), now_unix())?;

        let mut state = inner.state.borrow_mut();
        state.cache.insert(&sha256, reputation.clone());
        if let Some(path) = &inner.cache_path {
            state.cache.save(path);
        }
        Ok(Lookup::Found(reputation))
    }
}

thread_local! {
    static CLIENT: Client = Client::new(
        &std::env::var(API_URL_ENV).unwrap_or_else(|_| DEFAULT_API_URL.to_string()),
        Some(cache_path()),
        RateLimiter::new(MAX_REQUESTS_PER_MINUTE, WINDOW),
    );
}

/// Looks a hash up with the application's shared client (main thread only).
pub async fn check(sha256: &str, api_key: &str) -> Result<Lookup, VtError> {
    let client = CLIENT.with(Client::clone);
    client.check(sha256, api_key).await
}

#[cfg(test)]
mod tests {
    use std::io::{Read, Write};
    use std::net::TcpListener;

    use super::*;

    const HASH: &str = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";

    fn body(malicious: u64, suspicious: u64, undetected: u64) -> String {
        format!(
            r#"{{"data":{{"attributes":{{"last_analysis_stats":{{"malicious":{malicious},"suspicious":{suspicious},"undetected":{undetected},"harmless":0,"timeout":2}}}}}}}}"#
        )
    }

    #[test]
    fn parses_counts() {
        let reputation = parse_response(HASH, body(3, 1, 60).as_bytes(), 42).unwrap();
        assert_eq!(reputation.positives, 4);
        assert_eq!(reputation.total, 66);
        assert_eq!(reputation.summary(), "4 / 66");
        assert_eq!(reputation.checked_at, 42);
        assert!(reputation.permalink.ends_with(HASH));
    }

    #[test]
    fn rejects_garbage() {
        for bad in [
            "",
            "not json",
            "{}",
            r#"{"data":{"attributes":{}}}"#,
            r#"{"data":{"attributes":{"last_analysis_stats":{"malicious":-1}}}}"#,
            r#"{"data":{"attributes":{"last_analysis_stats":{"malicious":"many"}}}}"#,
            r#"{"data":{"attributes":{"last_analysis_stats":{"a":4294967295,"b":1}}}}"#,
        ] {
            assert!(
                matches!(
                    parse_response(HASH, bad.as_bytes(), 0),
                    Err(VtError::Parse(_))
                ),
                "{bad}"
            );
        }
    }

    #[test]
    fn validates_hashes() {
        assert!(is_valid_sha256(HASH));
        assert!(is_valid_sha256(&HASH.to_uppercase()));
        assert!(!is_valid_sha256(&HASH[1..]));
        assert!(!is_valid_sha256(&format!("{}/../x", &HASH[..56])));
        assert!(!is_valid_sha256(""));
    }

    #[test]
    fn rate_limiter_spreads_requests() {
        let start = Instant::now();
        let mut limiter = RateLimiter::new(2, Duration::from_secs(60));

        assert_eq!(limiter.reserve(start), Duration::ZERO);
        assert_eq!(
            limiter.reserve(start + Duration::from_secs(1)),
            Duration::ZERO
        );
        // the third has to wait for the first to leave the window
        assert_eq!(
            limiter.reserve(start + Duration::from_secs(2)),
            Duration::from_secs(58)
        );
        // the fourth waits for the second slot, one second later
        assert_eq!(
            limiter.reserve(start + Duration::from_secs(2)),
            Duration::from_secs(59)
        );
        // much later everything is free again
        assert_eq!(
            limiter.reserve(start + Duration::from_secs(600)),
            Duration::ZERO
        );
    }

    #[test]
    fn cache_roundtrip_and_validation() {
        let path = std::env::temp_dir().join(format!("res-vt-cache-{}", std::process::id()));
        let mut cache = Cache::default();
        cache.insert(
            HASH,
            Reputation {
                positives: 1,
                total: 70,
                permalink: report_url(HASH),
                checked_at: 7,
            },
        );
        cache.save(&path);
        let loaded = Cache::load(&path);
        assert_eq!(loaded.get(HASH), cache.get(HASH));

        // impossible counts and bad hashes are dropped
        let bad_hash = "a".repeat(64);
        std::fs::write(
            &path,
            format!(
                r#"{{"{HASH}":{{"positives":5,"total":2,"checked_at":1}},"nothash":{{"positives":0,"total":1,"checked_at":1}},"{bad_hash}":{{"positives":0,"total":1,"checked_at":1}}}}"#
            ),
        )
        .unwrap();
        let loaded = Cache::load(&path);
        assert!(loaded.get(HASH).is_none());
        assert!(loaded.get("nothash").is_none());
        assert!(loaded.get(&bad_hash).is_some());

        std::fs::write(&path, "garbage").unwrap();
        assert!(Cache::load(&path).get(&bad_hash).is_none());
        let _ = std::fs::remove_file(&path);
        assert!(Cache::load(&path).get(HASH).is_none());
    }

    /// Serves `responses` (status line + body), one per connection, and
    /// returns the base URL plus the requests received.
    fn serve(
        responses: Vec<(&'static str, String)>,
    ) -> (String, std::thread::JoinHandle<Vec<String>>) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let url = format!("http://{}/api/v3", listener.local_addr().unwrap());
        let handle = std::thread::spawn(move || {
            let mut requests = Vec::new();
            for (status, body) in responses {
                let (mut stream, _) = listener.accept().unwrap();
                let mut buffer = [0u8; 4096];
                let read = stream.read(&mut buffer).unwrap();
                requests.push(String::from_utf8_lossy(&buffer[..read]).to_string());
                let response = format!(
                    "HTTP/1.1 {status}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                );
                stream.write_all(response.as_bytes()).unwrap();
            }
            requests
        });
        (url, handle)
    }

    fn run<T>(future: impl std::future::Future<Output = T>) -> T {
        let context = glib::MainContext::new();
        context
            .with_thread_default(|| context.block_on(future))
            .unwrap()
    }

    fn client(url: &str) -> Client {
        run(async { Client::new(url, None, RateLimiter::new(100, Duration::from_secs(60))) })
    }

    #[test]
    fn lookup_over_http_sends_key_and_caches() {
        let (url, server) = serve(vec![("200 OK", body(2, 0, 50))]);
        let client = client(&url);

        let first = run(client.check(HASH, "secret-key")).unwrap();
        let Lookup::Found(reputation) = first else {
            panic!("expected a result");
        };
        assert_eq!((reputation.positives, reputation.total), (2, 54));

        // the second lookup must come from the cache: the server only
        // answers one connection
        assert_eq!(
            run(client.check(HASH, "secret-key")),
            Ok(Lookup::Found(reputation))
        );

        let requests = server.join().unwrap();
        assert_eq!(requests.len(), 1);
        assert!(
            requests[0].starts_with(&format!("GET /api/v3/files/{HASH} ")),
            "{}",
            requests[0]
        );
        assert!(requests[0].to_lowercase().contains("x-apikey: secret-key"));
    }

    #[test]
    fn status_codes_map_to_results() {
        let (url, server) = serve(vec![
            ("404 Not Found", "{}".into()),
            ("401 Unauthorized", "{}".into()),
            ("429 Too Many Requests", "{}".into()),
            ("500 Internal Server Error", "{}".into()),
            ("200 OK", "not json".into()),
        ]);
        let client = client(&url);

        assert_eq!(run(client.check(HASH, "k")), Ok(Lookup::Unknown));
        assert_eq!(run(client.check(HASH, "k")), Err(VtError::InvalidKey));
        assert_eq!(run(client.check(HASH, "k")), Err(VtError::RateLimited));
        assert_eq!(run(client.check(HASH, "k")), Err(VtError::Http(500)));
        assert!(matches!(
            run(client.check(HASH, "k")),
            Err(VtError::Parse(_))
        ));
        server.join().unwrap();
    }

    #[test]
    fn unknown_and_invalid_input_make_no_request() {
        // nothing is listening, a request would fail with a network error
        let client = client("http://127.0.0.1:1/api/v3");
        assert!(matches!(
            run(client.check("../../etc/passwd", "k")),
            Err(VtError::Parse(_))
        ));
        assert!(matches!(
            run(client.check(HASH, "k")),
            Err(VtError::Network(_))
        ));
    }
}
