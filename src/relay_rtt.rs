//! Persistent TCP-probe RTT hints for relay URL ordering.
//!
//! Stored beside config as `relay-rtt.json` (not in `config.toml`) so operator
//! edits to relay lists are not entangled with automatic latency samples.
//! Fresh cache entries (< [`CACHE_TTL`]) skip a synchronous probe on startup
//! and return immediately; a background refresh updates the file.

use std::collections::HashMap;
use std::fs;
use std::path::PathBuf;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};
use tracing::debug;

use crate::config;

/// How long a cached RTT stays "fresh" enough to skip a blocking probe.
pub const CACHE_TTL: Duration = Duration::from_secs(24 * 60 * 60);

#[derive(Debug, Clone, Serialize, Deserialize)]
struct Entry {
    /// Milliseconds; `None` / omitted means last probe failed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    rtt_ms: Option<u64>,
    /// Unix seconds when this sample was written.
    updated_unix: u64,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
struct CacheFile {
    #[serde(default)]
    relays: HashMap<String, Entry>,
}

fn cache_path() -> PathBuf {
    config::config_dir().join("relay-rtt.json")
}

fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn load() -> CacheFile {
    let path = cache_path();
    match fs::read_to_string(&path) {
        Ok(text) => serde_json::from_str(&text).unwrap_or_default(),
        Err(_) => CacheFile::default(),
    }
}

fn save(cache: &CacheFile) {
    let path = cache_path();
    if let Some(parent) = path.parent() {
        let _ = fs::create_dir_all(parent);
    }
    if let Ok(text) = serde_json::to_string_pretty(cache) {
        let _ = fs::write(&path, text);
    }
}

/// If every URL has a fresh cache entry, return them sorted by RTT (failures
/// last). Otherwise `None` — caller should probe synchronously.
pub fn order_from_fresh_cache(urls: &[String]) -> Option<Vec<String>> {
    if urls.is_empty() {
        return Some(Vec::new());
    }
    let cache = load();
    let now = now_unix();
    let ttl = CACHE_TTL.as_secs();
    let mut scored = Vec::with_capacity(urls.len());
    for (i, u) in urls.iter().enumerate() {
        let e = cache.relays.get(u)?;
        if now.saturating_sub(e.updated_unix) > ttl {
            return None;
        }
        let rank = e.rtt_ms.unwrap_or(u64::MAX / 2);
        scored.push((rank, i, u.clone()));
    }
    scored.sort_by(|a, b| a.0.cmp(&b.0).then(a.1.cmp(&b.1)));
    Some(scored.into_iter().map(|(_, _, u)| u).collect())
}

/// Merge probe results into the on-disk cache (best-effort).
pub fn record_probe_results(results: &[(String, Option<Duration>)]) {
    if results.is_empty() {
        return;
    }
    let mut cache = load();
    let now = now_unix();
    for (url, d) in results {
        cache.relays.insert(
            url.clone(),
            Entry {
                rtt_ms: d.map(|x| x.as_millis() as u64),
                updated_unix: now,
            },
        );
    }
    // Drop entries for URLs not seen in a long time? Keep simple: leave orphans;
    // file stays small (a handful of relays).
    save(&cache);
    debug!(n = results.len(), "updated relay RTT cache");
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    static LOCK: Mutex<()> = Mutex::new(());

    #[test]
    fn fresh_cache_orders_by_rtt() {
        let _g = LOCK.lock().unwrap();
        let dir = std::env::temp_dir().join(format!("link-p2p-rtt-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        let prev = std::env::var_os("XDG_CONFIG_HOME");
        std::env::set_var("XDG_CONFIG_HOME", &dir);

        record_probe_results(&[
            ("http://slow".into(), Some(Duration::from_millis(200))),
            ("http://fast".into(), Some(Duration::from_millis(10))),
            ("http://dead".into(), None),
        ]);
        let ordered = order_from_fresh_cache(&[
            "http://slow".into(),
            "http://dead".into(),
            "http://fast".into(),
        ])
        .expect("fresh");
        assert_eq!(
            ordered,
            vec![
                "http://fast".to_string(),
                "http://slow".to_string(),
                "http://dead".to_string()
            ]
        );

        match prev {
            Some(v) => std::env::set_var("XDG_CONFIG_HOME", v),
            None => std::env::remove_var("XDG_CONFIG_HOME"),
        }
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn stale_or_missing_returns_none() {
        let _g = LOCK.lock().unwrap();
        let dir = std::env::temp_dir().join(format!("link-p2p-rtt2-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        let prev = std::env::var_os("XDG_CONFIG_HOME");
        std::env::set_var("XDG_CONFIG_HOME", &dir);

        assert!(order_from_fresh_cache(&["http://x".into()]).is_none());

        match prev {
            Some(v) => std::env::set_var("XDG_CONFIG_HOME", v),
            None => std::env::remove_var("XDG_CONFIG_HOME"),
        }
        let _ = fs::remove_dir_all(&dir);
    }
}
