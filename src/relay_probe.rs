//! Concurrent TCP latency probe for relay URL ordering.
//!
//! Used before dial so the dial `EndpointAddr` lists the fastest responding
//! relay first. Magicsock may still pick by its own metrics; this only biases
//! the initial candidate order.
//!
//! Fresh samples are persisted under [`crate::relay_rtt`] (`relay-rtt.json`).
//! When every URL has a cache entry younger than [`relay_rtt::CACHE_TTL`], this
//! returns the cached order immediately and refreshes in the background so the
//! first dial is not blocked on TCP probes.
//!
//! **Limitation:** probes use TCP connect RTT. Hole-punch / QUIC traffic is
//! UDP — a host can pass TCP and still block UDP (or the reverse). Treat the
//! ranking as a soft hint; confirm real paths with `ping` / `stats`.

use std::net::ToSocketAddrs;
use std::time::{Duration, Instant};

use tracing::{debug, warn};

use tokio::net::TcpStream;
use tokio::time::timeout;

use crate::relay_rtt;

/// Sort relay URLs by TCP connect RTT (fastest first). Unreachable URLs keep
/// their relative order at the end and emit a warning so operators notice a
/// dead `--relay` before `wait_online` times out on n0 alone.
pub async fn order_by_connect_latency(urls: &[String]) -> Vec<String> {
    if urls.is_empty() {
        return Vec::new();
    }

    if let Some(cached) = relay_rtt::order_from_fresh_cache(urls) {
        debug!(n = cached.len(), "using fresh relay RTT cache (background refresh)");
        let urls_bg = urls.to_vec();
        tokio::spawn(async move {
            let _ = probe_and_record(&urls_bg).await;
        });
        return cached;
    }

    probe_and_record(urls).await
}

async fn probe_and_record(urls: &[String]) -> Vec<String> {
    if urls.len() == 1 {
        let u = &urls[0];
        let d = probe_one(u).await;
        if d.is_none() {
            warn!(
                relay = %u,
                "custom relay TCP probe failed (unreachable or timed out within 2s)"
            );
        }
        relay_rtt::record_probe_results(&[(u.clone(), d)]);
        return urls.to_vec();
    }

    let mut join = tokio::task::JoinSet::new();
    for (i, u) in urls.iter().cloned().enumerate() {
        join.spawn(async move {
            let d = probe_one(&u).await;
            (d, i, u)
        });
    }
    let mut scored = Vec::with_capacity(urls.len());
    while let Some(res) = join.join_next().await {
        if let Ok(row) = res {
            scored.push(row);
        }
    }
    scored.sort_by(|a, b| {
        let da = a.0.unwrap_or(Duration::from_secs(60));
        let db = b.0.unwrap_or(Duration::from_secs(60));
        da.cmp(&db).then(a.1.cmp(&b.1))
    });

    let results: Vec<(String, Option<Duration>)> = scored
        .iter()
        .map(|(d, _, u)| (u.clone(), *d))
        .collect();
    relay_rtt::record_probe_results(&results);

    for (d, _, u) in &scored {
        if d.is_none() {
            warn!(
                relay = %u,
                "custom relay TCP probe failed (unreachable or timed out within 2s)"
            );
        }
    }
    scored.into_iter().map(|(_, _, u)| u).collect()
}

/// Human-readable probe lines for `tun selftest` (ok / fail per URL).
pub async fn probe_report(urls: &[String]) -> Vec<(String, Option<Duration>)> {
    let mut out = Vec::with_capacity(urls.len());
    for u in urls {
        out.push((u.clone(), probe_one(u).await));
    }
    relay_rtt::record_probe_results(&out);
    out
}

async fn probe_one(url: &str) -> Option<Duration> {
    let addr = host_port(url)?;
    let start = Instant::now();
    timeout(Duration::from_secs(2), TcpStream::connect(addr))
        .await
        .ok()?
        .ok()?;
    Some(start.elapsed())
}

fn host_port(url: &str) -> Option<std::net::SocketAddr> {
    // Minimal parse: scheme://host:port/... or scheme://host/...
    // Bracketed IPv6 (`[::1]` / `[::1]:443`) must not use a naive rsplit on
    // ':' — the address itself contains colons.
    let rest = url
        .split_once("://")
        .map(|(_, r)| r)
        .unwrap_or(url);
    let hostport = rest.split('/').next()?.split('?').next()?;
    let default_port: u16 = if url.starts_with("https") { 443 } else { 80 };
    let (host, port) = if hostport.starts_with('[') {
        let end = hostport.find(']')?;
        let host = &hostport[1..end];
        let port = if hostport[end + 1..].starts_with(':') {
            hostport[end + 2..].parse().unwrap_or(default_port)
        } else {
            default_port
        };
        (host, port)
    } else if let Some((h, p)) = hostport.rsplit_once(':') {
        let port: u16 = p.parse().unwrap_or(default_port);
        (h, port)
    } else {
        (hostport, default_port)
    };
    (host, port).to_socket_addrs().ok()?.next()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_localhost_http() {
        let a = host_port("http://127.0.0.1:3340").expect("parse");
        assert_eq!(a.port(), 3340);
    }

    #[test]
    fn parses_ipv6_literal() {
        let a = host_port("http://[::1]:3340").expect("parse");
        assert_eq!(a.port(), 3340);
        assert!(a.ip().is_ipv6());
    }

    #[test]
    fn parses_ipv6_literal_default_http_port() {
        let a = host_port("http://[::1]").expect("parse");
        assert_eq!(a.port(), 80);
        assert!(a.ip().is_ipv6());
    }

    #[test]
    fn parses_ipv6_literal_default_https_port() {
        let a = host_port("https://[::1]/path").expect("parse");
        assert_eq!(a.port(), 443);
        assert!(a.ip().is_ipv6());
    }
}
