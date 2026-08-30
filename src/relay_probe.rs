//! Concurrent TCP latency probe for relay URL ordering.
//!
//! Used before dial so the dial `EndpointAddr` lists the fastest responding
//! relay first. Magicsock may still pick by its own metrics; this only biases
//! the initial candidate order.

use std::net::ToSocketAddrs;
use std::time::{Duration, Instant};

use tokio::net::TcpStream;
use tokio::time::timeout;

/// Sort relay URLs by TCP connect RTT (fastest first). Unreachable URLs keep
/// their relative order at the end.
pub async fn order_by_connect_latency(urls: &[String]) -> Vec<String> {
    if urls.len() <= 1 {
        return urls.to_vec();
    }
    let mut join = tokio::task::JoinSet::new();
    for (i, u) in urls.iter().cloned().enumerate() {
        join.spawn(async move {
            let d = probe_one(&u).await;
            (d.unwrap_or(Duration::from_secs(60)), i, u)
        });
    }
    let mut scored = Vec::with_capacity(urls.len());
    while let Some(res) = join.join_next().await {
        if let Ok(row) = res {
            scored.push(row);
        }
    }
    scored.sort_by(|a, b| a.0.cmp(&b.0).then(a.1.cmp(&b.1)));
    scored.into_iter().map(|(_, _, u)| u).collect()
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
    let rest = url
        .split_once("://")
        .map(|(_, r)| r)
        .unwrap_or(url);
    let hostport = rest.split('/').next()?.split('?').next()?;
    let default_port: u16 = if url.starts_with("https") { 443 } else { 80 };
    let (host, port) = if let Some((h, p)) = hostport.rsplit_once(':') {
        let host = h.trim_start_matches('[').trim_end_matches(']');
        let port: u16 = p.parse().unwrap_or(default_port);
        (host, port)
    } else {
        let host = hostport.trim_start_matches('[').trim_end_matches(']');
        (host, default_port)
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
}

