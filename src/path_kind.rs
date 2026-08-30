//! Accurate iroh path classification (direct IP vs relay).
//!
//! **Do not** infer path type from Quinn `ConnectionStats::udp_tx/rx`.
//! iroh's magicsock presents *both* relay and hole-punched IP paths to Quinn
//! as UDP, so those counters grow whenever any traffic flows — including a
//! pure relay session. That made `link-p2p ping` report "direct (UDP)" on
//! relay-only links.
//!
//! Use [`Connection::paths`] instead: each path exposes `is_selected` /
//! `is_ip` / `is_relay` from iroh's transport layer (iroh 1.1+).

use std::time::{Duration, Instant};

use iroh::endpoint::Connection;
use tokio::time;

/// Selected / available path kind for a live connection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum PathKind {
    /// The selected transmission path is a real IP address (hole-punched or LAN).
    Direct,
    /// The selected path is a relay; no IP path is open in this snapshot.
    Relay,
    /// Selected path is still relay, but an IP path is also open (upgrade in
    /// progress, or relay preferred).
    RelayWithDirectCandidate,
    /// No open paths yet (very early after connect).
    Unknown,
}

impl PathKind {
    /// Stable machine token for logs / JSON (`ping --format json`).
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::Direct => "direct",
            Self::Relay => "relay",
            Self::RelayWithDirectCandidate => "relay+direct-candidate",
            Self::Unknown => "unknown",
        }
    }

    pub(crate) fn is_direct(self) -> bool {
        matches!(self, Self::Direct)
    }
}

/// Classify from a `paths()` snapshot. Prefer the *selected* path; fall back
/// to whatever is open if nothing is marked selected yet.
pub(crate) fn path_kind(conn: &Connection) -> PathKind {
    let paths = conn.paths();
    let mut has_ip = false;
    let mut has_relay = false;
    let mut selected_is_ip: Option<bool> = None;

    for p in paths.iter() {
        if p.is_ip() {
            has_ip = true;
        }
        if p.is_relay() {
            has_relay = true;
        }
        if p.is_selected() {
            selected_is_ip = Some(p.is_ip());
        }
    }

    match selected_is_ip {
        Some(true) => PathKind::Direct,
        Some(false) if has_ip => PathKind::RelayWithDirectCandidate,
        Some(false) => PathKind::Relay,
        None if has_ip && !has_relay => PathKind::Direct,
        None if has_relay && !has_ip => PathKind::Relay,
        None if has_ip && has_relay => PathKind::RelayWithDirectCandidate,
        None => PathKind::Unknown,
    }
}

/// Short label for tracing (`path=direct` / `path=relay` / …).
pub(crate) fn path_label(conn: &Connection) -> &'static str {
    path_kind(conn).as_str()
}

/// Wait briefly for magicsock to upgrade relay → direct after connect.
///
/// Handshake often completes on relay first; a zero-wait snapshot then
/// under-reports direct. Caps at `budget` so ping stays snappy.
pub(crate) async fn settle_path_kind(conn: &Connection, budget: Duration) -> PathKind {
    if budget.is_zero() {
        return path_kind(conn);
    }
    let deadline = Instant::now() + budget;
    loop {
        let kind = path_kind(conn);
        if kind.is_direct() || Instant::now() >= deadline {
            return kind;
        }
        // Magicsock upgrades on its own schedule; poll paths() rather than
        // pulling in an extra StreamExt dependency.
        time::sleep(Duration::from_millis(100)).await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn path_kind_tokens_are_stable() {
        assert_eq!(PathKind::Direct.as_str(), "direct");
        assert_eq!(PathKind::Relay.as_str(), "relay");
        assert_eq!(
            PathKind::RelayWithDirectCandidate.as_str(),
            "relay+direct-candidate"
        );
        assert_eq!(PathKind::Unknown.as_str(), "unknown");
    }
}
