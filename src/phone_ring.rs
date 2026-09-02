//! Shared phone-mode ring policy (stream + TUN).
//!
//! Inbound strangers stay ringing until Accept / Reject / timeout. Known
//! contacts auto-accept (see callers). Ring timeout is intentionally longer
//! than QUIC idle so a human can pick up.

use std::time::Duration;

use iroh::EndpointId;

use crate::contacts::{self, ContactBook};

/// How long an unanswered inbound ring stays pending before the daemon
/// closes the connection. Shared by stream `call` and `tun call`.
pub const RING_TIMEOUT: Duration = Duration::from_secs(120);

pub fn is_known_contact(book: &ContactBook, peer: EndpointId) -> bool {
    contacts::name_for_id(book, peer).is_some()
}

pub fn resolve_peer_token(book: &ContactBook, to: &str) -> anyhow::Result<EndpointId> {
    Ok(contacts::resolve(book, to)?.id)
}

pub fn match_peer_token(book: &ContactBook, token: &str, peer: EndpointId) -> bool {
    if token.eq_ignore_ascii_case(&peer.to_string()) {
        return true;
    }
    if let Ok(id) = contacts::parse_endpoint_token(token) {
        return id == peer;
    }
    contacts::name_for_id(book, peer)
        .map(|n| n.eq_ignore_ascii_case(token))
        .unwrap_or(false)
}
