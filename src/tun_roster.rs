//! Reliable mesh roster (VIP ↔ EndpointId) for TUN hub/spoke.
//!
//! Carried on a bidi control stream *after* the VIP exchange. Datagrams stay
//! unreliable for IP packets; membership must not be lossy.
//!
//! Magic `LPR3` (TUN ALPN `link-p2p/tun/3`): each entry is
//! IPv4 (4) + IPv6 (16) + EndpointId (32) = 52 bytes.

use std::net::{Ipv4Addr, Ipv6Addr};

use anyhow::{bail, Context, Result};
use iroh::EndpointId;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use crate::i18n::{tr, tr_fmt};

/// Control-plane magic for TUN ALPN `link-p2p/tun/3`.
pub const ROSTER_MAGIC: &[u8; 4] = b"LPR3";

pub const MSG_SNAPSHOT: u8 = 1;
pub const MSG_JOINED: u8 = 2;
pub const MSG_LEFT: u8 = 3;
/// Spoke → hub after opening the control stream: visibility flags.
pub const MSG_HELLO: u8 = 4;
/// Bit 0 of HELLO flags: omit this spoke from roster broadcasts to others.
pub const HELLO_FLAG_HIDDEN: u8 = 0x01;

const ENTRY_LEN: usize = 52;
/// Defensive cap on snapshot membership (mirrors `tun_ctl::CTL_MAX_PEERS`).
pub const ROSTER_MAX_ENTRIES: usize = 4096;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RosterEntry {
    pub vip: Ipv4Addr,
    pub vip6: Ipv6Addr,
    pub id: EndpointId,
}

impl RosterEntry {
    pub fn encode(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(&self.vip.octets());
        out.extend_from_slice(&self.vip6.octets());
        out.extend_from_slice(self.id.as_bytes());
    }

    pub fn decode(buf: &[u8]) -> Result<(Self, usize)> {
        if buf.len() < ENTRY_LEN {
            bail!(tr!("roster entry truncated"));
        }
        let vip = Ipv4Addr::new(buf[0], buf[1], buf[2], buf[3]);
        let mut v6 = [0u8; 16];
        v6.copy_from_slice(&buf[4..20]);
        let vip6 = Ipv6Addr::from(v6);
        let mut id_bytes = [0u8; 32];
        id_bytes.copy_from_slice(&buf[20..52]);
        let id = EndpointId::from_bytes(&id_bytes)
            .context(tr!("invalid EndpointId in roster"))?;
        Ok((Self { vip, vip6, id }, ENTRY_LEN))
    }
}

pub fn encode_hello(hidden: bool) -> Vec<u8> {
    let mut out = Vec::with_capacity(6);
    out.extend_from_slice(ROSTER_MAGIC);
    out.push(MSG_HELLO);
    out.push(if hidden { HELLO_FLAG_HIDDEN } else { 0 });
    out
}

/// Read a spoke HELLO; returns whether the spoke asked to stay hidden.
pub async fn read_hello<R: AsyncReadExt + Unpin>(r: &mut R) -> Result<bool> {
    let mut hdr = [0u8; 6];
    r.read_exact(&mut hdr).await?;
    if &hdr[..4] != ROSTER_MAGIC {
        bail!(tr!("bad roster magic"));
    }
    if hdr[4] != MSG_HELLO {
        bail!(tr_fmt!("expected roster HELLO, got type {0}", hdr[4]));
    }
    Ok(hdr[5] & HELLO_FLAG_HIDDEN != 0)
}

pub fn encode_snapshot(entries: &[RosterEntry]) -> Vec<u8> {
    let n = entries.len().min(ROSTER_MAX_ENTRIES);
    let n_u16 = u16::try_from(n).unwrap_or(u16::MAX);
    let mut out = Vec::with_capacity(4 + 1 + 2 + n * ENTRY_LEN);
    out.extend_from_slice(ROSTER_MAGIC);
    out.push(MSG_SNAPSHOT);
    out.extend_from_slice(&n_u16.to_be_bytes());
    for e in entries.iter().take(n) {
        e.encode(&mut out);
    }
    out
}

pub fn encode_joined(entry: &RosterEntry) -> Vec<u8> {
    let mut out = Vec::with_capacity(4 + 1 + ENTRY_LEN);
    out.extend_from_slice(ROSTER_MAGIC);
    out.push(MSG_JOINED);
    entry.encode(&mut out);
    out
}

pub fn encode_left(entry: &RosterEntry) -> Vec<u8> {
    let mut out = Vec::with_capacity(4 + 1 + ENTRY_LEN);
    out.extend_from_slice(ROSTER_MAGIC);
    out.push(MSG_LEFT);
    entry.encode(&mut out);
    out
}

#[derive(Debug, Clone)]
pub enum RosterMsg {
    Snapshot(Vec<RosterEntry>),
    Joined(RosterEntry),
    Left(RosterEntry),
}

/// Read one length-prefixed-ish message: magic + type + body (no outer length;
/// body size is implied by type).
pub async fn read_msg<R: AsyncReadExt + Unpin>(r: &mut R) -> Result<RosterMsg> {
    let mut hdr = [0u8; 5];
    r.read_exact(&mut hdr).await?;
    if &hdr[..4] != ROSTER_MAGIC {
        bail!(tr!("bad roster magic"));
    }
    match hdr[4] {
        MSG_SNAPSHOT => {
            let mut nb = [0u8; 2];
            r.read_exact(&mut nb).await?;
            let n = u16::from_be_bytes(nb) as usize;
            if n > ROSTER_MAX_ENTRIES {
                bail!(tr_fmt!(
                    "roster snapshot has too many entries ({0} > {1})",
                    n,
                    ROSTER_MAX_ENTRIES
                ));
            }
            let mut entries = Vec::with_capacity(n);
            let mut buf = vec![0u8; ENTRY_LEN];
            for _ in 0..n {
                r.read_exact(&mut buf).await?;
                let (e, _) = RosterEntry::decode(&buf)?;
                entries.push(e);
            }
            Ok(RosterMsg::Snapshot(entries))
        }
        MSG_JOINED => {
            let mut buf = [0u8; ENTRY_LEN];
            r.read_exact(&mut buf).await?;
            let (e, _) = RosterEntry::decode(&buf)?;
            Ok(RosterMsg::Joined(e))
        }
        MSG_LEFT => {
            let mut buf = [0u8; ENTRY_LEN];
            r.read_exact(&mut buf).await?;
            let (e, _) = RosterEntry::decode(&buf)?;
            Ok(RosterMsg::Left(e))
        }
        other => bail!(tr_fmt!("unknown roster msg type {0}", other)),
    }
}

pub async fn write_msg<W: AsyncWriteExt + Unpin>(w: &mut W, bytes: &[u8]) -> Result<()> {
    w.write_all(bytes).await?;
    w.flush().await?;
    Ok(())
}

/// Tie-break: the numerically lower EndpointId dials; the other waits for accept.
pub fn should_dial(own: EndpointId, peer: EndpointId) -> bool {
    own < peer
}

#[cfg(test)]
mod tests {
    use super::*;
    use iroh::SecretKey;

    fn decode_snapshot_sync(bytes: &[u8]) -> Vec<RosterEntry> {
        assert_eq!(&bytes[..4], ROSTER_MAGIC);
        assert_eq!(bytes[4], MSG_SNAPSHOT);
        let n = u16::from_be_bytes([bytes[5], bytes[6]]) as usize;
        let mut entries = Vec::new();
        let mut off = 7;
        for _ in 0..n {
            let (e, used) = RosterEntry::decode(&bytes[off..]).unwrap();
            entries.push(e);
            off += used;
        }
        entries
    }

    #[test]
    fn roundtrip_snapshot() {
        let a = SecretKey::generate();
        let b = SecretKey::generate();
        let entries = vec![
            RosterEntry {
                vip: Ipv4Addr::new(172, 24, 1, 1),
                vip6: "fd24:ac18::1".parse().unwrap(),
                id: a.public(),
            },
            RosterEntry {
                vip: Ipv4Addr::new(172, 24, 1, 2),
                vip6: "fd24:ac18::2".parse().unwrap(),
                id: b.public(),
            },
        ];
        let bytes = encode_snapshot(&entries);
        assert_eq!(decode_snapshot_sync(&bytes), entries);
    }

    #[tokio::test]
    async fn snapshot_rejects_oversized_count() {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(ROSTER_MAGIC);
        bytes.push(MSG_SNAPSHOT);
        let n = (ROSTER_MAX_ENTRIES + 1) as u16;
        bytes.extend_from_slice(&n.to_be_bytes());
        let err = read_msg(&mut bytes.as_slice()).await.unwrap_err();
        let msg = format!("{err:#}").to_ascii_lowercase();
        assert!(msg.contains("too many") || msg.contains("entries"), "{msg}");
    }

    #[test]
    fn encode_snapshot_caps_at_max() {
        let id = SecretKey::generate().public();
        let entries: Vec<_> = (0..ROSTER_MAX_ENTRIES + 3)
            .map(|i| RosterEntry {
                vip: Ipv4Addr::new(172, 24, (i / 256) as u8, (i % 256) as u8),
                vip6: "fd24:ac18::1".parse().unwrap(),
                id,
            })
            .collect();
        let bytes = encode_snapshot(&entries);
        let n = u16::from_be_bytes([bytes[5], bytes[6]]) as usize;
        assert_eq!(n, ROSTER_MAX_ENTRIES);
    }

    #[test]
    fn hello_hidden_flag_roundtrip() {
        let bytes = encode_hello(true);
        assert_eq!(&bytes[..4], ROSTER_MAGIC);
        assert_eq!(bytes[4], MSG_HELLO);
        assert_eq!(bytes[5] & HELLO_FLAG_HIDDEN, HELLO_FLAG_HIDDEN);
        let bytes = encode_hello(false);
        assert_eq!(bytes[5] & HELLO_FLAG_HIDDEN, 0);
    }

    #[test]
    fn tie_break_symmetric() {
        let a = SecretKey::generate().public();
        let b = SecretKey::generate().public();
        assert_ne!(should_dial(a, b), should_dial(b, a));
        assert!(!should_dial(a, a));
    }

    #[test]
    fn only_one_side_dials_across_random_pairs() {
        for _ in 0..64 {
            let a = SecretKey::generate().public();
            let b = SecretKey::generate().public();
            if a == b {
                continue;
            }
            let ab = should_dial(a, b);
            let ba = should_dial(b, a);
            assert!(ab ^ ba, "exactly one of {{a→b, b→a}} must dial");
        }
    }
}
