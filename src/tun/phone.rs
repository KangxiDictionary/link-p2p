//! TUN phone mode: 1:1 peer calls with ring/accept for strangers.
//!
//! Known contacts auto-connect. Unknown inbound peers stay in
//! [`TunLiveState::pending_calls`] until Accept / Reject / timeout.
//! Outbound dials are queued via [`CallCmd`] from the control plane.

use std::time::{SystemTime, UNIX_EPOCH};

use super::*;
use crate::contacts;
use crate::tun_ctl::PendingCall;

const RING_TIMEOUT: Duration = Duration::from_secs(30);

struct Ringing {
    peer: EndpointId,
    conn: Connection,
    since: Instant,
    since_unix_ms: u64,
}

#[derive(Clone)]
struct ActivePeer {
    id: EndpointId,
    vip: Ipv4Addr,
    vip6: Ipv6Addr,
    outbound: mpsc::Sender<Bytes>,
}

type ActivePeers = Arc<arc_swap::ArcSwap<HashMap<EndpointId, ActivePeer>>>;
type RingingList = Arc<RwLock<Vec<Ringing>>>;

fn now_unix_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

fn is_known_contact(book: &contacts::ContactBook, peer: EndpointId) -> bool {
    contacts::name_for_id(book, peer).is_some()
}

fn resolve_peer_token(book: &contacts::ContactBook, to: &str) -> Result<EndpointId> {
    Ok(contacts::resolve(book, to)?.id)
}

fn match_peer_token(book: &contacts::ContactBook, token: &str, peer: EndpointId) -> bool {
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

async fn publish_pending(state: &TunLiveState, ringing: &RingingList) {
    let list = ringing.read().await;
    let calls: Vec<PendingCall> = list
        .iter()
        .map(|r| PendingCall {
            peer: r.peer.to_string(),
            since_unix_ms: r.since_unix_ms,
            direction: "in".into(),
        })
        .collect();
    state.set_pending_calls(calls).await;
}

async fn refresh_active_peers(state: &TunLiveState, peers: &ActivePeers) {
    let map = peers.load_full();
    let list: Vec<CtlPeer> = map
        .values()
        .map(|p| CtlPeer {
            vip: p.vip,
            vip6: p.vip6,
            id: p.id.to_string(),
        })
        .collect();
    state.set_peers(list).await;
}

/// Phone daemon: accept inbound, dial on [`CallCmd`], ring unknowns.
#[allow(clippy::too_many_arguments)]
pub async fn run_tun_phone(
    secret_key: SecretKey,
    tun_ip: Option<Ipv4Addr>,
    tun_ip6: Option<Ipv6Addr>,
    mtu: u16,
    relay: &[String],
    relay_only: bool,
    no_n0_relays: bool,
    keepalive: Duration,
    idle_timeout: Duration,
    tune: crate::TransportTune,
    allow: Option<HashSet<EndpointId>>,
    ui: crate::Ui,
    styler: Styler,
    hooks: Arc<TunHooks>,
) -> Result<()> {
    let (cmd_tx, mut cmd_rx) = mpsc::channel::<CallCmd>(TUN_CTRL_QUEUE);
    hooks.register_call_tx(cmd_tx);

    let endpoint = crate::build_endpoint(
        secret_key,
        relay,
        keepalive,
        idle_timeout,
        &tune,
        relay_only,
        no_n0_relays,
    )?
    .alpns(vec![TUN_ALPN.to_vec(), crate::PING_ALPN.to_vec()])
    .bind()
    .await
    .map_err(|e| {
        let err = anyhow::Error::new(e).context(tr!("binding endpoint"));
        hooks.signal_ready(Err(anyhow::anyhow!("{err:#}")));
        crate::exit::coded(crate::exit::CONNECT, err)
    })?;

    let own_id = endpoint.id();
    let own = match allocate_own_vips(tun_ip, tun_ip6, own_id) {
        Ok(v) => v,
        Err(e) => {
            hooks.signal_ready(Err(anyhow::anyhow!("{e:#}")));
            endpoint.close().await;
            return Err(e);
        }
    };
    if let Err(e) = crate::bring_endpoint_online(&endpoint, relay, no_n0_relays).await {
        hooks.signal_ready(Err(anyhow::anyhow!("{e:#}")));
        endpoint.close().await;
        return Err(e);
    }

    let (tun, tun_name) = match create_tun_device(own, mtu) {
        Ok(t) => t,
        Err(e) => {
            hooks.signal_ready(Err(anyhow::anyhow!("{e:#}")));
            endpoint.close().await;
            return Err(e);
        }
    };
    let (tun_io, mut from_tun) = spawn_tun_io(tun, mtu);
    hooks.state.set_vips(own).await;
    hooks.state.set_path_kind("idle").await;
    hooks.signal_ready(Ok(()));

    if !ui.quiet {
        ui.line(styler.ok(&tr_fmt!(
            "phone mode up. your virtual IPs: {0} / {1}",
            own.v4,
            own.v6
        )));
        ui.line(styler.dim(&tr_fmt!(
            "EndpointId {0} — dial with `tun call <contact>`",
            own_id
        )));
        ui.line(styler.dim(&tr!(
            "transport: QUIC datagrams (apps may use TCP/UDP inside the tunnel)"
        )));
    }

    // Contacts are stable for the daemon lifetime; reload via restart (or a
    // future ctl) rather than sync disk I/O on every dial/ring decision.
    let book = Arc::new(
        contacts::load(&contacts::contacts_path()).unwrap_or_default(),
    );

    let peers: ActivePeers = Arc::new(arc_swap::ArcSwap::from_pointee(HashMap::new()));
    let ringing: RingingList = Arc::new(RwLock::new(Vec::new()));
    let raise_gate = new_mtu_raise_gate();

    // Local TUN → active peer by destination VIP (v4 or v6).
    {
        let peers = Arc::clone(&peers);
        tokio::spawn(async move {
            while let Some(pkt) = from_tun.recv().await {
                let out = if let Some(dst) = ipv4_dst(&pkt) {
                    if dst == own.v4 || !vip_in_mesh(dst) {
                        None
                    } else {
                        peers
                            .load()
                            .values()
                            .find(|p| p.vip == dst)
                            .map(|p| p.outbound.clone())
                    }
                } else if let Some(dst) = ipv6_dst(&pkt) {
                    if dst == own.v6 || !vip6_in_mesh(dst) {
                        None
                    } else {
                        peers
                            .load()
                            .values()
                            .find(|p| p.vip6 == dst)
                            .map(|p| p.outbound.clone())
                    }
                } else {
                    None
                };
                if let Some(tx) = out {
                    let _ = tx.try_send(pkt);
                }
            }
        });
    }

    let mut tick = time::interval(Duration::from_secs(1));
    tick.set_missed_tick_behavior(time::MissedTickBehavior::Skip);

    loop {
        tokio::select! {
            incoming = endpoint.accept() => {
                let Some(incoming) = incoming else {
                    bail!(tr!("endpoint closed"));
                };
                let accepting = match incoming.accept() {
                    Ok(a) => a,
                    Err(e) => {
                        warn!(error = %e, "{}", tr!("rejecting malformed incoming connection"));
                        continue;
                    }
                };
                let conn = match accepting.await {
                    Ok(c) => c,
                    Err(e) => {
                        warn!(error = %e, "{}", tr!("completing connection handshake"));
                        continue;
                    }
                };
                if conn.alpn() == crate::PING_ALPN {
                    handle_ping_probe(conn);
                    continue;
                }
                let peer_id = conn.remote_id();
                if let Err(e) = check_allow(allow.as_ref(), peer_id) {
                    warn!(peer = %peer_id, error = format!("{e:#}"), "{}", tr!("TUN session error"));
                    conn.close(0u32.into(), b"denied");
                    continue;
                }
                if peers.load().contains_key(&peer_id) {
                    conn.close(0u32.into(), b"already connected");
                    continue;
                }
                if is_known_contact(&book, peer_id) {
                    spawn_phone_session(
                        tun_io.clone(),
                        tun_name.clone(),
                        own,
                        peer_id,
                        conn,
                        false,
                        mtu,
                        Arc::clone(&raise_gate),
                        Arc::clone(&peers),
                        Arc::clone(&hooks),
                        ui.quiet,
                        styler,
                        relay_only,
                        endpoint.clone(),
                    );
                } else {
                    info!(peer = %peer_id, "{}", tr!("incoming TUN call ringing"));
                    ringing.write().await.push(Ringing {
                        peer: peer_id,
                        conn,
                        since: Instant::now(),
                        since_unix_ms: now_unix_ms(),
                    });
                    publish_pending(&hooks.state, &ringing).await;
                }
            }
            cmd = cmd_rx.recv() => {
                let Some(cmd) = cmd else { break; };
                match cmd {
                    CallCmd::Dial { to } => {
                        match resolve_peer_token(&book, &to) {
                            Ok(peer_id) => {
                                if peer_id == own_id {
                                    warn!("{}", tr!("cannot call yourself"));
                                    continue;
                                }
                                if peers.load().contains_key(&peer_id) {
                                    info!(peer = %peer_id, "{}", tr!("already connected"));
                                    continue;
                                }
                                // Tie-break: only the lower id dials when both know each other.
                                if is_known_contact(&book, peer_id) && !should_dial(own_id, peer_id) {
                                    info!(
                                        peer = %peer_id,
                                        "{}",
                                        tr!("waiting for peer to dial (EndpointId tie-break)")
                                    );
                                    continue;
                                }
                                let dial_addr = match crate::build_dial_addr(peer_id, relay, &[]) {
                                    Ok(a) => a,
                                    Err(e) => {
                                        warn!(error = format!("{e:#}"), "{}", tr!("TUN call dial failed"));
                                        continue;
                                    }
                                };
                                let tun_io = tun_io.clone();
                                let tun_name = tun_name.clone();
                                let peers = Arc::clone(&peers);
                                let hooks = Arc::clone(&hooks);
                                let raise_gate = Arc::clone(&raise_gate);
                                let endpoint = endpoint.clone();
                                let quiet = ui.quiet;
                                tokio::spawn(async move {
                                    match endpoint.connect(dial_addr, TUN_ALPN).await {
                                        Ok(conn) => {
                                            spawn_phone_session(
                                                tun_io,
                                                tun_name,
                                                own,
                                                peer_id,
                                                conn,
                                                true,
                                                mtu,
                                                raise_gate,
                                                peers,
                                                hooks,
                                                quiet,
                                                styler,
                                                relay_only,
                                                endpoint,
                                            );
                                        }
                                        Err(e) => {
                                            warn!(
                                                peer = %peer_id,
                                                error = %e,
                                                "{}",
                                                tr!("TUN call dial failed")
                                            );
                                        }
                                    }
                                });
                            }
                            Err(e) => {
                                warn!(error = format!("{e:#}"), "{}", tr!("TUN call dial failed"));
                            }
                        }
                    }
                    CallCmd::Accept { peer } => {
                        let taken = {
                            let mut list = ringing.write().await;
                            let idx = list
                                .iter()
                                .position(|r| match_peer_token(&book, &peer, r.peer));
                            idx.map(|i| list.remove(i))
                        };
                        publish_pending(&hooks.state, &ringing).await;
                        match taken {
                            Some(r) => {
                                spawn_phone_session(
                                    tun_io.clone(),
                                    tun_name.clone(),
                                    own,
                                    r.peer,
                                    r.conn,
                                    false,
                                    mtu,
                                    Arc::clone(&raise_gate),
                                    Arc::clone(&peers),
                                    Arc::clone(&hooks),
                                    ui.quiet,
                                    styler,
                                    relay_only,
                                    endpoint.clone(),
                                );
                            }
                            None => {
                                warn!(
                                    peer = %peer,
                                    "{}",
                                    tr!("no pending call matching that peer")
                                );
                            }
                        }
                    }
                    CallCmd::Reject { peer } => {
                        let taken = {
                            let mut list = ringing.write().await;
                            let idx = list
                                .iter()
                                .position(|r| match_peer_token(&book, &peer, r.peer));
                            idx.map(|i| list.remove(i))
                        };
                        publish_pending(&hooks.state, &ringing).await;
                        if let Some(r) = taken {
                            r.conn.close(0u32.into(), b"rejected");
                            info!(peer = %r.peer, "{}", tr!("rejected TUN call"));
                        } else {
                            warn!(
                                peer = %peer,
                                "{}",
                                tr!("no pending call matching that peer")
                            );
                        }
                    }
                }
            }
            _ = tick.tick() => {
                let mut list = ringing.write().await;
                let before = list.len();
                list.retain(|r| {
                    if r.since.elapsed() > RING_TIMEOUT {
                        r.conn.close(0u32.into(), b"ring timeout");
                        false
                    } else {
                        true
                    }
                });
                if list.len() != before {
                    drop(list);
                    publish_pending(&hooks.state, &ringing).await;
                }
            }
            _ = hooks.cancel.notified() => {
                info!("{}", tr!("TUN daemon Shutdown requested"));
                break;
            }
        }
    }

    endpoint.close().await;
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn spawn_phone_session(
    tun_io: TunIo,
    tun_name: String,
    own: OwnVips,
    peer_id: EndpointId,
    conn: Connection,
    dialer: bool,
    mtu: u16,
    raise_gate: MtuRaiseGate,
    peers: ActivePeers,
    hooks: Arc<TunHooks>,
    quiet: bool,
    styler: Styler,
    relay_only: bool,
    endpoint: Endpoint,
) {
    crate::spawn_path_monitor(
        conn.clone(),
        peer_id,
        endpoint,
        relay_only,
        styler,
        quiet,
        "tun",
    );
    tokio::spawn(async move {
        if let Err(e) = phone_run_peer(
            tun_io,
            tun_name,
            own,
            peer_id,
            conn,
            dialer,
            mtu,
            raise_gate,
            peers,
            hooks,
            quiet,
        )
        .await
        {
            warn!(peer = %peer_id, error = format!("{e:#}"), "{}", tr!("TUN session error"));
        }
    });
}

#[allow(clippy::too_many_arguments)]
async fn phone_run_peer(
    tun: TunIo,
    tun_name: String,
    own: OwnVips,
    peer_id: EndpointId,
    conn: Connection,
    dialer: bool,
    user_mtu: u16,
    raise_gate: MtuRaiseGate,
    peers: ActivePeers,
    hooks: Arc<TunHooks>,
    quiet: bool,
) -> Result<()> {
    let peer = exchange_peer_vips(&conn, own, dialer).await?;
    if peer.v4 == own.v4
        || peer.v6 == own.v6
        || !vip_in_mesh(peer.v4)
        || !vip6_in_mesh(peer.v6)
    {
        bail!(tr_fmt!(
            "peer announced an unusable virtual IP {0} / {1}",
            peer.v4,
            peer.v6
        ));
    }

    let (out_tx, out_rx) = mpsc::channel::<Bytes>(TUN_PKT_QUEUE);
    spawn_peer_sender(
        tun.clone(),
        tun_name.clone(),
        own,
        peer_id,
        conn.clone(),
        out_rx,
        user_mtu,
        raise_gate,
    );

    // Atomic claim: rcu may retry under contention; success iff our peer_id
    // owns this VIP afterwards (no TOCTOU with a separate contains_key check).
    {
        let vip = peer.v4;
        let vip6 = peer.v6;
        let after = peers.rcu(|map| {
            if map.contains_key(&peer_id)
                || map
                    .values()
                    .any(|p| p.vip == vip || p.vip6 == vip6)
            {
                return (**map).clone();
            }
            let mut next = (**map).clone();
            next.insert(
                peer_id,
                ActivePeer {
                    id: peer_id,
                    vip,
                    vip6,
                    outbound: out_tx.clone(),
                },
            );
            next
        });
        match after.get(&peer_id) {
            Some(p) if p.vip == vip && p.vip6 == vip6 => {}
            _ => bail!(tr_fmt!(
                "virtual IP {0} / {1} is already claimed by another peer",
                vip,
                vip6
            )),
        }
    }
    if let Err(e) = add_peer_route(&tun_name, peer.v4, peer.v6) {
        peers.rcu(|map| {
            let mut next = (**map).clone();
            next.remove(&peer_id);
            next
        });
        return Err(e);
    }

    let _session_mtu = choose_mtu(user_mtu, &conn).unwrap_or(user_mtu);
    info!(%peer_id, vip = %peer.v4, vip6 = %peer.v6, path = path_label(&conn), "{}", tr!("TUN session established"));
    hooks.state.set_path_kind(path_label(&conn)).await;
    refresh_active_peers(&hooks.state, &peers).await;
    if !quiet {
        println!(
            "{}",
            tr_fmt!(
                "connected to {0} at {1} / {2}",
                peer_id.fmt_short(),
                peer.v4,
                peer.v6
            )
        );
    }

    // Peer → TUN (and only this peer; phone is 1:1 per session task).
    loop {
        tokio::select! {
            _ = conn.closed() => break,
            r = conn.read_datagram() => {
                match r {
                    Ok(data) => {
                        let ok_src = ipv4_src(&data).map(|s| s == peer.v4).unwrap_or(false)
                            || ipv6_src(&data).map(|s| s == peer.v6).unwrap_or(false);
                        if !ok_src {
                            continue;
                        }
                        let for_us = ipv4_dst(&data).map(|d| d == own.v4).unwrap_or(false)
                            || ipv6_dst(&data).map(|d| d == own.v6).unwrap_or(false);
                        if for_us {
                            tun.send(data).await;
                        }
                    }
                    Err(e) => {
                        warn!(peer = %peer_id, error = %e, "{}", tr!("datagram error; assuming transient path switch (iroh may be migrating the connection)"));
                    }
                }
            }
        }
    }

    peers.rcu(|map| {
        let mut next = (**map).clone();
        next.remove(&peer_id);
        next
    });
    refresh_active_peers(&hooks.state, &peers).await;
    if let Err(e) = del_peer_route(&tun_name, peer.v4, peer.v6) {
        warn!(%peer_id, error = %e, "{}", tr!("could not remove peer route"));
    }
    info!(%peer_id, vip = %peer.v4, vip6 = %peer.v6, "{}", tr!("peer left the mesh"));
    Ok(())
}
