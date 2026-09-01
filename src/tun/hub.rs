//! TUN hub: accept spokes, VIP exchange, roster fan-out, mesh routing.

use super::*;

/// One spoke currently attached to the hub.
#[derive(Clone)]
struct HubPeer {
    id: EndpointId,
    vip: Ipv4Addr,
    vip6: Ipv6Addr,
    conn: Connection,
    /// Non-blocking enqueue for datagrams destined to this spoke. A dedicated
    /// send task drains the channel so one congested peer cannot stall
    /// `read_datagram` / TUN demux for others (`send_datagram_wait` HoL).
    outbound: mpsc::Sender<Bytes>,
    /// When true, omit from roster snapshots / Joined broadcasts to others.
    hidden: bool,
}

/// Dual-stack peer index in one ArcSwap so claim/remove update v4+v6 atomically.
#[derive(Clone, Default)]
struct HubPeerIndex {
    by_v4: HashMap<Ipv4Addr, HubPeer>,
    by_v6: HashMap<Ipv6Addr, HubPeer>,
}

type HubPeers = Arc<arc_swap::ArcSwap<HubPeerIndex>>;
/// Control-stream writers for roster push (one per spoke).
type RosterFans = Arc<RwLock<HashMap<EndpointId, mpsc::Sender<Bytes>>>>;

fn enqueue_peer(peer: &HubPeer, pkt: Bytes) {
    // Drop on full — same semantics as a lossy link / full datagram window.
    let _ = peer.outbound.try_send(pkt);
}

/// Insert peer under both VIP keys, or leave the index unchanged if either VIP
/// is taken. Under `rcu` contention the closure may retry; success is verified
/// by checking that *our* `peer_id` owns `vip` afterwards (no TOCTOU window).
fn try_claim_peer(peers: &HubPeers, peer: HubPeer) -> Result<()> {
    let vip = peer.vip;
    let vip6 = peer.vip6;
    let peer_id = peer.id;
    let after = peers.rcu(|idx| {
        if idx.by_v4.contains_key(&vip) || idx.by_v6.contains_key(&vip6) {
            return (**idx).clone();
        }
        let mut next = (**idx).clone();
        next.by_v4.insert(vip, peer.clone());
        next.by_v6.insert(vip6, peer.clone());
        next
    });
    match after.by_v4.get(&vip) {
        Some(p) if p.id == peer_id => Ok(()),
        _ => bail!(tr_fmt!(
            "virtual IP {0} / {1} is already claimed by another peer",
            vip,
            vip6
        )),
    }
}

fn peers_remove(peers: &HubPeers, vip: Ipv4Addr, vip6: Ipv6Addr) {
    peers.rcu(|idx| {
        let mut next = (**idx).clone();
        next.by_v4.remove(&vip);
        next.by_v6.remove(&vip6);
        next
    });
}

async fn broadcast_roster(fans: &RosterFans, msg: Bytes) {
    let senders: Vec<_> = fans.read().await.values().cloned().collect();
    for tx in senders {
        let _ = tx.send(msg.clone()).await;
    }
}

/// Roster entries visible to other spokes (hub always included; hidden peers omitted).
fn hub_roster_snapshot(
    own_id: EndpointId,
    own: OwnVips,
    peers: &HubPeers,
) -> Vec<RosterEntry> {
    let mut entries = vec![RosterEntry {
        vip: own.v4,
        vip6: own.v6,
        id: own_id,
    }];
    for p in peers.load().by_v4.values() {
        if p.hidden {
            continue;
        }
        entries.push(RosterEntry {
            vip: p.vip,
            vip6: p.vip6,
            id: p.id,
        });
    }
    entries
}

fn lookup_hub_peer(peers: &HubPeers, pkt: &[u8]) -> Option<HubPeer> {
    let idx = peers.load();
    if let Some(dst) = ipv4_dst(pkt) {
        return idx.by_v4.get(&dst).cloned();
    }
    if let Some(dst) = ipv6_dst(pkt) {
        return idx.by_v6.get(&dst).cloned();
    }
    None
}

fn packet_destined_here(pkt: &[u8], own: OwnVips) -> bool {
    if let Some(dst) = ipv4_dst(pkt) {
        return dst == own.v4;
    }
    if let Some(dst) = ipv6_dst(pkt) {
        return dst == own.v6;
    }
    false
}

fn packet_src_matches_peer(pkt: &[u8], peer: &HubPeer) -> bool {
    if let Some(src) = ipv4_src(pkt) {
        return src == peer.vip;
    }
    if let Some(src) = ipv6_src(pkt) {
        return src == peer.vip6;
    }
    false
}

fn mesh_dst_ok(pkt: &[u8], peer: &HubPeer) -> bool {
    if let Some(dst) = ipv4_dst(pkt) {
        return vip_in_mesh(dst) && dst != peer.vip;
    }
    if let Some(dst) = ipv6_dst(pkt) {
        return vip6_in_mesh(dst) && dst != peer.vip6;
    }
    false
}

/// Hub: packets from the local TUN → spoke (by destination VIP).
async fn hub_tun_to_peers(
    mut from_tun: mpsc::Receiver<Bytes>,
    own: OwnVips,
    peers: HubPeers,
) {
    while let Some(pkt) = from_tun.recv().await {
        if packet_destined_here(&pkt, own) {
            continue;
        }
        let skip = match (ipv4_dst(&pkt), ipv6_dst(&pkt)) {
            (Some(dst), _) => !vip_in_mesh(dst),
            (None, Some(dst)) => !vip6_in_mesh(dst),
            (None, None) => true,
        };
        if skip {
            continue;
        }
        let Some(peer) = lookup_hub_peer(&peers, &pkt) else {
            tracing::debug!("no hub peer for destination VIP; dropping");
            continue;
        };
        enqueue_peer(&peer, pkt);
    }
}

/// Hub: packets from one spoke → local TUN and/or another spoke's outbound queue.
async fn hub_peer_to_mesh(
    tun: TunIo,
    own: OwnVips,
    peers: HubPeers,
    peer: HubPeer,
) {
    let peer_vip = peer.vip;
    let peer_id = peer.id;
    loop {
        tokio::select! {
            _ = peer.conn.closed() => {
                info!(peer = %peer_id, %peer_vip, "{}", tr!("peer disconnected"));
                break;
            }
            r = peer.conn.read_datagram() => {
                match r {
                    Ok(data) => {
                        if !packet_src_matches_peer(&data, &peer) {
                            tracing::debug!(%peer_vip, "dropping spoofed source VIP");
                            continue;
                        }
                        if packet_destined_here(&data, own) {
                            tun.send(data).await;
                            continue;
                        }
                        if !mesh_dst_ok(&data, &peer) {
                            continue;
                        }
                        let Some(other) = lookup_hub_peer(&peers, &data) else {
                            tracing::debug!("no hub peer for forwarded VIP; dropping");
                            continue;
                        };
                        enqueue_peer(&other, data);
                    }
                    Err(e) => {
                        warn!(peer = %peer_id, error = %e, "{}", tr!("datagram error; assuming transient path switch (iroh may be migrating the connection)"));
                    }
                }
            }
        }
    }
}

/// Exposed side (`tun serve`): hub for many concurrent spokes. Keeps accepting
/// while sessions run; pushes a VIP↔EndpointId roster; demuxes local TUN
/// traffic and forwards spoke→spoke (fallback when spokes have no direct path).
pub async fn run_tun_serve(
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
    hooks: Option<Arc<TunHooks>>,
) -> Result<()> {
    let endpoint = match crate::build_endpoint(
        secret_key,
        relay,
        keepalive,
        idle_timeout,
        &tune,
        relay_only,
        no_n0_relays,
    ) {
        Ok(b) => b
            .alpns(vec![TUN_ALPN.to_vec(), crate::PING_ALPN.to_vec()])
            .bind()
            .await
            .map_err(|e| {
                crate::exit::coded(
                    crate::exit::CONNECT,
                    anyhow::Error::new(e).context(tr!("binding endpoint")),
                )
            }),
        Err(e) => Err(e),
    };
    let endpoint = match endpoint {
        Ok(e) => e,
        Err(e) => {
            if let Some(h) = &hooks {
                h.signal_ready(Err(anyhow::anyhow!("{e:#}")));
            }
            return Err(e);
        }
    };

    let own_id = endpoint.id();
    let signal_err = |e: &anyhow::Error| {
        if let Some(h) = &hooks {
            h.signal_ready(Err(anyhow::anyhow!("{e:#}")));
        }
    };
    let own = match allocate_own_vips(tun_ip, tun_ip6, own_id) {
        Ok(v) => v,
        Err(e) => {
            signal_err(&e);
            endpoint.close().await;
            return Err(e);
        }
    };
    if let Err(e) = crate::bring_endpoint_online(&endpoint, relay, no_n0_relays).await {
        signal_err(&e);
        endpoint.close().await;
        return Err(e);
    }
    let (tun, tun_name) = match create_tun_device(own, mtu) {
        Ok(x) => x,
        Err(e) => {
            if let Some(h) = &hooks {
                h.signal_ready(Err(anyhow::anyhow!("{e:#}")));
            }
            endpoint.close().await;
            return Err(e);
        }
    };
    if let Some(h) = &hooks {
        h.state.set_vips(own).await;
        h.signal_ready(Ok(()));
    }
    let (tun_io, from_tun) = spawn_tun_io(tun, mtu);
    let raise_gate = new_mtu_raise_gate();
    let peers: HubPeers = Arc::new(arc_swap::ArcSwap::from_pointee(HubPeerIndex::default()));
    let fans: RosterFans = Arc::new(RwLock::new(HashMap::new()));

    tokio::spawn(hub_tun_to_peers(from_tun, own, Arc::clone(&peers)));

    if hooks.is_none() {
        ui.line(styler.banner("link-p2p tun serve"));
        ui.line(format!(
            "  {}",
            styler.dim(&tr!("your virtual IPs (the peer reaches you here):"))
        ));
        ui.line(format!("    {}", styler.highlight(&own.v4.to_string())));
        ui.line(format!("    {}", styler.highlight(&own.v6.to_string())));
        ui.line(format!(
            "  {}",
            styler.dim(&tr!(
                "your EndpointId (give this to peers running `tun connect --to`):"
            ))
        ));
        let ep_hex = own_id.to_string();
        ui.line(format!("    {}", styler.highlight(&ep_hex)));
        // Machine-readable for scripts / e2e — always stdout, even under `-q`.
        println!("ENDPOINT_ID={ep_hex}");
        ui.line(format!(
            "  {}",
            styler.dim(&tr!(
                "hub mode: roster + fallback forward; spokes may peer directly"
            ))
        ));
        ui.line(format!(
            "  {}",
            styler.dim(&tr!(
                "transport: QUIC datagrams (apps may use TCP/UDP inside the tunnel)"
            ))
        ));
        if allow.is_some() {
            ui.line(format!(
                "  {}",
                styler.dim(&tr!("only accepting connections from the --allow list"))
            ));
        }
        ui.line("");
        ui.line(styler.dim(&tr!("Press Ctrl+C to stop.")));
    } else {
        // Daemon: still emit machine-readable id on stdout of the worker (→ tun.log).
        let ep_hex = own_id.to_string();
        println!("ENDPOINT_ID={ep_hex}");
    }

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

                let tun_io = tun_io.clone();
                let peers = Arc::clone(&peers);
                let fans = Arc::clone(&fans);
                let tun_name = tun_name.clone();
                let raise_gate = Arc::clone(&raise_gate);
                let user_mtu = mtu;
                let hooks_s = hooks.clone();
                crate::spawn_path_monitor(
                    conn.clone(),
                    peer_id,
                    endpoint.clone(),
                    relay_only,
                    styler,
                    ui.quiet,
                    "tun",
                );
                let quiet = ui.quiet;
                tokio::spawn(async move {
                    if let Err(e) = hub_run_spoke(
                        tun_io,
                        tun_name,
                        own_id,
                        own,
                        peers,
                        fans,
                        peer_id,
                        conn,
                        user_mtu,
                        raise_gate,
                        quiet,
                        hooks_s,
                    )
                    .await
                    {
                        warn!(peer = %peer_id, error = format!("{e:#}"), "{}", tr!("TUN session error"));
                    }
                });
            }
            _ = tokio::signal::ctrl_c(), if hooks.is_none() => {
                ui.line(styler.warn(&tr!("shutting down...")));
                break;
            }
            _ = async {
                match &hooks {
                    Some(h) => h.cancel.notified().await,
                    None => std::future::pending().await,
                }
            } => {
                info!("{}", tr!("TUN daemon Shutdown requested"));
                break;
            }
        }
    }
    endpoint.close().await;
    Ok(())
}

async fn hub_run_spoke(
    tun: TunIo,
    tun_name: String,
    own_id: EndpointId,
    own: OwnVips,
    peers: HubPeers,
    fans: RosterFans,
    peer_id: EndpointId,
    conn: Connection,
    user_mtu: u16,
    raise_gate: MtuRaiseGate,
    quiet: bool,
    hooks: Option<Arc<TunHooks>>,
) -> Result<()> {
    let peer = exchange_peer_vips(&conn, own, false).await?;
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

    // Control stream: spoke opens after VIP exchange; optional HELLO then we push roster.
    let (mut ctrl_send, mut ctrl_recv) = time::timeout(VIP_EXCHANGE_TIMEOUT, conn.accept_bi())
        .await
        .map_err(|_| {
            crate::exit::coded(
                crate::exit::TIMEOUT,
                anyhow::anyhow!(tr!("peer did not open the TUN roster control stream")),
            )
        })?
        .context(tr!("accepting TUN roster control stream"))?;

    let hidden = match time::timeout(Duration::from_millis(800), read_hello(&mut ctrl_recv)).await {
        Ok(Ok(h)) => h,
        _ => false,
    };

    let (out_tx, out_rx) = mpsc::channel::<Bytes>(TUN_PKT_QUEUE);
    let (fan_tx, mut fan_rx) = mpsc::channel::<Bytes>(TUN_CTRL_QUEUE);
    let out_tx_mesh = out_tx.clone();
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

    try_claim_peer(
        &peers,
        HubPeer {
            id: peer_id,
            vip: peer.v4,
            vip6: peer.v6,
            conn: conn.clone(),
            outbound: out_tx.clone(),
            hidden,
        },
    )?;
    fans.write().await.insert(peer_id, fan_tx);

    if let Err(e) = add_peer_route(&tun_name, peer.v4, peer.v6) {
        peers_remove(&peers, peer.v4, peer.v6);
        fans.write().await.remove(&peer_id);
        return Err(e);
    }

    let session_mtu = choose_mtu(user_mtu, &conn).unwrap_or(user_mtu);
    info!(%peer_id, vip = %peer.v4, vip6 = %peer.v6, hidden, path = path_label(&conn), "{}", tr!("TUN session established"));
    info!(%peer_id, "{}", tr_fmt!(
        "TUN datagram negotiation: max_datagram_size={0}, interface MTU={1}",
        conn.max_datagram_size().unwrap_or_default(),
        session_mtu
    ));
    if !quiet {
        println!(
            "{}",
            tr_fmt!(
                "peer {0} joined at {1} / {2}",
                peer_id.fmt_short(),
                peer.v4,
                peer.v6
            )
        );
    }

    // Snapshot to the new spoke, then Joined to everyone else (skip if hidden).
    let snap = hub_roster_snapshot(own_id, own, &peers);
    let _ = write_msg(&mut ctrl_send, &encode_snapshot(&snap)).await;
    if !hidden {
        let joined = Bytes::from(encode_joined(&RosterEntry {
            vip: peer.v4,
            vip6: peer.v6,
            id: peer_id,
        }));
        broadcast_roster(&fans, joined).await;
    }

    if let Some(h) = &hooks {
        h.state.set_path_kind(path_label(&conn)).await;
        refresh_hub_peers_state(&h.state, &peers).await;
    }

    // Fan-out task: roster updates for this spoke.
    let ctrl_send_task = {
        let mut ctrl_send = ctrl_send;
        tokio::spawn(async move {
            while let Some(msg) = fan_rx.recv().await {
                if write_msg(&mut ctrl_send, &msg).await.is_err() {
                    break;
                }
            }
        })
    };

    let hub_peer = HubPeer {
        id: peer_id,
        vip: peer.v4,
        vip6: peer.v6,
        conn: conn.clone(),
        outbound: out_tx_mesh,
        hidden,
    };
    hub_peer_to_mesh(tun, own, Arc::clone(&peers), hub_peer).await;

    ctrl_send_task.abort();
    peers_remove(&peers, peer.v4, peer.v6);
    fans.write().await.remove(&peer_id);
    if !hidden {
        let left = Bytes::from(encode_left(&RosterEntry {
            vip: peer.v4,
            vip6: peer.v6,
            id: peer_id,
        }));
        broadcast_roster(&fans, left).await;
    }
    if let Some(h) = &hooks {
        refresh_hub_peers_state(&h.state, &peers).await;
    }
    if let Err(e) = del_peer_route(&tun_name, peer.v4, peer.v6) {
        warn!(%peer_id, error = %e, "{}", tr!("could not remove peer route"));
    }
    info!(%peer_id, vip = %peer.v4, vip6 = %peer.v6, "{}", tr!("peer left the mesh"));
    Ok(())
}

async fn refresh_hub_peers_state(state: &TunLiveState, peers: &HubPeers) {
    let idx = peers.load_full();
    let list: Vec<CtlPeer> = idx
        .by_v4
        .values()
        .map(|p| CtlPeer {
            vip: p.vip,
            vip6: p.vip6,
            id: p.id.to_string(),
        })
        .collect();
    state.set_peers(list).await;
}
