//! TUN hub: accept spokes, VIP exchange, roster fan-out, mesh routing.

use super::*;

/// One spoke currently attached to the hub.
#[derive(Clone)]
struct HubPeer {
    id: EndpointId,
    conn: Connection,
    /// Non-blocking enqueue for datagrams destined to this spoke. A dedicated
    /// send task drains the channel so one congested peer cannot stall
    /// `read_datagram` / TUN demux for others (`send_datagram_wait` HoL).
    outbound: mpsc::Sender<Bytes>,
    /// When true, omit from roster snapshots / Joined broadcasts to others.
    hidden: bool,
}

type HubPeers = Arc<RwLock<HashMap<Ipv4Addr, HubPeer>>>;
/// Control-stream writers for roster push (one per spoke).
type RosterFans = Arc<RwLock<HashMap<EndpointId, mpsc::Sender<Bytes>>>>;

fn enqueue_peer(peer: &HubPeer, pkt: Bytes) {
    // Drop on full — same semantics as a lossy link / full datagram window.
    let _ = peer.outbound.try_send(pkt);
}

async fn broadcast_roster(fans: &RosterFans, msg: Bytes) {
    let senders: Vec<_> = fans.read().await.values().cloned().collect();
    for tx in senders {
        let _ = tx.send(msg.clone()).await;
    }
}

/// Roster entries visible to other spokes (hub always included; hidden peers omitted).
async fn hub_roster_snapshot(
    own_id: EndpointId,
    own_vip: Ipv4Addr,
    peers: &HubPeers,
) -> Vec<RosterEntry> {
    let mut entries = vec![RosterEntry {
        vip: own_vip,
        id: own_id,
    }];
    for (vip, p) in peers.read().await.iter() {
        if p.hidden {
            continue;
        }
        entries.push(RosterEntry {
            vip: *vip,
            id: p.id,
        });
    }
    entries
}

/// Hub: packets from the local TUN → spoke (by destination VIP).
async fn hub_tun_to_peers(
    mut from_tun: mpsc::Receiver<Bytes>,
    own_vip: Ipv4Addr,
    peers: HubPeers,
) {
    while let Some(pkt) = from_tun.recv().await {
        let Some(dst) = ipv4_dst(&pkt) else {
            continue;
        };
        if dst == own_vip || !vip_in_mesh(dst) {
            continue;
        }
        let peer = {
            let map = peers.read().await;
            map.get(&dst).cloned()
        };
        let Some(peer) = peer else {
            tracing::debug!(%dst, "no hub peer for destination VIP; dropping");
            continue;
        };
        enqueue_peer(&peer, pkt);
    }
}

/// Hub: packets from one spoke → local TUN and/or another spoke's outbound queue.
async fn hub_peer_to_mesh(
    tun: TunIo,
    own_vip: Ipv4Addr,
    peers: HubPeers,
    peer_vip: Ipv4Addr,
    peer: HubPeer,
) {
    loop {
        tokio::select! {
            _ = peer.conn.closed() => {
                info!(peer = %peer.id, %peer_vip, "{}", tr!("peer disconnected"));
                break;
            }
            r = peer.conn.read_datagram() => {
                match r {
                    Ok(data) => {
                        let Some(src) = ipv4_src(&data) else { continue };
                        if src != peer_vip {
                            tracing::debug!(%peer_vip, %src, "dropping spoofed source VIP");
                            continue;
                        }
                        let Some(dst) = ipv4_dst(&data) else { continue };
                        if dst == own_vip {
                            tun.send(data).await;
                            continue;
                        }
                        if !vip_in_mesh(dst) || dst == peer_vip {
                            continue;
                        }
                        let other = {
                            let map = peers.read().await;
                            map.get(&dst).cloned()
                        };
                        let Some(other) = other else {
                            tracing::debug!(%dst, "no hub peer for forwarded VIP; dropping");
                            continue;
                        };
                        enqueue_peer(&other, data);
                    }
                    Err(e) => {
                        warn!(peer = %peer.id, error = %e, "{}", tr!("datagram error; assuming transient path switch (iroh may be migrating the connection)"));
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
    let own_vip = tun_ip.unwrap_or_else(|| derive_vip(own_id));
    let signal_err = |e: &anyhow::Error| {
        if let Some(h) = &hooks {
            h.signal_ready(Err(anyhow::anyhow!("{e:#}")));
        }
    };
    if let Err(e) = ensure_vip_free(own_vip) {
        signal_err(&e);
        endpoint.close().await;
        return Err(e);
    }
    if let Err(e) = crate::bring_endpoint_online(&endpoint, relay, no_n0_relays).await {
        signal_err(&e);
        endpoint.close().await;
        return Err(e);
    }
    let (tun, tun_name) = match create_tun_device(own_vip, mtu) {
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
        h.state.set_vip(own_vip).await;
        h.signal_ready(Ok(()));
    }
    let (tun_io, from_tun) = spawn_tun_io(tun, mtu);
    let raise_gate = new_mtu_raise_gate();
    let peers: HubPeers = Arc::new(RwLock::new(HashMap::new()));
    let fans: RosterFans = Arc::new(RwLock::new(HashMap::new()));

    tokio::spawn(hub_tun_to_peers(from_tun, own_vip, Arc::clone(&peers)));

    if hooks.is_none() {
        ui.line(styler.banner("link-p2p tun serve"));
        ui.line(format!(
            "  {}",
            styler.dim(&tr!("your virtual IP (the peer reaches you here):"))
        ));
        ui.line(format!("    {}", styler.highlight(&own_vip.to_string())));
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
                        own_vip,
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
    own_vip: Ipv4Addr,
    peers: HubPeers,
    fans: RosterFans,
    peer_id: EndpointId,
    conn: Connection,
    user_mtu: u16,
    raise_gate: MtuRaiseGate,
    quiet: bool,
    hooks: Option<Arc<TunHooks>>,
) -> Result<()> {
    let peer_vip = exchange_peer_vip(&conn, own_vip, false).await?;
    if peer_vip == own_vip || !vip_in_mesh(peer_vip) {
        bail!(tr_fmt!(
            "peer announced an unusable virtual IP {0}",
            peer_vip
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

    let (out_tx, out_rx) = mpsc::channel::<Bytes>(256);
    let (fan_tx, mut fan_rx) = mpsc::channel::<Bytes>(32);
    let out_tx_mesh = out_tx.clone();
    spawn_peer_sender(
        tun.clone(),
        tun_name.clone(),
        own_vip,
        peer_id,
        conn.clone(),
        out_rx,
        user_mtu,
        raise_gate,
    );

    {
        let mut map = peers.write().await;
        if map.contains_key(&peer_vip) {
            bail!(tr_fmt!(
                "virtual IP {0} is already claimed by another peer",
                peer_vip
            ));
        }
        map.insert(
            peer_vip,
            HubPeer {
                id: peer_id,
                conn: conn.clone(),
                outbound: out_tx,
                hidden,
            },
        );
    }
    fans.write().await.insert(peer_id, fan_tx);

    if let Err(e) = add_peer_route(&tun_name, peer_vip, own_vip) {
        peers.write().await.remove(&peer_vip);
        fans.write().await.remove(&peer_id);
        return Err(e);
    }

    let session_mtu = choose_mtu(user_mtu, &conn).unwrap_or(user_mtu);
    info!(%peer_id, %peer_vip, hidden, path = path_label(&conn), "{}", tr!("TUN session established"));
    info!(%peer_id, "{}", tr_fmt!(
        "TUN datagram negotiation: max_datagram_size={0}, interface MTU={1}",
        conn.max_datagram_size().unwrap_or_default(),
        session_mtu
    ));
    if !quiet {
        println!(
            "{}",
            tr_fmt!(
                "peer {0} joined at {1}",
                peer_id.fmt_short(),
                peer_vip
            )
        );
    }

    // Snapshot to the new spoke, then Joined to everyone else (skip if hidden).
    let snap = hub_roster_snapshot(own_id, own_vip, &peers).await;
    let _ = write_msg(&mut ctrl_send, &encode_snapshot(&snap)).await;
    if !hidden {
        let joined = Bytes::from(encode_joined(&RosterEntry {
            vip: peer_vip,
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
        conn: conn.clone(),
        outbound: out_tx_mesh,
        hidden,
    };
    hub_peer_to_mesh(tun, own_vip, Arc::clone(&peers), peer_vip, hub_peer).await;

    ctrl_send_task.abort();
    peers.write().await.remove(&peer_vip);
    fans.write().await.remove(&peer_id);
    if !hidden {
        let left = Bytes::from(encode_left(&RosterEntry {
            vip: peer_vip,
            id: peer_id,
        }));
        broadcast_roster(&fans, left).await;
    }
    if let Some(h) = &hooks {
        refresh_hub_peers_state(&h.state, &peers).await;
    }
    if let Err(e) = del_peer_route(&tun_name, peer_vip) {
        warn!(%peer_id, error = %e, "{}", tr!("could not remove peer route"));
    }
    info!(%peer_id, %peer_vip, "{}", tr!("peer left the mesh"));
    Ok(())
}

async fn refresh_hub_peers_state(state: &TunLiveState, peers: &HubPeers) {
    let map = peers.read().await;
    let list: Vec<CtlPeer> = map
        .iter()
        .map(|(vip, p)| CtlPeer {
            vip: *vip,
            id: p.id.to_string(),
        })
        .collect();
    state.set_peers(list).await;
}

