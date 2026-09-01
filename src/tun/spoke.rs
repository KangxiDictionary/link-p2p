//! TUN spoke: dial hub, install mesh route, optional peer-to-peer shortcuts.

use super::*;

/// Spoke-side mesh table: hub fallback + optional direct peer connections.
#[derive(Clone)]
struct SpokeMesh {
    #[allow(dead_code)]
    own_id: EndpointId,
    #[allow(dead_code)]
    own: OwnVips,
    hub_vip: Option<Ipv4Addr>,
    hub_vip6: Option<Ipv6Addr>,
    hub_out: Option<mpsc::Sender<Bytes>>,
    /// Direct links keyed by IPv4 VIP.
    direct: HashMap<Ipv4Addr, mpsc::Sender<Bytes>>,
    /// Direct links keyed by IPv6 VIP.
    direct6: HashMap<Ipv6Addr, mpsc::Sender<Bytes>>,
    /// Known EndpointId → VIPs (from roster); used to decide dial vs wait.
    roster: HashMap<EndpointId, OwnVips>,
}

impl SpokeMesh {
    fn new(own_id: EndpointId, own: OwnVips) -> Self {
        Self {
            own_id,
            own,
            hub_vip: None,
            hub_vip6: None,
            hub_out: None,
            direct: HashMap::new(),
            direct6: HashMap::new(),
            roster: HashMap::new(),
        }
    }

    fn clear_hub(&mut self) {
        self.hub_vip = None;
        self.hub_vip6 = None;
        self.hub_out = None;
    }

    fn lookup_out(&self, pkt: &[u8]) -> Option<mpsc::Sender<Bytes>> {
        if let Some(dst) = ipv4_dst(pkt) {
            // The hub's own VIP always goes via the dedicated hub connection
            // (hub_out). A roster-dial of the hub must never install a direct
            // link that shadows it: that direct connection has no roster
            // control stream and the hub rejects it, so packets would vanish.
            if self.hub_vip == Some(dst) {
                return self.hub_out.clone();
            }
            if let Some(tx) = self.direct.get(&dst) {
                return Some(tx.clone());
            }
            if vip_in_mesh(dst) {
                return self.hub_out.clone();
            }
            return None;
        }
        if let Some(dst) = ipv6_dst(pkt) {
            if self.hub_vip6 == Some(dst) {
                return self.hub_out.clone();
            }
            if let Some(tx) = self.direct6.get(&dst) {
                return Some(tx.clone());
            }
            if vip6_in_mesh(dst) {
                return self.hub_out.clone();
            }
        }
        None
    }
}

type SharedSpokeMesh = Arc<arc_swap::ArcSwap<SpokeMesh>>;

fn mesh_update(mesh: &SharedSpokeMesh, f: impl FnOnce(&mut SpokeMesh)) {
    // Infrequent join/leave path: clone snapshot, mutate, store. Packet path
    // only `load()`s and never waits.
    let mut next = (*mesh.load_full()).clone();
    f(&mut next);
    mesh.store(Arc::new(next));
}

fn spawn_conn_sender(
    tun: TunIo,
    tun_name: String,
    own: OwnVips,
    peer: EndpointId,
    conn: Connection,
    rx: mpsc::Receiver<Bytes>,
    user_mtu: u16,
    raise_gate: MtuRaiseGate,
) {
    spawn_peer_sender(tun, tun_name, own, peer, conn, rx, user_mtu, raise_gate);
}

async fn spoke_install_direct(
    mesh: &SharedSpokeMesh,
    tun: TunIo,
    tun_name: &str,
    own: OwnVips,
    peer_id: EndpointId,
    peer: OwnVips,
    conn: Connection,
    user_mtu: u16,
    raise_gate: MtuRaiseGate,
) {
    if peer.v4 == own.v4 || peer.v6 == own.v6 {
        return;
    }
    let (tx, rx) = mpsc::channel::<Bytes>(TUN_PKT_QUEUE);
    spawn_conn_sender(
        tun.clone(),
        tun_name.to_string(),
        own,
        peer_id,
        conn.clone(),
        rx,
        user_mtu,
        raise_gate,
    );
    {
        let tx4 = tx.clone();
        mesh_update(mesh, |g| {
            g.roster.insert(peer_id, peer);
            g.direct.insert(peer.v4, tx4);
            g.direct6.insert(peer.v6, tx);
        });
    }
    info!(%peer_id, vip = %peer.v4, vip6 = %peer.v6, path = path_label(&conn), "{}", tr!("direct mesh link ready"));
    // Read datagrams from this direct link into TUN.
    let mesh_drop = Arc::clone(mesh);
    let peer_c = peer;
    let span = tracing::info_span!("spoke_direct_recv", %peer_id);
    tokio::spawn(
        async move {
            loop {
                tokio::select! {
                    _ = conn.closed() => break,
                    r = conn.read_datagram() => {
                        match r {
                            Ok(data) => {
                                let ok = ipv4_src(&data).map(|s| s == peer_c.v4).unwrap_or(false)
                                    || ipv6_src(&data).map(|s| s == peer_c.v6).unwrap_or(false);
                                if !ok {
                                    continue;
                                }
                                tun.send(data).await;
                            }
                            Err(_) => break,
                        }
                    }
                }
            }
            mesh_update(&mesh_drop, |g| {
                g.direct.remove(&peer_c.v4);
                g.direct6.remove(&peer_c.v6);
            });
            info!(%peer_id, vip = %peer_c.v4, "{}", tr!("direct mesh link closed"));
        }
        .instrument(span),
    );
}

async fn spoke_try_dial_peer(
    endpoint: Endpoint,
    mesh: SharedSpokeMesh,
    tun: TunIo,
    tun_name: String,
    own_id: EndpointId,
    own: OwnVips,
    entry: RosterEntry,
    user_mtu: u16,
    allow: Option<HashSet<EndpointId>>,
    raise_gate: MtuRaiseGate,
) {
    let peer = entry.id;
    async move {
        spoke_try_dial_peer_inner(
            endpoint, mesh, tun, tun_name, own_id, own, entry, user_mtu, allow, raise_gate,
        )
        .await;
    }
    .instrument(tracing::info_span!("spoke_try_dial", %peer))
    .await;
}

async fn spoke_try_dial_peer_inner(
    endpoint: Endpoint,
    mesh: SharedSpokeMesh,
    tun: TunIo,
    tun_name: String,
    own_id: EndpointId,
    own: OwnVips,
    entry: RosterEntry,
    user_mtu: u16,
    allow: Option<HashSet<EndpointId>>,
    raise_gate: MtuRaiseGate,
) {
    if entry.id == own_id || entry.vip == own.v4 || entry.vip6 == own.v6 {
        return;
    }
    if let Err(e) = check_allow(allow.as_ref(), entry.id) {
        warn!(peer = %entry.id, error = format!("{e:#}"), "{}", tr!("skipping mesh peer (not allowed)"));
        return;
    }
    if !should_dial(own_id, entry.id) {
        return;
    }
    if mesh.load().direct.contains_key(&entry.vip) {
        return;
    }
    let dial = EndpointAddr::from(entry.id);
    match endpoint.connect(dial, TUN_ALPN).await {
        Ok(conn) => {
            match exchange_peer_vips(&conn, own, true).await {
                Ok(vip) if vip.v4 == entry.vip && vip.v6 == entry.vip6 => {
                    // Spokes do not open a roster control stream on direct links.
                    spoke_install_direct(
                        &mesh,
                        tun,
                        &tun_name,
                        own,
                        entry.id,
                        vip,
                        conn,
                        user_mtu,
                        raise_gate,
                    )
                    .await;
                }
                Ok(vip) => {
                    warn!(
                        peer = %entry.id,
                        expected_v4 = %entry.vip,
                        expected_v6 = %entry.vip6,
                        got_v4 = %vip.v4,
                        got_v6 = %vip.v6,
                        "{}",
                        tr!("direct mesh VIP mismatch; closing")
                    );
                }
                Err(e) => {
                    warn!(peer = %entry.id, error = format!("{e:#}"), "{}", tr!("direct mesh VIP exchange failed"));
                }
            }
        }
        Err(e) => {
            info!(peer = %entry.id, error = %e, "{}", tr!("direct mesh dial failed; using hub fallback"));
        }
    }
}

async fn spoke_apply_roster_msg(
    endpoint: Endpoint,
    mesh: SharedSpokeMesh,
    tun: TunIo,
    tun_name: String,
    own_id: EndpointId,
    own: OwnVips,
    msg: RosterMsg,
    user_mtu: u16,
    allow: Option<HashSet<EndpointId>>,
    raise_gate: MtuRaiseGate,
    quiet: bool,
) {
    match msg {
        RosterMsg::Snapshot(entries) => {
            let mut entries = entries;
            // Prefer peers that historically punched through before unknown /
            // relay-heavy ones (soft order only; hub fallback still works).
            crate::path_stats::sort_by_direct_history(&mut entries, |e| e.id.to_string());
            for e in entries {
                if e.id == own_id {
                    continue;
                }
                mesh_update(&mesh, |g| {
                    g.roster.insert(
                        e.id,
                        OwnVips {
                            v4: e.vip,
                            v6: e.vip6,
                        },
                    );
                });
                let ep = endpoint.clone();
                let mesh = Arc::clone(&mesh);
                let tun = tun.clone();
                let tun_name = tun_name.clone();
                let allow = allow.clone();
                let raise_gate = Arc::clone(&raise_gate);
                tokio::spawn(async move {
                    spoke_try_dial_peer(
                        ep,
                        mesh,
                        tun,
                        tun_name,
                        own_id,
                        own,
                        e,
                        user_mtu,
                        allow,
                        raise_gate,
                    )
                    .await;
                });
            }
        }
        RosterMsg::Joined(e) => {
            if e.id == own_id {
                return;
            }
            mesh_update(&mesh, |g| {
                g.roster.insert(
                    e.id,
                    OwnVips {
                        v4: e.vip,
                        v6: e.vip6,
                    },
                );
            });
            if !quiet {
                println!(
                    "{}",
                    tr_fmt!(
                        "mesh peer {0} at {1} / {2}",
                        e.id.fmt_short(),
                        e.vip,
                        e.vip6
                    )
                );
            }
            tokio::spawn(spoke_try_dial_peer(
                endpoint,
                mesh,
                tun,
                tun_name,
                own_id,
                own,
                e,
                user_mtu,
                allow,
                raise_gate,
            ));
        }
        RosterMsg::Left(e) => {
            mesh_update(&mesh, |g| {
                g.roster.remove(&e.id);
                g.direct.remove(&e.vip);
                g.direct6.remove(&e.vip6);
            });
            info!(peer = %e.id, vip = %e.vip, vip6 = %e.vip6, "{}", tr!("mesh peer left"));
        }
    }
}

/// Connecting side (`tun connect`): join a hub mesh, learn the roster, try
/// direct spoke links, fall back to hub forward.
#[allow(clippy::too_many_arguments)]
pub async fn run_tun_connect(
    secret_key: SecretKey,
    to: &str,
    tun_ip: Option<Ipv4Addr>,
    tun_ip6: Option<Ipv6Addr>,
    mtu: u16,
    relay: &[String],
    relay_only: bool,
    no_n0_relays: bool,
    to_addr: Vec<SocketAddr>,
    keepalive: Duration,
    idle_timeout: Duration,
    tune: crate::TransportTune,
    allow: Option<HashSet<EndpointId>>,
    ui: crate::Ui,
    styler: Styler,
    hooks: Option<Arc<TunHooks>>,
) -> Result<()> {
    let hidden = std::env::var_os("LINK_P2P_TUN_HIDDEN").is_some();
    run_tun_connect_inner(
        secret_key,
        to,
        tun_ip,
        tun_ip6,
        mtu,
        relay,
        relay_only,
        no_n0_relays,
        to_addr,
        keepalive,
        idle_timeout,
        tune,
        allow,
        hidden,
        ui,
        styler,
        hooks,
    )
    .await
}

/// Connecting side with explicit roster visibility.
#[allow(clippy::too_many_arguments)]
async fn run_tun_connect_inner(
    secret_key: SecretKey,
    to: &str,
    tun_ip: Option<Ipv4Addr>,
    tun_ip6: Option<Ipv6Addr>,
    mtu: u16,
    relay: &[String],
    relay_only: bool,
    no_n0_relays: bool,
    to_addr: Vec<SocketAddr>,
    keepalive: Duration,
    idle_timeout: Duration,
    tune: crate::TransportTune,
    allow: Option<HashSet<EndpointId>>,
    hidden: bool,
    ui: crate::Ui,
    styler: Styler,
    hooks: Option<Arc<TunHooks>>,
) -> Result<()> {
    crate::reject_relay_only_with_to_addr(relay_only, &to_addr)?;
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
        crate::exit::coded(
            crate::exit::CONNECT,
            anyhow::Error::new(e).context(tr!("binding endpoint")),
        )
    })?;

    let hub_id: EndpointId = match to.parse() {
        Ok(id) => id,
        Err(e) => {
            let err = anyhow::Error::new(e).context(tr_fmt!("'{0}' is not a valid EndpointId", to));
            if let Some(h) = &hooks {
                h.signal_ready(Err(anyhow::anyhow!("{err:#}")));
            }
            endpoint.close().await;
            return Err(err);
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

    let dial_addr = match crate::build_dial_addr(hub_id, relay, &to_addr) {
        Ok(a) => a,
        Err(e) => {
            signal_err(&e);
            endpoint.close().await;
            return Err(e);
        }
    };
    if !to_addr.is_empty() && hooks.is_none() {
        ui.line(format!(
            "  {}",
            styler.dim(&tr_fmt!(
                "dialing the peer's direct address hint(s): {0}",
                to_addr
                    .iter()
                    .map(|a| a.to_string())
                    .collect::<Vec<_>>()
                    .join(", ")
            ))
        ));
    }

    let (tun, tun_name) = match create_tun_device(own, mtu) {
        Ok(x) => x,
        Err(e) => {
            signal_err(&e);
            endpoint.close().await;
            return Err(e);
        }
    };
    if let Some(h) = &hooks {
        h.state.set_vips(own).await;
        // Spoke ready after TUN exists; hub dial may still be in progress.
        h.state.apply_phase(PhaseEvent::Ready).await;
        h.signal_ready(Ok(()));
    }
    let (tun_io, mut from_tun) = spawn_tun_io(tun, mtu);
    let raise_gate = new_mtu_raise_gate();
    let mesh: SharedSpokeMesh =
        Arc::new(arc_swap::ArcSwap::from_pointee(SpokeMesh::new(own_id, own)));

    // Long-lived TUN → mesh demux (hub and direct outs live in SpokeMesh).
    {
        let mesh_d = Arc::clone(&mesh);
        let own_c = own;
        tokio::spawn(async move {
            while let Some(pkt) = from_tun.recv().await {
                if packet_is_own(&pkt, own_c) {
                    continue;
                }
                let out = mesh_d.load().lookup_out(&pkt);
                if let Some(tx) = out {
                    let _ = tx.try_send(pkt);
                }
            }
        });
    }

    // Accept inbound direct mesh dials (and ping) for the process lifetime.
    {
        let endpoint_acc = endpoint.clone();
        let mesh_acc = Arc::clone(&mesh);
        let tun_acc = tun_io.clone();
        let tun_name_acc = tun_name.clone();
        let allow_acc = allow.clone();
        let raise_gate_acc = Arc::clone(&raise_gate);
        tokio::spawn(async move {
            while let Some(incoming) = endpoint_acc.accept().await {
                let Ok(accepting) = incoming.accept() else {
                    continue;
                };
                let Ok(conn) = accepting.await else {
                    continue;
                };
                if conn.alpn() == crate::PING_ALPN {
                    handle_ping_probe(conn);
                    continue;
                }
                if conn.alpn() != TUN_ALPN {
                    continue;
                }
                let peer = conn.remote_id();
                if let Err(e) = check_allow(allow_acc.as_ref(), peer) {
                    warn!(%peer, error = format!("{e:#}"), "{}", tr!("TUN session error"));
                    conn.close(0u32.into(), b"denied");
                    continue;
                }
                // Only accept if we are the lower id (tie-break): the other side dials.
                if should_dial(own_id, peer) {
                    conn.close(0u32.into(), b"tie-break");
                    continue;
                }
                let tun = tun_acc.clone();
                let mesh = Arc::clone(&mesh_acc);
                let tun_name = tun_name_acc.clone();
                let raise_gate = Arc::clone(&raise_gate_acc);
                tokio::spawn(async move {
                    match exchange_peer_vips(&conn, own, false).await {
                        Ok(vip) => {
                            spoke_install_direct(
                                &mesh, tun, &tun_name, own, peer, vip, conn, mtu, raise_gate,
                            )
                            .await;
                        }
                        Err(e) => {
                            warn!(%peer, error = format!("{e:#}"), "{}", tr!("TUN session error"));
                        }
                    }
                });
            }
        });
    }

    let mut connected_once = false;
    let mut backoff = crate::Backoff::new(crate::RECONNECT_BASE, crate::RECONNECT_MAX);
    let mut delay: Option<Duration> = None;
    loop {
        if let Some(d) = delay {
            tokio::select! {
                _ = time::sleep(d) => {}
                _ = tokio::signal::ctrl_c(), if hooks.is_none() => {
                    ui.line(styler.warn(&tr!("shutting down...")));
                    endpoint.close().await;
                    return Ok(());
                }
                _ = async {
                    match &hooks {
                        Some(h) => h.cancel.notified().await,
                        None => std::future::pending().await,
                    }
                } => {
                    info!("{}", tr!("TUN daemon Shutdown requested"));
                    endpoint.close().await;
                    return Ok(());
                }
            }
        }

        ui.line(styler.info(&tr_fmt!("dialing {0}...", hub_id)));
        let session_started = Instant::now();
        let session = async {
            let conn = endpoint
                .connect(dial_addr.clone(), TUN_ALPN)
                .await
                .map_err(|e| {
                    crate::exit::coded(
                        crate::exit::CONNECT,
                        anyhow::Error::new(e).context(tr!("connecting to remote endpoint")),
                    )
                })?;
            let hub = exchange_peer_vips(&conn, own, true).await?;

            // Control stream for roster (we are dialer → open_bi).
            let (mut ctrl_send, mut ctrl_recv) = conn
                .open_bi()
                .await
                .context(tr!("opening TUN roster control stream"))?;
            let _ = write_msg(&mut ctrl_send, &encode_hello(hidden)).await;
            drop(ctrl_send); // hub writes; we only read

            let user_mtu = mtu;
            let mut session_mtu = choose_mtu(user_mtu, &conn)?;
            set_tun_mtu(&tun_name, session_mtu)?;
            add_mesh_route(&tun_name)?;
            info!(peer_id = %hub_id, path = path_label(&conn), "{}", tr_fmt!(
                "TUN datagram negotiation: max_datagram_size={0}, interface MTU={1}",
                conn.max_datagram_size().unwrap_or_default(),
                session_mtu
            ));
            crate::spawn_path_monitor(
                conn.clone(),
                hub_id,
                endpoint.clone(),
                relay_only,
                styler,
                ui.quiet,
                "tun",
            );

            if let Some(h) = &hooks {
                h.state.set_path_kind(path_label(&conn)).await;
                h.state.apply_phase(PhaseEvent::Connected).await;
            }

            let (hub_tx, hub_rx) = mpsc::channel::<Bytes>(TUN_PKT_QUEUE);
            spawn_conn_sender(
                tun_io.clone(),
                tun_name.clone(),
                own,
                hub_id,
                conn.clone(),
                hub_rx,
                user_mtu,
                Arc::clone(&raise_gate),
            );
            {
                mesh_update(&mesh, |g| {
                    g.hub_vip = Some(hub.v4);
                    g.hub_vip6 = Some(hub.v6);
                    g.hub_out = Some(hub_tx);
                    g.roster.insert(hub_id, hub);
                });
            }

            if !connected_once {
                connected_once = true;
                if hooks.is_none() {
                    ui.line(styler.ok(&tr_fmt!(
                        "connected. your virtual IPs: {0} / {1}",
                        own.v4,
                        own.v6
                    )));
                    ui.line(styler.dim(&tr_fmt!(
                        "hub {0} is at {1} / {2} (path {3}); peers may connect directly",
                        hub_id.fmt_short(),
                        hub.v4,
                        hub.v6,
                        path_label(&conn)
                    )));
                    ui.line(styler.dim(&tr!(
                        "transport: QUIC datagrams (apps may use TCP/UDP inside the tunnel)"
                    )));
                    ui.line(styler.dim(&tr!("Press Ctrl+C to stop.")));
                }
            }

            if let Some(h) = &hooks {
                let peers: Vec<CtlPeer> = mesh
                    .load()
                    .roster
                    .iter()
                    .map(|(id, v)| CtlPeer {
                        vip: v.v4,
                        vip6: v.v6,
                        id: id.to_string(),
                    })
                    .collect();
                h.state.set_peers(peers).await;
            }

            // Roster reader
            let endpoint_r = endpoint.clone();
            let mesh_r = Arc::clone(&mesh);
            let tun_r = tun_io.clone();
            let tun_name_r = tun_name.clone();
            let allow_r = allow.clone();
            let raise_gate_r = Arc::clone(&raise_gate);
            let quiet_r = ui.quiet;
            let roster_task = tokio::spawn(async move {
                loop {
                    match read_msg(&mut ctrl_recv).await {
                        Ok(msg) => {
                            spoke_apply_roster_msg(
                                endpoint_r.clone(),
                                Arc::clone(&mesh_r),
                                tun_r.clone(),
                                tun_name_r.clone(),
                                own_id,
                                own,
                                msg,
                                user_mtu,
                                allow_r.clone(),
                                Arc::clone(&raise_gate_r),
                                quiet_r,
                            )
                            .await;
                        }
                        Err(e) => {
                            warn!(error = format!("{e:#}"), "{}", tr!("roster control stream closed"));
                            break;
                        }
                    }
                }
            });

            // Hub → TUN
            let tun_h = tun_io.clone();
            let hub_c = hub;
            let conn_r = conn.clone();
            let hub_read = tokio::spawn(async move {
                loop {
                    tokio::select! {
                        _ = conn_r.closed() => break,
                        r = conn_r.read_datagram() => {
                            match r {
                                Ok(data) => {
                                    let ok = match (ipv4_src(&data), ipv6_src(&data)) {
                                        (Some(src), _) => vip_in_mesh(src) || src == hub_c.v4,
                                        (None, Some(src)) => vip6_in_mesh(src) || src == hub_c.v6,
                                        (None, None) => false,
                                    };
                                    if !ok {
                                        continue;
                                    }
                                    tun_h.send(data).await;
                                }
                                Err(_) => break,
                            }
                        }
                    }
                }
            });

            let end = loop {
                tokio::select! {
                    biased;
                    _ = tokio::signal::ctrl_c(), if hooks.is_none() => {
                        ui.line(styler.warn(&tr!("shutting down...")));
                        break SessionEnd::CtrlC;
                    }
                    _ = async {
                        match &hooks {
                            Some(h) => h.cancel.notified().await,
                            None => std::future::pending().await,
                        }
                    } => {
                        info!("{}", tr!("TUN daemon Shutdown requested"));
                        break SessionEnd::CtrlC;
                    }
                    _ = conn.closed() => {
                        info!(peer_id = %hub_id, "{}", tr!("peer disconnected"));
                        break SessionEnd::PeerGone;
                    }
                    _ = time::sleep(Duration::from_secs(2)) => {
                        let _ = refresh_tun_mtu(
                            &tun_name,
                            user_mtu,
                            &conn,
                            &mut session_mtu,
                            raise_after_now(&raise_gate),
                        );
                        if let Some(h) = &hooks {
                            h.state.set_path_kind(path_label(&conn)).await;
                        }
                    }
                }
            };

            roster_task.abort();
            hub_read.abort();
            mesh_update(&mesh, |g| g.clear_hub());
            Ok::<_, anyhow::Error>((end, true))
        }
        .await;

        let (end, had_route) = match session {
            Ok(x) => x,
            Err(e) => {
                warn!(peer_id = %hub_id, error = format!("{e:#}"), "{}", tr!("TUN session error"));
                (SessionEnd::PeerGone, false)
            }
        };
        if matches!(end, SessionEnd::CtrlC) {
            if had_route {
                let _ = del_mesh_route(&tun_name);
            }
            break;
        }
        let lived = session_started.elapsed();
        if let Some(next) = backoff.after_session(lived, crate::MIN_STABLE_CONN) {
            delay = Some(next);
            info!(
                peer_id = %hub_id,
                lived_ms = lived.as_millis() as u64,
                "{}",
                tr_fmt!("reconnecting in {0}", format!("{next:?}"))
            );
        } else {
            // Stable session ended — redial without climbing backoff, but
            // still take the base delay so we don't hot-loop on a flapping hub.
            let next = crate::RECONNECT_BASE;
            delay = Some(next);
            info!(peer_id = %hub_id, "{}", tr_fmt!("reconnecting in {0}", format!("{next:?}")));
        }
    }
    let _ = del_mesh_route(&tun_name);
    endpoint.close().await;
    Ok(())
}

fn packet_is_own(pkt: &[u8], own: OwnVips) -> bool {
    if let Some(dst) = ipv4_dst(pkt) {
        return dst == own.v4;
    }
    if let Some(dst) = ipv6_dst(pkt) {
        return dst == own.v6;
    }
    false
}
