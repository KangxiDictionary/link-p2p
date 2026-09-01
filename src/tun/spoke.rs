//! TUN spoke: dial hub, install mesh route, optional peer-to-peer shortcuts.

use super::*;

/// Spoke-side mesh table: hub fallback + optional direct peer connections.
struct SpokeMesh {
    #[allow(dead_code)]
    own_id: EndpointId,
    #[allow(dead_code)]
    own_vip: Ipv4Addr,
    hub_vip: Option<Ipv4Addr>,
    hub_out: Option<mpsc::Sender<Bytes>>,
    /// Direct links keyed by VIP.
    direct: HashMap<Ipv4Addr, mpsc::Sender<Bytes>>,
    /// Known EndpointId → VIP (from roster); used to decide dial vs wait.
    roster: HashMap<EndpointId, Ipv4Addr>,
}

impl SpokeMesh {
    fn new(own_id: EndpointId, own_vip: Ipv4Addr) -> Self {
        Self {
            own_id,
            own_vip,
            hub_vip: None,
            hub_out: None,
            direct: HashMap::new(),
            roster: HashMap::new(),
        }
    }

    fn clear_hub(&mut self) {
        self.hub_vip = None;
        self.hub_out = None;
    }

    fn lookup_out(&self, dst: Ipv4Addr) -> Option<mpsc::Sender<Bytes>> {
        if let Some(tx) = self.direct.get(&dst) {
            return Some(tx.clone());
        }
        if self.hub_vip == Some(dst) || vip_in_mesh(dst) {
            return self.hub_out.clone();
        }
        None
    }
}

type SharedSpokeMesh = Arc<RwLock<SpokeMesh>>;

fn spawn_conn_sender(
    tun: TunIo,
    tun_name: String,
    own_vip: Ipv4Addr,
    peer: EndpointId,
    conn: Connection,
    rx: mpsc::Receiver<Bytes>,
    user_mtu: u16,
    raise_gate: MtuRaiseGate,
) {
    spawn_peer_sender(tun, tun_name, own_vip, peer, conn, rx, user_mtu, raise_gate);
}

async fn spoke_install_direct(
    mesh: &SharedSpokeMesh,
    tun: TunIo,
    tun_name: &str,
    own_vip: Ipv4Addr,
    peer_id: EndpointId,
    peer_vip: Ipv4Addr,
    conn: Connection,
    user_mtu: u16,
    raise_gate: MtuRaiseGate,
) {
    if peer_vip == own_vip {
        return;
    }
    let (tx, rx) = mpsc::channel::<Bytes>(256);
    spawn_conn_sender(
        tun.clone(),
        tun_name.to_string(),
        own_vip,
        peer_id,
        conn.clone(),
        rx,
        user_mtu,
        raise_gate,
    );
    {
        let mut g = mesh.write().await;
        g.roster.insert(peer_id, peer_vip);
        g.direct.insert(peer_vip, tx);
    }
    info!(%peer_id, %peer_vip, path = path_label(&conn), "{}", tr!("direct mesh link ready"));
    // Read datagrams from this direct link into TUN.
    let mesh_drop = Arc::clone(mesh);
    let peer_vip_c = peer_vip;
    tokio::spawn(async move {
        loop {
            tokio::select! {
                _ = conn.closed() => break,
                r = conn.read_datagram() => {
                    match r {
                        Ok(data) => {
                            let Some(src) = ipv4_src(&data) else { continue };
                            if src != peer_vip_c {
                                continue;
                            }
                            tun.send(data).await;
                        }
                        Err(_) => break,
                    }
                }
            }
        }
        let mut g = mesh_drop.write().await;
        g.direct.remove(&peer_vip_c);
        info!(%peer_id, %peer_vip_c, "{}", tr!("direct mesh link closed"));
    });
}

async fn spoke_try_dial_peer(
    endpoint: Endpoint,
    mesh: SharedSpokeMesh,
    tun: TunIo,
    tun_name: String,
    own_id: EndpointId,
    own_vip: Ipv4Addr,
    entry: RosterEntry,
    user_mtu: u16,
    allow: Option<HashSet<EndpointId>>,
    raise_gate: MtuRaiseGate,
) {
    if entry.id == own_id || entry.vip == own_vip {
        return;
    }
    if let Err(e) = check_allow(allow.as_ref(), entry.id) {
        warn!(peer = %entry.id, error = format!("{e:#}"), "{}", tr!("skipping mesh peer (not allowed)"));
        return;
    }
    if !should_dial(own_id, entry.id) {
        return;
    }
    {
        let g = mesh.read().await;
        if g.direct.contains_key(&entry.vip) {
            return;
        }
    }
    let dial = EndpointAddr::from(entry.id);
    match endpoint.connect(dial, TUN_ALPN).await {
        Ok(conn) => {
            match exchange_peer_vip(&conn, own_vip, true).await {
                Ok(vip) if vip == entry.vip => {
                    // Spokes do not open a roster control stream on direct links.
                    spoke_install_direct(
                        &mesh,
                        tun,
                        &tun_name,
                        own_vip,
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
                        expected = %entry.vip,
                        got = %vip,
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
    own_vip: Ipv4Addr,
    msg: RosterMsg,
    user_mtu: u16,
    allow: Option<HashSet<EndpointId>>,
    raise_gate: MtuRaiseGate,
    quiet: bool,
) {
    match msg {
        RosterMsg::Snapshot(entries) => {
            for e in entries {
                if e.id == own_id {
                    continue;
                }
                mesh.write().await.roster.insert(e.id, e.vip);
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
                        own_vip,
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
            mesh.write().await.roster.insert(e.id, e.vip);
            if !quiet {
                println!(
                    "{}",
                    tr_fmt!("mesh peer {0} at {1}", e.id.fmt_short(), e.vip)
                );
            }
            tokio::spawn(spoke_try_dial_peer(
                endpoint,
                mesh,
                tun,
                tun_name,
                own_id,
                own_vip,
                e,
                user_mtu,
                allow,
                raise_gate,
            ));
        }
        RosterMsg::Left(e) => {
            let mut g = mesh.write().await;
            g.roster.remove(&e.id);
            g.direct.remove(&e.vip);
            info!(peer = %e.id, vip = %e.vip, "{}", tr!("mesh peer left"));
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
            let err = anyhow::Error::new(e)
                .context(tr_fmt!("'{0}' is not a valid EndpointId", to));
            if let Some(h) = &hooks {
                h.signal_ready(Err(anyhow::anyhow!("{err:#}")));
            }
            endpoint.close().await;
            return Err(err);
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

    let (tun, tun_name) = match create_tun_device(own_vip, mtu) {
        Ok(x) => x,
        Err(e) => {
            signal_err(&e);
            endpoint.close().await;
            return Err(e);
        }
    };
    if let Some(h) = &hooks {
        h.state.set_vip(own_vip).await;
        // Spoke ready after TUN exists; hub dial may still be in progress.
        h.signal_ready(Ok(()));
    }
    let (tun_io, mut from_tun) = spawn_tun_io(tun, mtu);
    let raise_gate = new_mtu_raise_gate();
    let mesh: SharedSpokeMesh = Arc::new(RwLock::new(SpokeMesh::new(own_id, own_vip)));

    // Long-lived TUN → mesh demux (hub and direct outs live in SpokeMesh).
    {
        let mesh_d = Arc::clone(&mesh);
        tokio::spawn(async move {
            while let Some(pkt) = from_tun.recv().await {
                let Some(dst) = ipv4_dst(&pkt) else { continue };
                if dst == own_vip {
                    continue;
                }
                let out = mesh_d.read().await.lookup_out(dst);
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
                let Ok(accepting) = incoming.accept() else { continue };
                let Ok(conn) = accepting.await else { continue };
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
                    match exchange_peer_vip(&conn, own_vip, false).await {
                        Ok(vip) => {
                            spoke_install_direct(
                                &mesh,
                                tun,
                                &tun_name,
                                own_vip,
                                peer,
                                vip,
                                conn,
                                mtu,
                                raise_gate,
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
            let hub_vip = exchange_peer_vip(&conn, own_vip, true).await?;

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
            }

            let (hub_tx, hub_rx) = mpsc::channel::<Bytes>(256);
            spawn_conn_sender(
                tun_io.clone(),
                tun_name.clone(),
                own_vip,
                hub_id,
                conn.clone(),
                hub_rx,
                user_mtu,
                Arc::clone(&raise_gate),
            );
            {
                let mut g = mesh.write().await;
                g.hub_vip = Some(hub_vip);
                g.hub_out = Some(hub_tx);
                g.roster.insert(hub_id, hub_vip);
            }

            if !connected_once {
                connected_once = true;
                if hooks.is_none() {
                    ui.line(styler.ok(&tr_fmt!("connected. your virtual IP: {0}", own_vip)));
                    ui.line(styler.dim(&tr_fmt!(
                        "hub {0} is at {1} (path {2}); peers may connect directly",
                        hub_id.fmt_short(),
                        hub_vip,
                        path_label(&conn)
                    )));
                    ui.line(styler.dim(&tr!("Press Ctrl+C to stop.")));
                }
            }

            if let Some(h) = &hooks {
                let peers: Vec<CtlPeer> = mesh
                    .read()
                    .await
                    .roster
                    .iter()
                    .map(|(id, vip)| CtlPeer {
                        vip: *vip,
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
                                own_vip,
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
            let hub_vip_c = hub_vip;
            let conn_r = conn.clone();
            let hub_read = tokio::spawn(async move {
                loop {
                    tokio::select! {
                        _ = conn_r.closed() => break,
                        r = conn_r.read_datagram() => {
                            match r {
                                Ok(data) => {
                                    let Some(src) = ipv4_src(&data) else { continue };
                                    if !vip_in_mesh(src) && src != hub_vip_c {
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
            mesh.write().await.clear_hub();
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


