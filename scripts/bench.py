#!/usr/bin/env python3
"""Bulk TCP throughput benchmark for link-p2p's stream-forwarding ceiling.

Measures send-only throughput of:
  A) raw loopback TCP        (the machine's ceiling, no user-space stack)
  B) through the tunnel       (serve --forward + connect --listen)
and samples CPU% of the serve/connect processes during the tunnel run.

Usage: bench.py <tunnel_listen_port> <serve_pid> <connect_pid> <seconds>
"""
import os
import socket
import sys
import threading
import time

CHUNK = 1 << 20  # 1 MiB


def sink_server(port, results, key, conns=1):
    """Accept `conns` connections, drain them, record aggregate bytes/time."""
    srv = socket.socket()
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", port))
    srv.listen(conns + 4)

    totals = [0] * conns

    def drain(idx, conn):
        n = 0
        while True:
            d = conn.recv(CHUNK)
            if not d:
                break
            n += len(d)
        conn.close()
        totals[idx] = n

    threads = []
    t0 = time.monotonic()
    for i in range(conns):
        conn, _ = srv.accept()
        th = threading.Thread(target=drain, args=(i, conn))
        th.start()
        threads.append(th)
    for th in threads:
        th.join()
    dt = time.monotonic() - t0
    srv.close()
    results[key] = (sum(totals), dt)


def sender(port, seconds):
    c = socket.create_connection(("127.0.0.1", port), timeout=10)
    # Hard timeout so a stalled peer (e.g. QUIC flow-control backpressure
    # far below loopback speed) can't wedge sendall forever; the loop check
    # only runs between sendalls, so a blocked sendall would hang the bench.
    c.settimeout(5)
    buf = b"x" * CHUNK
    t0 = time.monotonic()
    total = 0
    deadline = t0 + seconds
    while True:
        try:
            c.sendall(buf)
        except socket.timeout:
            break  # peer isn't draining; report what got through
        total += len(buf)
        if time.monotonic() >= deadline:
            break
    try:
        c.shutdown(socket.SHUT_WR)
    except OSError:
        pass
    # wait for server EOF so timing includes final drain
    try:
        c.settimeout(2)
        c.recv(1024)
    except socket.timeout:
        pass
    c.close()
    return total, time.monotonic() - t0


def cpu_pct(pid, t0_utime, t0_stime, wall):
    try:
        with open(f"/proc/{pid}/stat") as f:
            parts = f.read().split()
        utime = int(parts[13])
        stime = int(parts[14])
        ticks = (utime - t0_utime) + (stime - t0_stime)
        hz = os.sysconf("SC_CLK_TCK")
        return 100.0 * ticks / hz / wall
    except Exception:
        return float("nan")


def sample_procs(pids):
    out = {}
    for pid in pids:
        with open(f"/proc/{pid}/stat") as f:
            parts = f.read().split()
        out[pid] = (int(parts[13]), int(parts[14]))
    return out


def main():
    tunnel_port = int(sys.argv[1])
    serve_pid = int(sys.argv[2])
    connect_pid = int(sys.argv[3])
    seconds = float(sys.argv[4])
    parallel = int(sys.argv[5]) if len(sys.argv) > 5 else 1

    results = {}

    # --- A: raw loopback baseline ---
    raw_port = 19011
    t = threading.Thread(target=sink_server, args=(raw_port, results, "raw"))
    t.start()
    time.sleep(0.3)
    sent, _ = sender(raw_port, seconds)
    t.join()
    total, dt = results["raw"]
    print(f"raw loopback : {total / dt / 1e6:8.1f} MB/s  ({total / 1e6:.0f} MB in {dt:.2f}s)")

    # --- B: through the tunnel (P parallel streams) ---
    t = threading.Thread(
        target=sink_server, args=(19012, results, "tunnel", parallel)
    )
    t.start()
    time.sleep(0.3)
    cpu_before = sample_procs([serve_pid, connect_pid])
    t0 = time.monotonic()

    def tunnel_sender():
        sender(tunnel_port, seconds)

    threads = [threading.Thread(target=tunnel_sender) for _ in range(parallel)]
    for th in threads:
        th.start()
    for th in threads:
        th.join()
    t.join()
    wall = time.monotonic() - t0
    cpu_after = sample_procs([serve_pid, connect_pid])
    total, dt = results["tunnel"]
    print(
        f"tunnel x{parallel}  : {total / dt / 1e6:8.1f} MB/s  ({total / 1e6:.0f} MB in {dt:.2f}s)"
    )
    for pid, label in ((serve_pid, "serve"), (connect_pid, "connect")):
        before = cpu_before[pid]
        after = cpu_after[pid]
        pct = cpu_pct(pid, before[0], before[1], wall)
        print(f"  {label} (pid {pid}) CPU: {pct:5.1f}%")

    if total > 0 and results["raw"][0] > 0:
        ratio = (total / dt) / (results["raw"][0] / results["raw"][1])
        print(f"tunnel/raw ratio: {ratio * 100:.0f}%")


if __name__ == "__main__":
    main()
