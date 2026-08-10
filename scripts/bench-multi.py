#!/usr/bin/env python3
"""Multi-connection scaling experiment (multiprocessing: no GIL skew).

N fully independent (serve, connect) pairs, each its own identity + UDP
socket + QUIC connection. Sinks and senders run in separate OS processes so
the measurement itself isn't GIL-bound.

Usage: bench-multi.py <n_pairs> <sink_base_port> <listen_base_port> <seconds>
       <pid...>   # all serve+connect pids, for CPU sampling
"""
import multiprocessing as mp
import os
import socket
import sys
import time

CHUNK = 1 << 20


def sink_process(port, q):
    srv = socket.socket()
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", port))
    srv.listen(4)
    conn, _ = srv.accept()
    n = 0
    while True:
        d = conn.recv(CHUNK)
        if not d:
            break
        n += len(d)
    conn.close()
    srv.close()
    q.put(n)


def sender_process(port, seconds):
    c = socket.create_connection(("127.0.0.1", port), timeout=10)
    c.settimeout(5)
    buf = b"x" * CHUNK
    t0 = time.monotonic()
    total = 0
    deadline = t0 + seconds
    while True:
        try:
            c.sendall(buf)
        except socket.timeout:
            break
        total += len(buf)
        if time.monotonic() >= deadline:
            break
    try:
        c.shutdown(socket.SHUT_WR)
    except OSError:
        pass
    try:
        c.settimeout(2)
        c.recv(1024)
    except socket.timeout:
        pass
    c.close()


def proc_cpu(pid):
    try:
        with open(f"/proc/{pid}/stat") as f:
            p = f.read().split()
        return int(p[13]) + int(p[14])
    except Exception:
        return 0


def run_k(k, sink_base, listen_base, seconds, pids, hz):
    q = mp.Queue()
    sinks = [
        mp.Process(target=sink_process, args=(sink_base + i, q), daemon=True)
        for i in range(k)
    ]
    for p in sinks:
        p.start()
    time.sleep(0.3)

    cpu0 = sum(proc_cpu(p) for p in pids)
    t0 = time.monotonic()
    senders = [
        mp.Process(target=sender_process, args=(listen_base + i, seconds), daemon=True)
        for i in range(k)
    ]
    for p in senders:
        p.start()
    for p in senders:
        p.join()
    for p in sinks:
        p.join()
    wall = time.monotonic() - t0
    cpu1 = sum(proc_cpu(p) for p in pids)

    counts = [q.get() for _ in range(k)]
    total = sum(counts)
    rate = total / wall / 1e6
    cpu = 100.0 * (cpu1 - cpu0) / hz / wall
    per = [f"c{i + 1}:{counts[i] / wall / 1e6:.0f}" for i in range(k)]
    print(
        f"k={k:2d}  aggregate {rate:7.1f} MB/s  "
        f"({', '.join(per)})  CPU {cpu:5.1f}%  "
        f"per-conn {rate / k:6.1f} MB/s"
    )


def main():
    n_pairs = int(sys.argv[1])
    sink_base = int(sys.argv[2])
    listen_base = int(sys.argv[3])
    seconds = float(sys.argv[4])
    pids = [int(x) for x in sys.argv[5:]]
    hz = os.sysconf("SC_CLK_TCK")

    for k in (1, n_pairs,):
        if k > n_pairs:
            break
        run_k(k, sink_base, listen_base, seconds, pids, hz)
        time.sleep(1)  # let connections settle between rounds


if __name__ == "__main__":
    main()
