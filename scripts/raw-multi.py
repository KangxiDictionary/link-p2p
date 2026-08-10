#!/usr/bin/env python3
"""Control experiment: does aggregate RAW TCP on the tailscale0 interface
(100.123.130.118) scale with the number of parallel connections, or does it
also plateau ~650 MB/s like the QUIC tunnel did?"""
import multiprocessing as mp
import socket
import sys
import time

CHUNK = 1 << 20
IP = "100.123.130.118"


def sink_process(port, q):
    srv = socket.socket()
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind((IP, port))
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
    c = socket.create_connection((IP, port), timeout=10)
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
    c.close()


def run_k(k, seconds):
    # each pair gets its own port on the same IP
    base = 20000 + k * 100  # avoid reuse conflicts between rounds
    q = mp.Queue()
    sinks = [
        mp.Process(target=sink_process, args=(base + i, q), daemon=True)
        for i in range(k)
    ]
    for p in sinks:
        p.start()
    time.sleep(0.3)
    t0 = time.monotonic()
    senders = [
        mp.Process(target=sender_process, args=(base + i, seconds), daemon=True)
        for i in range(k)
    ]
    for p in senders:
        p.start()
    for p in senders:
        p.join()
    for p in sinks:
        p.join()
    wall = time.monotonic() - t0
    counts = [q.get() for _ in range(k)]
    rate = sum(counts) / wall / 1e6
    per = [f"{c / wall / 1e6:.0f}" for c in counts]
    print(f"raw k={k:2d}  aggregate {rate:7.1f} MB/s  ({', '.join(per)})")


if __name__ == "__main__":
    seconds = float(sys.argv[1]) if len(sys.argv) > 1 else 5
    for k in (1, 4, 8):
        run_k(k, seconds)
        time.sleep(1)
