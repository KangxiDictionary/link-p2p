# Unix-style UX

CLI shape aimed at scripts, `ssh`/`rsync`, and shell plumbing.

## Stream / identity plumbing

| Flag / mode | Behavior |
|---|---|
| `connect --stdio` | Bidirectional stdio ↔ QUIC stream (e.g. `ssh -o ProxyCommand=…`, `rsync -e`). Human banners go to **stderr** so stdout stays clean. |
| `--to -` | Read the peer `EndpointId` from **stdin** (one line / token). |
| `ping --format json` | Machine-parseable ping result on stdout. |

## Exit codes

| Code | Meaning |
|---|---|
| 0 | Success |
| 1 | Other / unexpected error |
| 2 | Usage / bad arguments |
| 3 | Connect failed |
| 4 | Timeout |
| 5 | Denied (peer not on `--allow` / allowlist) |

## Quiet / verbose vs `RUST_LOG`

| Flag | Role |
|---|---|
| `-q` | Quieter user-facing output (banners / progress). |
| `-v` / `-vv` | More user-facing detail. |
| `RUST_LOG` | Structured tracing (this crate + iroh / deps). Independent of `-q`/`-v`; use both when you need logs *and* quiet banners. |

Default without `RUST_LOG` remains roughly `link_p2p=info,iroh=warn`.

## Environment (flags win)

| Variable | Purpose |
|---|---|
| `LINK_P2P_TO` | Peer EndpointId (same as `--to`) |
| `LINK_P2P_RELAY` | Relay URL |
| `LINK_P2P_ALLOW` | Allowlist EndpointId(s) for serve |
| `LINK_P2P_PASSPHRASE` | Identity passphrase (prefer over flag; avoids `ps` / history) |
| `LINK_P2P_CC` | Congestion control (`cubic` / `bbr3`, …) |
| `LINK_P2P_SEND_WINDOW` | QUIC send window (bytes) |
| `LINK_P2P_STREAM_RECV_WINDOW` | Per-stream recv window (bytes) |

Explicit CLI flags always override the corresponding env var.

## Completions and man

```bash
link-p2p completions fish|bash|zsh|powershell|elvish
link-p2p man | gzip -c > /usr/local/share/man/man1/link-p2p.1.gz   # example install
```

`link-p2p man` prints a lightweight troff page built from the same localized
clap `Command` tree as `--help` (no extra man-generator crate). Shell
completion install paths are the same as in the README.
