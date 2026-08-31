# Documentation index

Single entry point for link-p2p docs. Each topic lives in **one** place (SSOT).

Root [README.md](../README.md) is the product landing page (what / install /
quick start). Everything else is here.

---

## User guide

| Document | Contents |
|---|---|
| [user-guide/usage.md](user-guide/usage.md) | Stream, SOCKS5, identity, relays, ops flags, security, systemd, logging, i18n |
| [user-guide/platforms.md](user-guide/platforms.md) | Linux / macOS / Windows differences, env vars, exit codes, Unix-only features |

---

## Architecture & subsystems

| Document | Contents |
|---|---|
| [architecture/performance.md](architecture/performance.md) | Throughput methodology, loopback numbers, config attribution, transport matrix |
| [subsystems/tun.md](subsystems/tun.md) | TUN design, routing, MTU, daemon control plane plan, release checklist |
| [roadmap.md](roadmap.md) | Known gaps and planned work |
| [testing.md](testing.md) | Test scripts and two-machine harness |

---

## Contributing

| Document | Contents |
|---|---|
| [CONTRIBUTING.md](../CONTRIBUTING.md) | Commits, SemVer, releases, build, cross-compile |

---

## Audience map

| You are… | Start here |
|---|---|
| New user | README → usage |
| Platform-specific setup | platforms |
| Debugging slow tunnel | architecture/performance |
| Shipping TUN changes | subsystems/tun (checklist) |
| Cutting a release | CONTRIBUTING |
| Adding a feature | roadmap + CONTRIBUTING |
