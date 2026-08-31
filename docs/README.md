# Documentation index

Single entry point for link-p2p docs. Each topic lives in **one** place (SSOT).

---

## User guide

For operators and end users running link-p2p.

| Document | Contents |
|---|---|
| [README.md](../README.md) | Install, quick start, CLI overview |
| [user-guide/platforms.md](user-guide/platforms.md) | Linux / macOS / Windows differences, env vars, exit codes, Unix-only features |

---

## Architecture

For contributors and advanced users diagnosing behaviour.

| Document | Contents |
|---|---|
| [architecture/performance.md](architecture/performance.md) | Throughput methodology, loopback numbers, config attribution, transport matrix |
| [subsystems/tun.md](subsystems/tun.md) | TUN design, routing, MTU, release acceptance checklist |
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
| New user | README → platforms |
| Debugging slow tunnel | architecture/performance |
| Shipping TUN changes | subsystems/tun (checklist) |
| Cutting a release | CONTRIBUTING |
| Adding a feature | roadmap + CONTRIBUTING |
