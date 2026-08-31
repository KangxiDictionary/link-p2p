# Contributing

Conventions for commits, versioning, releases, and building link-p2p from source.

**Summary:** Conventional Commits, SemVer, one logical change per commit (code +
tests + docs + changelog together), tag-driven releases.

---

## Commits

### Format

```
<type>(<scope>): <subject>

<body — why this change exists, not a log of steps>
```

Subject: imperative, lowercase, ≤ ~72 chars. Body explains *why* and *what*.

### Types

| type | used for | example |
|---|---|---|
| `feat` | user-visible capability | `feat: add ping subcommand` |
| `fix` | bug fix | `fix: print banner only after listener binds` |
| `refactor` | behaviour-preserving restructure | `refactor: extract shared Backoff type` |
| `perf` | measured performance change | `perf: batch datagram reads in tun loop` |
| `docs` | docs only | `docs: explain n0 relay warning` |
| `test` | tests/scripts only | `test: split phase scripts into server/client` |
| `chore` | build, deps, housekeeping | `chore: gitignore /tmp.log` |
| `dist` | release plumbing, CI | `dist: add release workflow` |

`feat` is for user-observable changes. Internal work is `refactor`/`perf`/`chore`.

### Scopes

Optional greppable module names: `tun`, `i18n`, `socks5`, `transport`, `call`, etc.

### Granularity

**One commit = one logical change**, including code, tests, docs, and changelog
line when user-visible. Do not split “code commit” + “docs commit” for the same
change.

- Commit only when it compiles and passes `cargo test`.
- Never commit WIP.
- Split only for genuinely independent changes.

### Signing

Commits are GPG-signed (`commit.gpgsign=true`). If signing fails in CI/automation,
re-sign before pushing:

```sh
git rebase --exec 'git commit --amend -S --no-edit' <last-signed-commit>
git push --force-with-lease origin master
```

Re-signing rewrites hashes — **re-point affected tags** (see [History rewriting](#history-rewriting-and-tags)).

---

## Versioning (SemVer)

`MAJOR.MINOR.PATCH` in `Cargo.toml` must match `CHANGELOG.md`.

| bump | when |
|---|---|
| MAJOR | incompatible behaviour (or 0.x → 1.x graduation) |
| MINOR | new user-visible feature; in 0.x also breaking changes (call out in changelog) |
| PATCH | bug fix / internal improvement only |

On `0.x`: `### Added` → MINOR; `### Fixed` only → PATCH.

**When to release:** user-visible milestone done, tested, changelog entry in place.
Milestone cadence (days to weeks), not per-commit.

---

## CHANGELOG

[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) format. Always keep
`## [Unreleased]` at the top.

- User-visible changes update `[Unreleased]` **in the same commit as the code**.
- At release: rename to `## [<version>] - <YYYY-MM-DD>`. Do not add new content at tag time.
- Release workflow extracts the version section for GitHub release notes.

---

## Releasing

CI builds tarball + `SHA256SUMS` on any pushed `v*` tag.

**Checklist before tagging:**

1. `cargo build --release && cargo clippy -- -D warnings && cargo test`
2. If msgids changed: `scripts/check_i18n.py` — 0 missing / 0 stale
3. User-visible changes since last tag are under `[Unreleased]`
4. `Cargo.toml` version matches changelog
5. Real-network harness run when NAT/relay/migration may be affected

**Steps:**

```sh
git commit -S -m "chore: release v<version>"
git tag -s v<version>
git push origin master
git push origin v<version>
```

**Post-release:** download tarball, `sha256sum -c SHA256SUMS`, smoke `./link-p2p --version` and `--help` (catalogs load).

---

## History rewriting and tags

After rebase/re-sign, verify `git log --format='%h %G? %s'`, re-point tags
(`git tag -f v0.1.0 <hash> && git push --force origin v0.1.0`), confirm release page.

---

## Branches

Single maintainer: commit on `master`, self-test before push. Revisit when a second
contributor appears or CI can run full e2e.

---

## Building

### From source (Linux)

```bash
cargo build --release
```

Requires network (crates.io). Catalog build needs `msgfmt` (gettext); without it,
UI falls back to English.

### Cross-compile Windows from Linux

```bash
rustup target add x86_64-pc-windows-gnu   # once
# Arch/CachyOS: sudo pacman -S mingw-w64-gcc

cargo build --release --target x86_64-pc-windows-gnu
```

Artifacts:

```
target/x86_64-pc-windows-gnu/release/link-p2p.exe
target/x86_64-pc-windows-gnu/release/locales/   # copy next to exe
```

MinGW linker is configured in `.cargo/config.toml`. For TUN on Windows, add official
signed `wintun.dll` beside the exe (see [platform guide](docs/user-guide/platforms.md)).

### i18n check

```bash
scripts/check_i18n.py
```

When adding strings, update all catalogs under `locales/`.

---

## Testing

See [docs/testing.md](docs/testing.md). Minimum before push:

```bash
./scripts/test.sh
```

TUN release changes: run checklist in [docs/subsystems/tun.md](docs/subsystems/tun.md).

Performance work: [docs/architecture/performance.md](docs/architecture/performance.md).
