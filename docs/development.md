# Development conventions: commits, versions, releases

How this repo handles commit granularity, versioning, changelog hygiene,
and shipping a release. Short version: **Conventional Commits, SemVer, one
logical change per commit, a CHANGELOG entry shipped in the same commit as
the change it describes, and a tag-driven release workflow.**

This is a single-maintainer project today; the conventions below are chosen
so the history stays reviewable *without* a PR process, and so a release
takes five minutes instead of an afternoon.

---

## 1. Commits

### 1.1 Format

```
<type>(<scope>): <subject>

<body — why this change exists, not a log of steps>
```

The subject is imperative, lowercase, ≤ ~72 chars. The body explains the
*why* and the *what* (e.g. "ping to tun serve was dead code because iroh
rejects ALPNs not listed in `Builder::alpns`" — not "added PING_ALPN to
alpns list").

### 1.2 Types

| type      | used for                                                          | example subject                                |
|-----------|-------------------------------------------------------------------|------------------------------------------------|
| `feat`    | user-visible new capability (CLI flag, subcommand, mode)          | `feat: add ping subcommand (RTT + path report)`|
| `fix`     | a bug, including a fix that lands mid-release                     | `fix: print banner only after listener binds`  |
| `refactor`| behaviour-preserving restructuring                                | `refactor: extract shared Backoff type`        |
| `perf`    | measured performance change (cite the number)                     | `perf: batch datagram reads in tun loop`       |
| `docs`    | docs only (README, docs/, help text, comment-only)                | `docs: explain n0 relay warning root cause`    |
| `test`    | tests/scripts only                                                | `test: split phase scripts into server/client` |
| `chore`   | build, deps, changelog-only, housekeeping                         | `chore: gitignore /tmp.log`                    |
| `dist`    | release plumbing: packaging, license, CI workflow, release notes  | `dist: add GPL-3.0 license and release workflow`|

`feat` is reserved for things a *user* can observe. Everything internal is
`refactor`/`perf`/`chore`. When in doubt, prefer the narrower type.

### 1.3 Scopes

Free-form module names — the point is greppability, not taxonomy. Use what
already appears in history: `tun`, `i18n`, `socks5`, `systemd`, `scripts`,
`transport`, `identity`, `ping`, `connect`, `serve`, `logs`, `streams`,
`phase0`/`phase1`. Omit the scope when none fits.

### 1.4 Granularity (the rule that keeps history readable)

**One commit = one logical change — and a logical change includes its
code, its tests, its docs, and its changelog line, all in the same
commit.** Do not split a change into "code commit" + "docs commit" +
"changelog commit": those are one commit, or they are three *independent*
changes, never three pieces of one change.

- Work on a topic until it compiles and passes `cargo test`, then commit.
- Never commit "work in progress". A commit is a checkpoint a reviewer can
  stand on, not a save-game.
- Split only when two changes are genuinely independent (different
  subsystems, different risks). If they touch the same files or answer the
  same review/diagnosis, they are one commit.
- Small related fixes from one review round may be merged into a single
  commit with a body listing each (`fix: register PING_ALPN...; log-drop
  summary; shared Backoff` is the model).

### 1.5 Signing

Every commit is GPG-signed (`commit.gpgsign=true`). When an environment
cannot unlock the key interactively, commit with `-c commit.gpgsign=false`
**and re-sign immediately** — do not leave unsigned commits on the remote:

```sh
git rebase --exec 'git commit --amend -S --no-edit' <last-signed-commit>
git push --force-with-lease origin master
```

Re-signing rewrites every hashed commit, so **also re-point any tags** that
fell on the rewritten range (see §5).

### 1.6 Hygiene

- `git status` before every commit; never let scratch files in
  (`tmp.log` was accidentally pushed once — it is now gitignored).
- Keep the working tree clean between commits.

---

## 2. Versioning (SemVer)

`MAJOR.MINOR.PATCH`:

| bump   | when                                                              |
|--------|-------------------------------------------------------------------|
| MAJOR  | incompatible *behaviour* change (not just flags) — or the 0.x → 1.x graduation |
| MINOR  | new user-visible feature; in 0.x also any breaking change, noted explicitly in the changelog |
| PATCH  | bug fix / internal improvement only                               |

We are on `0.x`: no compatibility promise yet. Bump `MINOR` for every new
capability (a changelog `### Added` entry implies MINOR), `PATCH` for
`### Fixed` only. `cargo` version in `Cargo.toml` and the CHANGELOG version
must always agree.

**When to cut a release:** when a user-visible milestone is done, tested
(build + clippy + tests + the real-machine checks that apply), and its
changelog entry is in place. Do not release per commit, and do not hoard
unreleased work until it rots — a milestone-sized cadence (days to a couple
of weeks) fits this project. Breaking changes in 0.x are fine, just bump
MINOR and call them out.

---

## 3. CHANGELOG

- Format: [Keep a Changelog](https://keepachangelog.com/en/1.1.0/). There
  is always an `## [Unreleased]` section at the top.
- **Update timing:** a user-visible change (`### Added` / `### Fixed` /
  `### Changed` / `### Removed`) updates `[Unreleased]` **in the same
  commit as the code** — see §1.4. Pure refactors and internal docs do not
  need an entry. If you wrote a line in the changelog, it ships with the
  code, not in a separate commit afterwards.
- **At release time:** rename `[Unreleased]` to `## [<version>] - <date>`
  (ISO date). Do not add new content at that point — the entry was already
  written when the change landed.
- The release workflow extracts the release body from the `## [<version>]`
  section, so a release **must** have its changelog section present before
  the tag is pushed, or the GitHub release body falls back to a placeholder.

---

## 4. Releasing (tag-driven)

CI builds a prebuilt tarball + `SHA256SUMS` from any pushed `v*` tag and
uses the CHANGELOG section as the release notes. The human's job is the
checklist and the tag:

**Checklist before tagging:**

1. `cargo build --release && cargo clippy -- -D warnings && cargo test` all
   green.
2. If any msgid changed: `scripts/check_i18n.py` reports 0 missing / 0 stale
   (all three catalogs).
3. Every user-visible change since the last tag is under `[Unreleased]` in
   CHANGELOG.md.
4. `Cargo.toml` version bumped to the target, matching the changelog.
5. Anything the change touches in the real-network harness
   (`scripts/phase*-{server,client}.sh`) has been run on two machines if
   the change plausibly affects NAT traversal / relay / migration.

**Steps:**

```sh
# 1. Bump version + changelog in one commit
#    (Cargo.toml version, and [Unreleased] -> [<version>] - <date>)
git commit -S -m "chore: release v<version>"

# 2. Tag (annotated, signed) and push both
git tag -s v<version>
git push origin master
git push origin v<version>
```

The workflow then builds `link-p2p-x86_64-unknown-linux-gnu.tar.gz` +
`SHA256SUMS` and drafts the release from the changelog section.

**Post-release verification:** download the tarball from the release page,
`sha256sum -c SHA256SUMS`, and smoke-run `./link-p2p --version` +
`./link-p2p --help` to confirm the packaged `.mo` catalogs load (any
language).

**Hotfix / patch release:** normal `fix:` commit (same-commit changelog
line), bump PATCH, same tag flow. No release branch in 0.x.

---

## 5. History rewriting and tags

Rewriting history (re-signing, rebasing, filter-branch) **orphans every
commit and tag** that pointed into the rewritten range — tags do not move
on their own. After any rewrite:

1. Verify the new chain is fully signed: `git log --format='%h %G? %s'`.
2. Re-point affected tags onto their signed equivalents and force-push
   them (`git tag -f v0.1.0 <new-hash> && git push --force origin v0.1.0`).
3. Confirm the release page still resolves (the tarball content is
   unchanged if the tree is unchanged).

An orphaned tag on an unsigned commit is worse than a wrong-looking hash:
anyone who checks out the tag gets a build that did not come from master.

---

## 6. Branches / workflow

Single maintainer today: **commit on `master`, self-test before push,
no PRs.** This is deliberate — the real-network tests can't run in CI, so a
PR review would review a change nobody could fully verify. Revisit this
when a second contributor appears, or when an automated e2e harness can run
in CI (local relay, no external network).
