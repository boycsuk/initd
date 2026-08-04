# Project: initd

> Structure: WHAT / WHY / HOW. Keep this file <200 lines. Critical rules must be backed by a hook — this file is advisory.
> Extended conventions live in `.claude/rules/`: rules with a `paths:` frontmatter field load only for matching files; the rest load every session.

## WHAT — Stack
- Rust (latest stable, edition 2024) — single statically-linked binary
- TUI: `ratatui` + `crossterm` (task tree browser with live command output)
- Target: Linux servers, multi-distro (Debian/Ubuntu, Arch and Alpine implemented; RHEL/SUSE admitted by the design)
- Database: none — state lives in the host system itself

## WHAT — Versions
- Runtime: Rust latest stable via `rustup` (1.95.0 at bootstrap, 2026-04), edition 2024
- Package manager: `cargo`
- Build targets: `x86_64-unknown-linux-musl`, `aarch64-unknown-linux-musl` (static, glibc-independent)
- TUI: `ratatui` 0.30 + `crossterm` 0.29; errors: `thiserror` 2.0
- Database engine: n/a

## WHAT — Commands
- Install: `cargo build`
- Dev: `cargo run`
- Build: `cargo build --release --target x86_64-unknown-linux-musl`
- Test: `cargo nextest run`
- Lint: `cargo clippy --all-targets --all-features -- -D warnings`
- Typecheck: `cargo check --all-targets`
- Format: `cargo fmt --all`
- Audit: `cargo deny check`

## WHAT — Structure
- `src/main.rs` — entry point: dispatches to TUI (no args) or CLI subcommand
- `src/error.rs` — domain error type; carries structured data only, never display text
- `src/i18n/` — message catalogue + locale resolution (dependency-free; every user-facing string goes through it)
- `src/distro/` — `/etc/os-release` detection and family resolution
- `src/backend/` — one module per distro family, each resolving the names a capability has there, plus the implementations they share: `systemd` and `systemd_user`, `unix_files`, `unix_accounts` and `shadow_accounts`, `nftables`, `procfs_sysctl`, `wg_tools`, `release_installer`
- `src/domain/` — capability traits: packages, services and user services, files, account reading and writing, firewall, sysctl, WireGuard, verified binaries
- `src/tasks/` — the task tree exposed by the TUI (each task is typed Rust, declares supported distros)
- `src/tui/` — `ratatui` rendering, navigation, execution output pane
- `src/exec/` — `Executor` trait + `LocalExecutor` (the single choke point for running commands), `MockExecutor` and `PrivilegeEscalator`
- `tests/` — integration tests
- `docs/` — portable contract (see below)

## WHAT — Distribution
- Distributed as a static musl binary via **GitHub Releases** (x86_64 + aarch64).
- Bootstrap install is a one-liner in the linutil style: `curl -fsSL <url> | sh`, where the script downloads the release binary and **verifies its checksum** before executing.
- No deployment target, no hosting, no reverse proxy — the tool runs *on* the server being administered.

## WHAT — External integrations (MCP)
- **serena** — symbol-level navigation (LSP-backed). Locating trait implementations across distro backends, finding references, rewriting function bodies.
- **graphify** — knowledge graph of the codebase. Structural and ripple-effect questions ("what breaks if this trait changes"), mapping unfamiliar areas.

### When to prefer Serena tools over native Claude Code tools

Serena operates at the **symbol level** (LSP-backed), not the text level. Prefer it for:
- **Locating a symbol's definition** → `find_symbol` instead of `Grep` + `Read`.
- **Finding all references to a function/class** → `find_referencing_symbols` instead of `Grep`.
- **Renaming or rewriting a function body** → `replace_symbol_body` instead of `Edit` (it preserves siblings and indentation correctly).
- **Inserting code adjacent to a symbol** → `insert_after_symbol` / `insert_before_symbol`.
- **Getting a structural overview of a file** → `get_symbols_overview` instead of reading the whole file.

Keep using native tools for:
- Plain text files, configs, markdown (no LSP gain).
- One-off reads of a known path (`Read` is faster).
- Edits where line-level precision matters more than symbol semantics.

Serena writes onboarding summaries to `.serena/memories/*.md` — these ARE committed (team-wide context). `.serena/project.local.yml` is gitignored (personal overrides).

### Graphify (graph-level companion, same `.mcp.json` as Serena)

Where Serena works at the symbol level, Graphify answers **structural / ripple-effect** questions over a knowledge graph of the whole codebase: "what depends on this", "what breaks if I change X" (`get_pr_impact`, `shortest_path`), or mapping an unfamiliar area (`query_graph`, `get_neighbors`). Workflow: **graph first, then Serena** — query the graph for shape and blast radius, then act on the symbols with Serena.

Reach the graph two ways over the same `graphify-out/graph.json`:
- **MCP tools** (`query_graph`, `get_neighbors`, `shortest_path`, `get_pr_impact`) for impact analysis mid-task.
- **CLI** for focused lookups: `graphify query "<question>"` (scoped subgraph, cheaper than grepping), `graphify path "<A>" "<B>"` (relationships), `graphify explain "<concept>"`. Use `graphify-out/wiki/index.md` for broad navigation; read `graphify-out/GRAPH_REPORT.md` only for whole-architecture review. After editing code, `graphify update .` refreshes it (AST-only, no API cost).

One-time setup — run `/graphify .` once to build `graphify-out/graph.json` (the MCP server stays unavailable until then). You do NOT need to run `graphify install`: the graph-first `PreToolUse` nudge ships centrally as `prefer-graphify.{sh,ps1}` and is merged into this project's hooks by `--serena` (gated on the graph existing, so it's silent until you build it). Heed the nudge when you see it: the graph answers structure questions faster than scanning files. `graphify-out/` is gitignored build output.

## WHAT — Task areas

Twenty-eight tasks across six areas: identity and access, remote access (SSH
and WireGuard), network (firewall and kernel parameters), services (rootless
containers, web server), the developer environment, and hardening. `docs/cli.md`
lists every one, and a test compares that list against the tree in both
directions so it cannot drift.

## WHY — Architectural decisions

- **Distro differences are resolved by a per-family backend behind a trait, not by conditionals inside each task.** Detection reads `/etc/os-release` once at startup and resolves a backend (Debian/RHEL/Arch/SUSE/Alpine). Tasks call the trait and stay distro-agnostic. Adding a distro must mean adding one module, never editing every task — with N tasks, per-task branching would repeat the same `match` N times and each new distro would touch all of them.

- **Tasks are native typed Rust, not embedded shell scripts.** linutil (the inspiration for this tool) embeds `.sh` files described by TOML. That is faster to contribute to but gives up type safety, testability, and compile-time checking, and inherits every difference between distro shells. Since the real value here is the distro abstraction, tasks must be able to *call* it — a shell script cannot.

- **All command execution goes through the `Executor` trait, even though only `LocalExecutor` exists.** The tool runs on the machine it administers, so local execution is the only implementation needed today. The trait exists so that remote execution (SSH) can be added later as a second implementation. Without it, `std::process::Command` calls would spread across the codebase and adding a transport layer would mean touching every call site. Cost of the indirection now: one layer. Cost later: a full refactor.

- **Privileged commands hand the terminal over; the password is never captured by the TUI.** `sudo` prompts on the TTY, but raw mode disables echo and line buffering and the alternate screen hides the prompt, so the TUI leaves both before spawning and restores them after — the pattern ratatui documents for spawning an external editor. The final `clear()` is required, not cosmetic: programs that query terminal colours otherwise leave raw ANSI RGB values printed inside the restored interface. **Rejected:** reading the password into a masked TUI field and piping it to stdin. It would hold the password in process memory, and `sudo` requires a TTY by default. Note `run0` authenticates through polkit and isolates its own prompt, but it is a symlink to `systemd-run` and does not exist without systemd — which is why the mechanism is resolved at runtime rather than assumed.

- **`sshd -t` approves configurations nobody can connect to, so hardening is measured by a real login.** Validation parses the file; it cannot say whether a client and this daemon agree on a cipher, a key exchange and a MAC. A daemon given `Ciphers 3des-cbc` alone passes `sshd -t` and refuses every client — verified in a container. That is the failure `ssh.harden-strict` is documented as the only tier able to cause, so `tests/integration_connection.rs` starts a daemon and authenticates against it, and `tests/integration_old_client.rs` does so from an OpenSSH 8.4 client against a 10.x server, since an algorithm the server now insists on is one an older client may never have learned. Two harness details are load-bearing and were each found by a test failing for the wrong reason: the daemon must be started *after* the configuration is written (the tasks reload a unit that does not exist in a container, and a daemon started first stops listening), and the login must not be root (`ssh.harden` writes `PermitRootLogin no`, so a root session is refused by design).

- **`docs/cli.md`'s exit-code contract is verified against the binary, because it exists for automation rather than for readers.** A script that retries on `1` and gives up on `2` depends entirely on the difference, and nothing checked that the two stayed distinct. `tests/integration_shared.rs` walks every documented case; it was confirmed to catch a violation by introducing one, rather than assumed to. The lesson alongside it: an exit code alone can misidentify *why* something failed — port 1 exits non-zero in a container with no `sshd_config` to edit, which reads as the range check rejecting a valid port until the message is read. Assert on the message when the code has more than one possible cause.

- **A container test may only invoke tools present in every base image, and the failure mode is a test that lies rather than one that fails.** `diff`, then `cmp`, then `pgrep` each turned out to be missing from one of the two images. A missing comparison tool reports "differs", which failed the revert scenario whose revert had worked *and* passed the keep scenario, which asserts the files differ; a missing `pgrep` turned a wait-until-listening loop into a fixed thirty-second sleep that happened to be long enough. Substituting one tool for another repeated the bug twice, so the rule is to prefer what coreutils guarantees (`sha256sum` over `cmp`) or a condition the program itself produces (sshd's pid file over a process lookup), and to check any new tool against both images before relying on it. Where a helper does the comparing, pin it with its own scenario: a comparator that is wrong in either direction is invisible in the scenarios that use it.

- **`Revert` is reachable only through the TUI, so that is where it is tested — driven by tmux, under systemd.** There is no `initd revert` subcommand by the same reasoning that keeps `ssh.allow-users` out of the CLI: a revert without a verification window is the operation the window exists to make safe. That leaves the interface as the only route, and rendering tests against a `TestBackend` cannot press keys. tmux is what makes the interface assertable — ratatui needs a real terminal, and the alternate screen means a pipe renders nothing while `script(1)` captures nothing readable once the program exits; tmux allocates the pty *and* dumps a live pane, without adding a crate to audit. It also has to run under systemd: without it `ssh.harden` writes the file, fails at `systemctl reload`, and the task ends `FAILED` — and a failed task offers nothing to keep or revert, so the verification window never opens. `tests/integration_tui.rs` reaches that window, presses `R`, and compares the restored file byte for byte with what preceded it.

- **Verifying `systemctl` needs systemd as PID 1, which needs `--cgroupns=host` as well as `--privileged`.** Without the second flag systemd exits 255 immediately and logs nothing, which reads like a broken image rather than a missing flag. `tests/integration_systemd.rs` is where `ssh.install` is observed to actually enable and start the right unit — `ssh.service` on Debian, `sshd.service` on Arch — a divergence that until then had only ever been checked against a mock. It is a separate binary that skips where the host will not grant those capabilities, because a rootless Docker has not found a bug. Assertions there compare `systemctl` output line by line: `is-active` answers `inactive` for a unit that does not exist, and `inactive` contains `active`, so a substring check passed against a container where the package had failed to install.

- **A failing `sshd -t` does not always mean the config is wrong.** Verified empirically on a fresh Arch container: validation fails with `no hostkeys available -- exiting` on a perfectly valid file, simply because host keys have not been generated. Treating every non-zero exit as "invalid config" would make the tool roll back good changes. The classification lives in `src/tasks/sshd_config.rs`; extend `NON_SYNTAX_FAILURES` when another such case appears. A mock would never have surfaced this — it only showed up in a real container.

- **User-facing text lives in the i18n catalogue, never in the code that raises it.** `Error` variants and TUI strings carry structured data; `src/i18n/` renders them in the locale resolved from the environment. The catalogue is a closed enum rendered by an exhaustive `match`, with no external dependency: a missing translation is a compile error rather than a runtime lookup miss, and adding a language means adding one module instead of touching every call site. `fluent` and `rust-i18n` were rejected — both resolve at runtime and pull in dependency trees to audit, for a catalogue this small.

- **Whether a locked password blocks a key depends on how the distribution *built* OpenSSH, not on how it is configured.** The `platform_locked_account()` check is compiled behind `!options.use_pam`: Debian and Arch build with PAM, so it is compiled out and a `!` hash admits a key; Alpine builds without it — `UsePAM` is not even a directive its `sshd -T` recognises — so the check runs and the same hash refuses everything. Found when an Alpine container refused a test account created by `adduser -D` despite it holding a valid key. `users.lock-root` uses expiry regardless, because that is the one mechanism meaning the same thing on all three.

- **A secret is written into a file whose mode is already right, never tightened afterwards.** `wireguard.install` wrote `wg0.conf` and then chmodded it, leaving the server's private key world-readable for as long as the two calls took. Brief, and long enough for any account on the box. It surfaced from `wg genkey` warning about the same mistake in a test's own redirect — not from a mock, which has no opinion about modes. The pattern to keep: create the file empty, set the mode, then write. An empty file discloses nothing.

- **Static musl binaries, not glibc.** A binary linked against a recent glibc fails on older servers — exactly the machines an administration tool needs to reach. musl links statically and runs anywhere, which matters more here than the marginal performance difference.

- **The `curl | sh` installer verifies checksums before executing.** Piping a remote script into a shell runs unverified remote code, and this tool runs as root. Checksum verification against a published GitHub Release is the minimum mitigation; the release binaries are the source of truth, the install script is only a convenience wrapper. <!-- TODO: consider signing releases (minisign/cosign) once the release pipeline exists. -->

## WHAT — Deliberately not built yet

Absent by decision, not oversight. The design admits each without rework:

- **RHEL and SUSE families.** Adding one means adding a backend module, never editing a task.
- **Remote execution over SSH.** The `Executor` trait exists precisely so this becomes a second implementation; `LocalExecutor` is the only one today.
- **Release pipeline** — GitHub Releases, checksummed `curl | sh` installer. The musl targets build correctly (`cargo build --release --target x86_64-unknown-linux-musl` yields a ~789 KB static-pie binary), but nothing publishes them.
- **General package administration.** Installing arbitrary packages is a
  different shape of task from the ones here: every task in the tree today
  names a capability the backend resolves, and a free-text package name has no
  backend to resolve it against.
- **A second WireGuard interface.** `wg0` is fixed rather than asked for,
  because a second interface is a different topology and not a different value.

## HOW — Conventions
Detailed conventions live in `.claude/rules/` (those with a `paths:` field load only for matching files; the rest load every session):
- Code quality → `.claude/rules/code-quality.md` (loads for source files via `paths:`)
- Security → `.claude/rules/security.md`
- Workflow → `.claude/rules/workflow.md`
- AI collaboration → `.claude/rules/ai-collaboration.md`

**Minimum rules that apply everywhere:**
- Follow the existing style in neighboring files before inventing new patterns.
- Strict typing wherever the language allows it.
- Explicit error handling, no swallowed errors.
- Tests for new logic (at minimum: happy path + 1 edge case).
- Atomic commits: one logical change per commit.
- `CHANGELOG.md` updated with every relevant change (Keep a Changelog format).

## Don't
- DO NOT branch on the distro inside a task. If a task needs `match distro`, the missing abstraction belongs in a domain trait — put it there instead.
- DO NOT call `std::process::Command` outside `src/exec/`. Every command goes through `Executor`, or the future SSH implementation becomes a full refactor.
- DO NOT use `unwrap()` / `expect()` / `panic!` in production paths. This runs as root on someone's server: a panic mid-operation can leave the system half-configured. Propagate errors and report them in the TUI.
- DO NOT hardcode paths to binaries (`/usr/bin/apt`). They differ across distros — resolve via `PATH`.
- DO NOT assume a package name is the same across distros (`docker.io` vs `docker` vs `docker-ce`). Names belong in the per-family backend.
- DO NOT run destructive operations without an explicit confirmation step in the TUI.
- DO NOT add dependencies without explicit confirmation — every new dep is audited (`cargo deny check`).
- DO NOT mix refactor with feature in the same commit — it complicates rollback.
- DO NOT use `git commit --amend` without explicit user request — always create a new commit.
- DO NOT auto-sign commits with `Co-Authored-By` unless explicitly requested.

## Workflow
- Changes touching >3 files: **plan mode first** (use `/plan-feature`).
- Before declaring a task done: **always** `/verify`.
- Before each commit: `/changes` to review the diff, then `/commit` (it updates CHANGELOG.md).
- When opening a new session in an ongoing project: `/resume-context`.
- When I correct a systematic mistake: use `/compound` so it does not happen again.
- Before merging anything that touches I/O, auth, or deps: `/security-review`.
- Branch model: feature branches by default. The `guard-push-main` hook blocks direct pushes to main/master. If this project intentionally lives on main (solo project, prototype, scratch repo), add `"allowPushToMain": true` to `.claude/settings.local.json` (see `settings.local.json.example`). Force pushes stay blocked regardless.

## Portable docs — `docs/`
- `docs/` is the **portable contract** of this project, split across self-maintained files: `cli.md` (the programmatic contract — subcommands, arguments, exit codes; this was `backend.md`, renamed because `initd` exposes no network API), `ui.md` (the visual contract of the TUI — panels, keys, style roles), `user-stories.md` (the behavioral contract — everything the user can do, interface-agnostic), and `conventions.md` (how to write the code — a portable mirror of `.claude/rules/` for tools that don't run Claude Code). It exists so that tools or contributors who can only see one slice of the repo (Xcode workspace, embedded subdir, sandboxed editor) can still build the right mental model and follow the same conventions. Each file carries its own maintenance rules in its header, so it stays usable even where `/update-docs` is not available. See `docs/README.md`.
- **Coverage over depth.** Every capability the system exposes must appear in `docs/`, even if as a one-liner. A reader of `docs/` should be able to answer *"what can this system do?"* without opening the source. Detail per entry can be shallow; the list of entries must be exhaustive.
- **Mandatory step at task close.** Before declaring any task done, ask yourself: *"did this change a contract another part of the system relies on?"* If yes, run `/update-docs` **before** `/commit`. This is non-negotiable — desynced docs are worse than no docs.
- **What counts as a contract change** (update required):
  - `cli.md`: added/removed/renamed subcommand or task id, changed arguments, changed output, changed exit codes, changed error semantics.
  - `ui.md`: added/removed/renamed panel, changed what a panel does, changed a key binding, or added/rebound a style role.
  - `user-stories.md`: the user can now do something new, can no longer do it, or achieves it differently (write it interface-agnostic; add a TUI/CLI exception only if the two genuinely differ).
  - Any new file under `docs/` when a new contract producer/consumer appears.
- **What does NOT count** (skip — do not pollute docs with noise):
  - Internal refactors, renamed private helpers, logging, formatting, dependency bumps with no behavior change.
  - Tests, build/CI config, comments.
  - Bug fixes that restore documented behavior rather than change it.
- **If unsure, invoke `/update-docs` anyway.** The skill detects "nothing to update" and exits — false positives cost nothing, false negatives leave stale docs.

## Source hierarchy for research
1. **Official library documentation** (project docs sites, package READMEs) — fetch via `WebFetch` / `WebSearch`.
2. **Specialized forums** (GitHub Issues, Stack Overflow) for real-world user solutions.
3. **Your own training knowledge** as a last resort — it may be outdated.

<!-- "Compact Instructions" is not a Claude Code API — there is no named contract by that name.
     This works because CLAUDE.md is re-injected after /compact, so guidance placed here survives
     compaction. Recent Claude Code also asks the model to preserve sensitive user instructions
     during compaction (changelog 2.1.139). Treat the section below as advisory. -->
## On compaction (advisory)
When this conversation is compacted, preserve:
- Design decisions made and their justification.
- Error messages encountered and how they were resolved.
- List of files modified and why.
- Any "Don't" rule discovered during the session that is not yet codified.

Summarize briefly:
- Exploration steps that did not lead anywhere.
- Trial-and-error iterations on code that is now finalized.
