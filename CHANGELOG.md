# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- `ssh.harden-strict`, which narrows the key exchange, cipher, MAC and host key
  algorithms to a modern set, requires 3072-bit RSA keys and disables TCP
  forwarding. Separate from `ssh.harden` because it is the only hardening that
  can stop a client which could connect before.
- Algorithm lists are filtered against `ssh -Q` before being written. The
  published hardened lists name algorithms that do not exist on every release —
  post-quantum key exchange arrived in OpenSSH 9 — and a name the daemon cannot
  parse costs the whole change, since `sshd -t` rejects the file and the backup
  is restored over it. The intersection walks the hardened list rather than the
  query output, because these are preference lists and `ssh -Q cipher` leads
  with `3des-cbc`.
- A directive whose algorithms cannot be determined, or which would be narrowed
  to fewer than two, is left at the system default and reported on stderr. A
  list naming one algorithm refuses every client lacking it, while the
  compiled-in default admits a reasonable range.
- `ssh.allow-users`, restricting login to named accounts. Interactive interface
  only: `AllowUsers` naming an account that does not exist yields a
  configuration `sshd -t` accepts and that matches nobody, and the CLI has no
  verification window to undo it. Every named account must exist and at least
  one must both hold an authorised key and be an account the server still
  admits — naming only root where root login is already disabled is refused,
  since holding a key is not the same as being able to log in.
- `AccountReader`, a capability for asking whether an account exists. Behind a
  trait because `getent` is absent from busybox, so Alpine will need its own
  implementation.
- `docs/tui-specification.html`, the interface's visual contract: nine screens
  drawn as literal character grids at 80×24 and 120×40, plus the keyboard map,
  style table, layout geometry and state machine the implementation follows.
- Rendering tests that assert against a real `TestBackend` buffer rather than
  against constraint arithmetic, since the specification's mockups are literal
  grids and can be diffed cell by cell.
- Initial project setup with `.claude/` template (CLAUDE.md, hooks, agents, skills, rules).
- Cargo scaffolding: edition 2024 crate with `ratatui` 0.30, `crossterm` 0.29 and `thiserror` 2.0.
- Domain error type carrying structured data only, rendered through an i18n
  catalogue so no user-facing text is embedded in the code.
- Message catalogue (`src/i18n/`) with locale resolution from `LC_ALL`/`LC_MESSAGES`/`LANG`,
  dependency-free and exhaustive at compile time. English is the default and fallback.
- Distribution detection from `/etc/os-release`, resolving `ID` and falling back
  to `ID_LIKE` for derivatives (Ubuntu → Debian, EndeavourOS → Arch). An
  unsupported distribution is a propagated error, never a panic.
- `Executor` trait as the single command-execution choke point, with streaming
  output and stdin support; `LocalExecutor` as the only implementation today.
- `PrivilegeEscalator` trait with runtime detection of `sudo`, `doas` and `run0`
  through `PATH`. No escalation when already root; a clear error when no
  mechanism exists.
- Domain traits `PackageManager`, `ServiceManager` and `FileEditor`, plus
  Debian and Arch backends holding every distro-specific name.
- SSH task tree, distro-agnostic throughout: install and enable, harden the
  configuration, authorise a public key, and change the port.
- Terminal interface (`ratatui`) with a task tree, live output pane and a
  confirmation dialog for destructive operations. Unsupported tasks stay
  visible with the reason.
- CLI subcommands `detect`, `privileges`, `list`, `run`, `authorize-key` and
  `change-port`.
- Container integration tests against real Debian and Arch images, ignored by
  default (`cargo nextest run -- --ignored`).
- `deny.toml` policy for `cargo deny`: permissive licences only, yanked crates
  and unknown registries rejected, scoped to the musl and gnu targets `initd`
  ships on.

### Added
- Connection tests that start a real daemon and authenticate against it, so
  the hardening tiers are measured by whether a client can still log in rather
  than by whether the file parses. `sshd -t` answers a different question than
  it appears to: a configuration narrowed to an empty or mutually unusable set
  of algorithms is perfectly *valid*, validation succeeds, and nobody can
  connect. Confirmed in a container — a daemon given `Ciphers 3des-cbc` alone
  passes `sshd -t` and refuses every client — which is precisely the failure
  `ssh.harden-strict` is documented as the only tier able to cause, and the one
  the previous suite would have reported green.
- The scenarios log in as an unprivileged account, not root: `ssh.harden`
  writes `PermitRootLogin no`, so a root session after hardening would fail for
  a reason unrelated to connectivity.
- A complementary scenario reads the authentication methods the *running*
  daemon still offers, from its own refusal message, proving hardening took
  something away rather than only that it took nothing needed. Read from the
  daemon rather than from `sshd_config`, since a directive written into a file
  the daemon never loaded would satisfy a grep and change nothing.
- `.github/workflows/ci.yml`, running format, lint, the unit suite and the
  container suite. Arch runs as a separate scheduled job that never blocks a
  merge: it is a rolling image, so the strict tier's algorithm filtering can
  genuinely change outcome when OpenSSH moves upstream. That signal is worth
  having as its own notification rather than as red on an unrelated pull
  request. A third job builds against the `rust-version` declared in
  `Cargo.toml`, which nothing previously enforced.
- `INITD_REQUIRE_DOCKER`, which turns the container tests' skip-without-Docker
  into a failure. Skipping is right on a developer machine and wrong in CI,
  where a misconfigured runner would report a green suite having executed none
  of them.

### Changed
- Container integration tests are driven by an image matrix rather than one
  file per distribution. Everything a scenario needs to know about a family —
  its package-manager commands, the name `initd detect` must report — lives in
  a single `Image` entry, and scenarios that must hold everywhere are written
  once and expanded across the matrix by a `for_each_image!` macro. Adding a
  distribution was going to mean writing a fresh copy of every scenario, which
  is the duplication the backend abstraction exists to prevent in the code
  itself; now it means adding an entry. A declarative macro rather than a loop
  over the matrix, because a loop is a single test: the first family to fail
  would hide every family after it, and the failure would name a line rather
  than a distribution. No dependency was added — `rstest` would have done the
  same, but the matrix has to stay cheap to extend, not cheap to write once.
- Package names are no longer restated in the tests. A scenario that needs
  OpenSSH installed asks the matrix entry for the command, so the test cannot
  agree with itself while disagreeing with the backend.
- The per-distribution test files keep only behaviour whose reason is specific
  to that family, and each states the reason: Arch covers the missing host keys
  that make every `sshd -t` inconclusive, Debian covers the packaging that
  makes it conclusive. Everything else was an invariant in disguise.
- Scenarios that assert a written configuration is one sshd accepts now
  generate host keys first. The matrix surfaced this immediately: five
  scenarios passed on Debian and failed on Arch, because Debian's packaging
  generates host keys while Arch leaves it to a systemd unit that never runs
  in a container. Without them `sshd -t` reports `no hostkeys available` and
  decides nothing, so those scenarios were asserting a verdict that was never
  reached — passing on one family and proving nothing on the other. Finding
  that is what running the same scenario across families is for.
- `ssh.harden` sets seventeen directives rather than four: the authentication
  limits, the forwarding switches, the idle timeout and the verbose logging
  that records which key each login used. Every one either matches an OpenSSH
  default or tightens something no ordinary client depends on, so a client that
  could connect before still can.
- Keyboard-interactive authentication is probed rather than assumed. Its
  keyword was renamed in OpenSSH 8.7 and the current name is unknown before
  6.9, so no single spelling is safe across the versions this tool is pointed
  at. Both are tested with `sshd -t -o` and only the accepted ones are written;
  when neither is recognised the setting is left alone and reported, rather
  than costing the other sixteen directives.
- A refused change now raises `LockoutRisk` naming which account is at fault,
  instead of `InvalidSshdConfig` carrying an English sentence. Nothing is
  invalid about the configuration in that case — the tool is refusing to write
  one that would strand the administrator — and error variants are meant to
  carry structured data, with the wording living in the catalogue.
- The task tree is now recursive: a category holds tasks, further categories,
  or both, to any depth. `TaskGroup` was a single flat level and could not
  express an area with internal structure.
- SSH tasks are grouped under `Remote Access > SSH > {Service, Configuration,
  Keys}`. The top level is named for what its members do rather than for a
  protocol, so WireGuard joins it without renaming anything. Task identifiers
  are unchanged, so `initd run <task-id>` is unaffected.
- The TUI navigates by drilling down: one level is shown at a time, `Enter`
  opens a category or runs a task, and `Esc`/`Backspace`/`←`/`h` returns to the
  parent. The panel title is a breadcrumb of the current path.
- `Esc` no longer quits. It means "go back", so overshooting by one level
  cannot drop the administrator out of the program mid-session; `q` quits from
  anywhere.
- Category rows are selectable, since a category that cannot be selected cannot
  be opened.
- `initd list` prints the tree indented by level instead of one heading per
  area. No subcommand, argument or exit code changed.
- The interface is built from one-line bands rather than bordered blocks:
  header, body, status row and key bar. Bordered chrome spent six of the
  twenty-four rows a terminal is assumed to have; it now spends three.
- Every style the interface draws is named once in `src/tui/style.rs` and
  referenced from call sites. A `Style` built where it is used drifts from its
  siblings the moment either is edited.
- Layout geometry lives in `src/tui/layout.rs` as constraint lists, switching
  between a fixed-width tree (≥100 columns), a proportional split (72–99) and a
  single pane below that. A terminal under 60×15 gets a stated requirement
  instead of a partial interface.
- Task rows carry glyph markers — `!` destructive, `·` unsupported — and
  categories carry their task count, right-aligned. Colour alone never carries
  a signal, so a monochrome or `NO_COLOR` terminal loses nothing.
- The status row opens with a state pill (`READY`, `RUNNING`, `DONE`, `FAILED`,
  `CONFIRM`, `UNSUPPORTED`) in fixed cells at the left edge, so the operator's
  eye never searches for it and the outcome of a task is legible without
  reading the message beside it.
- Refusals — "already at the top level", "not supported on arch" — flash beside
  the pill for two seconds and expire on their own, rather than overwriting the
  state. The administrator no longer loses sight of what the tool is doing
  because a key was refused.
- The header states the machine's hostname and how root is obtained (`root via
  sudo`) alongside the distribution. An administrator with several terminals
  open can see which machine is about to change without asking, and knows
  whether privileged work will succeed before starting it rather than when it
  fails.
- Tasks run on their own thread and report back through a channel the event
  loop drains each tick. Execution used to block the interface for its whole
  duration: nothing could be shown while a package installed, nothing could be
  cancelled, and the rollback countdown could not tick because the event loop
  was not running.
- The password is asked for once, before the interface starts, while the
  terminal is still ordinary and `sudo` can draw its own prompt. `initd` never
  reads it. The timestamp sudo leaves behind covers the commands the tasks go
  on to run, so the screen is no longer torn down and rebuilt around every
  privileged command. Measured on Debian 13 and Arch — see
  `docs/sudo-timestamp-findings.md`.
- Privileged commands inherit stdin instead of being given `/dev/null`. Both
  distributions key sudo's timestamp by terminal, and a process with no
  terminal is refused even when the session that spawned it has authenticated;
  `Command::output()` sets that redirection implicitly.
- `Ctrl-C` asks a running task to stop at its next step boundary. It is
  cooperative rather than a kill — stopping mid-write is how a half-written
  configuration file happens — and the tool says *stopping* until the step
  actually ends rather than claiming it has already stopped.
- The status row carries a spinner and an elapsed clock while a task runs, both
  driven by the clock rather than by arriving output: over a slow link a quiet
  command and a frozen screen are otherwise indistinguishable. The spinner is
  ASCII, since braille frames are missing or double-width in too many of the
  fonts a server console has.
- Quitting is refused while a task runs, naming `Ctrl-C` as the way to stop.
- Below 72 columns the two panes become two views of one area, switched with
  `Tab`. Both were previously handed the whole width and drawn on top of each
  other, so the output overwrote the tree. The header trades the host facts for
  a `tasks / output` indicator at that width, since nothing else would say
  which of the two is showing.
- `?` opens a help overlay listing every binding grouped by where it applies,
  from anywhere including on top of a dialog. It scrolls rather than dropping
  what will not fit: the section worth reading most — `K` and `R`, the keys
  that cannot be guessed from anywhere else — is the one at the end, and a
  fixed overlay lost it. Any key other than the movement keys closes it,
  including `?` itself, and that key does not also do whatever it normally
  would.
- A change that could sever the administrator's own access is applied and then
  held for sixty seconds rather than declared done. `sshd -t` proves the syntax
  and a reload proves the daemon accepted it, but neither proves the
  administrator can still log in — only a second session does. `K` keeps the
  change, `R` puts it back, and running out of time puts it back too: the
  default outcome of silence is the safe one, because someone who has just
  locked themselves out cannot press a key to undo it.
- `K` and `R` are uppercase deliberately, since lowercase `k` is "move up"
  everywhere else and this is the one place a mistyped navigation key would do
  something unrecoverable. Quitting and starting another task are both refused
  while a change is unsettled, and neither is offered in the key bar.
- Tasks report what they leave behind: `Outcome::Done` for work that cannot
  cost anyone their way in, `Outcome::Revertible` for a change that can. The
  CLI has no window to offer — it exits immediately — so it names the backup it
  kept instead.
- Tasks declare the values they need instead of being constructed with them.
  The tree previously built `ChangePort { port: 22 }` and `AuthorizeKey { key:
  "" }` with placeholders, so pressing Enter in the TUI meant asking to change
  the port to the one already in use, or to authorise an empty key. The task
  tree can now offer a task without inventing values for it, and the CLI and
  the TUI each supply them their own way.
- The TUI collects those values in a modal form before running anything.
  Validation runs on every keystroke and is drawn beneath the field it belongs
  to, stating what is wrong rather than that something is; a field rejects
  characters its kind cannot contain, so a port field cannot be made to hold
  letters at all. A public key is verified by what it parses to — its type and
  comment — since 380 characters cannot be checked by reading them.
- The order is now values, then consent, then the work. A confirmation states
  what will happen, which it could not do before it knew the values.
- `initd run` refuses a task that collects values, naming them, rather than
  failing later on a value nobody was asked for.
- `Esc` on a form with typed values asks before discarding, and any other key
  disarms the prompt so a stale one cannot be answered by a keystroke aimed at
  something else. An untouched form closes outright.
- The confirmation dialog accepts `y` and `n`, with `n` and `Esc` both meaning
  the safe answer.
- Focus moves between the tree and the output with `Tab`, and with nothing
  else. `j` and `k` mean "next" and "previous" in both panes, so a single key
  says which one they address; overloading a movement key with focus is how
  keys start leaking between panes. The focused pane is bordered in cyan, and
  the tree's selected row stays visible when focus leaves it.
- The output pane follows the newest output until the administrator scrolls,
  states which of the two it is doing on its bottom border (`follow` /
  `detached`), and marks the write position with `▌` while following — a quiet
  command and a frozen screen otherwise look identical over a slow link. `w`
  toggles wrapping, `G` re-attaches to the tail, and scrolling back to the
  bottom re-attaches on its own.
- The output buffer holds 5000 lines in a `VecDeque` instead of 2000 in a
  `Vec`. Dropping the oldest line from a `Vec` shifted every remaining element,
  which at that cap meant thousands of moves per line for a chatty package
  manager once the buffer was full.
- The tree shows a scrollbar when a level overflows its pane, and only then.
- `g` and `G` jump to the first and last row of a level.
- The key bar follows the focused pane and the selected row rather than listing
  every binding, since a bar that never changes is one that stops being read.
- Text that overflows its column is marked with `…` rather than clipped in
  silence. Breadcrumbs lose their head and task titles their tail, since a path
  is identified by where it ends and a task by how its name starts: `… Access ›
  SSH › Configuration` and `Install and enable the SSH s…`. A title cut to
  `Install and enable the SSH ser` reads as a real name, so the administrator
  cannot tell anything is missing.

### Deprecated

### Removed

### Fixed

### Security
- File contents are written through stdin rather than as command arguments, so
  no shell escaping is needed and no input can be interpolated into a command
  line running as root.
- Every file modification takes a backup first, and `sshd -t` validates the
  result before the service is reloaded; a configuration rejected for a syntax
  error is rolled back and never committed.
- A failing `sshd -t` caused by missing host keys is distinguished from a real
  syntax error, so a valid configuration is not discarded (verified on a fresh
  Arch container).
- Hardening refuses to disable password authentication when no authorised key
  exists, which would otherwise lock the administrator out of a remote server.
- `reload` is used instead of `restart` so applying a change never drops the
  administrator's own SSH session.
- `~/.ssh` is created 700 and `authorized_keys` 600, the permissions sshd
  requires before it will honour a key.
- Public keys are validated structurally before being written: a malformed
  entry makes sshd ignore the whole file.
