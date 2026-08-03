# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
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

### Changed
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
