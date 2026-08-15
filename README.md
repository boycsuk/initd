# initd

A terminal interface for administering a Linux server: one static binary, no
daemon, no configuration file, no network surface.

It runs *on* the machine it administers. State lives in the host itself — in
`/etc/ssh/sshd_config`, in the firewall ruleset, in systemd's units — so there
is nothing for `initd` to keep and nothing left behind when you delete the
binary.

## Why

Server administration is the same twenty tasks on every machine, spelled
differently on each distribution. `initd` resolves the difference once —
package names, service names, whether the account suite is shadow or busybox —
and presents one task list that works the same on Debian, RHEL, Arch, Alpine
and openSUSE.

The distribution is detected from `/etc/os-release`. Nothing selects it by
hand.

## Quickstart

```sh
curl -fsSL https://raw.githubusercontent.com/boycsuk/initd/main/install.sh | sh
initd
```

The script verifies the release binary's SHA-256 against the published
checksums before installing it, and exits rather than skipping that check.

## What it does

52 tasks across six areas: identity and access, remote access (SSH and
WireGuard), network (firewall and kernel parameters), services, the developer
environment, and hardening. 17 of them pair an install with its undo.

```sh
initd                        # the interactive interface
initd list                   # every task, and which ones apply here
initd run ssh.harden         # one task, non-interactively
initd version
```

[`docs/cli.md`](docs/cli.md) lists every task id, argument and exit code.

## Two things to know before running it

**A change that could lock you out is applied, then verified.** `initd` can
prove a configuration parses and that the daemon accepted it. It cannot prove
*you* can still log in — only a second session proves that. So those tasks
start a countdown: the previous configuration goes back unless you confirm from
another session. Losing the connection counts as not confirming, which is the
case the window exists for. It cannot survive `SIGKILL` or a power cut, and the
banner says so.

**Your password is never typed into this interface.** Commands needing root go
through `sudo`, `doas` or `run0`, whichever is present. When one is about to
prompt, `initd` hands the terminal back so the prompt appears where you can
read and answer it.

## Install

Requirements: none at runtime. The binaries are `x86_64` and `aarch64`,
statically linked against musl, so they run on older servers where a recent
glibc would not.

| Variable | Default | Meaning |
|---|---|---|
| `INITD_INSTALL_DIR` | `/usr/local/bin` | Where to put the binary |
| `INITD_VERSION` | `latest` | A release tag to install instead of the newest |

You do not need to be root, but you do need a route to it — root itself, or an
account that can `sudo` without being prompted. There is no user-level
fallback: `initd` installs packages and edits `/etc`, so a copy in a home
directory would be a program that starts and then fails at the first thing you
ask of it. The script refuses instead, and says which of the two problems you
have.

To uninstall: `rm "$(command -v initd)"`. That removes the tool, not the
changes it made — those live in the system's own configuration.

What the checksum does not defend against is stated rather than implied: anyone
able to publish a release writes both the binary and its digest.

## Build from source

Needs Rust 1.95 or newer and a musl C linker (`musl-tools` on Debian, `musl` on
Arch). Without the linker the build fails at link time, well after the
toolchain reports itself ready.

```sh
cargo build --release --target x86_64-unknown-linux-musl
```

```sh
cargo nextest run                        # unit tests, offline
cargo nextest run --run-ignored all      # adds the container tests, needs Docker
cargo clippy --all-targets --all-features -- -D warnings
cargo deny check
```

The container tests are ignored by default because they pull real Debian, Arch,
Alpine, Rocky and openSUSE images and install real packages. They exist because
a mock has no opinion about whether the unit is called `ssh.service` or
`sshd.service`.

## Documentation

- [`docs/cli.md`](docs/cli.md) — subcommands, arguments, exit codes, every task id
- [`docs/ui.md`](docs/ui.md) — panels, keys, style roles
- [`docs/user-stories.md`](docs/user-stories.md) — what an administrator can do, interface-agnostic

## License

MIT. See [`LICENSE`](LICENSE).
