# initd

A terminal interface for administering a Linux server, as a single static
binary with no daemon, no configuration file and no network surface.

It runs *on* the machine it administers. State lives in the host system itself
— in `/etc/ssh/sshd_config`, in the firewall's ruleset, in systemd's units —
so there is nothing for `initd` to keep and nothing left behind when the binary
is removed.

## What it does

Twenty-eight tasks across six areas: identity and access, remote access (SSH
and WireGuard), network (firewall and kernel parameters), services (rootless
containers and a web server), the developer environment, and hardening.

Run it with no arguments for the interactive interface, or with a subcommand
to perform one action and exit — the mode for scripts and for machines with no
interactive terminal.

```
initd                                    # the interactive interface
initd list                               # every task, and which apply here
initd run ssh.harden                     # one task, non-interactively
initd version                            # which build this is
```

Debian/Ubuntu, RHEL/Rocky/Alma, Arch and Alpine are supported. The distribution
is detected from `/etc/os-release`; nothing selects it by hand.

## Two properties worth knowing before you run it

**A change that could lock you out is applied, not declared done.** `initd` can
prove a configuration is valid and that the daemon accepted it. It cannot prove
that *you* can still log in — only a second session proves that. So those tasks
open a verification window: the change is applied, a countdown starts, and the
previous configuration goes back unless you confirm. Losing the connection
counts as not confirming, which is deliberate — that is the failure the window
exists for.

**Your password is never typed into this interface.** Commands needing root are
escalated through `sudo`, `doas` or `run0`, whichever is in `PATH`. When one of
them is about to prompt, `initd` hands the terminal back so the prompt is drawn
where you can read and answer it.

## Install

```sh
curl -fsSL https://raw.githubusercontent.com/boycsuk/initd/main/install.sh | sh
```

The script downloads the release binary for your architecture and **verifies
its SHA-256 against the published checksums before installing**. Every path
that would skip that check exits instead. Piping a remote script into a shell
runs unverified remote code, and this tool runs as root — the checksum is the
point of the file rather than a nicety.

What it does not defend against is stated rather than implied: anyone able to
publish a release writes both the binary and its digest. Signing would close
that and nothing else, at the cost of requiring `minisign` on a freshly
provisioned server — which is the case the one-liner exists for. That trade is
recorded in `CLAUDE.md`.

Environment variables the script accepts:

| Variable | Default | Meaning |
|---|---|---|
| `INITD_INSTALL_DIR` | see below | Where to put the binary |
| `INITD_VERSION` | `latest` | A release tag to install instead of the newest |

**You do not need to be root, and you do not need to set anything.** With no
`INITD_INSTALL_DIR`, the script installs to `/usr/local/bin` when it can write
there and to `~/.local/bin` when it cannot — so `curl … | sh` works as whoever
happens to be logged in. If that directory is not on your `PATH`, the script
says so and prints the line to add; it does not edit your shell profile, which
is not a change this tool was asked to make.

To uninstall, remove the binary — `rm "$(command -v initd)"` finds it wherever
the script put it. Note that this
removes the tool, not the changes it made — those live in the system's own
configuration, by design.

Prebuilt binaries are `x86_64` and `aarch64`, linked against musl and static,
so they run on older servers where a recent glibc would not.

## Build from source

```sh
cargo build --release --target x86_64-unknown-linux-musl
```

Needs a musl C linker: `musl-tools` on Debian, `musl` on Arch. Without it the
build fails at link time, long after the toolchain reports itself ready — the
most common first-build failure here.

```sh
cargo nextest run                        # unit tests, offline
cargo nextest run --run-ignored all      # adds the container tests (needs docker)
cargo clippy --all-targets -- -D warnings
cargo deny check
```

The container tests are ignored by default because they pull real Debian, Arch,
Alpine and Rocky images and install real packages. They exist because a mock
has no opinion about whether the unit is called `ssh.service` or `sshd.service`.

## Documentation

`docs/` is the portable contract, written to be usable without this repository's
tooling:

- [`docs/cli.md`](docs/cli.md) — subcommands, arguments, exit codes, every task id
- [`docs/ui.md`](docs/ui.md) — the interface: panels, keys, style roles
- [`docs/user-stories.md`](docs/user-stories.md) — what an administrator can do, interface-agnostic
- [`docs/conventions.md`](docs/conventions.md) — how the code is written

`CLAUDE.md` records the architectural decisions and, more usefully, the ones
that were rejected and why.

## Licence

MIT. See [`LICENSE`](LICENSE).
