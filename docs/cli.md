# CLI

> **What this file is.** The public surface of the command-line interface:
> every subcommand (arguments, output, exit codes), the shared error model, and
> the conventions a caller — a person or a script — must know. It is the
> contract automation codes against. Internal implementation details do NOT
> belong here.
>
> **What this file is NOT.** Not the visual contract (`ui.md` has the terminal
> interface: panels, keys, styles), not behavior in user terms
> (`user-stories.md` has what the administrator can do). This file answers
> "what can I invoke, and what comes back".
>
> **How to keep it true (no tooling required).** Plain Markdown — maintain it
> by hand in any editor. With Claude Code, `/update-docs` updates it from the
> diff; without it (a sandboxed editor, a teammate), edit it directly. Update
> whenever a subcommand is added/removed/renamed, or its arguments, output or
> exit codes change. **Coverage over depth:** every subcommand must appear,
> even as a one-liner; the list must be exhaustive even if each entry is
> shallow. A reader should be able to answer "what can this tool do?" without
> opening the source.
>
> **Note.** This file was previously `backend.md`. `initd` runs on the machine
> it administers and exposes no network API, so the CLI *is* its programmatic
> contract.

## Overview

`initd` is a single statically-linked binary that administers the Linux server
it runs on. Invoked with no arguments it starts the interactive interface
(documented in `ui.md`); invoked with a subcommand it performs one action and
exits, which is the mode intended for scripts and for machines with no
interactive terminal.

There is no network surface, no daemon and no configuration file. Authority
comes from the operating system: commands that need root are escalated through
`sudo`, `doas` or `run0`, whichever is found in `PATH`.

## Conventions

- **Distribution detection is implicit.** Every task-running subcommand detects
  the distribution first and selects the matching backend. No flag chooses it.
- **Privilege escalation is implicit.** Commands that need root are wrapped in
  the detected mechanism. Running as root skips escalation entirely.
- **Output goes to stdout, diagnostics to stderr.** A task's progress is
  stdout; warnings (such as socket activation overriding a port) are stderr.
- **Errors are localised.** Messages render in the language resolved from
  `LC_ALL`, `LC_MESSAGES` or `LANG`, falling back to English.
- **Idempotent where possible.** An operation that finds the system already in
  the desired state reports it and changes nothing.
- **A change to a configuration file is recorded, and the task says whether it
  was.** Seven tasks copy the previous version under `/var/lib/initd` before
  replacing it — the four that edit `sshd_config`, `caddy.security-headers`,
  `fail2ban.install` and `fish.install` — and print one line saying the change
  can be put back later, or that it cannot. Recording is best effort: a host
  with a read-only `/var/lib`, or one where `initd` runs unprivileged, still
  applies the change correctly and exits `0`, having said no record was kept. A
  script that needs the guarantee should check for that line rather than for
  the exit code.
- **Two tasks deliberately record nothing, and one file is never copied at
  all.** `ssh.authorize-key` records nothing because restoring its file
  *removes* an authorised key — the direction that locks an administrator out
  rather than rescuing them. `wireguard.add-peer` records nothing because
  `wg0.conf` holds the server's private key and every peer's preshared key, so
  a copy of it is a copy of all of them.

  For that file the guarantee is stronger than "not recorded": nothing copies
  it, ever. Both `wireguard.install` and `wireguard.add-peer` write it through
  a path that takes no sidecar backup, because the ordinary one leaves
  `wg0.conf.initd.bak` beside the original and only copies named in the index
  are ever pruned. What that gives up is a way back from a failed write —
  acceptable because the write is atomic, so the file is the old version or
  the new one and never a third state. Removing a peer is `wg0.conf` minus one
  block, which an administrator can do with an editor; recovering a leaked
  private key is not something anybody can do.
- **A directive the daemon will not honour is reported on stderr.** Every task
  that edits `sshd_config` reads the effective configuration back afterwards and
  names any directive the daemon disagrees with. Debian 12, Ubuntu 22.04 and
  RHEL 9 ship `Include /etc/ssh/sshd_config.d/*.conf` as the first line, and
  sshd takes the first occurrence of a directive — so a drop-in left there by a
  provider image wins over what was written, while `sshd -t` still approves.
  openSUSE Includes the same directory *before* its own crypto-policies
  drop-in, which is why the same mechanism that makes `ssh.harden-strict`
  unsupported on RHEL leaves it supported there. The
  task succeeds and exits `0`: what it wrote is correct, and a drop-in is often
  deliberate. A script that treats hardening as complete on exit `0` should read
  stderr too.

## Exit codes

| Code | Meaning |
|------|---------|
| `0`  | The command succeeded. |
| `1`  | The command failed; the reason is printed to stderr. |
| `2`  | The invocation was wrong: unknown subcommand, or missing/invalid arguments. |

## Subcommands

### `initd`

Starts the interactive interface. See `ui.md`.

### `initd version`

Prints which build this is, as `initd <version>`. Also accepted as
`initd --version` and `initd -V`, since both are habits and neither should
send someone to the usage text.

**Output:** one line on **stdout**, not stderr — a version was asked for rather
than gone wrong. It is the first thing a bug report needs: a report against a
binary nobody can identify cannot be acted on.

**Errors:** none. It reads nothing about the host, so there is nothing to fail.

### `initd detect`

Prints the detected distribution and the family whose backend will be used.

**Output:** `distribution`, `id`, `version` (or `(rolling)` when the system
declares no `VERSION_ID`), and `family` (`debian`, `arch`, `alpine`, `rhel` or
`suse`).

**Errors:** an unsupported distribution exits `1`, naming the `ID` and
`ID_LIKE` that were found and the families that are supported.

### `initd privileges`

Prints the privilege escalation mechanism resolved for this system, an example
of a wrapped command, and the effective uid.

**Output:** `escalation` (`sudo`, `doas`, `run0`, `none (already root)` or
`unavailable`), `example`, `effective uid`.

### `initd list`

Lists the task tree. Tasks not supported on the running distribution are
listed and marked rather than hidden.

**Output:** the tree, indented two spaces per level. Category rows end in `:`;
task rows carry a support marker (`[ ]` supported, `[!]` not supported on this
distribution), the identifier and the title. Identifiers are padded to a common
width so titles line up regardless of depth.

```
Remote Access:
  SSH:
    Service:
      [ ] ssh.install        Install and enable the SSH server
    Configuration:
      [ ] ssh.harden         Harden the SSH configuration
      [ ] ssh.harden-strict  Harden the SSH cryptography
      [ ] ssh.change-port    Change the SSH port
    Keys:
      [ ] ssh.authorize-key  Authorise a public key
    Access:
      [ ] ssh.allow-users    Restrict SSH login to named users
```

Nesting is unbounded: a category may contain tasks, further categories, or
both. Task identifiers stay globally unique and independent of position, so
`run <task-id>` is unaffected by where a task sits in the tree.

### `initd run <task-id> [name=value ...]`

Runs any task, supplying the values it declared. Task identifiers come from
`initd list`; running one with no values prints what it accepts, with defaults
and hints.

**Arguments:** `<task-id>` — required, e.g. `ssh.install`. Then zero or more
`name=value` pairs, in any order. A parameter with a default may be omitted; an
explicit value always wins over one the task merely suggests.

Values are checked against the same rules the interactive form applies. A CLI
argument never passes through the keystroke filter, so this is the only barrier
between an argument and a system file.

**A secret given here is an argument of `initd` itself.** `users.create`
accepts `password=…`, and the tool keeps it out of the `argv` of every command
it *spawns* — `chpasswd` reads it from stdin for exactly that reason. It cannot
do anything about its own: `/proc/<pid>/cmdline` publishes this process's
arguments to every account on the box while it runs, and the shell records the
line in its history. The interactive form is where a password can be typed
without either happening; on the command line, prefer creating the account
without one and setting it with `passwd` afterwards.

**Errors:** an unknown identifier exits `2`, as does a name the task does not
declare, a value that fails validation, and a missing value with no default —
each naming what was wrong rather than restating the whole usage. A task
unsupported on the running distribution exits `1`.

`authorize-key` and `change-port` remain as their own subcommands, since both
predate this and scripts use them.

**Two tasks are refused here whatever arguments are given:** `ssh.allow-users`
and `users.lock-root`. Both apply a change that can end the session applying
it, and the interactive interface holds such a change open until the
administrator proves from a second session that they can still get in,
reverting on its own when they cannot. The CLI exits immediately, so it has no
window to offer and nothing rolls a mistake back.

Both exit `2`, not `1`: the request was never going to run, which is an
invocation error rather than a task that tried and failed. A script that
retries on `1` must not retry these.

### `initd authorize-key <user> <key>`

Appends a public key to a user's `authorized_keys`, creating `~/.ssh` with the
permissions sshd requires (700 on the directory, 600 on the file).

**Arguments:**
- `<user>` — required; the account whose `authorized_keys` is modified.
- `<key>` — required; the public key. Remaining arguments are joined with
  spaces, so an unquoted key pasted on the command line still works.

**Behaviour:** existing keys are preserved, and adding a key already present is
a no-op. Keys are compared by type and body, ignoring the trailing comment.

**Errors:** a structurally invalid key exits `1` before anything is written, as
does a `~/.ssh` or `authorized_keys` that is a symbolic link. The tools this
uses follow links, and the directory sits inside a home its own account
controls, so a link there would have root apply the mode, the ownership and the
key somewhere else. The message names the path: a link into shared storage is
something an administrator may have set up deliberately.

### `initd change-port <port>`

Changes the port sshd listens on, backing up and validating the configuration
before reloading the service.

**Arguments:** `<port>` — required; an integer between 1 and 65535.

**Behaviour:** a configuration rejected by `sshd -t` is rolled back and the
service is not reloaded. Warns when a firewall or SELinux may need the new port
opened, and — on Debian — when `ssh.socket` is active, since the socket rather
than `sshd_config` decides the port in that case.

**Errors:** a non-numeric port exits `2`; a port outside 1–65535 exits `1`.

## Tasks

Tasks are the unit of work shared by the CLI and the interactive interface.
Every task runs through `initd run <task-id>`, with any values it needs given
as `name=value` pairs.

Two are marked *interactive only* below, and that is a decision rather than a
gap in the CLI: see the note under the table.

The **Lockout** column marks the tasks whose change can end the session
applying it — the ones the interactive interface frames in red and warns about
before running. It is not a list of what modifies the machine: nearly every
task does, and the interactive interface confirms before all of them. On the
command line, running the subcommand *is* the confirmation.

### Identity & Access

| Task id | Invocation | Lockout | Summary |
|---------|-----------|---------|---------|
| `users.create` | `run <id> name=value` | no | Creates an account with a home directory and membership of the group granting sudo on this distribution. `password=` is optional: empty or absent leaves the account without one, and a value is applied through `chpasswd` on stdin. |
| `users.set-shell` | `run <id> name=value` | yes | Sets an account's login shell. Refuses a shell absent from `/etc/shells`. |
| `users.delete` | interactive only | yes | Deletes an account. `home=` chooses `keep` (the default, leaving the files on disk owned by a user id nothing claims) or `delete`. Interactive only: the confirmation names the home directory *and its measured size* before anything happens, and with `home=delete` there is nothing to put back afterwards. |
| `users.lock-root` | interactive only | yes | Expires the root account so no method admits it, including the provider's rescue console. Takes no arguments: it scans every account on the host and refuses unless at least one of them can escalate *and* authenticate — by an authorised key or by a usable password. The confirmation lists each account that qualifies, with the credential it gets in by. |

### Remote Access — SSH

| Task id | Invocation | Lockout | Summary |
|---------|-----------|---------|---------|
| `ssh.install` | `run ssh.install` | no | Installs the OpenSSH server and enables it at boot. |
| `ssh.harden` | `run ssh.harden` | yes | Disables root login, password authentication, agent and X11 forwarding, tunnelling and user environments; limits authentication attempts and the login grace period; enables verbose logging. Refuses when no authorised key exists. |
| `ssh.harden-strict` | `run ssh.harden-strict` | yes | Restricts key exchange, cipher, MAC and host key algorithms to a modern set, requires 3072-bit RSA keys, and disables TCP forwarding. Refuses when no authorised key exists. |
| `ssh.authorize-key` | `authorize-key <user> <key>` | no | Adds a public key to a user's `authorized_keys`. |
| `ssh.change-port` | `change-port <port>` | yes | Changes the port sshd listens on. |
| `ssh.allow-users` | interactive only | yes | Restricts SSH login to named accounts. |

### Remote Access — WireGuard

| Task id | Invocation | Lockout | Summary |
|---------|-----------|---------|---------|
| `wireguard.status` | `run wireguard.status` | no | Reports whether the tunnel is up and how many peers are configured. |
| `wireguard.install` | `run <id> name=value` | no | Installs WireGuard, generates the server keys and writes `wg0.conf`. Refuses to overwrite an existing configuration. |
| `wireguard.uninstall` | `run <id> name=value` | yes | Brings `wg0` down, disables it at boot and removes the WireGuard tools. `removal=` chooses `remove` (the default) or `purge`, which decides only what the package manager takes. `wg0.conf` and the server keys are left on disk either way: they cannot be regenerated to match peers that already hold the public key, so removing them is not something a field with two near-identical values should decide. Lockout because an administrator connected *over* the tunnel loses the session applying it. |
| `wireguard.add-peer` | `run <id> name=value` | no | Generates a peer keypair, records it on the server, and prints the client configuration once. |

### Network

| Task id | Invocation | Lockout | Summary |
|---------|-----------|---------|---------|
| `firewall.status` | `run firewall.status` | no | Reports whether inbound filtering is active, which ports it admits, and whether the ruleset is restored at boot — the running ruleset cannot be read for the last of those, and the difference is a whole firewall after a restart. |
| `firewall.enable` | `run <id> name=value` | yes | Denies inbound traffic by default, admitting established connections, loopback and the SSH port. The ruleset is saved where the boot replays it; on a host with no service manager it reports that it was saved and will not be replayed. |
| `firewall.allow-port` | `run <id> name=value` | no | Admits inbound traffic on one port, for one protocol. Saved across reboots on the same terms as `firewall.enable`. Reports when nothing is being filtered yet, since a port "opened" against no policy admits nothing it did not already. |
| `sysctl.ip-forward` | `run sysctl.ip-forward` | no | Enables IP forwarding, now and across reboots. |
| `sysctl.unprivileged-ports` | `run sysctl.unprivileged-ports` | no | Lets an unprivileged process bind 80 and 443. |

### Services

| Task id | Invocation | Lockout | Summary |
|---------|-----------|---------|---------|
| `docker-rootless.install` | `run <id> name=value` | no | Installs the Docker engine under one account, with lingering enabled. Refuses an account with no subordinate id range. Where the distribution packages no Docker, registers Docker's own repository first, refusing if its signing key does not match the fingerprint this build carries. |
| `docker-rootless.uninstall` | `run <id> name=value` | no | Stops the named account's engine, runs upstream's own `dockerd-rootless-setuptool.sh uninstall` as that account, and stops it lingering. Containers, images and volumes under the account's directory are left alone, and so is the Docker package — another account may be running its own engine from it. |
| `caddy.install` | `run caddy.install` | no | Installs Caddy. From the distribution where one packages it, and it is enabled; otherwise from a checksum-verified release, and no service is enabled because there is no unit to enable. Writes no site configuration either way. |
| `caddy.uninstall` | `run <id> name=value` | no | Stops Caddy, disables it at boot and removes it. `removal=` chooses `remove` (the default, keeping configuration for a reinstall to find) or `purge`. Where the distribution packages no Caddy, deletes the verified release binary this tool installed — and only that one: a copy found elsewhere on `PATH` is named and left alone. |
| `caddy.validate` | `run caddy.validate` | no | Asks Caddy whether its configuration parses. |
| `caddy.security-headers` | `run caddy.security-headers` | yes | Defines a snippet setting HSTS, nosniff, frame-deny and a referrer policy. Rolls back if the result does not parse. |

### Developer environment

| Task id | Invocation | Lockout | Summary |
|---------|-----------|---------|---------|
| `fish.install` | `run fish.install` | no | Installs fish and registers it in `/etc/shells`. |
| `fish.uninstall` | `run <id> name=value` | no | Removes fish. Its `/etc/shells` entry stays: an account still set to it would otherwise have a login shell no file admits. |
| `zellij.install` | `run <id> name=value` | no | Installs Zellij. From the distribution where one packages it, otherwise from a checksum-verified release. `version=` defaults to the newest release this build carries a digest for, and only those may be named: a version published upstream after this binary was built has no compiled-in digest and is refused, naming the ones it knows. |
| `zellij.uninstall` | `run <id> name=value` | no | Removes Zellij. Where it came from a release rather than a package, deletes the binary this tool installed at `/usr/local/bin` — and only that one: a copy found elsewhere on `PATH` is named and left where it is. |
| `mise.install` | `run mise.install` | no | Installs mise. From the distribution where one packages it, otherwise from a checksum-verified release. |
| `mise.uninstall` | `run <id> name=value` | no | Removes mise. Toolchains it installed under each account's own directory stay — this tool did not write them. |
| `rust.install` | `run <id> name=value` | no | Installs rustup and a stable toolchain for one account. |
| `rust.uninstall` | `run <id> name=value` | no | Removes rustup. An account's own `~/.rustup` and `~/.cargo` stay: this tool installed the manager, not what was built with it. |

### Hardening

| Task id | Invocation | Lockout | Summary |
|---------|-----------|---------|---------|
| `fail2ban.install` | `run <id> name=value` | no | Watches the authentication log and bans addresses that fail repeatedly. Conflicts with `crowdsec.install`. |
| `fail2ban.uninstall` | `run <id> name=value` | no | Stops fail2ban, disables it at boot and removes it. Bans it had applied lapse when the daemon stops — they live in its own state, not in the firewall's saved ruleset. |
| `crowdsec.install` | `run crowdsec.install` | yes | Bans addresses a reputation network has seen attacking others. Reports what this host sees in exchange. Conflicts with `fail2ban.install`. |
| `crowdsec.uninstall` | `run <id> name=value` | no | Stops CrowdSec, disables it at boot and removes it. The host stops contributing what it sees, and stops benefiting from what the network has seen. |
| `updates.unattended-security` | `run updates.unattended-security` | no | Applies security updates automatically, never rebooting. Debian only. |
| `updates.unattended-security.disable` | `run <id> name=value` | no | Removes unattended-upgrades. Security updates stop being applied without anyone asking — the machine goes on looking exactly the same, which is why the task says so. |

### Two tasks have no CLI form

Deliberate, not an oversight, and for the same reason in both cases.

`users.lock-root` expires the root account. Every other change this tool makes
is recoverable from a console; this one can require the hosting provider's
rescue media. It takes no arguments — it scans every account the host has and
refuses to run at all unless one of them can escalate and can authenticate, by
an authorised key *or* by a usable password, since expiry goes through PAM and
therefore bars the rescue console too, which never consults `authorized_keys`.
Accounts that do not qualify are reported with the reason each was set aside,
because one of those reasons is a fact about the distribution rather than about
the account: openSUSE ships `%wheel` commented out, so membership reads back
true on an account that still cannot escalate, and the remedy is a line to
uncomment rather than a `usermod`.

But those checks establish that a way back in *should* work, not that it does.
Only a second session can prove that, and only the interactive interface can
wait for one.

`ssh.allow-users` is the other. `AllowUsers` naming an account that does not
exist produces a configuration `sshd -t` accepts and that matches nobody, so
every login is refused — and unlike a syntax error, nothing rolls it back. The
interactive interface holds the change open until the administrator confirms
from a second session that they can still log in, and reverts on its own
otherwise. The CLI has no such window: it exits immediately, printing the
backup path to a session that may already be the last one open.

The task's own guards still apply wherever it runs: every named account must
exist, and at least one must hold an authorised key.

Both refusals exit `2`. The distinction this file sells to scripts holds here:
`1` is a task that ran and failed, `2` is a request the CLI would not accept —
and one of these never reached a command.

### Partially applied directives

`ssh.harden-strict` exits `0` having written the file, but not necessarily
every directive it names. Where the local OpenSSH reports too few of the
hardened algorithms to narrow a list safely — or cannot be asked at all — that
one directive is left at the system default and a line naming it is written to
stderr. Scripts that require a specific algorithm list must check the resulting
file rather than the exit code.

`ssh.harden` behaves the same way for keyboard-interactive authentication,
whose directive was renamed in OpenSSH 8.7: both spellings are probed and only
the accepted ones are written.

## Error model

Errors print to stderr as `error: <message>` and exit `1`. The message names
what failed and, where relevant, the underlying cause: the command that
returned non-zero along with its stderr, the file that could not be read, or
the executable missing from `PATH`.

Destructive operations never leave the system half-configured: files are backed
up before being written, configurations are validated before a service is
reloaded, and a rejected configuration is restored from its backup.
