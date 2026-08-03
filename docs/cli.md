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

## Exit codes

| Code | Meaning |
|------|---------|
| `0`  | The command succeeded. |
| `1`  | The command failed; the reason is printed to stderr. |
| `2`  | The invocation was wrong: unknown subcommand, or missing/invalid arguments. |

## Subcommands

### `initd`

Starts the interactive interface. See `ui.md`.

### `initd detect`

Prints the detected distribution and the family whose backend will be used.

**Output:** `distribution`, `id`, `version` (or `(rolling)` when the system
declares no `VERSION_ID`), and `family` (`debian` or `arch`).

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

**Output:** one group heading per area, then one line per task with its
identifier and title.

### `initd run <task-id>`

Runs a task that takes no arguments. Task identifiers come from `initd list`.

**Arguments:** `<task-id>` — required, e.g. `ssh.install`.

**Errors:** an unknown identifier exits `2`; a task unsupported on the running
distribution exits `1`.

### `initd authorize-key <user> <key>`

Appends a public key to a user's `authorized_keys`, creating `~/.ssh` with the
permissions sshd requires (700 on the directory, 600 on the file).

**Arguments:**
- `<user>` — required; the account whose `authorized_keys` is modified.
- `<key>` — required; the public key. Remaining arguments are joined with
  spaces, so an unquoted key pasted on the command line still works.

**Behaviour:** existing keys are preserved, and adding a key already present is
a no-op. Keys are compared by type and body, ignoring the trailing comment.

**Errors:** a structurally invalid key exits `1` before anything is written.

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
Those taking no arguments run through `initd run <task-id>`; the rest have a
dedicated subcommand.

| Task id | Invocation | Destructive | Summary |
|---------|-----------|-------------|---------|
| `ssh.install` | `run ssh.install` | no | Installs the OpenSSH server and enables it at boot. |
| `ssh.harden` | `run ssh.harden` | yes | Disables root login and password authentication. Refuses when no authorised key exists. |
| `ssh.authorize-key` | `authorize-key <user> <key>` | no | Adds a public key to a user's `authorized_keys`. |
| `ssh.change-port` | `change-port <port>` | yes | Changes the port sshd listens on. |

## Error model

Errors print to stderr as `error: <message>` and exit `1`. The message names
what failed and, where relevant, the underlying cause: the command that
returned non-zero along with its stderr, the file that could not be read, or
the executable missing from `PATH`.

Destructive operations never leave the system half-configured: files are backed
up before being written, configurations are validated before a service is
reloaded, and a rejected configuration is restored from its backup.
