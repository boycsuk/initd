# User stories

> **What this file is.** The behavioral contract of the product: everything
> the user must be able to DO, written as user stories — independent of which
> screen or platform implements it. It is the single source of truth for
> "what can this product do for its user?". A reader of this file alone should
> be able to list every capability without opening the source or the other
> docs.
>
> **What this file is NOT.** Not the API (`backend.md` lists endpoints), not
> the visual map (`ui.md` lists screens and tokens), not implementation. A
> story says *what the user achieves and why*, never *how it is built*.
>
> **Platform model: parity by default, exceptions only.** Assume every story
> works the same on every client (web, iOS, Android, desktop). Write each
> story once. Only when a capability genuinely differs on a platform do you
> add a short exception line under it — do not tag every story with a platform
> matrix when almost all of them are identical. If a whole story is
> platform-specific, say so in its own line.
>
> **How to keep it true (no tooling required).** Plain Markdown — maintain it
> by hand in any editor (Xcode, a sandboxed editor, a teammate without Claude
> Code). With Claude Code, `/update-docs` can update it from the diff. Update
> it whenever a user-facing capability is added, removed, or changes what the
> user can achieve. **Coverage over depth:** every capability must appear,
> even as a one-liner; the *what* must be exhaustive, the *how* can stay out.
> A new capability with no story here is a contract that does not exist for
> anyone reading only `docs/`.

## Format

Group stories by area (epic). Within each, one bullet per capability:

> As a **\<role\>**, I can **\<do something\>** so that **\<benefit\>**.

Add nested lines only when they carry contract-level information:
- **Acceptance:** the observable condition that proves it works (optional but
  recommended for non-obvious stories).
- **Platform exception:** only if a platform differs. e.g.
  *"iOS only — uses the native share sheet"* or *"Not on web — requires the
  camera"*.

Keep stories outcome-focused. "I can reset my password" is a story; "the
reset button is blue" is not (that is `ui.md`), and "calls `POST /auth/reset`"
is not (that is `backend.md`).

## Interfaces

`initd` has two clients over the same tasks, so "platform exception" here means
TUI or CLI:

- **TUI** — the interactive interface, started by running `initd` with no
  arguments.
- **CLI** — one subcommand per task, for scripting and for machines without an
  interactive terminal.

## Roles

- **Administrator** — runs `initd` on the Linux server being administered.
  There is no login and no second role: authority comes from the operating
  system, through `sudo`, `doas` or `run0`.

## Stories

### Orientation

- As an **administrator**, I can see which distribution `initd` detected so
  that I know it will use the right commands for my system.
  - Acceptance: `initd detect` prints the distribution name, its id, its
    version and the resolved family (`debian` or `arch`).
  - Acceptance: on an unsupported distribution the command reports which
    family was missing instead of crashing.
- As an **administrator**, I can see which privilege escalation mechanism will
  be used so that I can diagnose a system where `sudo` is absent.
  - Acceptance: `initd privileges` names the mechanism (`sudo`, `doas`,
    `run0`, or none when already root) and shows an example command.
- As an **administrator**, I can list the available tasks and see which ones
  run on my system so that I know what is possible before changing anything.
  - Acceptance: tasks not supported on the running distribution are still
    listed, marked, and never silently hidden.
- As an **administrator**, I can browse the tasks grouped by area rather than
  as one flat list, so that I can find what I need as the tool grows.
  - Acceptance: tasks are organised into categories that may themselves contain
    categories, to any depth.
  - Acceptance: a task's identifier does not change when it is regrouped, so
    scripts calling it keep working.
  - TUI exception: categories are opened one level at a time, with a breadcrumb
    showing the current location and a way back to the parent.
  - CLI exception: the whole tree is printed at once, indented by level.

### SSH server

- As an **administrator**, I can install and enable the SSH server so that the
  machine accepts remote connections after a reboot.
  - Acceptance: the correct package for the distribution is installed
    (`openssh-server` on Debian, `openssh` on Arch) and the correct unit is
    enabled (`ssh.service` on Debian, `sshd.service` on Arch).
  - Acceptance: running it again on a machine that already has SSH does not
    reinstall the package.
- As an **administrator**, I can harden the SSH configuration so that the
  server refuses root logins, password authentication, forwarding and
  tunnelling, limits how long and how often a client may try to authenticate,
  and records which key each login used.
  - Acceptance: the previous configuration is copied aside before anything is
    written.
  - Acceptance: the operation is refused, with an explanation, when no
    authorised key exists — otherwise it would lock me out.
  - Acceptance: a configuration rejected by `sshd -t` is rolled back and the
    service is not reloaded.
  - Acceptance: a directive this version of OpenSSH does not recognise is
    skipped and reported, rather than written and taking every other directive
    down with it when the file is rejected.
  - Acceptance: nothing here stops a client that could connect before from
    connecting, as long as it holds a key.
- As an **administrator**, I can restrict the SSH cryptography to a modern set
  so that weak algorithms are refused.
  - Acceptance: only algorithms this OpenSSH reports it supports are written —
    an older server is never handed a name it cannot parse.
  - Acceptance: a list that would be narrowed to fewer than two algorithms is
    left at the system default and I am told which one and why, because a list
    naming a single algorithm is more brittle than the default.
  - Acceptance: the strongest algorithms are offered first, regardless of the
    order the system reports them in.
  - Acceptance: I am warned that old clients may no longer be able to connect.
  - Acceptance: the change is held open until I confirm I still have access.
- As an **administrator**, I can restrict SSH login to a named set of accounts
  so that no other account can log in.
  - Acceptance: an account that does not exist on this host is refused before
    anything is written — a typo would otherwise produce a configuration that
    refuses every login.
  - Acceptance: the operation is refused when none of the named accounts holds
    an authorised key, since password authentication may already be disabled.
  - Acceptance: an account the server already refuses does not count as a way
    back in — naming only root on a server where root login is disabled is
    refused, even though root holds a key.
  - Acceptance: I am told which accounts will still be able to log in before
    the change takes effect.
  - Acceptance: a value that would inject another directive into the
    configuration is rejected.
  - Acceptance: the change is held open until I confirm I still have access.
  - CLI exception: available in the interactive interface only. The CLI has no
    verification window, and this is the one change where losing it means
    losing the machine.
- As an **administrator**, I can authorise a public key for a user so that they
  can log in without a password.
  - Acceptance: `~/.ssh` ends up mode 700 and `authorized_keys` mode 600, the
    permissions sshd requires before honouring the key.
  - Acceptance: keys already in the file are preserved, and adding the same key
    twice does not duplicate it.
  - Acceptance: a malformed key is rejected before anything is written.
  - Acceptance: I am shown what the key parsed as — its type and comment —
    since a 380-character key cannot be verified by reading it.
- As an **administrator**, I watch a task's output as it happens, so that I can
  tell a slow command from a stalled one.
  - Acceptance: output appears as the task produces it, not once it ends.
  - Acceptance: the interface stays usable while a task runs — I can scroll,
    read and switch panes.
  - Acceptance: a spinner and an elapsed clock keep moving even when the
    command itself says nothing for a long time.
  - Acceptance: I am asked for my password once, before the interface starts,
    rather than each time a task needs root.
  - TUI exception: the CLI prints output to the terminal as it arrives and has
    no interface to keep responsive.
- As an **administrator**, I can stop a running task without leaving the
  machine half-configured.
  - Acceptance: stopping takes effect between two commands, never in the middle
    of one.
  - Acceptance: until the current step finishes, the tool says it is *stopping*
    rather than claiming it has stopped.
  - Acceptance: once stopped, I am told where it got to.
  - Acceptance: I cannot quit while a task is running; I am told to stop it
    first.
- As an **administrator**, I get a window to prove I still have access after a
  change that could lock me out, so that a mistake undoes itself instead of
  stranding me.
  - Acceptance: the change is applied and held, not declared done — the tool
    cannot know whether I can still log in, only whether the daemon accepted
    the configuration.
  - Acceptance: I am told to open a second session and check, because that is
    the only thing that actually proves it.
  - Acceptance: the previous configuration goes back on its own if I do not
    confirm within the window. An administrator who has just locked themselves
    out cannot press a key to undo it.
  - Acceptance: keeping the change needs a deliberate keypress that no
    navigation key can produce by accident.
  - Acceptance: I cannot quit, or start another task, while a change is
    unsettled — leaving would abandon it with nobody left to put it back.
  - TUI exception: the CLI exits immediately and has no window to offer, so it
    names the backup it kept instead.
- As an **administrator**, I am asked for the values a task needs before it
  runs, so that no task acts on a value I did not supply.
  - Acceptance: a value that would be rejected is reported as I type it, saying
    what is wrong rather than merely that something is.
  - Acceptance: the task does not run until every value is accepted, and I am
    shown which field is standing in the way.
  - Acceptance: where a task already has a value on this host — the current SSH
    port — the field starts on it, so confirming needs no retyping.
  - Acceptance: cancelling a form I have typed into asks before discarding it.
  - TUI exception: the CLI supplies these values as arguments instead, and
    refuses `initd run` for such a task, naming the values it needs.
- As an **administrator**, I can change the port SSH listens on so that the
  server is not exposed on the default port.
  - Acceptance: the change is validated before the service is reloaded, and
    rolled back if the resulting configuration is invalid.
  - Acceptance: I am warned that a firewall or SELinux may still block the new
    port.
  - Acceptance: on Debian, I am warned when `ssh.socket` is active, because the
    socket — not `sshd_config` — decides the port in that case.

### Running tasks safely

- As an **administrator**, I am asked to confirm before any operation that
  could lock me out of the server, so that a stray keystroke cannot strand me.
  - Acceptance: the confirmation defaults to "no".
  - Platform exception: TUI only. On the CLI, running the subcommand *is* the
    confirmation.
- As an **administrator**, I can watch a task's output as it runs so that I can
  see what is happening rather than waiting for a result.
  - Platform exception: the TUI shows it in a scrollable pane; the CLI prints
    it as it arrives.
- As an **administrator**, I can enter my password when a task needs root, so
  that privileged operations work from the interactive interface.
  - Acceptance: the password prompt is legible, and the interface is intact
    afterwards, with no leftover escape sequences on screen.
  - Platform exception: TUI only — the CLI inherits the terminal directly.
- As an **administrator**, I keep a usable terminal even if `initd` fails, so
  that a crash does not leave me with a broken shell.
