# User stories

> **What this file is.** The behavioral contract of the product: everything
> the user must be able to DO, written as user stories — independent of which
> screen or platform implements it. It is the single source of truth for
> "what can this product do for its user?". A reader of this file alone should
> be able to list every capability without opening the source or the other
> docs.
>
> **What this file is NOT.** Not the programmatic contract (`cli.md` lists
> subcommands, arguments and exit codes), not
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
reset button is blue" is not (that is `ui.md`), and "runs `initd run
users.lock-root`" is not (that is `cli.md`).

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
    version and the resolved family (`debian`, `arch`, `alpine` or `rhel`).
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
- As an **administrator**, I am told why a task cannot run on this machine, so
  that I can tell a missing package from a deliberate policy from a bug.
  - Acceptance: a task unsupported here stays visible rather than being hidden;
    a tool that hides what it will not do cannot be reasoned about.
  - Acceptance: selecting it explains the refusal in terms of this
    distribution — what is not packaged, what would override the change, what
    could not be verified — rather than only marking it unavailable.
  - Acceptance: the explanation is specific enough to act on, whether that
    means installing something myself or reporting that the reason is stale.
- As an **administrator**, I can find a task without knowing which area holds
  it, so that browsing is not the only way to reach one.
  - Acceptance: I can search by what I remember — the title as the interface
    shows it, or the identifier as `cli.md` and my scripts name it.
  - Acceptance: the search covers every task, not only the group I am looking
    at, and each result says which area it came from.
  - Acceptance: case does not matter.
  - Acceptance: a result takes me to the task rather than running it, so a
    mistyped query cannot start anything. Running it still needs the same
    confirmation and the same values as reaching it by browsing.
  - Acceptance: I am told when nothing matched, rather than shown an empty list
    that looks the same as a tool with no tasks in it.
  - TUI exception: the CLI has no cursor to move, and `initd list` already
    prints every task with its area — piping that to a pager or to `grep` is
    the same capability by the shell's own means.

### Accounts

- As an **administrator**, I can create an account that can administer the
  server, so that I do not have to work as root.
  - Acceptance: it joins whichever group grants sudo on this distribution —
    `sudo` on Debian, `wheel` on Arch and Alpine — and the membership is read
    back rather than assumed, because the command reports success either way.
  - Acceptance: it is created without a password by default, so it can only be
    reached with a key — but I can give it one, in the same form. That default
    is right for an account reached over SSH and wrong for the one that has to
    get in through the provider's rescue console, which is a local TTY where no
    key is offered at all.
  - Acceptance: the password field is masked as I type, one bullet per
    character, and leaving it empty means no password. There is no second field
    asking whether to use the first: an empty value already answers that, and
    asking twice is what this did for a while — a text field taking the word
    `yes`, which answered "answer yes or no" to somebody typing a password.
  - Acceptance: the password never reaches the arguments of any command the
    tool runs, never reaches the output pane, and is never drawn. It is applied
    through `chpasswd`, which reads it from stdin; `useradd -p` would put it in
    `argv`, where `/proc/<pid>/cmdline` publishes it to every account on the
    machine. **This is the one value the tool holds in memory**, and it is a
    deliberate exception to the rule that keeps `sudo` prompting on the TTY
    rather than through a field here — see `docs/conventions.md`.
  - Acceptance: an account that already exists is refused rather than adopted,
    and refused **while I type it** rather than once the form has closed. The
    form used to mark a name the host already carries as acceptable and let me
    submit it, so the one mistake this field invites was the one its live
    validation did not catch. The task's own check still runs — it is the
    barrier; this is the earlier warning, and the only one on a host whose
    account list could not be read.
  - Acceptance: the accounts this host already has are **not** offered here,
    since every one of them is a value this task refuses.
- As an **administrator**, I can change an account's login shell, so that a
  user gets the shell they prefer.
  - Acceptance: a shell absent from `/etc/shells` is refused before anything is
    written, since the system would refuse it afterwards.
  - Acceptance: an account this host does not have is refused as I type it,
    the mirror of the rule that stops me creating one it already has. Every
    field naming an account states which it expects, so neither mistake waits
    for the task to run.
- As an **administrator**, I can lock the root account, so that it cannot be
  logged into at all.
  - Acceptance: refused unless another account already exists, is in the
    administrative group, and can authenticate — by an authorised key or by a
    usable password. Either counts, because expiry is applied through PAM and
    so bars every channel including the provider's rescue console, which never
    consults `authorized_keys`; demanding a key measured SSH when the question
    was about every way in, and refused the account a distribution's installer
    made. A `!` or `*` hash is not a password: neither can be produced by any
    input.
  - Acceptance: I am told that root will no longer log in by any route,
    including the rescue console, and the account that keeps access is named
    back to me before I confirm — it is the only echo of what I typed before an
    irreversible operation.
  - Acceptance: the account is expired, not merely password-locked. Whether a
    locked password also blocks a key depends on how the distribution built
    OpenSSH — it does on Alpine, which builds without PAM, and does not on
    Debian or Arch, which do. Expiry is the one mechanism that means the same
    thing everywhere.
  - Acceptance: locking an already-locked root reports that, rather than
    failing or implying it did the work again.

### Hardening

- As an **administrator**, I can ban addresses that repeatedly fail to log in,
  so that the log stays readable and an attacker loses their cheapest option.
  - Acceptance: the two banners on offer each name the other as a conflict.
    Both write ban rules through the firewall and neither observes the other's,
    so a host running both bans twice and unbans unpredictably.
  - Acceptance: the jail watches the port SSH is on, named explicitly — the
    service name resolves to 22 whatever the daemon is listening on.
  - Acceptance: the reputation-network option is confirmed before it starts,
    since it reports what this host sees to a third party.
  - Acceptance: it says plainly that its agent decides and does not block; a
    bouncer is what enforces.
- As an **administrator**, I can have security updates applied without waiting
  for someone to log in.
  - Acceptance: it never reboots on its own. A tool that reboots a server on
    its own schedule is one nobody can plan around, so the need for a reboot is
    reported instead.
  - Acceptance: writing the policy is not treated as success — the timer that
    applies it is confirmed enabled.
  - Platform exception: Debian only. Arch and Alpine are rolling releases with
    no equivalent, so the task is shown unsupported there rather than doing
    something different under the same name.

### Developer environment

- As an **administrator**, I can install a shell, a multiplexer, a version
  manager or a language toolchain, so that the box has the tools I work with.
  - Acceptance: installing a tool asks first, like everything else that
    changes the machine, but without the lockout warning — it changes nothing
    about how anyone logs in or what the machine serves, and a warning that
    appears everywhere is read nowhere.
  - Acceptance: installing a shell registers it in `/etc/shells` at the path
    the system actually resolves, and says plainly that no account has adopted
    it yet.
- As an **administrator**, I can install a tool my distribution does not
  package, without trusting the download.
  - Acceptance: the checksum is compiled into this build, not fetched alongside
    the archive. One served by the same host proves only that the transfer
    finished.
  - Acceptance: a version this build carries no digest for is refused, and the
    versions it does know are named.
  - Acceptance: the archive is verified before it is extracted.
  - Acceptance: a host that already has the binary downloads nothing.

### Containers and web server

- As an **administrator**, I can install a container engine that runs as an
  ordinary account rather than as root, so that a container escape lands in a
  user instead of on the machine.
  - Acceptance: the account is allowed to keep services running with no session
    open. Without that the engine stops at logout and nothing restarts it after
    a reboot.
  - Acceptance: an account with no subordinate id range is refused before
    anything is installed, since no container could start.
  - Acceptance: the engine is confirmed running rather than assumed. Enabling a
    service reports that the command ran, not that the service came up.
  - Acceptance: where my distribution packages no Docker, the engine comes from
    Docker's own repository, and that repository is registered only after its
    signing key is checked against a fingerprint the tool carries from sources
    independent of the host serving the key. A key that does not match refuses
    the whole operation and leaves the machine unchanged.
  - Platform exception: not on Alpine, which has no per-user service manager at
    all. The engine runs under the account's own systemd instance and OpenRC
    has no equivalent, so the task is shown unsupported rather than failing
    partway through.
- As an **administrator**, I can install a web server that obtains its own
  certificates.
  - Acceptance: the tool says the firewall must admit 80 and 443, and says
    separately that the name has to resolve here before a certificate can be
    issued — the second is reported, never checked, because nothing on this
    host can see it.
- As an **administrator**, I can check the web server's configuration parses
  before a reload acts on it.
  - Acceptance: the server is asked, rather than the file being read. Directive
    order in a Caddyfile is not its source order.
- As an **administrator**, I can add hardening response headers, so that every
  site I opt in gets them.
  - Acceptance: they are offered as a snippet to import, not applied globally.
    Applying them to every site silently would change how an already-deployed
    application behaves.
  - Acceptance: forwarding headers are left alone — the server sets those, and
    overwriting them breaks client-IP detection.
  - Acceptance: a change that does not parse is rolled back, since a broken
    configuration takes every site down at the next reload.

### WireGuard

- As an **administrator**, I can see whether the tunnel is up and how many peers
  are configured, so that I know the state before changing it.
  - Acceptance: "configured but down" is distinct from "up". A configured
    interface that is not running carries nothing.
- As an **administrator**, I can install a WireGuard server, so that I can reach
  private services without exposing them.
  - Acceptance: installing over an existing configuration is refused. A new
    server key silently invalidates every peer configured against the old one.
  - Acceptance: the tool says that forwarding and an open UDP port are still
    needed. Without them the tunnel establishes and carries nothing.
- As an **administrator**, I can add a peer and get its configuration, so that a
  device can connect.
  - Acceptance: the client route covers IPv4 *and* IPv6. Routing only
    `0.0.0.0/0` leaves the device's own IPv6 route in place, so traffic to a
    dual-stack destination leaves outside the tunnel.
  - Acceptance: each peer is authorised for exactly one address. A wider mask
    would let any peer send as any other.
  - Acceptance: an address another peer holds is refused. Two peers on one
    address means the second to connect takes the first one's traffic.
  - Acceptance: the peer's private key is shown once and never stored, so the
    tool cannot leak later what it does not keep.
  - Acceptance: adding a peer does not drop the tunnels already established.

### Firewall and kernel parameters

- As an **administrator**, I can see whether the firewall is filtering and which
  ports it admits, so that I know what is reachable before I change anything.
  - Acceptance: "not filtering" and "filtering nothing" are reported
    differently. They look alike in a listing and mean opposite things.
- As an **administrator**, I can turn on default-deny inbound filtering without
  losing the session I am running it from.
  - Acceptance: the SSH port is admitted by the same ruleset that installs the
    policy, not by a second command afterwards.
  - Acceptance: established connections and loopback keep working, so the host
    can still reach its own package mirror and talk to itself.
- As an **administrator**, I can open a port, naming its protocol.
  - Acceptance: a rule for TCP does not admit UDP. WireGuard is UDP, and a
    TCP rule for its port admits none of its traffic.
- As an **administrator**, I can enable IP forwarding and unprivileged port
  binding, so that a VPN can route and a rootless container engine can serve.
  - Acceptance: applied immediately *and* across reboots. Either alone reports
    success over a system that does not behave as described.
  - Acceptance: a parameter already holding the value says so rather than
    silently doing nothing.

### SSH server

- As an **administrator**, I can install and enable the SSH server so that the
  machine accepts remote connections after a reboot.
  - Acceptance: the correct package for the distribution is installed
    (`openssh-server` on Debian, `openssh` on Arch and Alpine) and the correct
    service is enabled — `ssh.service`, `sshd.service`, or the `sshd` init
    script where there are no units at all.
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
  - Acceptance: losing the session counts as not confirming. If my connection
    drops — which is exactly what the change I am verifying can cause — the
    previous configuration goes back before the tool exits, rather than the
    countdown dying with it.
  - Acceptance: I am told what the automatic revert cannot survive, instead of
    being left to assume it survives everything. A killed-outright process and
    a machine losing power both leave the change applied.
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
  - Acceptance: where the host enforces SELinux, the new port is labelled for
    SSH before the daemon is reloaded, so it can bind it. Where nothing
    enforces, nothing is run.
  - Acceptance: I am warned that a firewall may still block the new port.
  - Acceptance: on Debian, I am warned when `ssh.socket` is active, because the
    socket — not `sshd_config` — decides the port in that case.

### Running tasks safely

- As an **administrator**, I am asked to confirm before **anything that changes
  the machine**, so that no task installs software, enables a daemon or writes
  a configuration file on a keystroke alone.
  - Acceptance: only a task that purely reads runs without asking — today
    `firewall.status`, `wireguard.status` and `caddy.validate`, and each says
    so about itself. A task that writes cannot stay silent by omission: asking
    is what it gets for saying nothing, which is the opposite of how this
    behaved when `ssh.install` put an SSH server on a machine and enabled it
    without a word.
  - Acceptance: the confirmation defaults to "no".
  - Acceptance: the dialog has two levels, and the difference is what keeps
    either worth reading. A change that could end the session applying it — the
    firewall, the SSH ones, a login shell, locking root — is framed in red and
    states the lockout risk. Everything else asks plainly, in the ordinary
    frame. A red border on every task would mark none of them.
  - Acceptance: the tree's `!` marker follows the same line, so the column
    still names the handful that can strand me rather than nearly every row.
  - Platform exception: TUI only. On the CLI, running the subcommand *is* the
    confirmation.
- As an **administrator**, I am offered the values this machine already records
  — the accounts it has, the shells it admits — so that I am not guessing at
  something already written down.
  - Acceptance: the values come from the host rather than from a list built
    into the tool, so a machine with an unusual account or an extra shell
    offers it too.
  - Acceptance: accounts a person logs in as are offered before the service
    ones, since a stock system carries far more of the latter. None is hidden:
    a service account is a legitimate answer.
  - Acceptance: these are suggestions, never the permitted set. Every such
    field stays typeable, because an account can be created between one attempt
    and the next and the tool must not refuse what the system accepts.
  - Acceptance: a machine whose account or shell file cannot be read offers
    nothing and still lets me type the value. A convenience must not become a
    prerequisite.
  - Platform exception: TUI only. On the CLI the value is an argument, where
    the shell's own completion and `getent` are the same capability by other
    means.
- As an **administrator**, I can watch a task's output as it runs so that I can
  see what is happening rather than waiting for a result.
  - Acceptance: starting a task does not move my cursor. Where I was reading
    and what the arrow keys address are my decision, and a task that moved them
    would make running two in a row cost an extra keystroke to undo.
  - Platform exception: the TUI shows it in a scrollable pane; the CLI prints
    it as it arrives.
- As an **administrator**, I can take a task's output away with me — into a bug
  report, a ticket, a message to whoever maintains the machine.
  - Acceptance: I get the lines whole, not the part that fitted on screen. A
    transcript with every long line cut is worse than none, because it looks
    complete.
  - Acceptance: I get the output and nothing else — no borders, no markers from
    the panel beside it.
  - Acceptance: it works over SSH, landing on the clipboard of the machine I am
    sitting at rather than the one being administered.
  - Acceptance: I am told what was sent, never that it arrived. The terminal
    may refuse, and it does not say so — a claim the tool cannot check is one
    I would learn to disbelieve.
  - Platform exception: TUI only. The CLI writes to stdout, where a pipe or a
    redirect is the same capability by the shell's own means.
- As an **administrator**, I am told what a finished task invalidated elsewhere,
  so that I find out from the tool rather than from a service that has stopped
  answering.
  - Acceptance: warnings are reported, never acted on — the tool does not
    change anything the administrator did not ask it to change.
  - Acceptance: a warning about something beyond this machine — a hosting
    provider's firewall, a DNS record — is marked differently from one the tool
    can check, and its text says it was not verified. The tool never implies it
    inspected something it cannot reach.
  - Acceptance: nothing is reported when the task changed nothing that matters,
    such as setting the SSH port to the value it already had.
- As an **administrator**, I can enter my password when a task needs root, so
  that privileged operations work from the interactive interface.
  - Acceptance: the password prompt is legible, and the interface is intact
    afterwards, with no leftover escape sequences on screen.
  - Platform exception: TUI only — the CLI inherits the terminal directly.
- As an **administrator**, I keep a usable terminal even if `initd` fails, so
  that a crash does not leave me with a broken shell.
