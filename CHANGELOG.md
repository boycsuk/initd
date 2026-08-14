# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Fixed
- **`docker.rootless` refused every host that had a Docker engine.** It asked
  `is_installed_here`, which is whether *this tool's* copy sits in
  `/usr/local/bin` — its own directory for release binaries. No route to Docker
  writes there: the distribution's package and Docker's own repository both
  install `/usr/bin/docker`. So the check ran `test -f /usr/local/bin/docker`,
  found nothing, and raised "the docker engine is not installed on this host",
  which `docker.install` could not clear — installing the package lands in the
  directory the check was not looking at, leaving the task permanently
  unrunnable.

  The doc comment above it described `is_installed`, a PATH lookup, and the code
  beneath it asked a different question. `sshd_is_present` records having had
  this exact bug and `caddy_is_present` explains why it uses the other method;
  Docker was the one that was missed.

  The two tests either side of it could not catch it. Both feed a positional
  `MockExecutor` that hands back the next reply whatever was asked, so a reply
  labelled `command -v docker` satisfied `test -f /usr/local/bin/docker` just as
  happily. The new test asserts the command *text*.

- **Every `sshd_config`-editing task refused on a host with SSH preinstalled.**
  Four tasks — `ssh.harden`, `ssh.harden-strict`, `ssh.change-port` and
  `ssh.allow-users` — reported "the SSH server is not installed" on a Debian 13
  VPS plainly serving SSH, and the tree greyed their rows out with it.

  A lookup was asked of the inherited `PATH`. `initd` is unprivileged and
  escalates command by command, so it inherits the *operator's* environment, and
  a non-root login on Debian gets no `/usr/sbin` — which is where `sshd` lives.
  The comment on `program_check` asserted the opposite, that the probe "inherits
  the environment of a process that did" escalate, and reasoned from there that
  sudo's `secure_path` restored the directory. No such process exists: bare
  `initd` is the documented invocation in both `docs/cli.md` and the README.

  `Command::locating` now sets a `PATH` of its own instead of trusting the one
  it inherits, which fixes both the `requires()` declaration and the `run`
  guard, for every capability, at the one site all of them already passed
  through. The four system directories come first and `/usr/local/bin` is kept
  after them: dropping it would answer the SSH question and blind the lookup to
  `mise`, `zellij` and this tool's own copies, which is the same defect pointing
  the other way.

  It travels as the command's environment rather than inside the script, so the
  output pane still shows `sh -c command -v sshd` — a lookup prefixed by six
  directories reads as noise at exactly the moment an operator reads it closely,
  which is when the program was not found.

  Not caught because every container scenario runs as root inside Docker, whose
  `PATH` includes `/usr/sbin`. The suite exercised the one environment under
  which the check worked.

- **`firewall.manage-ports` reported no front-end on a host that had one.**
  Both firewall front-ends were detected by the only unprivileged command in
  modules where every other call is `.privileged()` — and privileged calls reach
  `/usr/sbin` through sudo's `secure_path` while these did not. `nft` and
  `firewall-cmd` both live there, so an operator who was not root got "no
  inbound filtering front-end is installed on this host" from a box that was
  filtering. `firewall.enable` had worked on the same box minutes earlier for
  the single reason that it was run as root.

  Detection is a gatekeeper — `firewall_for` picks the front-end every other
  firewall call then drives — so one invisible binary disabled the lot.

  `nft` is now found through `Command::locating`, which carries its own search
  path. firewalld could not use the same fix: `firewall-cmd --state` has to
  *run* the binary, since its whole purpose is telling a stopped daemon from an
  absent one, and both have it on disk. It gets the same directories through the
  command's environment instead.

  Worth more on RHEL than the shared cause suggests: firewalld is the first
  candidate there, so an invisible `firewall-cmd` reads as absent and silently
  promotes nftables — which would then write a table of this tool's own over a
  host whose ruleset firewalld holds, the outcome `RhelBackend::firewalls`
  orders the two candidates to prevent.

  Detection stays on the `Executor` rather than reading the filesystem directly,
  so the answer goes on describing the host the commands will run on when a
  second implementation runs them over SSH.

- **Applying a kernel parameter looked like it had done nothing.** The row went
  on offering to apply it and never offered the undo, so an operator had no way
  to tell the change had landed.

  The rows are reversible and correctly wired, and the interface does re-probe
  after a run. What failed is one layer below: `is_persisted` read the drop-in
  through the privileged file editor, on the probe thread, which may not raise a
  password prompt. The read returned `NoTerminalForPrompt`, `measure` folded
  that into `Presence::Unknown`, and `Unknown` draws the forward verb.

  Intermittent in the way that hides a defect: the startup `sudo -v` keeps a
  timestamp live for a few minutes, so it worked right after launch and stopped
  later — and never worked at all under `doas` or `run0`.

  The read is unprivileged now, which is sound because
  `/etc/sysctl.d/99-initd.conf` is mode `0644` in a `0755` directory by this
  tool's own choice: the privilege bought nothing. `FileEditor::read` keeps it
  for the files where it buys everything — `sshd_config` is mode `600` — so the
  unprivileged path is a second method rather than a weakening of the first.

- **A firewall enabled as root read as "not filtering" from an admin account.**
  The row went on offering to enable an active firewall, and the port table
  opened without the SSH port in it — on a host that was admitting it.

  `nft list` exits 1 both for a table that does not exist and for one the caller
  may not read, and `Nftables::state` collapsed the two into "nothing is
  filtered". Everything downstream inherited that: the tree drew the forward
  verb, and the port table — which is *declarative*, so a row missing from it is
  a port asked to be closed — opened empty.

  The interface authenticates once at startup and the helper's timestamp lapses
  while the session stays open, so this is not a state an operator arrives in.
  It is one the screen decays into after fifteen minutes on Debian, five on
  Arch, and immediately under `doas` or `run0`, which keep no timestamp at all.

  Now separated by what `nft` says, since the exit code cannot tell them apart:
  a refusal raises `FirewallStateUnreadable`, a missing table stays an answer.
  `Presence::Unknown` replaces `Absent` where the front-end could not be
  reached, and the port table refuses to open rather than opening blank, naming
  what to do — running any task re-authenticates.

- **`initd run firewall.manage-ports` could close every port it can close.**
  The worst of these, and its own comment described it: "without this an
  invocation naming no ports would declare the empty set, and the empty set
  closes everything". `open_ports_value` was that *without this* — it answered
  `""` for a ruleset it could not read, and `""` is the empty set.

  Reachable without privilege, which is the documented way to run this: listing
  needs root, so an unprivileged `initd run firewall.manage-ports` naming no
  ports resolved "every port currently open" to "none of them" and asked for all
  of them to be closed, the session's own among them. It raises now.

  `ManagePorts::run` was never the hole — it reads the ruleset privileged and
  fails outright if that read fails. The value was resolved *before* run, where
  an empty answer is indistinguishable from an operator meaning it.

### Added
- **The installer says what it is replacing.** Re-running it already upgraded
  correctly — `install` overwrites, including over a *running* binary, which it
  replaces by inode so an open session goes on working against the copy it
  started with. What it did not do is say so, and the command that upgrades is
  the command that downgrades: installing an older release over a newer one
  happened in silence.

  Both versions are read from the binaries themselves rather than from the tag
  asked for, since `INITD_VERSION` is usually `latest` and `latest` compares
  against nothing. The downloaded copy has been checksum-verified by then, so
  asking it is not a new trust.

  It names both versions rather than judging the direction: `sort -V` is not
  POSIX and busybox's is a stub, and a comparison that sorts `0.10.0` below
  `0.9.0` is worse than none. Every failure in this path is silent — a courtesy
  line must not stop an install that would have replaced the copy anyway.

- **`users.lock-root` runs in both directions, and is now "Manage root
  access".** Locking root was reachable and undoing it was not: the row
  reported "root is already locked" and did nothing, so an account barred by
  this tool could only be restored by hand.

  One row rather than a reversible pair, because the two differ in *where* the
  direction can be decided. A pair decides it in the probe thread, and the
  question — is root locked — is answered by `/etc/shadow`, mode `640`. The
  probe may not prompt, so it would answer `Unknown` for every operator who is
  not root, and `Unknown` draws the forward verb: the row would offer to lock a
  root already locked, which is recovered through the hosting provider's rescue
  console.

  The confirmation decides instead. It is a point of interaction and may
  escalate — `lockout_warning` already spends seventeen privileged commands
  there — so by the time an operator is reading the dialog, the direction has
  been measured. Where it cannot be read, neither direction is offered rather
  than the forward one being assumed.

  The task id stays `users.lock-root`, so nothing that scripts it breaks.

  Unlocking runs no way-back-in scan: that guard protects the locking
  direction, and running it here would refuse on a host with no other
  administrator — precisely the host where restoring root matters most. It sets
  no password either, and says so, because "unlocked" and "can log in" are one
  sentence in English and two fields in `/etc/shadow`.

- **A locked account read as unlocked wherever `/etc/shadow` could not be
  read.** `grep` exits non-zero both for "no such account" and for "permission
  denied", and `is_locked` reported both as "not locked" — the same defect as
  the firewall's, in the account database, and in the direction that offers to
  lock a root that is already locked.

### Added
- **A guard that would have caught four of these at once.** Two tests walk the
  real tree against all five families and assert that no row's presence and no
  task's requirements are measured by a privileged command. The probe thread
  runs with `Prompting::Refuse`, so such a command cannot succeed there — it
  returns `NoTerminalForPrompt`, which each caller folded into a
  definite-looking answer.

  Every probe test before this used a positional `MockExecutor`, which has no
  opinion about privilege, so each of these defects passed the suite for as long
  as it shipped. `MockExecutor::any_privileged` already existed; nothing in the
  probe tests had asked it.

  The firewall is exempt on the merits rather than grandfathered: `nft list`
  genuinely requires root and has no unprivileged spelling, unlike the sysctl
  drop-in, which was world-readable all along. What that row must do instead —
  answer `Unknown` rather than `Absent` — has a test of its own.

## [0.3.0] — 2026-08-13

### Changed
- **BREAKING: `docker-rootless.install` is now two tasks, `docker.install` and
  `docker.rootless`.** Scripts calling
  `initd run docker-rootless.install user=deploy` must now call
  `initd run docker.install` followed by
  `initd run docker.rootless user=deploy`. `docker-rootless.uninstall` is
  `docker.rootless-off`, and `docker.uninstall` is new.

  One task meant two scopes — an engine belongs to the machine, a rootless
  setup belongs to one account — so a single capability had to resolve one
  package name for both jobs. On three of the five families the name it
  resolved was wrong, and none of it was visible because the only container
  coverage Docker had was a refusal.

  Measured, per family. `docker-ce-rootless-extras` declares
  `Enhances: docker-ce`, not `Depends`: on `debian:13`, installing it alone
  brings in `rootlesskit` and the two setup scripts and leaves the host with no
  daemon and no client at all. On Arch no official package ships
  `dockerd-rootless-setuptool.sh` — `pacman -F` finds only `extra/rootlesskit`
  — so the task ran a script that was never there, while a comment in the
  backend asserted it was. On openSUSE the script lives in
  `docker-rootless-extras`, a package the task never installed.

  Each family now installs the way its own documentation says. Docker publishes
  a repository for Debian, Ubuntu, RHEL and its rebuilds, and there the five
  packages upstream's page lists are installed in **one** transaction — which
  is why `PackageManager::install` takes a slice rather than a name. Arch,
  openSUSE and Alpine are not platforms Docker publishes for, so they install
  the distribution's own package.

  `docker.rootless` refuses a host with no engine, naming `docker.install`
  rather than letting upstream's script fail in terms that name neither this
  tool nor the step that was missed.

- **Alpine can install the Docker engine.** It was refused for the whole
  capability on the stated grounds that the distribution packages no Docker. It
  packages both halves — `docker-29.5.2-r0` and `docker-rootless-extras`,
  measured on `alpine:3.23`. What Alpine has no answer for is a per-user
  service manager, so only `docker.rootless` refuses it now, and the refusal
  says OpenRC rather than saying "not packaged" about two packages that are.

- **BREAKING: `firewall.allow-port` is now `firewall.manage-ports`, and it
  declares a set rather than adding one rule.** Scripts calling
  `initd run firewall.allow-port port=8080 protocol=tcp` must become
  `initd run firewall.manage-ports ports="…"`, naming every port that should be
  open rather than the one being added.

  The old task could add a rule and never remove one — `FirewallManager` had
  `allow` and no per-port inverse at all, so the only way to close a port was
  `firewall.disable`, which turns the whole firewall off. Asked for as a table
  of ports, which is a declaration by its nature: a row deleted is a port
  closed.

  The value is one parameter spelled the way every front-end spells a port,
  `ports="22/tcp 443/tcp"`, which is what keeps the CLI able to say the same
  thing as the table without a second grammar. It defaults to what the host
  currently admits, in both interfaces — so an invocation naming nothing is a
  no-op rather than "close everything", which is what the empty set does mean
  when it is written out.

  Ports are opened before any is closed. A set moving a service from one port
  to another must have the new one admitted first, or the session dies in the
  window between the two commands — the same reasoning that makes
  `firewall.enable` build its ruleset in one transaction.

  It carries a lockout confirmation where the old task carried none, and the
  warning asks the inverse question `firewall.enable`'s does: there the risk is
  naming the wrong port to keep, here it is a row left out of a table, and
  nothing about deleting a row announces that the row was the one carrying the
  session. Where the closing set holds the port `sshd -T` reports, the dialog
  says so in red. Where it does not, it still declines to promise safety — a
  jump host or a forwarded port arrives by a route nothing here can see.

  Four tasks that name a firewall task as the remedy for a port they need —
  `ssh.change-port`, two in WireGuard, and Caddy — were updated with it. They
  are display-only, so a stale id would not have broken a jump; it would have
  told an operator to run something that no longer exists.

- **`firewall.status` says how each port came to be open.** A port admitted by
  a *service* now reads `22/tcp is open (admitted by ssh)`, because that is the
  distinction deciding whether anything can close it.

- **The key bar and the verification banner are no longer rebuilt several times
  a frame.** `fitted` re-totalled every hint on each shedding pass, and
  `Lang::render` allocates a `String` per label, so a row of eight hints cost
  up to five full passes — and the verification banner was built once to be
  measured, thrown away, and built again to be drawn, ten times a second for
  the whole countdown. Both now measure what they already built.

- **Two style-table entries that had outlived their callers were removed**, and
  `style.rs` now marks what is unused per item rather than through a blanket
  `#![allow(dead_code)]` on the module. The blanket one was hiding exactly what
  `layout.rs` records it hid there — `GAUGE` and `RESULT_FAIL` had no caller
  and no pending one, with no `Gauge` widget anywhere in the tree — while the
  header maintained a hand-written list of undrawn entries that had drifted
  from the code it described.

- **The bootstrap-installer scenarios guard against a container that never
  started.** Without it a Docker daemon refusing to start reported as
  `a_tampered_binary_is_refused` failing — "the install script does not verify
  checksums" — which is a security claim about a script that never ran. The
  systemd image builder also takes the build lock its sibling has always taken;
  in a second test binary the lock could not reach, several scenarios could each
  build the same image at `-j8`.

- **Seven comments still stated the pre-update task counts.** The test pinning
  them names the files to correct and was passing, because the constants had
  been updated and the prose had not. Its own guidance was part of the problem:
  it suggested searching for the *new* spelling, which finds the sentences that
  are already right, and missed the count worn as an adjective ("fifty
  implementations"). Both holes are now named in the failure message.

### Fixed
- **The interface's own threads could raise a password prompt under the
  alternate screen.** `LocalExecutor` asked `auth_need()` only when it held a
  `TerminalBroker`, so the two executors built without one — the main thread's
  and the probe thread's — skipped the check entirely and spawned with the
  terminal inherited. On a host whose helper has no live timestamp (`doas`
  without `persist`, or `sudo` after Arch's five minutes) opening the history
  overlay or reverting drew a prompt into the alternate screen in raw mode,
  where it cannot be read and the keystrokes answering it are not echoed: the
  interface appears to hang. Worse on the hangup path, where there is no
  terminal at all — the revert the verification window promises would fail
  silently and leave the change it was undoing in place.

  "No broker" meant two opposite things: on the command line `sudo` *should*
  prompt, and under the interface it must not. Both were spelled `None`, so a
  third state was added rather than inferred — `LocalExecutor::silent` refuses
  with `NoTerminalForPrompt`, naming the command, since the operator's remedy
  is to authenticate before the interface needs to rather than to retry. A
  comment in `probe.rs` asserted both that every query there was unprivileged
  and that a brokerless executor refused; neither was true, which is likely why
  the two privileged calls beneath it went unnoticed.

- **`wireguard.uninstall` ignored `has_purge_for()`.** RHEL and SUSE have no
  purge and both package WireGuard, so `removal=purge` performed a plain
  removal and said nothing — an operator who asked for the configuration to go
  would find their old settings back after reinstalling. The shared helper
  every other task delegates to has consulted the backend and reported
  `TaskPurgeUnavailable` since it was written; this task cannot delegate, its
  unit being a `wg-quick@` template instance, and the copy had lost the gate.

- **A backup copy of the WireGuard private key was left world-readable.**
  `write_uncopied` staged through `tee`, which creates under the process umask,
  and the `chmod` that followed ran only when an existing file's mode was being
  preserved — which a rewrite of `wg0.conf` does not do. The staging file is
  now created at `0600` with `install -m` before anything is written into it,
  and a file this tool creates is given `0644` outright rather than inheriting
  the staging mode. `/var/lib/initd/backups.jsonl` had the same shape on its
  first append and is fixed the same way.

- **The two-host scenarios mounted a binary four of the six images cannot
  run.** `TwoHosts::start_server` called `binary_path()` where the systemd
  helper calls `binary_for(image)`, so Rocky, Alpine, Tumbleweed and Leap got
  the glibc-linked build and every command died with `GLIBC_2.39 not found`.
  Because `configure` is redirected to `/dev/null`, the failure was silent and
  inverted the test: sshd came up unhardened, the old client connected, and
  `an_old_client_survives_the_safe_tier` passed while asserting that hardening
  had not locked it out.

- **The history overlay truncated paths by character count rather than by
  cells**, so a path from `backups.jsonl` holding a wide character overran its
  row — and since the ellipsis is prepended last, the ellipsis was what the
  pane clipped. A second copy of `truncate_head`, measuring the way the one in
  `render.rs` documents as wrong.

- **`users.lock-root` took group membership as proof of escalation.** An
  administrator who takes `%sudo` out of `/etc/sudoers` leaves an account that
  reads back as a member of a group granting it nothing — so the guard counted
  it as a way back in and would have approved locking root on a machine nobody
  can administer. The mechanism for this existed and was applied to one case
  only: `admin_group_grants_alone` was added for openSUSE, where the
  distribution ships `%wheel` commented out. This is the same end state reached
  by a local edit rather than by how the distribution ships, so it is a separate
  refusal that names sudo and the command to check it with.

  Asked by exit code rather than by reading sudo's answer. Measured on
  `debian:13`: `sudo -l -U <user>` exits 0 whether or not anything is granted
  and puts the verdict in a sentence, while `sudo -l -U <user> /bin/true` exits
  0 or 1. Reading the sentence would mean matching another program's
  user-facing text, and sudo ships translations for `es`, `ja` and `nl`.

  **Only the refusal is believed**, which openSUSE is why: it ships
  `ALL ALL=(ALL) ALL` with `Defaults targetpw`, so every account is granted
  everything *using root's password* — measured on `opensuse/tumbleweed`, where
  an account in no administrative group at all answers 0. Counting that as a way
  back in would approve the lockout on the strength of a credential the lockout
  itself removes. A host with no `sudo` answers "nothing learnt" and leaves the
  earlier checks as the verdict, rather than refusing a `doas` machine for the
  absence of a program it does not use.

- **Four SSH tasks wrote `sshd_config` on hosts with no SSH server.** The write
  is validated by running `sshd -t` over the result — correct, since what
  matters is the file the daemon will read — but that is also the only thing
  that would have noticed the daemon was missing, and it notices by failing to
  run a program that is not there. `ProgramNotFound` then travelled past the
  branch that restores the backup, so the host was left holding an edited
  configuration nothing had checked, for a server it does not have. Checked once
  in `write_validated`, which all four reach through.

- **The three git configuration tasks reported success on hosts with no git.**
  They write files rather than running `git config` — deliberately, since it is
  the same write with one fewer program involved and keeps root from following a
  symlinked `~/.gitconfig` — and the cost of that choice is that none of them
  can discover git is missing. "identity set" on a host with no git is a true
  sentence that reads as a working setup. A note rather than a refusal: writing
  ahead of the install is harmless and the file is read once git arrives, so the
  silence was the defect and not the write.

- **`fail2ban.install` watched port 22 whatever port SSH was on.** The field
  carried a compiled-in `22` and never read the host, so on a machine where
  `ssh.change-port` had moved the daemon the jail installed, wrote its
  configuration, started its service and **reported success while protecting
  nothing** — and no later task disagreed with it.

  `LiveDefault::SshPort` already existed for exactly this and was wired to two
  fields; its own comment said "both fields that ask for it" while three asked.
  The other two fail loudly when wrong — a closed port drops the session, a
  wrong "changing from" is read before `Enter` — which is why this was the one
  that survived. A test now asserts over the whole tree that any port field
  naming SSH reads it from the host, so a fourth inherits the requirement
  rather than repeating the defect.

- **`caddy.security-headers` left the snippet written on a host with no Caddy.**
  Validation runs *after* the write, deliberately — what matters is whether the
  file the server will read parses. But a missing binary raises `ProgramNotFound`
  from the validation itself, and `?` carried it past the branch that restores
  the backup: the file stayed modified, unvalidated, under an error naming
  `PATH` rather than the task that installs the server. The presence check now
  runs before the file is touched, and reports `caddy is not installed on this
  host — run caddy.install first`.

- **`caddy.validate` could not tell a missing server from a broken config, nor
  a missing config from a broken one.** Both arrived as somebody else's error:
  `ProgramNotFound` for the first, and for the second Caddy's own `open …: no
  such file` wrapped as `InvalidCaddyfile` — which reads as a syntax error and
  sends the operator to edit a file that was never written. Three outcomes now,
  because they call for three different actions.

- **`wireguard.add-peer` failed with a raw `cat` error on a host with no
  server.** `files.read` was called with no existence guard, so adding a peer to
  a WireGuard that was never installed reported `cat:
  /etc/wireguard/wg0.conf: No such file or directory`. `WireguardNotConfigured`
  — "run wireguard.install first" — already existed and was reachable only from
  the other direction: a file that *was* read and held no `PrivateKey` line.
  `wireguard.status` has guarded the same path since it was written.

- **`mise.install` pointed at a task that does not exist.** Its consequence named
  `mise.activate`, which is not in the tree and never was, so an operator reading
  it went looking for a row that was never built. Activation is a line in the
  operator's own shell configuration, which this tool does not edit — so the row
  names itself and says what to add, the way `gh.install` does about a token it
  cannot supply. The unit test beside it asserted the broken name rather than
  the property; a tree-wide test now checks every consequence resolves to a real
  task, and it was confirmed to catch this one by name.

- **The verification banner never drew the one line stating the limit of its
  promise.** `"Reverts while this session lives."` was written, documented, and
  outside the drawn area at every terminal size — measured absent at 60×15,
  72×24, 80×24, 100×30 and 120×40. The layout reserved five rows for a top
  border and *five* lines, so the last fell off. The banner therefore promised
  the revert unconditionally, in the one screen where this project argues
  hardest that a promise with a silent exception teaches people to disbelieve
  all of it — and `SIGKILL` and a power cut are real exceptions it cannot cover.

  The height is now derived from the lines rather than chosen beside them. The
  defect was not the number five: it was that two things which must agree were
  free to be edited apart, and a translation long enough to wrap would have
  reintroduced it. A test asserts the sentence reaches the buffer at each of
  those sizes.

- **Below 72 columns an applied, unkept change was invisible.** At that width
  one pane is drawn at a time and `Tab` chooses which — and the tool never moves
  focus, so with the cursor where it starts, a narrow terminal drew an ordinary
  task list while `sshd_config` was already written and sixty seconds from being
  put back. No countdown, no `K`/`R`, and the key bar is dropped below 24 rows
  as well, so nothing on screen said a change was pending at all. 60×15 is
  inside the supported range — a phone SSH client, a split tmux pane. The
  window now takes the body regardless of which pane holds focus, because a
  safety state that `Tab` can hide is one the operator has to already know about
  in order to find.

- **Pasting a public key submitted the form.** Bracketed paste was never
  enabled, so pasted text arrived one key event at a time and its trailing
  newline landed on the form's `Enter` arm — sending the form on whatever had
  been delivered so far, and on a multi-field form putting the remainder in the
  wrong field. A key is pasted far more often than it is typed, which the
  parameter's own comment already said. The paste now arrives whole and is
  inserted through the field, so the newline is filtered where every other
  character is rather than being special-cased; outside a field it is discarded,
  since replaying its characters over the tree would run whatever they happen to
  be bound to. Disabled again on exit, so the shell the operator returns to does
  not receive its pastes wrapped in escape sequences.

- **`?` did nothing in the three states that most need it.** The confirmation
  dialog, the verification window and the recorded changes each swallowed it,
  although `mode` has always ranked help above everything and `mode_under_help`
  exists to keep painting what the overlay covers — the machinery was built and
  unreachable from the dialog that is about to change the machine, the window
  with a timer running whose two answers are capitals, and the view whose
  `Enter` restores a configuration file.

- **The first `Esc` over a dialog holding typed values changed nothing on
  screen.** The armed state was computed and never drawn, so the press looked
  like a dropped keystroke — and the reflex that invites is pressing `Esc`
  again, which is the press that discards the work. An invisible guard converts
  a one-press loss into a two-press loss instead of preventing one. The footer
  now reads `Esc again to discard`, in the parameter form and the ports table.

- **RHEL's Docker repository served no metadata.** The `baseurl` was the
  archive root, with no `$releasever/$basearch/stable` tail, so every install
  failed at `dnf install` reporting a repository it could not download.
  Measured: `.../centos/9/x86_64/stable/repodata/repomd.xml` answers 200 and
  `.../centos/repodata/repomd.xml` answers 404. dnf expands both variables
  itself; what it cannot do is invent the path they belong in.

- **Registering an APT repository assumed tools the host may not have.** `curl`
  and `gpg` are absent from a bare `debian:13`, and so is the CA bundle — so
  the key check reported a perfectly good key as unreadable, which reads as
  Docker having published a bad key rather than as this host having nothing to
  read it with. They are installed first, which is the first step of Docker's
  own installation page. A refused key still writes no source, no keyring and
  no key; what it can now leave behind is three ordinary tools, which the test
  for that property states rather than glossing.

  Both were found the same afternoon by a container scenario that reaches the
  install. Nothing had, before: Docker's only container coverage was a refusal,
  and a test that asserts what a task refuses proves nothing about what it does.

### Added
- **A row whose precondition is unmet now refuses `Enter`, rather than only
  saying so.** It is dimmed and carries `-` in the flag column, exactly as a
  task the distribution cannot run is dimmed and carries `·`, and the key bar
  drops its `Enter` hint instead of promising an action the row will decline.

  Advisory was the first version and was worse than either choice:
  `firewall.manage-ports` on a host with no policy still collected a set of
  ports and still opened its red lockout dialog before the guard inside the task
  refused — a sequence of decisions spent on an outcome that was never
  available.

  The marker outranks `!`, which looks wrong and is not. `!` warns that acting
  on the row could end the session; a row whose precondition is unmet will not
  act, so the warning describes something that cannot happen while the marker
  describes why the key does nothing.

  **A requirement the probe could not measure still refuses nothing.** The
  probe has no privilege escalation by design, so "could not ask" is its
  ordinary answer rather than an edge case, and a row greyed out on the strength
  of a question nobody managed to ask is one the operator can neither run nor
  explain. The guard inside `run` remains the barrier behind both: it asks the
  host at the moment it would act, where the interface reports what was last
  measured.

- **Nine tasks now state what must run first, not one.** The mechanism landed
  with a single declaration; the eight tasks whose guards already refused for a
  missing dependency — the four that edit `sshd_config`, `wireguard.add-peer`,
  `docker.rootless`, `caddy.validate` and `caddy.security-headers` — declare it
  too, so each row says so before `Enter` rather than after.

  All eight share one shape: the thing they configure has to be installed, and
  a task installs it. `program_check` is written once for that rather than eight
  times, and asks the `PATH`.

  **That it may ask the `PATH` at all was measured, and openSUSE nearly broke
  it.** `command -v sshd` answers for root on all six images and for an
  unprivileged login on four: openSUSE's `/etc/profile` sets
  `PATH=/usr/local/bin:/usr/bin:/bin` for anyone who is not root, so `sshd` is
  invisible there. What rescues it is that these tasks are reached through
  `sudo`, whose `secure_path` puts `/usr/sbin` back — measured on Tumbleweed,
  where `sudo sh -c 'command -v sshd'` answers and the same question in a login
  shell does not. The probe thread does not escalate but inherits the
  environment of a process that did, which is what makes it hold; a caller
  running these checks from an unprivileged context would have to look on disk
  instead. Recorded beside the helper rather than left to be rediscovered.

  A test pins the pairing a signature cannot: every task that refuses at run
  time for a missing dependency must also declare it. A guard and a declaration
  are two pieces of code saying one thing, and nothing else would notice them
  disagreeing.

- **A task can state what must already be true, and the row says so before
  `Enter` is pressed.** `Task::requires` declares a precondition as a task id
  and a runnable check — the inverse edge of `Consequence::Invalidates`, and
  deliberately the same shape. The detail pane reads it: `firewall.manage-ports`
  on a host with no policy now says *"Not ready yet: run firewall.enable
  first."* instead of being drawn exactly like a row that would work.

  Every guard in this tree lives inside a `run`, which is why this was needed:
  the refusals are good — that one names the task and changes nothing — but an
  operator met them one keystroke at a time.

  **Advisory, never a gate.** The task's own guard stays the barrier. A check
  costs a command, and one per row per frame would put a second of `fork`/`exec`
  in the path of every keypress; and the background probe that runs these has no
  privilege escalation by design, so "could not ask" is its ordinary answer for
  anything privileged. That state draws nothing, because a row greyed out by a
  probe that failed is one the operator can neither run nor explain.

  `FirewallManager::active_check` is new for the same reason `open_port_check`
  exists: the question is spelled per front-end, and a task asking it directly
  would pick `nft` — which names a table that does not exist on RHEL, where the
  rules live in a firewalld zone. Both needles were measured rather than
  assumed; `nft list table inet initd` prints `table inet initd` for an empty
  table as well as a populated one, so a freshly enabled firewall reads as
  active.

  A test asserts every requirement resolves to a real task and that none names
  the task stating it — a row telling the operator to run itself first names no
  step they can take.

- **The help overlay explains the row markers.** `!`, `…`, `·`, `•` and `?` now
  have a legend under the tree's key list, each drawn in the colour it has on
  the row.

  A flag is the only thing on screen carrying meaning with no word beside it.
  Every other glyph either names a key that was pressed or sits next to text
  explaining it, so the markers were the one thing an operator could see and
  have no way to look up from inside the tool — `docs/ui.md` had the table, and
  that file is not on the server being administered. `?` is the worst of the
  five: it is transient, usually gone a few hundred milliseconds after startup,
  so it is seen too rarely to be learnt by repetition.

  The colour is part of the answer, not decoration: someone asking about a red
  `!` is asking about the red. `›` is left out — it opens a level, which
  pressing `Enter` on it demonstrates faster than a line of text can.

  A test asserts every marker the tree draws appears in the legend, so one added
  later and forgotten fails the build rather than shipping unexplained; it was
  confirmed to catch a removed entry by name.

- **`→` opens the selected category in the task tree.** The inverse of `←`,
  which leaves one. Without it the arrows could walk out of a level but not into
  one: descending needed `Enter` while ascending had `Esc`, `Backspace` and `←`.

  It is deliberately narrower than `Enter`, which opens a category *or* runs a
  task. On a task row `→` does nothing at all. An arrow is a movement key, and
  an operator descending a level and overshooting onto a task must not find that
  the next `→` began changing the machine — reaching a task and reaching for the
  next arrow are one keystroke apart.

  Not added to the key bar: on a category it would say what `Enter open` already
  says, and the bar sheds hints by width, so a synonym would push out something
  that is not one. The help overlay lists it, which is where bindings are
  enumerated.

- **The header says a task is alive, and which one.** While a task runs it
  trades the distribution and the privilege mechanism — two facts that do not
  change, and both back when the task ends — for a turning throbber, the task's
  id and an elapsed `m:ss`.

  Nothing had signalled liveness since the status line was removed: a spinner
  and a wall-clock timer went with it, leaving the output pane's write cursor,
  which neither moves nor counts. So a command that is merely slow — an
  `apt-get` resolving mirrors over a laggy link — was indistinguishable from a
  session that had stopped answering, and the reflex that follows is closing the
  terminal, which raises `SIGHUP` and reverts an unrelated unkept change. The
  failure was self-inflicted by the absence of the signal.

  Elapsed time rather than progress, because a task's command count is not known
  before it runs and a percentage would be invented. The throbber is indexed off
  elapsed time rather than a counter, so it animates on the redraw the event
  loop already performs — no extra wakeups, no new state beyond one `Instant`.
  The words beside it carry the meaning, so a terminal without the braille
  glyphs loses nothing.

- **A stop that has been asked for is acknowledged.** The key bar drops
  `Ctrl-C stop` for `stopping after this command` as soon as the request lands.
  Cancellation is refused between commands rather than interrupting the one in
  flight, so a task mid-`dnf install` can absorb a minute before anything else
  changes — a minute during which the screen was byte-identical to before the
  keypress and still advertised the key. Pressing it again is silently ignored,
  and the next escalation is closing the terminal, which raises `SIGHUP`. The
  state was already tracked; it simply never reached the screen. The label says
  `stopping after this command` rather than `stopping`, which would read as
  "killed" — the command in flight is still changing the machine.

- **`docker.install` and `docker.uninstall`, the engine as a machine-wide
  thing.** Installs the container engine and starts it, enabling it at boot,
  and reads both back rather than trusting a command that exited zero. It
  states — without doing it — that adding an account to the `docker` group
  makes that account equivalent to root, since that is the usual next step and
  nothing about the command announces what it grants. The removal leaves
  `/var/lib/docker` alone: images and volumes are the operator's data, and
  nothing here could put them back.

- **The rootless setup on Arch, which no official package provides.** Every
  other family installs the setup script from a package. Arch ships none —
  measured — so the script is fetched from `get.docker.com/rootless`, and the
  task says so before it runs: upstream publishes no per-artefact digest, which
  makes it the one route in this tool that executes code it cannot verify. It
  is stated as a consequence on that family alone, because a warning shown
  everywhere is one nobody reads where it matters.

- **A port can be closed through the front-end that opened it.**
  `FirewallManager::close` is the per-port inverse of `allow`, and it answers
  whether the port is closed *afterwards* rather than whether the command
  succeeded. The two are different claims, and on firewalld they routinely
  disagree.

  On nftables, `nft` deletes a rule by handle and by nothing else — there is no
  "delete the rule that says this". The handles are re-read with `nft -a` at
  the moment of deletion rather than remembered, since a cached handle names
  whatever rule holds that identity now. Measured on `debian:13`: handles are
  stable identities rather than positions, so removing one leaves the others
  answering to the same numbers, and the table and chain carry `# handle` of
  their own — which a looser parse would collect and go on to delete a chain.
  Every duplicate of a rule is deleted rather than the first, because a
  hand-edited ruleset can hold two and closing one leaves the port open under a
  task reporting it closed.

  On firewalld it is `--remove-port` twice, runtime and permanent, never
  `--reload` — the mirror of how a port is added and for a sharper reason: a
  reload standing between an opening and a closing would discard the opening.

- **The ports table, the first dialog here whose contents are a list.** Every
  other task collects a fixed run of fields; a set of ports has a length
  nothing declares in advance. Rows are added with `a`, removed with `d`,
  edited with `Enter`, and the set is applied with `Tab`. Cell editing reuses
  the form's own field wholesale, so the readline bindings, live validation and
  the scrolling window over a long value are the ones that already existed.

  **A row the host admits by a route this tool cannot undo is drawn and
  refused, not hidden.** firewalld's `--list-ports` and its services are two
  different things that `FirewallState.allowed` had been reporting as one, and
  `--remove-port 22/tcp` against the `ssh` service exits zero having closed
  nothing. So `AllowedPort` now carries a `PortOrigin`, service rows are dimmed
  with the service named in a `SOURCE` column, and `d` on one answers with a
  sentence rather than a deletion. Hiding them was the alternative and is worse
  in both directions: the operator leaves believing a port closed, and the
  table disagrees with `firewall.status` on the same host.

  A range stays one row rather than being expanded into the ports it covers.
  `--remove-port 8000-8080/tcp` closes it wholesale, so the range as written is
  both the honest description and the closeable unit; expanding it would offer
  eighty-one removals, none of which work.

  **The table is ruled** — three columns divided by vertical lines, with a rule
  above the heading, below it, and under the last row — and drawn at 88 columns
  rather than the 72 every other dialog shares. Both are about what it holds:
  three columns of left-aligned text read as one ragged block, and the shared
  width is a floor set by the parameter form's footer, for dialogs whose content
  is prose and reads worse the wider it gets.

  **The same rule cannot be listed twice**, and it is the *pair* that must be
  unique rather than the number: `443/tcp` and `443/udp` are two rules and both
  are legitimate, so refusing the second by port alone would refuse a set an
  operator legitimately wants. The typed value stays and the cell stays open,
  since taking back what somebody typed while telling them it collided leaves
  them nothing to correct — the first attempt reverted it, and on a row just
  added that meant the port simply disappeared.

  **Every defect in the drawing was found by dumping the rendered screen and
  reading it**, which is worth recording because none of them was something an
  assertion in this suite was watching for: a row reserved for a rule this
  dialog does not draw, a refusal that inherited an area with no gutter and ran
  into the border ending mid-word, a closing rule pinned to the foot of the
  frame and left hanging three lines under the last port, and a right-hand rule
  a cell outside it. The height constant was wrong three times in three
  directions — eight left a band of empty space, six dropped the last port off
  the bottom, seven is what the screen shows. Space is the thing no test looks
  at unless it is told to; all of them have tests now.

- **A port opened while the operator was deciding is reported rather than
  closed.** The table carries what the host admitted when it opened, so the
  task can tell "the operator removed this" from "this appeared since". Without
  it the two are the same difference, and the second would be silently undone.


- **The kernel-parameter rows report whether this tool declares the parameter,
  and offer to stop.** Reported as tasks with no way to tell they had already
  been run: `Enable IP forwarding` read the same before and after running it.

  What is measured is deliberately *not* the running value. Something else on
  the host is often setting it — measured on `debian:13`, `net.ipv4.ip_forward`
  is 1 because Docker set it and declared it in no file — so a row reading the
  kernel would offer to undo a change this tool never made. The probe reads
  `/etc/sysctl.d/99-initd.conf` instead, which is the only part that is ours.

  For the same reason the inverse removes the declaration and leaves the
  running value alone. A `sysctl` has no unset state: `ip_forward` is 0 or 1,
  and 0 is a policy rather than an absence, so there is nothing to restore to.
  Writing the opposite would take a setting away from whoever else was relying
  on it under the name of undoing our own change. The task says whether the
  parameter still holds its value afterwards, because usually it does.

  Both rows name `Capability::Sysctl`, which cannot tell them apart — it would
  answer "is `sysctl` installed" for two rows asking which *parameter* is
  declared. The probe takes the row's id for that reason, and a test asserts one
  row never reads the other's parameter as its own.

- **The firewall's confirmation names the port and what getting it wrong
  costs.** It showed the generic lockout sentence — "this operation can lock
  you out of a server you reach over SSH, make sure you have another way in" —
  which is true here and unactionable: it names no port, and that dialog is the
  last place the value can still be changed.

  It now reads like `users.lock-root`'s, which was the shape asked for: a red
  block naming the port about to be the only one admitted, and saying plainly
  that a session arriving over SSH depends on it. Where the value disagrees
  with what `sshd -T` reports the host is serving, it says so and names the
  port to use instead — the case that ends the session, and the one an operator
  who has not thought about it cannot see.

  The agreeing case still warns rather than reassuring. `sshd -T` says what the
  daemon serves, not how the operator reached it: a jump host, a forwarded port
  or a provider console all end up here, so "these match, you are safe" would
  be a promise made on evidence that does not support it.

- **The firewall row now offers to disable when the host is already
  filtering.** Reported as a row offering to enable a firewall that was plainly
  on. `firewall.enable` and a new `firewall.disable` share a row like every
  other reversible pair, and the probe decides which verb by asking what the
  host is *doing* rather than what it has installed — the one capability where
  those differ, since every Debian can install `nft` and none filters until
  told to.

  Disabling removes only what this tool created: the `inet initd` table, the
  saved ruleset and the boot unit, or firewalld's daemon where that is the
  front-end. A ruleset somebody else wrote is left alone — a task named for
  undoing its own change must not become the one that flushed Docker's rules.
  Both halves, because a table removed while the boot still replays it is a
  firewall that returns at the next restart, reported as off.

  The saved ruleset is emptied rather than deleted: measured, `nft -f` on an
  empty file exits 0 and leaves the ruleset empty, while a deleted file leaves
  the unit failing at every boot instead of having nothing to do.

- **`ssh.uninstall` exists, against this project's own advice.** It was absent
  by decision — removing the SSH server over its own connection is the single
  operation here with no route back, since the session ends mid-removal and
  reinstalling needs the network path that just closed. Added on request; the
  reasoning has not stopped being true, so it carries the strongest
  confirmation the interface has and says plainly that recovery is the
  provider's console. `docs/user-stories.md` records the reversal rather than
  quietly dropping the promise it made.

- **`ssh.install` reports which OpenSSH the host runs.** Asked for because
  `openssh-server is already installed` says nothing about *what* is installed,
  and the version is what decides which hardening tier is safe —
  `ssh.harden-strict` insists on algorithms an older client may never have
  learned.

  Read from `sshd -V` rather than `ssh -V`: Rocky's `openssh-server` package
  installs no client at all, so asking the client answers `command not found`
  on a host with a working daemon. And read from **stderr**, which is where all
  three implementations print it while leaving stdout empty and exiting 0 —
  measured on `debian:13`, `alpine:3.23` and `rockylinux:9`. This project had
  already paid for that once: two helpers in the container suite read `ssh -V`
  from stdout, so the versions a scenario existed to compare were always blank.

  Only the OpenSSH field is kept. The rest of the banner names the
  distribution's patch level and OpenSSL's version, which answer a different
  question. A version that cannot be read is left out rather than failing the
  task: it is one line of narration after the daemon is already installed and
  running.

- **The description and the output now share the right-hand pane, and `o` folds
  the output away.** The pane used to show one or the other, chosen by whether
  any output existed — so once a task had run, every task selected afterwards
  had its description displaced by the previous one's transcript, with no way
  back until another task started. Reported as the output covering the
  description, which is exactly what it was.

  The description takes up to seven rows and the output takes the rest. A
  ceiling rather than a share: a description is a sentence or two of known
  length while a transcript grows, so splitting by percentage would leave half
  the pane blank above a log that is scrolling.

  `o` folds the output away entirely, for when a long transcript is worth the
  whole pane. It folds rather than clears — the transcript is still there when
  it comes back, which is what the pane's own design is careful about — and it
  takes the focus with it, or the arrow keys would go on scrolling something
  nobody can see while the tree appeared frozen.

  The short-terminal threshold was measured rather than derived, and the first
  attempt was dead code: the sum of the two pane minima is 14, the interface
  refuses to draw below 15 rows at all, and the pane at that height is 13 — so
  a branch guarding "too short to split" could never be reached while reading
  as though it covered the case. It is 18 rows of pane, which is reachable and
  pinned from both sides.

### Fixed
- **`firewall.enable` offered a hardcoded `22` for the port keeping the session
  alive.** Reported as a question that made no sense — *"why do I have to give a
  port when I just want to turn the firewall on?"* — which turned out to be two
  defects wearing one face.

  **The dangerous one:** the port field admits one port through a default-deny
  policy so the operator's own connection survives, and it proposed `22`
  regardless of what the host was serving. On a machine whose SSH had been
  moved, taking the default admitted a port nothing listens on and closed the
  one carrying the session. The field that exists to prevent a lockout was the
  most reliable way to cause one. It now opens on whatever `sshd -T` reports,
  falling back to the file and only then to 22 — measured on `debian:13`, where
  a host with no `Port` line at all still serves 22, so parsing only the file
  would have found nothing in the commonest case. **The CLI had the same hole**
  and now shares the fix: `initd run firewall.enable` with no arguments reads
  the host too.

  **The one that prompted the report:** nothing on screen explained why the
  question was being asked. The description said "denies inbound traffic by
  default" and the field said "SSH port", which reads as an unrelated question
  in a task whose name is a verb with no object. The description now leads with
  what *closes*, names the connection being read over as one of the things at
  risk, and the field is labelled "Port to keep open" — the question it is
  actually asking. The lockout warning says what stops answering before it
  mentions the hosting provider's firewall.

  `ssh.change-port` had the same stale default, and `docs/user-stories.md` has
  promised since before it was true that the field "starts on the current
  port". It does now.

- **Opening a port on a host with no firewall policy blamed the rule.**
  Reported from a Debian 13 host where `nft` was installed and working:
  `firewall.allow-port` answered `Error: Could not process rule: No such file
  or directory`, naming a file for a table nobody had created. `firewall.enable`
  had never run there, so the table the rule targets did not exist.

  The task *did* carry a note for this condition — "nothing is being filtered
  yet" — and it ran **after** the rule was added, twenty-five lines further
  down. On a host with no table the rule cannot be added at all, so the note
  was unreachable in exactly the case it was written for. It is now a refusal,
  before anything is written, naming the task that fixes it.

  Refused rather than repaired, and the alternatives are worth recording.
  Creating the table here would leave an `accept` rule in a ruleset with no
  default-deny policy — a firewall that filters nothing while looking
  configured, which is worse than the error. Enabling the policy is not this
  task's to do: it can end the session that asked for it, which is why
  `firewall.enable` carries a lockout confirmation and this one does not.

- **`ssh.install` never reported an SSH server that was already installed.** It
  detected it correctly when run, but the tree asked the host nothing, so the
  row read the same whether or not the package was there.

  The probe measured only reversible pairs, reasoning that a lone task has no
  verb to choose. It has none — and it can still say whether the thing is
  present. `ssh.install` is deliberately inverse-less, since removing the SSH
  server over SSH is the one operation this tool refuses to offer, so it could
  never be measured. Lone tasks are now measured when they declare a subject,
  which keeps the cost to one query per task that has something to report.

  A reversible row says "already there" by switching verbs; a one-verb row
  carries a flag instead — a new one rather than the existing `✓`, which
  already means *this session installed it*.

- **Two package managers resolved names against an index nobody had
  refreshed.** Found while verifying the sysctl fix on a clean `debian:13`:
  `apt-get install -y procps` answers `E: Unable to locate package procps` and
  exits 100. The package exists and the name is right — nothing had told apt
  where to look. That reads as this backend naming the package wrong, which is
  the one thing a per-family backend exists to get right.

  **Arch had the same defect and a louder symptom.** `pacman -S` never
  refreshes its databases, so on `archlinux:latest`, whose image ships them
  empty, it warns `database file for 'core' does not exist (use '-Sy' to
  download)` and fails with `target not found`. It is now `-Sy`, which syncs
  and installs in one operation.

  Measured before deciding, rather than assumed to be free: on Debian a refresh
  with the lists already fresh costs **342 ms** against 1019 ms cold, on an
  install that itself takes 1567 ms. Cheap enough to pay every time, and far
  cheaper than a name resolved against a stale index. On Arch the sync costs
  274 ms.

  **The other three families were checked and need nothing**: Alpine's `apk
  add --no-cache` fetches the index as part of the operation, and dnf and
  zypper refresh on their own. Verified on `alpine:3.23`, `rockylinux:9` and
  `opensuse/tumbleweed`, each installing successfully from a clean image.

  `-Syu` was considered and rejected for Arch. It would remove the
  partial-upgrade risk that `-Sy` carries, and it would do so by letting a task
  asked to install `nftables` upgrade the kernel and every library on a
  production server. A full upgrade has its own reboot, its own timing and its
  own confirmation, none of which this task has.

  Verified end to end on both families from a clean image, in the exact
  condition that failed: Debian now reports `Installing procps...` and Arch
  `installing nftables` where both previously refused.

- **Thirty field hints were written, compiled, and never drawn.** Reported
  against `firewall.enable`, whose dialog asks for an "SSH port" and gave no
  reason to — the hint answering that question, `kept open, so this session
  survives`, had been on the field all along and the form rendered no hint at
  all. `Param::with_hint` is called thirty times across the tree and
  `header_line` never read the field.

  Several of the missing ones resolve an ambiguity the label cannot: `keep
  leaves the files on disk; delete removes them`, `must appear in /etc/shells`,
  `space-separated; every other account is refused`.

  Drawn beside the label rather than on a row of its own, for the reason the
  code already gives about the option counter: a row per field is the
  difference between fitting a 24-row terminal and not. When the row is too
  tight it is dropped whole rather than truncated — half a sentence reads as a
  defect, and the verdict it would crowd out is the part of the row nobody can
  work without. Pinned in both directions, since a hint that never appears and
  one that pushes the verdict off the edge are both regressions.

- **Rootless Docker blamed the engine for a session that was never
  established.** Reported from a Debian 13 host:
  `runuser -l deploy -c 'systemctl --user disable --now docker.service'`
  answered `Failed to connect to user scope bus via local transport:
  $DBUS_SESSION_BUS_ADDRESS and $XDG_RUNTIME_DIR not defined (consider using
  --machine=<user>@.host …)`. That names two variables, no cause, and suggests
  a flag for reaching another host's bus.

  Both user-service tasks rely on `runuser -l` to open a login session, and on
  `pam_systemd` inside it to set those variables. Debian lists that module in
  `/etc/pam.d/runuser-l` as `-session optional pam_systemd.so`, where the
  leading `-` means a failure is **not even logged**: the shell starts
  perfectly with an empty environment, and every `systemctl --user` after it
  addresses nothing. Reproduced under systemd as PID 1 by preventing
  `systemd-logind` from creating a session.

  Both tasks now ask whether the session is reachable and refuse with an error
  naming `systemd-logind`. The install asks beside its existing subordinate-id
  check, for the same stated reason — discovering it at `enable --now` wastes
  the install. The uninstall asks again rather than trusting the install, since
  the two run at different times, and refuses rather than skipping: a teardown
  that ran on regardless would remove the engine's files while leaving a unit
  nothing stopped, and report success over a half-removed install.

  **Exporting the variables was measured and rejected**, which is worth
  recording because it was the obvious fix and it does not work: the bus socket
  lives *inside* `/run/user/<uid>`, which `logind` creates, so pointing at a
  directory nothing created answers `No such file or directory` — the same
  failure with a different spelling. With the session healthy `runuser -l`
  populates both variables unaided, even without lingering, so there is nothing
  to repair and the honest response is to refuse.

  A second defect surfaced while verifying the first:
  `docker-rootless.uninstall` never checked that the account exists, so
  `user=noexiste` reported the service manager unreachable — true of an account
  that is not there, and it sends the reader to `systemd-logind` over a typo.
  The install had always made that check; its inverse had not.

- **`sysctl` was assumed present on every host, and is packaged separately on
  four of the five families.** Reported from a Debian 13 host, where both
  kernel-parameter tasks answered `FAILED — program sysctl`.

  The firewall had a `is_available` on its trait and sysctl had none, so there
  was nowhere to hang the check: `SysctlManager` grew one, and `Capability`
  grew a `Sysctl` variant so each backend names its own package. The exhaustive
  `match` did its job — the new variant produced **16** compile errors naming
  exactly the sites that had to decide.

  The two halves failed differently, which is why the check is asked once up
  front rather than inferred from either. Reading runs unprivileged and raises
  `ProgramNotFound`; writing is wrapped in `sudo`, so the binary that gets
  spawned *exists* and what comes back is exit 127 with `sudo: sysctl: command
  not found` on stderr — a generic command failure carrying the real cause in
  text nothing parses.

  Package names were measured rather than assumed, and disagree three ways:
  `procps` on Debian and openSUSE, `procps-ng` on RHEL and Arch, and on Alpine
  **no package at all** — `sysctl` there is a busybox applet
  (`/sbin/sysctl -> /bin/busybox`), so it cannot be missing and installing
  anything would be wrong. That family is refused rather than sent to `apk add
  ""`.

  **The obvious availability check was wrong and was measured before it
  shipped.** `sysctl --version` was written first; busybox rejects it *and*
  `-V` with exit 1, so the check would have declared the tool absent across all
  of Alpine — the same trap as the installer's `sha256sum --ignore-missing`,
  which this project has already paid for once. It reads `kernel.ostype`
  instead, which procps and busybox both answer with `Linux`.

  **A second defect surfaced only because the first was fixed.** On
  `rockylinux:9` there is no `/etc/sysctl.d`, and installing `procps-ng` does
  not create one — Debian's `procps` does, and Alpine and Arch ship it, so four
  families hid the fifth. The task got past the install and failed at
  `tee: /etc/sysctl.d/99-initd.conf.initd.new: No such file or directory`, a
  write failing for a reason that names a temporary file rather than the
  missing directory. The drop-in's parent is now created first.

  Verified end to end on `rockylinux:9`, the worst case, where the task now
  reports `Installing procps-ng...` and `net.ipv4.ip_forward = 1, now and after
  a reboot`. Alpine and Arch were checked to still install nothing.

- **A firewall front-end that is not installed made three tasks report a broken
  tool.** Reported from a Debian 13 host: `firewall.status`, `firewall.enable`
  and `firewall.allow-port` each answered `nft --version` / `FAILED — program
  nft`, which reads as the tool being broken rather than as a package nobody
  had installed.

  `Nftables::is_available` propagated `ProgramNotFound` with `?` instead of
  answering `false`. An absent binary produces no process at all — the `spawn`
  fails — so the one case the check exists for was the one it could not report.
  Both callers were defeated at once, and both already had correct code for it:
  `firewall.status` carries a message naming the front-ends it looked for, and
  `firewall.enable` carries a branch that installs the package, with a comment
  saying it exists so nobody sees "command not found". Neither was reachable.

  Measured on `rockylinux:9` with no front-end installed: `firewall.status` now
  answers `none of these is installed: firewalld, nftables` and
  `firewall.enable` answers `installing nftables`, where both previously failed.

  `Firewalld::is_available` had the same defect and mattered more, because RHEL
  asks firewalld **first**: a host whose administrator removed it to drive `nft`
  directly failed on the first candidate and never reached the second — a state
  that backend's own documentation calls ordinary rather than broken.

  **The test that should have caught it asserted the bug instead.** It scripted
  the absence as `Reply::failure(127, "nft: not found")` — a *process* that ran
  and reported not-found, which only a shell produces, and no shell is in this
  path. It passed for as long as the defect lived, asserting the install on a
  host that had `nft` all along. The mock could not express the real case:
  `Reply` modelled only "a process finished with this status", so
  `Reply::NotFound` was added to model "no process ran". A defect a test cannot
  express is one review has to catch every time, and this one was already
  handled correctly twice in the same file.
- **Two scenarios were deleting each other's containers, and blaming the code
  for it.** `TwoHosts::start` named its containers from `image.family`, which
  answers `suse` for both Tumbleweed and Leap — so the two built the same three
  names, and `start` begins by tearing down leftovers under those names.
  Running in parallel, whichever started second removed the other's containers
  mid-scenario.

  What CI reported was
  `ssh.harden must not lock out an old client (client Error response from
  daemon: No such container: initd-client-suse-safe …)`: the tier under test
  blamed for a pair of containers another test had just removed. The surviving
  scenario had waited its full 180s for a server that no longer existed, then
  continued — the silent-degradation shape this project condemns elsewhere —
  and took 207s to fail. It now takes 13s and passes.

  **The identical mistake is recorded on `Image::family_tag` itself**, which
  exists because committed images collided the same way and whose comment
  describes this failure word for word. The lesson was applied there and not
  one file along. Nothing else was affected: every other use of `image.family`
  in the tests is a message or an assertion about the family, which is what it
  is for.

  A second defect surfaced with it, in the helper that reads OpenSSH versions
  for that message: it returned Docker's own error *as though it were a
  version*. `(client Error response from daemon: No such container …)` reads as
  a version string until somebody looks twice, and buried the actual finding.
  It now says `<container is gone: …>`.

  Full suite: 1633 tests in 474s, down from 559s — the openSUSE pair no longer
  fight each other.

## [0.2.1] — 2026-08-12

One change, and it reverses a decision made hours earlier in the same day —
which is worth saying plainly rather than presenting the second answer as if
it had always been the plan.


### Fixed
- **The installer no longer demands root, but it does demand a route to it.**
  Reported from a real host: `curl … | sh` as `deploy` answered
  `could not write to /usr/local/bin — run as root, or set INITD_INSTALL_DIR`.
  Asking for an environment variable was the wrong answer, and so was the first
  replacement: falling back to `~/.local/bin`, which shipped in 0.2.0.

  **An account that can escalate installs system-wide.** The script asks
  whether it can become root *without being asked for a password* — `sudo -n`,
  `doas -n`, `run0 --no-ask-password`, each of which answers rather than
  prompting — and uses it when the answer is yes. That is the same reasoning
  `LocalExecutor` follows before every privileged command: ask before a helper
  asks.

  **And an account with no route to root is refused rather than served a binary
  that cannot work.** A `~/.local/bin` fallback was written, measured and
  removed. `initd` administers the machine — **138** of the commands it runs
  are privileged — so a copy in an account that cannot escalate is a program
  that starts, draws its interface and fails at the first thing anybody asks of
  it. The fallback turned "you cannot install this" into "you have installed
  this and it does not work", which is the worse of the two.

  The refusal distinguishes two situations that look alike. An account with no
  `sudo` at all is told to find an administrator; an account whose `sudo` would
  prompt is told to run `curl … | sudo sh` or `sudo -v` first — telling *that*
  reader to find an administrator would be telling them to find themselves.
  Verified on all four cases in a container, with the prompting one run under
  `timeout` and stdin closed so hanging fails the test rather than stalling it.

- **The installer never worked on Alpine, which is how this was found.** Its
  `sha256sum` is a busybox applet, and busybox knows neither `--ignore-missing`
  nor `--check` — both answered `unrecognized option`, so verification failed
  on a *genuine* release and the script refused to install, reporting tampering
  where there was none. Measured against busybox 1.37.0, and against GNU
  coreutils 8.32 and 9.7. The digest is now compared as two strings, which
  every one of the three accepts.

  The existing tests could not have caught it: they set `INITD_INSTALL_DIR` and
  so never reached the fallback, and — worse — they asserted
  `observed.contains("INSTALLED")`, which **`NOT_INSTALLED` satisfies**. That is
  the substring trap this project already recorded for `is-active`, where
  `inactive` contains `active`. All three assertions now compare whole lines,
  and the new test was checked by deleting the fallback and confirming it fails.

## [0.2.0] — 2026-08-12

### Changed
- **The container suite runs in half the time: 1044s to 564s, measured with the
  cached images deleted first so the figure includes building them.**

  The cost was dnf, and the mechanism was worth measuring rather than guessing
  at. On `rockylinux:9`, `/var/cache/dnf` is 4 KB on the bare image and **69 MB**
  after a single `dnf install` — a solv cache built once and then reused, with
  the file's mtime unchanged on the second call. Per scenario: 6551 ms on the
  bare image, 2199 ms on the metadata-only cache the harness already built, and
  **313 ms** with the packages baked in. `cached_image` was already the right
  shape and already committed an image; it stopped at the refresh.

  Three "obvious" dnf mitigations were measured and dropped. `fastestmirror` is
  already off by default; `install_weak_deps=False` installs the same eleven
  packages; and `max_parallel_downloads=10` makes it **worse** — 37.3s against
  6.0s. One claim that circulated during the investigation was wrong and is
  recorded here so nobody re-derives it: Rocky does **not** ship
  `tsflags=nodocs`, which is Fedora's default. Its `dnf.conf` has five lines and
  `tsflags` is not among them.

  `.config/nextest.toml` bounds what `--test-threads` never did. That flag
  limits test *processes*; the expensive thing is a container, and eight test
  binaries were each free to start one. A `containers` test group makes the
  eight mean eight containers. The filter deliberately excludes the harness's
  own unit tests, which live in the same binaries and start nothing.

  `slow-timeout` reports at a minute and `terminate-after` kills at five. The
  ceiling is generous on purpose: openSUSE's sshd takes 111-122s to start under
  load, so a tighter one would kill scenarios that were going to pass. Retries
  are deliberately **not** configured — nextest would mark a recovered test
  FLAKY and count it as a pass, and this suite's flakiness has twice turned out
  to be a real defect.

  A lock file serialises building one image's cache. nextest runs each test in
  its own process, so a `Mutex` reaches none of the others: at `-j8`, eight
  scenarios finding no cache all built one, each downloading the same metadata.

  **The ceiling above killed a release, and the fix is where preparation
  happens rather than how long it is given.** `terminate-after` was written to
  bound a stuck scenario, and it reached something else: the first scenario to
  touch an image also *builds* it. On this machine that is 25s; on the
  two-core runner CI uses it is over 300s, so the two Rocky scenarios that
  happened to be building it were killed at five minutes — and since every
  other Rocky scenario was waiting for that image, the run stopped after 16 of
  1628 tests. Nothing was published, because `Build` needs `verify`.

  Raising the ceiling would have treated the symptom and left the same failure
  waiting on a slower machine. Instead `prepare_the_images` builds all six and
  asserts nothing, and each CI job runs it as its own step before the suite,
  where no test's timeout can reach it. Measured: 138s for six images here, and
  the suite then runs in 559s.

  nextest's setup scripts are the idiomatic answer and were declined: they are
  still experimental, and a release path is the wrong place to depend on that.


Nine tasks, three fixes for failures reported from a running server, and a key
for the console those failures were seen on. Nothing a script depended on
changed: no task id was renamed, no exit code moved, and the tree's regrouping
is a matter for the interface alone.

### Added
- **git and the GitHub CLI, with the configuration each needs to be usable.**
  Seven tasks: `git.install` / `git.uninstall`, `git.identity`,
  `git.default-branch`, `git.safe-directory`, and `gh.install` /
  `gh.uninstall`.

  git is the one capability all five families package under one name — worth
  stating, since it is the shape the backend indirection exists because most
  capabilities do *not* have. `gh` is the immediate counter-example: `gh` on
  Debian, Ubuntu and openSUSE, `github-cli` on Arch and Alpine, and nothing at
  all in Red Hat's repositories. Two priors were wrong and measured rather than
  assumed — `gh` **is** in Debian main (2.46 in trixie), which
  `packages.debian.org`'s keyword search does not surface, and the name splits
  by family rather than by packaging system.

  **RHEL reaches it through a checksum-verified release, and GitHub's own
  repository was declined on timing rather than principle.** That repository's
  signing key is mid-rotation: the certificate this build would have pinned
  (`2C6106201985B60E6C7AC87323F3D4EA75716059`) **expires 2026-09-05**, and its
  replacement appears on `keyserver.ubuntu.com` and not on `keys.openpgp.org` —
  and that keyserver accepts unverified uploads, so its copy corroborates
  nothing. Pinning either would be wrong differently: one stops working within
  weeks, the other was never independently published. The releases carry no PGP
  signature either, but the digests are measured, which is the standard
  `rustup-init` is already held to. The release is also the newer artefact:
  2.97.0 against Debian's 2.46.

  **The configuration is what upstream calls mandatory or strongly recommended,
  and nothing else.** git exits 128 without an identity — measured on 2.47.3,
  printing `*** Please tell me who you are.` — so `git.identity` writes
  `user.name` and `user.email` into an account's *own* `~/.gitconfig`, never
  system-wide, since one `user.email` for a host would attribute everybody's
  commits to one person. `git.safe-directory` covers the case that actually
  bites on a server: since CVE-2022-24765 git refuses to read a repository owned
  by somebody else, which a deploy checkout usually is. `git.default-branch`
  silences the ten-line hint `git init` prints. Deliberately absent:
  `pull.rebase`, `push.default`, `core.editor` and `core.autocrlf` — preference
  rather than requirement, and the last is a Windows concern that is actively
  wrong on a Linux server.

  `git config` is not shelled out to, for the reason nothing here shells out to
  the program that owns a file: the value would reach a shell, and a name
  carrying an apostrophe is ordinary. `tasks/gitconfig.rs` parses the subset it
  writes and leaves every other line exactly as found — an operator's config is
  theirs, and `safe.directory` is appended to rather than replaced, since
  replacing would un-trust a checkout that worked yesterday.

  Verified on all five families against real hosts rather than mocks, because a
  mock answers whatever it is asked: git *reads back* the identity, the default
  branch and both trusted paths on Debian 13, Arch, Alpine 3.23, Rocky 9 and
  Tumbleweed — and on Rocky the release path installed 2.97.0 where no package
  exists.

- **`rust.install` runs on RHEL, and on the Debian suites that package no
  `rustup`.** RHEL's refusal named the condition it was waiting for —
  `rustup-init` is checksummed per architecture, and only the archive path pins
  a version, so a digest compiled into this build does not invalidate itself on
  the next rustup release. That path exists, so the refusal is lifted. Alpine
  keeps its own: it has no `runuser` (measured across all five images), and
  busybox's `su` has different session semantics.

  Debian gains the same route where it needs it. `RUST_PACKAGE` was
  unconditional while `rustup` is in trixie and **not in bookworm**, so
  `rust.install` failed on oldstable exactly as `mise.install` failed on trixie.
  Resolved per suite by `DebianBackend::for_distribution`, from the codename
  rather than `VERSION_ID` — Ubuntu declares `24.04` where Debian declares `13`,
  and comparing those as numbers means knowing which family's scale is being
  read. A codename this build does not know falls to the verified installer,
  which is the safe direction.

  **The toolchain is installed for an account, not for the machine**, which is
  what the task's description has always promised and what rustup requires:
  measured in a container, `rustup-init` writes `rustup` plus **thirteen
  symlinks** — `cargo`, `rustc`, `rustdoc` and ten more — that dispatch on
  `argv[0]`, and the binary resolves `~/.cargo` and `~/.rustup` from the
  environment at run time. Installed under `/usr/local` and run with
  `HOME=/root` it answers `no installed toolchains`, so a system-wide copy would
  not have been one. Its own anti-root guard does not fire on a genuine root
  login and `-y` makes that path exit zero, so where the toolchain lands had to
  be decided here rather than left to the artefact.

  `Release` gained a `Payload`, because `rustup-init` is a bare ELF and the
  installer ran `tar -xf` unconditionally. `BinaryInstaller` gained
  `run_installer`, because the artefact is not the tool: it installs into the
  account's own directory and then has no purpose, so leaving it in
  `/usr/local/bin` would put a spent installer on `PATH` for everybody.

  rustup signs nothing here — the toolchain is signed, `rustup-init` is not, and
  the request has been open since 2016 with a second closed as not planned. What
  the compiled-in digest claims is therefore narrower than Docker's
  independently-published fingerprint: that the artefact is byte-identical to
  the one this project inspected. It is stated that way in the table rather than
  implied. `curl https://sh.rustup.rs | sh` was declined for the reason CrowdSec
  is declared absent on RHEL — its 910 lines verify nothing, and its only
  mention of `sha256` is the name of a TLS ciphersuite.

  **Two defects surfaced only in containers, and neither could have been found
  by a mock.** The staging script's `trap` fired when *its* shell exited, which
  is before the installer runs — deleting the binary the next command was about
  to execute, and reporting it as a missing file. And `sha256sum -c` writes
  `download: OK` to **stdout**, which ran together with the staged path the same
  script returns, so the caller read `…/download: OK…` as a path and the
  installer failed with exit 127. A mock answers whatever it is asked and has no
  opinion about either. Verified end to end afterwards on `rockylinux:9` and
  `debian:12` — `rustup` and `cargo` present in the account's own `~/.cargo/bin`
  with `cargo` a symlink, nothing written to `/usr/local/bin`, no staging
  directory left behind — and on `debian:13`, which takes the package route and
  downloads nothing.

  `rust.uninstall` stopped promising something it cannot keep on the new route.
  `rustup self uninstall` prints "removing rustup home" and "removing cargo
  home" and means both — measured, the two directories are gone afterwards, and
  there is no flag that spares them. The task said toolchains stay where they
  are; it now says that where the distribution packaged the manager, and says
  what goes with it where it did not.
- **`Ctrl-L` repaints the screen.** Drawing writes only the cells that changed,
  so anything else writing to the same terminal leaves damage no later frame
  repairs. On a server that "anything else" is the kernel — `printk` goes
  straight to the console device, around the escape-sequence processing the
  alternate screen relies on, so the alternate screen does not isolate the
  interface from it. Reported from a VPS panel's web console, where
  `systemd-ssh-generator` failing to query an `AF_VSOCK` CID was drawn through
  the panels; that console is also where an unconfigured server is administered
  from, before SSH is reachable.

  Suppressing the messages instead was rejected: `/proc/sys/kernel/printk` and
  `setterm -msg off` are machine-global, they blind anyone on another console,
  and they would silence the kernel during exactly the changes — hardening SSH,
  filtering a port — worth watching. The key follows htop and nvtop; k9s has
  declined the same request twice and leaves users restarting.

  A form keeps the chord for its own list of host-offered values, which
  `docs/ui.md` documents and which the readline keys beside it make the natural
  spelling. Taking it globally broke that list silently, and the test that
  presses it to open one is what caught it.

### Changed
- **`devtools.rs` became `devtools/`, one file per tool, and git and GitHub got
  a category of their own.** The file had reached 2145 lines holding six tools
  and twelve tasks; `ssh/` set the precedent for what to do about that. Nothing
  about any task changed — the split is by `pub struct`, the bodies were moved
  rather than retyped, and the suite runs the same 1064 tests it did before.

  The grouping is about the screen rather than the code. Flat, git's five rows
  and gh's two crowded out the four tools beside them, and "set a git identity"
  read as a peer of "install the fish shell". Nested, the area is six rows
  again.

  **Two categories rather than one**, because they are two tools: git runs on
  this machine and needs configuring before it will commit, `gh` is a client for
  somebody else's service and needs a token. Grouping them would be grouping by
  the word they share — and somebody installing git on a build server has no
  business being shown GitHub. GitHub holds one row today, which is a category
  with room in it rather than a category that earned its keep.

  Task ids are untouched by the move: where a task sits in the tree is a matter
  for the interface, and a script naming `git.identity` keeps working wherever
  it is drawn.

  Two things the split surfaced rather than caused: `InstallZellij::latest` was
  private to a file that no longer holds its only caller, and the test module
  had been relying on imports its neighbours brought in.

### Fixed
- **The two-container harness gave up on openSUSE's sshd before it answered.**
  `DAEMON_WAIT_TRIES` was ninety seconds, chosen in the same commit whose own
  note recorded openSUSE taking "111s and 118s" — a ceiling set below a number
  already measured beside it. Because the wait continues rather than failing,
  running out does not produce a slow test: it sends the login to a daemon that
  has not finished starting, and the scenario reports `ssh.harden` locking out
  an old client. Two full runs at `-j8` collected on it, at 111s and 122s.

  Now a hundred and eighty. Measured beside those failures: the same scenario
  alone takes **14.9s**, a seven-fold spread that is contention rather than
  anything about the daemon or the tier under test. The ceiling costs nothing
  when the daemon is quick — the loop returns on the first try that sees the
  line.

- **`docker-rootless.install` failed on Debian with "no installation
  candidate".** The backend named `docker-ce-rootless-extras`, which is correct
  — Debian's own `docker.io` carries no `dockerd-rootless-setuptool.sh`, so
  there would be nothing for the task to run — but that package is served by
  Docker's repository and nothing registered it. The task has asked
  `repository_for` since RHEL needed it; Debian answered `None`, so the step was
  skipped and `apt-get` was sent looking for a package no Debian suite has ever
  carried. It reads as a wrong package name rather than as a missing source.

  `AptRepositories` is the deb822 counterpart to `RpmRepositories`, in the same
  order for the same reason: the key is fetched, its fingerprint derived on the
  host, and only a match writes anything. Two things differ, both measured.

  APT expands `$(ARCH)` and nothing else, so unlike dnf's `$releasever` the
  suite cannot be deferred to the package manager — `Repository` carries one,
  read from the host's `VERSION_CODENAME`, and a repository reaching the
  registrar without one is refused rather than guessed at. `$(ARCH)` is also
  **not** expanded in the `Architectures:` field, which the first attempt
  assumed by extrapolating from the path: measured on `debian:13`, that source
  registers, updates without complaint, and resolves the package to
  `Candidate: (none)` — the symptom of having no repository, reached through a
  repository that is there. The field is omitted so APT uses the host's own.

  The key is placed in `/etc/apt/keyrings` and named by `Signed-By` rather than
  dropped in `trusted.gpg.d`, where it would vouch for every source on the
  machine including Debian's.

  The fingerprint is `9DC858229FC7DD38854AE2D88D81803C0EBFCD88`, and it is not
  the RPM one already in the tree — different keys, different UIDs, and using
  either where the other belongs refuses every legitimate key. Docker's own
  pages no longer print it, so it was taken from `keys.openpgp.org` and
  `keyserver.ubuntu.com`, derived from raw packet bytes rather than read off a
  page. It pins the *primary* key: Docker signs its `InRelease` with a subkey,
  so a check comparing a signature's issuer against this value would refuse a
  correct key.

  Verified end to end on `debian:13` rather than against a mock: the fingerprint
  matches, the package goes from `Candidate: (none)` to
  `5:29.7.2-1~debian.13~trixie`, `/usr/bin/dockerd-rootless-setuptool.sh` is
  present afterwards, and nothing lands in `trusted.gpg.d`.

- **`mise.install` failed on Debian with "Unable to locate package mise".** No
  Debian or Ubuntu suite has ever carried it — bookworm, trixie, forky, sid and
  jammy through resolute all checked, where every search hit is a substring
  (`misery`, a tail of `*-pro-mise-*` JavaScript packages). The task already
  routes an empty name to the verified musl release, as it does on RHEL and
  openSUSE, and already carries the digests; only the Debian constant claimed
  otherwise. Three lines above it, `ZELLIJ_PACKAGE` records that blog posts
  claiming `apt install zellij` works are wrong — mise had fallen into the same
  trap without the note.

  The test that should have caught it asserted the opposite: it ran the task
  against Debian and checked the command mentioned `apt-get`, which a mock
  answers whatever it is asked. A mock has no opinion about whether a package
  exists. It now runs against Arch, which does package mise.

- **A child that exits before reading its stdin no longer reports a broken pipe
  instead of its own refusal.** `join_stdin_writer` turned every write failure
  into `CommandIo`, and the owned-directory script refuses a planted symlink by
  exiting 9 *without* consuming stdin — so the write landed on a closed pipe and
  the operator would have been handed a generic I/O error in place of
  `UnsafeSymlink`, sent looking for a disk fault rather than for the account
  racing them for the path. The exit code is the answer in that case and the
  caller reads it a line later. Every other write error is still surfaced: a
  pipe broken for any other reason means the child did not receive what it was
  given, which for a file write is the difference between the new contents and
  nothing.

  Found by CI, which lost the race this machine kept winning — the same
  `unix_files` test passed here ten times in a row and failed on a loaded
  runner. Its own helper had the matching defect and panicked on the expected
  broken pipe; the new `local.rs` test fails without the fix rather than
  depending on who wins.

- **The two-container harness waited for something openSUSE never produces.**
  `TwoHosts::start_server_daemon` polled `/run/sshd.pid` for thirty seconds and
  then continued as though the daemon were up. openSUSE's sshd does not write
  that file — measured on Tumbleweed, where the daemon answers immediately and
  the file is still absent a minute later — so the wait always ran its full
  length. Thirty seconds happened to cover it on a quiet machine; on CI it did
  not, and `an_old_client_survives_the_safe_tier::tumbleweed` failed against a
  daemon that had not finished starting, reporting it as `ssh.harden` locking
  out an old client.

  The wait now greps the daemon's own `Server listening on ...` line out of the
  log the harness already captures, with a ninety-second ceiling: openSUSE takes
  111s and 118s in the scenarios that install most, where the other four images
  answer on the first try. `/dev/tcp` was tried first and rejected on
  measurement — it is a bash extension, and Debian's `dash` and Alpine's busybox
  `ash` report "not listening" forever. `ss`, `nc` and `netstat` are each in
  exactly one image, and `ssh` is absent from Rocky.

- **`client_version` and `server_version` always returned nothing.** OpenSSH
  prints `-V` on stderr and both helpers read only stdout, so every scenario
  that names the versions it compared printed `(client , server )`. That is how
  the CI failure above was reported, and the blank is what sent the reader to
  `ssh.harden` rather than to the harness. Both streams are read now, and a
  container that answers nothing at all says so rather than rendering as empty.

### Changed
- A multi-line `sh -c` script renders as `<n-line script>` rather than in full.
  `Command`'s `Display` is what the output pane announces before a command runs
  and what `CommandFailed` carries when one fails, so the fourteen-line
  owned-directory write would have buried every `ssh.authorize-key` transcript
  under a program the operator did not write — and repeated it inside the error.
  A one-line script is still shown as it is: `sh -c 'command -v fish'` is
  exactly what somebody wants to see when a program is not found.
- The bordered panel is built in one place. Nine call sites wrote
  `Block::default().borders(Borders::ALL).border_style(…).title(…)` in full —
  `search.rs` had resorted to a comment saying it was drawn "like every other
  overlay", which is a function's job rather than a comment's — and now call
  `layout::framed`. The horizontal rule two dialogs drew, one as a `Paragraph`
  and one as a `Line`, is `layout::dialog_rule`. The confirmation dialog's
  partly-bordered footer still builds its own `Block`: there is one of those and
  no pattern to share.
- The recorded-changes overlay's title is framed by spaces, like every other
  pane title. `HelpTitle` and `SearchTitle` carry theirs in the catalogue and
  `HistoryTitle` did not, so its words sat against the border's corner while the
  panes beside it had air.
- `rpm -q` is asked in one place. RHEL and SUSE both answered `is_installed`
  with the same command under the same reasoning — SUSE's copy said "for the
  reason RHEL records", which is the sentence that says a function was wanted —
  so it moved to `backend/rpm_packages.rs`. `install` and `remove` stay where
  they are: `dnf install -y` and `zypper --non-interactive install` differ in
  more than spelling, and folding them together would hide that behind a
  shared name.
- `i18n/en.rs` carries the same fifteen section headers as `i18n/mod.rs`. The
  two are coupled one-to-one — the enum and its rendering — and `en.rs` repeated
  only the eight `Interface: *` ones, so its match ran unheaded until halfway
  down.

### Fixed
- Comments that had stopped being true. `Mode::Running` described reading a
  spinner and a clock from `Running`, which has held neither since the status
  line was removed; a test's comment said the status row "keeps the summary" in
  the present tense, and its name still claimed the row existed;
  `backup_index.rs` said in two places that `wireguard.add-peer` is what writes
  `wg0.conf` without recording, when `wireguard.install` writes it twice the
  same way — the rule is the path, not the caller, which is precisely the lesson
  that finding cost; and `field_indent` claimed no ordinary command output has a
  two-space gap "at the head of a line", when it looks for one anywhere past the
  first column and so hangs `ls -l` output under a spurious label.
- `docs/user-stories.md` promised, as an acceptance criterion, "a spinner and an
  elapsed clock keep moving" — removed in the same commit that wrote the
  contradiction into `docs/ui.md` four hundred lines away. It now describes the
  write cursor and states the limit the cursor does not cover.
- **The two kinds of consequence are drawn apart, as `docs/ui.md` already said
  they were.** `consequence` and `consequence_external` were declared, described
  in the role table, and justified in `style.rs` — the administrator has to be
  able to tell a warning the tool can settle from one that is theirs to chase —
  and neither was ever applied. A consequence rides an ordinary `Stdout` line
  and the pane took its colour from the stream, so both drew in `normal` and the
  distinction survived only in the glyph. Unlike the three roles the document
  admits are undrawn, these two were not on that list.

  `OutputLine` now carries an optional `Emphasis` — what the line *is*, not what
  colour it takes, so `exec` gains no opinion about presentation and the command
  line ignores it. Resolving it in `style_of` rather than at the call site is
  what keeps a wrapped consequence from returning to `normal` halfway through.
- **A wrapped line no longer pushes the newest output off the screen.** The
  output pane hands its scroll offset to a widget that measures in *wrapped*
  rows, and computed it from the number of *source* lines. One long line
  therefore scrolled the view further than there was content for: at 40 columns
  a 200-character line wraps to five rows, and four rows of the newest output
  went off the bottom while the pane still reported itself as following. Found
  while making the pane cheaper to draw, not by a test — nothing rendered a
  wrapped line and then looked for the tail.

- **The output pane wraps only what it draws.** `render` rebuilt every retained
  line each frame — up to `MAX_LINES`, which a package installation reaches —
  to draw a few dozen rows, at ten frames a second, with a `String` clone per
  line. It now walks back from the newest until the viewport is covered, which
  is also what makes the row count above correct: the walk counts rows, so the
  offset is measured in the same unit the widget uses. A line straddling the top
  edge is gathered whole and scrolled past rather than dropped.
- **A password no longer survives being formatted.** `PasswordPolicy::Set` and
  the TUI's `Field` both derived `Debug` while holding a plaintext secret — the
  field's buffer being exactly what masking keeps off the screen. Nothing
  printed either today, which is the argument for fixing it rather than against:
  the leak would arrive with a `{:?}` somebody adds while debugging an unrelated
  field, and would not look like a change to how passwords are handled. Both now
  write `Debug` by hand; a secret field reports its length, which is already on
  screen as one bullet per character.
- **`ssh.authorize-key` no longer leaves a window for a link planted after its
  check.** The task asked whether `~/.ssh` and `authorized_keys` were symlinks,
  then ran up to eight further privileged commands — `install -d`, two `chown`s,
  a `chmod`, the write — each resolving those paths afresh. `chown` and `chmod`
  follow links, and the account that owns the home is the one process certain to
  be watching for the gap, so a link planted after the check had root apply an
  ownership or a mode wherever it pointed.

  The whole sequence is now one privileged invocation that re-checks between its
  own steps and exits 9 naming the path it refused. The staging file is created
  by `install` with its final mode and owner already on it, so there is no
  moment when the key exists and its mode does not — a stronger guarantee than
  the create-empty-then-chmod ordering it replaces. Paths travel as positional
  parameters, never interpolated into the script.

  Verified against a real shell rather than a mock, which records commands
  without running them: five tests cover the modes, the absent staging file,
  a link planted in place of the file, one in place of the directory, and a
  rewrite keeping its mode.

  `FileEditor::set_owner` went with it, having lost its last caller.
- **A generated WireGuard key no longer reaches the output pane.** `wg genkey`
  and `wg genpsk` print the secret on stdout, and every line of stdout is handed
  to whatever is observing the executor — which under the interface is the
  transcript an administrator scrolls, pastes into a bug report and copies to
  the clipboard with OSC 52. The protection that existed covered the other
  direction only: `Command::stdin` keeps a key out of `argv`, and `wg pubkey`
  consumes one that way, so a key was safe while being *read* and published
  while being *made*.

  `Command::secret_output()` marks the command whose output is itself the
  secret, and `LocalExecutor` takes the unobserved path for it even when the
  interface is watching. The caller still receives the key in `Output`; what is
  withheld is the audience. The command line is still announced, so the
  transcript shows that a key was generated.

  Neither of the two tests guarding this file could have caught it: both drive
  `MockExecutor`, which has no observer to leak to. The new one attaches a real
  observer and asserts the key never arrives.

- **A task the operator stops now drops the password it was given.** The
  cancellation branch of `finish_run` returned before the wipe, so a
  `users.create` stopped between `chpasswd` and the admin-group work left the
  plaintext password in `ran_with` for the rest of the session — the outcome an
  operator reaches deliberately, by pressing a key, having decided something is
  wrong. The same early return skipped the presence refresh, leaving the tree
  claiming an installed state that a half-applied task had invalidated.

  Both obligations moved into `finish_bookkeeping`, which every way a task can
  end now reaches. The existing test only ever exercised `AccountExists`; the
  new one exercises `Cancelled` and fails without the fix.

### Removed
- The status line is gone, and with it `src/tui/status.rs`, the nine states, the
  twenty-eight messages they carried, and five style roles. Nothing is drawn on
  the bottom border now but the tree's census.
  
  What it said was already on screen said better. `CONFIRM` and `INPUT` named a
  dialog occupying the middle of the terminal; `UNSUPPORTED` duplicated a dimmed
  row, a flag in its own column and the detail pane; the two outcomes moved into
  the transcript. What genuinely goes with it and has no replacement is the
  liveness pair — a spinner and a wall-clock timer — which were the only thing
  distinguishing a quiet command from a session that had stopped answering over
  a slow link. The output pane's write cursor is what is left, and it neither
  moves nor counts.

  **A refused keystroke now produces no signal at all.** Pressing `Enter` on a
  task this host cannot run, or `q` while one is running, is declined silently —
  indistinguishable from a key that never arrived. Nine of the twenty-eight
  messages were refusals of that kind. Stated in `docs/ui.md` and
  `docs/user-stories.md` as a known limit rather than left for an operator to
  discover.

  A task now jumps the pane back to its tail when it finishes. Without it a task
  narrating more lines than the pane is tall — `users.lock-root` examines
  twenty-one accounts on a stock `debian:13` — left its own report below the
  visible rows, which is a correct refusal nobody can see. Measured in a
  container.

### Changed
- A failed task is reported in the output pane, in labelled fields, and no longer
  anywhere else. `FAILED` and `CANCELLED` left the border first, for the reason
  the whole line went a commit later: an outcome belongs beside the commands that
  produced it. The border was one line that ratatui truncates without an
  ellipsis, so what it could carry was a task id and a word —
  `docker-rootless.uninstall — failed` — while the exit code and the stderr that
  say *why* were either buried mid-sentence or cut.

  The structure was always there and was thrown away: `CommandFailed` carries
  `command`, `code` and `stderr` as three values, and every failure was
  flattened to one sentence before anything stored it. `Error::to_fields` is a
  second seam to text beside `to_msg`, exhaustive rather than defaulted — a
  variant added without deciding its labels fails to compile, since the
  alternative is a new error rendering as an empty block at the moment somebody
  needs it most. Errors whose whole content is a sentence with no value in it
  keep that sentence: a heading over an empty column reports less than the line
  it replaced.

  Three headings, distinguished because they call for different actions:
  `FAILED`, `STOPPED` (naming the command it stopped *before*, so what ran and
  what did not is legible) and `COULD NOT RESTORE` (the machine is in neither
  state, which is worse than a task that did not run).

### Fixed
- Terminal escape sequences are stripped from what a command prints, so a script
  that colours unconditionally no longer puts raw codes on the screen. A child
  here inherits a pipe rather than a terminal, and plenty of programs colour
  anyway: `dockerd-rootless-setuptool.sh` emitted its `[ERROR]` wrapped in SGR,
  ratatui drew the escapes as text, and the operator read
  `[101m[97m[ERROR][49m[39m Refusing to install…`. Stripped rather than
  interpreted — the words are what a bug report needs — and stripped at the
  executor, which is where every line of every command already passes and so
  covers the transcript as well as the pane.

  Two independent paths reach the same text and only one was covered at first.
  `spawn_reader` handles the streamed case; the unobserved capture is the other,
  and it is the one the CLI takes, every backend that parses what a program
  printed, and the `stderr` a failing command carries into `CommandFailed` — so
  the report an operator reads was still full of codes after the first fix. Found
  by running a real command rather than by reasoning about the two call sites.
- Closing a form or declining a confirmation no longer leaves `cancelled` on the
  border. It stated back a decision the operator had just made, and outlived the
  moment: nothing clears the status until the next thing sets it, so the word sat
  there while they carried on navigating. Pressing `Esc` is answered by the form
  leaving the screen. The other nine `State::Ready` sites already reported
  nothing for the same situation, and `Msg::StatusCancelled` is gone — in a
  closed catalogue rendered by an exhaustive `match`, an entry nothing reaches is
  debt rather than flexibility. Nothing had pinned the border staying clear here,
  which is why a test now does, confirmed against the previous behaviour rather
  than assumed to catch it.
- Two paths reported a failure only on the border, and one of them is the worst
  outcome this tool can reach. `revert_change` rendered the error into a status
  message and wrote nothing to the pane, so the evidence that a machine is in
  neither state was exactly what truncation took; `restore_recorded` had the
  same shape, its own comment already saying the two digests *are* the evidence.
  Both go through the field report now.
- Wrapped field values hang under the value rather than returning to the left
  margin, where a continuation read as another label in the column above it.
  Found by rendering a frame rather than by a test: ratatui's `Wrap` knows
  nothing about indents. Writing its test then found a second defect — a break
  landing on a space carried it into the next row, moving that row one cell out
  of the column, invisible until the third row of a long value.
- `NON_LOGIN_SHELLS` was short by five names, so accounts that log nobody in
  were ranked as people. Read out of each image's own `/etc/passwd` rather than
  reasoned about, which is what the list had been. `/usr/bin/nologin` is the
  costly one: Arch merged `/sbin` into `/usr/bin`, so that is what *every*
  system account there carries, and the whole family ranked as `Human` — the
  scan consulted forty service accounts before the two that matter, and the
  account chooser opened on them. `/bin/nologin` answers on Arch too;
  `/sbin/halt` and `/sbin/shutdown` are on Alpine and Rocky, `/bin/sync` on
  Debian, Alpine and Rocky. The paths resolve to one file on Arch, which does
  not close it: this compares the text `/etc/passwd` holds.

  Ordering only. The rank orders and never filters, so no account was ever
  hidden from `users.lock-root` by this — a property its own test already pins.
  The fix was confirmed to fail against the previous list rather than assumed
  to, and a second test asserts the reverse direction, since a list that grew
  by five could as easily swallow a real login shell.

### Changed
- `users.lock-root` no longer asks which account keeps access. It opened a form
  with a chooser offering every account on the host, and did exactly one thing
  with the answer: check it. The task never locked that account, never modified
  it and never recorded it anywhere — the hint admitted as much, *"root is
  locked; this one is only checked"*. The label had been rewritten once before,
  on the theory that the field read as "the account to lock"; renaming it did
  not help, because the field was the problem. It now scans every account the
  host has and answers the question itself.
- The guard this replaces got stronger rather than weaker. `NoWayBackIn` meant
  "the name you typed does not work" — try another — and now means *this host
  has no way out*, which is the claim the task always wanted to make and could
  not while it was checking one name. It carries how many accounts were
  examined, so it asserts no more than it measured. Approving when some account
  passes is correct: if a way back in exists, it exists.
- The confirmation shows every account that keeps access, each with the
  credential it gets in by, instead of naming back the one just typed. That is
  the difference between checking an answer you had to know in advance and
  recognising your own account in a list. The list scrolls where it is longer
  than the dialog — a warning carrying one row per administrator is unbounded,
  and a dialog sized to all of them grows past the terminal, where centring
  clamps it and the answers at the bottom are what disappear.
- The three refusals that used to abort the task are now a per-account
  diagnosis. They described a name the operator had typed and now describe a
  fact about an account nobody nominated, which is the difference between an
  error and a diagnosis. `AdminGroupGrantsNothing` is why they stay distinct:
  it names openSUSE's commented-out `%wheel` and the line to uncomment, and no
  amount of `usermod` addresses that. `AdminCannotBeRoot` is gone — with
  nothing typed, root cannot be nominated; it survives as an exclusion from the
  scan, pinned by a host holding only root being refused.
- Where nothing says which account the session escalated from — a root console,
  `su -`, `run0` — the dialog says so rather than marking a row it cannot
  justify. Never a refusal: the signal is an environment variable set by
  whoever is already root, and refusing on an unanswerable question would
  strand the provider's rescue console, which is the case this task exists for.

  The scan orders by the conventional uid threshold and never filters by it, so
  a site numbering a real administrator below 1000 is not reported as stranded;
  and it does not stop at the first account that passes, since the operator's
  decision is whether *theirs* is listed and a list of one cannot answer that.
  Both are the obvious optimisation and both were confirmed to fail their tests
  when introduced, rather than assumed to. The scan costs one command per
  account plus three per administrator — measured at 17 on a stock `debian:13`,
  13 on `rockylinux:9` and 19 on `alpine:3.23`, where four were spent before.
  The estimate before measuring was twenty-five; a stock image stays well under
  the bound because almost nothing is in the admin group. Paid when the dialog
  opens, never in the path of a keystroke.

  Six container images confirm it on real hosts, which is where the rule about
  openSUSE showed itself again: with `admin_group_grants_alone` false for that
  family, two administrators holding passwords and `wheel` are correctly
  discarded, so that image asserts the other half of the same rule.

### Fixed
- `wireguard.add-peer` no longer leaves a copy of the server's private key on
  disk. The task deliberately writes no entry in the index, and its comment
  said so, but the generic `write` beneath it still copied `wg0.conf` to
  `wg0.conf.initd.bak` before every change — a second copy of the private key
  and of every peer's preshared key, sitting beside the original for the life
  of the host. Nothing ever removed it: retention only reaches copies the index
  names, so skipping the index and keeping the sidecar got exactly the
  disclosure the retention bound exists to prevent. The mode was never the
  problem — `cp -p` preserves `0600` inside a `0700` directory — and neither
  was volume, since the fixed suffix means one copy rather than one per peer.
  What was wrong is that key material outlived the write that produced it, on
  a file whose whole design is that one copy is enough.
- `wireguard.install` was leaking the same key by the same mechanism, one task
  earlier, and only a container found it. It writes `wg0.conf` in two steps so
  the mode is set before the key exists, and the second step copied the file it
  was about to write into. On a host where a first run failed — Alpine's does,
  at `rc-update` — the copy left behind was the full configuration: measured at
  0 bytes after the install and 151 after the next task touched the path. Every
  write to that path now refuses to copy, because the rule is the file rather
  than the moment.
- The test that was supposed to prevent it now can. `no_copy_of_the_key_file_is_ever_kept`
  asserted only that no command mentioned `/var/lib/initd`, which the sidecar
  in `/etc/wireguard` passed without difficulty — and the mock reply it needed
  was already in the list, labelled `// backup`, so the copy was visible to
  whoever wrote the test. It now refuses `.initd.bak` and any `cp` at all, and
  was confirmed to fail against the previous code rather than assumed to.

- Comments that counted four families or twenty-eight tasks now count the five
  and the thirty-nine that exist. Two of them were wrong about more than a
  number: the trait's note on purging named RHEL alone where openSUSE answers
  the same way and for the same reason, and the note on removal cascading said
  "the other two" where three families decline it and two cannot. The three
  that narrate a past measurement keep it, with the tense made explicit where a
  reader would otherwise re-derive the figure and find it different.
- `layout.rs` no longer points at a test that was renamed out from under it,
  and `signals.rs` no longer says three signals are caught where two are.
- The space around a key hint is the interface's, not the translator's. Eight
  catalogue entries carried their own padding — `" cancel"`, `" choose   "` —
  while the key bar's own code wrapped labels in `format!(" {} ")` under a
  comment saying a label carrying its spaces could not be reused where the
  spacing differs. Both were true at once, so editing `" cancel"` in a
  translation moved the layout, and the trailing runs were invisible in a
  diff. `style::key_hint` now owns the spacing and the eleven sites that drew
  the pair by hand call it.
- The search overlay draws its heading and its result count in the same style
  roles every other overlay uses. It passed both as bare strings, so the one
  modal rendered its chrome in the border's colour while the six beside it did
  not.

### Added
- openSUSE and SLES are a supported family. Tumbleweed and Leap 16.0 were both
  measured rather than one standing in for the other, and every name in the
  backend comes from asking the distribution: `zypper` for packages,
  `sshd.service` for the unit, and the capabilities openSUSE packages that RHEL
  has to fetch as verified releases — Caddy, fish, rustup and fail2ban among
  them.
- A family may now disagree with itself. Tumbleweed packages Zellij and Leap
  16.0 does not, so the backend resolves a *distribution* where the other four
  resolve only a family — the mechanism RHEL already used for Docker's
  repository paths, reached here for an unrelated reason, which is what makes
  it a pattern rather than a one-off. It is also why openSUSE is the one family
  carrying two container images: a matrix holding only the rolling variant
  would have agreed with the backend about a name the stable one lacks.
- Being in the administrative group and being able to escalate are now separate
  questions. Four families answer them identically, which is why one was long
  assumed to imply the other; openSUSE ships `%wheel` commented out in
  `/usr/etc/sudoers`, so joining the group grants nothing. `users.create` writes
  a drop-in under `sudoers.d` — created at `0440`, because sudo silently ignores
  a drop-in it considers too permissive — and validates the result with
  `visudo -c`, since a sudoers file that does not parse disables sudo entirely
  rather than ignoring the bad line.
- The administrative group is created where the distribution does not ship it.
  `wheel` comes from `system-group-wheel` on openSUSE, required only by the
  desktop patterns, so a minimally installed server has no such group and
  `usermod -aG` against a missing one exits 6.

- The key bar names `h history`, which it had not. The key answered from
  anywhere and the help overlay documented it, but the bar is where an operator
  looks to find out what a state accepts — so the view was reachable only by
  somebody who already knew it was there. It is offered unconditionally, where
  `Esc back` and `Tab output` are not, and the difference is what an empty one
  leads to: `Tab` with nothing to read opens a mute pane, while `h` on a host
  where nothing was recorded answers the question it was pressed to ask — has
  this tool changed anything here — and *no* is an answer. Testing that first
  would also mean reading the host's index to draw a frame.
- `H` opens the recorded changes and any one of them can be put back. The list
  names the task that made each change as well as when — ten recorded states of
  one file are ten indistinguishable timestamps otherwise, and choosing between
  them is what the list is for. Restoring asks first, at the same tier as every
  other change that can end the session, since restoring an `sshd_config` is
  exactly as able to lock somebody out as writing one was.
- A refusal reports as *not restored* rather than as a failure. The refusals —
  the file edited since, the copy damaged — leave the machine exactly as it
  was, which is a different thing from a command that broke, and a host with
  nothing recorded gets a sentence rather than an empty list.
- A change to a configuration file can now be put back in a later session, not
  only in the one that made it. Seven tasks leave a record — the four that edit
  `sshd_config`, Caddy's headers snippet, fail2ban's jail and fish's entry in
  `/etc/shells` — copying the previous version under `/var/lib/initd` with a
  timestamp in its name. The copy `write` already took is moved there rather
  than a second one being made: `.initd.bak` is one fixed name per file, so the
  copy the first change leaves is the copy the second change destroys.
- The record is not state and is built to stay that way. It answers one
  question — is there a copy of how this file looked before initd touched it,
  and where — while `PermitRootLogin` is still read from `sshd_config`.
  Append-only, because a half-written final line is invalid JSON and is
  discarded, where rewriting in place would need a lock and a lock would need a
  stale-lock story on a machine that may reboot underneath it. No secret can
  reach it: the writer takes a typed record with no free-form field.
- Restoring across sessions refuses where restoring within one need not. A day
  later the file may have been edited by hand, and putting the copy over that
  would discard somebody's work while reporting success — so the live file is
  hashed against what this tool wrote, the copy against what was recorded, and
  either mismatch stops with both digests named. A file that could not be read
  is a separate answer from one that changed, because the two call for
  different actions.
- Two tasks deliberately record nothing, and say so where somebody would look
  for the missing call. `wireguard.add-peer` writes the one file holding the
  server's private key and every peer's preshared key, and a copy of it would
  be a second copy of all of them. `ssh.authorize-key` is the one file whose
  restoration *removes* an authorised key — the direction that locks an
  administrator out rather than rescuing them.

### Changed
- A closed choice is chosen rather than typed. `remove`/`purge`, `tcp`/`udp`
  and `keep`/`delete` were three fields that named their two answers in a hint
  and then made the operator spell one correctly — on the removal's case, a
  choice deciding whether a hand-edited configuration file survives. `↑↓` now
  steps between them and `Ctrl-L` opens the list, the mechanism the account and
  shell fields already used. Unlike those, these lists *are* the permitted set
  rather than a convenience, so two tests keep them in step with the validators
  that enforce them: one that every offered value passes its validator, one
  that every kind with a closed validator offers a list at all.
- The removal depth is no longer asked for where the answer would be ignored.
  It decides whether configuration survives and it decides that through a
  package manager, so on a family that packages no Zellij or Caddy — Debian
  installs both as verified release binaries — the undo deletes a file and both
  answers name the same `rm`. The log read identically either way, which is how
  this was found. `has_purge_for` already refused to offer the field on RHEL
  for the same reason; nothing had asked the question one step earlier. A task
  whose only field is filtered out now opens no form at all. The CLI still
  accepts `removal=` there and says why it could not be honoured, since a
  script should not quietly mean something weaker on one host than another.
- The vim movement keys are gone. `h`, `j`, `k`, `g` and `G` moved the cursor
  in five separate places — the tree, the output, the help overlay, the
  recorded changes and a form's option list — and the arrows, `Home` and `End`
  did the same in every one of them. What the letters bought was a second way
  to do what an arrow already did; what they cost was five keys nobody could
  spend on anything else. `f` keeps following the newest output, since
  re-attaching to the tail has no arrow of its own and dropping both would
  make scrolling away from it one-way.
- The recorded changes open with `h` rather than `H`, which the retirement is
  what made possible. `h` was the fourth way to leave a category, after `Esc`,
  `Backspace` and `←`, and a key pressed by reflex is a poor neighbour for a
  list that rewrites configuration files — one slipped `Shift` away. Nothing
  presses it by reflex now. `K` and `R` stay capitals in the verification
  window even though the reason they were capitals has gone: that is the one
  place where a key pressed by accident does something unrecoverable, so it
  should cost a deliberate `Shift` rather than a letter that could be a slip.

### Fixed
- The container matrix ran eleven times slower than it needed to, on the
  strength of a measurement nobody had taken. `--test-threads 1` was documented
  as the answer for six images on a host with more cores than memory, and the
  helper that panics on `Docker exited 125` recommended it too. Measured: a live
  container is **4.7 MiB** against **13 GB free**, and sixteen simultaneous
  starts of the largest image fail **zero** times. Memory was never the
  constraint — the recurring cause is the daemon refusing every start at once
  (`unsupported protocol` under WSL2, cleared by `wsl --shutdown`), which looks
  identical from inside a test and which serialising does not fix. The full
  suite is **1531 tests in 8m57s at `-j8`, against ~97 minutes serially**. The
  guard itself was never wrong about what it saw; what it got wrong was the
  advice appended to a correct observation, which is the part nothing tests.
- Confirming a task on a row that pairs an install with its undo did nothing at
  all. The eleven reversible rows resolve to one half or the other through the
  probe, and every other part of the interface asked it — the row drew the
  right verb, the cursor selected the right task, the confirmation named it —
  but the one function that *starts* the work matched `Node::Task` alone and
  returned silently on anything else. No output, no status, no command: from
  the operator's side, indistinguishable from a keypress that never arrived.
  A lone task ran perfectly, which is why the feature looked whole. There was
  already a test that a shared row draws the half it would run; nothing checked
  that it then ran it, so the rule was verified on the screen and not in the
  work. Resolved through `probe::task_for` now, the same call drawing uses,
  which is the thing that was documented as the one place the choice is made.
- The key bar ran off the edge of a narrow terminal, and what sits at that edge
  is `q quit`. It is a paragraph that does not wrap, so a row too short for
  every hint lost the last of them silently rather than rearranging — leaving
  the key that leaves the program undiscoverable on exactly the terminal where
  the operator most needs it. The margin had been one column: the fullest bar
  measured 59 against a minimum width of 60, so it was correct only by
  accident, and nothing tested it. Hints are now given up least-useful-first —
  `Tab output`, then `h history`, then `/ find`, then `Esc back` — ordered by
  how discoverable each key is elsewhere rather than by how often it is
  pressed, since `?` documents them all while leaving a category has no route
  but `Esc`. `↑↓`, `Enter` and `q` are never dropped. Measured from the
  rendered labels rather than a constant, because a translated label is a
  different width and a budget fixed by English would overflow in any language
  with longer words.
- A container the daemon could not start was reported as a failing assertion
  about the code. `docker run` exits 125 with empty output when it refuses, and
  empty output is also what a scenario whose assertion genuinely failed
  produces — so sixteen scenarios named the backend as broken when the host had
  run out of memory. Both container helpers now stop with the image and both
  streams named. The trigger was arithmetic rather than a defect: nextest sizes
  parallelism by cores, and six images need more memory than four on a host
  with more cores than gigabytes, so the container matrix now documents
  `--test-threads 1`.
- `users.lock-root` would have approved an account that cannot escalate. Its
  whole purpose is refusing to lock root while nobody else can administer the
  machine, and it asked the only question that used to mean that: membership of
  the administrative group. On openSUSE that reading is true and irrelevant, so
  the guard would have passed and left the operator with no way back in. It now
  refuses with an error of its own rather than reusing "not an administrator" —
  that message would send somebody to `usermod` for a problem `usermod` cannot
  repair, and assert a membership the system contradicts.
- The five SSH tasks read `/etc/ssh/sshd_config` before editing it, and on
  openSUSE that file does not exist: the package installs its configuration to
  `/usr/etc/ssh/sshd_config` under the `/usr/etc` split, while sshd runs
  perfectly well. The backend now seeds the canonical path from the packaged
  copy before any task reads it — fixed once rather than in each of the five,
  which is the shape of change where the sixth is the one that forgets. The
  packaged file is copied rather than edited in place, since rpm owns it and
  restores it on upgrade.
- Deleting the account the session is being administered as is now refused
  rather than warned about. It was only ever a warning because nothing resolved
  who had escalated; measuring settled that — `logname` answers `root` under
  sudo, `id -un` answers `root`, and `who am i` is empty without a TTY, which
  busybox does not recognise at all. All three describe the process, which by
  then is root. `SUDO_USER` and `DOAS_USER` describe who made it root, and both
  helpers set them. Where nothing says — a direct root login, `su -`, `run0`
  through polkit — the confirmation's warning stands, since refusing a question
  that cannot be answered would stop a root console deleting any account.
- Choosing `purge` on RHEL quietly did a plain removal. rpm has no purge — an
  edited file survives as `.rpmsave` whichever is asked — and `has_purge_for`
  existed to keep the choice from being offered there, but nothing consulted
  it. `Task::params` has no backend to ask, so the field is drawn everywhere;
  the task now says what the package manager cannot do instead of accepting an
  answer it will ignore. An operator who picked `purge` and was given a removal
  in silence would believe their configuration was gone, and find their old
  settings back on the next install.
- The record's own directory and file were world-readable. `install -d` applies
  the mode it is given to the leaf and leaves the parent at the umask, so
  `/var/lib/initd` came out `0755` under a correctly-`0700` `backups`; and the
  append is a shell redirect, so the index itself landed `0644`. No key
  material was exposed — the one file holding any is deliberately never copied
  — but the names were a map of every path this tool has changed, readable by
  any account. Found by running the real command sequence on `debian:13` and
  `alpine:3.23` rather than against a mock, since a umask is a thing only a
  filesystem has.

- `root` cannot be deleted, refused in the code rather than warned about in a
  dialog — a confirmation is dismissible, and this is not a decision that
  should be reachable by pressing through one. Locking root stays on offer,
  guarded by proving another account can still get in; a provider's rescue
  console undoes a lock and cannot undo a deletion. The confirmation for every
  other account now also says that deleting it ends this session if it is the
  account being administered from, which is what the tool can honestly claim:
  nothing here resolves who is running it, so it names the account rather than
  implying a check it did not make.
- A measurement arriving as the probe's thread exits is no longer lost.
  `is_finished` answered through its own `try_recv`, which *consumes* — so a
  result landing between the last drain and that question was received,
  discarded, and its row left showing the install verb for the rest of the
  session. Narrow, and the case that lands in it is the one that matters most:
  the refresh after a task probes a single subject, so the thread sends once
  and returns immediately. Found in review, and the test was written against
  the defect before the fix — the first attempt passed with the bug still in.
- `wireguard.uninstall` never deletes `wg0.conf`, and now says so. The task,
  `cli.md` and `user-stories.md` all claimed the keys were removed on purge;
  the code passed the choice to the package manager and stopped there, which
  is the safer of the two behaviours and not the documented one. Corrected
  towards the code rather than the docs: that file holds the server's private
  key, every peer already holds the matching public one, and regenerating it
  invalidates every client rather than restoring anything — not a decision for
  a field whose two values sit one character apart.
- `users.delete` removes an account, and its home directory is a field rather
  than a policy: both answers are defensible — a home holding dotfiles is
  residue, one holding a year of someone's work is not something a form should
  decide about — which is exactly why neither is safe as a default nobody
  stated. It defaults to keeping the files.
- The confirmation for it is the one warning in the tool that runs commands.
  Every other is written from what the form already collected; this one asks
  the host where the home is and how much is in it, because "also delete the
  home directory?" is a question answered by habit while "deploy will be
  deleted, and so will /home/deploy — 2.4 GiB of files this tool did not create
  and cannot put back" is one that gets read. A directory that cannot be
  measured says so rather than reporting zero: unreadable and empty are
  different facts, and "(0 B)" understates the stake by exactly the amount that
  matters. Verified by breaking the measurement on purpose and watching the
  test fail.
- It is refused on the command line, joining the two tasks already there but
  for a different reason. Those apply a change the interactive interface holds
  open until the operator proves they can still get in; this one cannot be held
  open at all — with `home=delete` there is nothing to put back, and the
  interactive confirmation is the only place the path and its size are stated
  before it happens.
- It is *not* paired with `users.create` in one row, unlike everything the tool
  installs. A pair asks "is the subject present?" and shows one verb; there is
  no such subject here, since one task takes a name that must not exist and the
  other a name that must. The host cannot answer which applies, because the
  answer depends on a name nobody has typed yet.
- Ten things this tool installs, it can now remove: Caddy, rootless Docker,
  fish, Zellij, mise, rustup, fail2ban, CrowdSec, WireGuard and unattended
  security updates. Each shares a row with the install it undoes, and the row
  shows whichever verb the host justifies. `ssh.install` is deliberately not
  among them — a tool driven over SSH does not remove the SSH server, and the
  verification window cannot help: the process that would undo it is being torn
  down by the disconnection it caused.
- Nine of the ten go through one function rather than being ten near-copies,
  because the copy that drifts is the one nobody notices. It mirrors the branch
  the install took — asking `has_package_for` again, in the same order — so a
  released binary is never handed to `apt-get remove` and a packaged one never
  has `/usr/local/bin` searched for it. The unit is stopped *before* the package
  goes: the reverse leaves a running daemon whose unit file has been deleted.
  WireGuard is the exception, and only because `wg-quick@` is a template rather
  than a unit.
- Every removal asks how thorough to be, and defaults to keeping configuration.
  A reinstall then finds what was there, where the other default would delete a
  hand-edited `jail.local` on the strength of a field nobody read. The field is
  not drawn on RHEL at all, because rpm has no purge and a choice with one
  outcome invites a decision and then ignores it.
- An uninstall never reverts. The verification window exists for a change whose
  undo is cheap and local — restore a file, reload a unit — and undoing an
  uninstall means reinstalling over the network, which fails outright on a host
  with no egress. A countdown promising an undo that cannot run is worse than
  no countdown.
- `wireguard.uninstall` is the one that can end the session applying it, and
  says so with the red frame the other lockouts use: an administrator connected
  over the tunnel loses the connection when `wg0` goes down. It is offered
  anyway, unlike SSH, because reaching a host over WireGuard is a choice and a
  console can undo it.
- Two things surfaced from making the tree longer rather than from thinking
  about it. The tree pane is measured against its longest title, so ten new
  rows widened it — and one of them, at 49 cells, was shortened instead of
  widening the pane for every row to fit a single name. A test helper that
  walked the tree looking for tasks could not see inside a pair, which is the
  same blind spot the tree's own traversals had and were taught about.
- A row that can go either way asks the host which way it is, on a thread of
  its own. The queries are unprivileged — every package manager reads a
  world-readable database, and `command -v` asks the shell — but eleven of them
  in series cost between 200 and 900 milliseconds on a slow VPS, paid before
  the first frame on exactly the hardware this tool exists for. So rows start
  unmeasured and settle over the following moments, and an unmeasured row shows
  the *install* verb: offering to install what is already there wastes a
  keystroke, while offering to remove what was never installed does nothing and
  explains nothing. While the answer is outstanding the row says so, because
  those few hundred milliseconds are long enough to press a key in.
- Nothing is measured while a task runs, and what a finished task touched is
  forgotten rather than kept. A package manager holds a lock, and an answer
  taken while an install is half done describes neither the machine before nor
  the one after. The re-measurement afterwards runs on the failure path too: a
  task that installed the package and then failed to enable the unit leaves the
  host in a state nobody knows, and the answer from before it ran describes a
  machine that no longer exists.
- What a row draws and what pressing it runs resolve through one function, so
  they cannot disagree. Rendering "Uninstall Caddy" over a key that starts
  `caddy.install` is the worst thing this feature could do, and two copies of
  the rule is how it would happen. The test reads the title back off the
  rendered line and compares it against the task the same state resolves to —
  and was confirmed to fail when the resolution was deliberately broken, rather
  than assumed to.
- The capability traits gained the verbs that undo what they do: packages can
  be removed or purged, units disabled and stopped, an account deleted, a
  directory measured. Nothing calls them yet. What each family does differs
  more than the naming suggests and was written down where it is read rather
  than assumed: removal never cascades on Debian or Arch — no `--auto-remove`,
  no `-Rs`, because what those reach cannot be stated before they run — while
  apk decides for itself and says so; and RHEL cannot purge at all, since rpm
  leaves an edited file as `.rpmsave` whatever is asked, so `has_purge_for`
  answers false there and the choice is not offered rather than being offered
  and ignored.
- Removing a downloaded binary asks a different question from installing one.
  `is_installed` reports whether a program is anywhere on `PATH`, which is
  right before installing and wrong before removing: an operator holding
  `~/.cargo/bin/zellij` satisfies it, so a row keyed on that answer offered to
  uninstall a binary `/usr/local/bin` never held — reporting success having
  done nothing, or deleting a file this tool did not write from a directory it
  does not own. `is_installed_here` asks about the one path the installer
  writes, `location_of` names the copy it found so the interface can say where
  it is, and removal builds its path from the install directory rather than
  from what the shell resolved.
- A unit that no longer exists is the state an uninstall wanted, not a failure.
  Removing a package takes its unit with it, so stopping the service afterwards
  would otherwise fail at the last step having done everything it was asked.
  systemd overloads exit code 1 for "no such unit" and for "I will not", so the
  two are told apart by its own wording — the one place matching another
  program's text is unavoidable, and marked as such. OpenRC needs no such
  rescue, and its two commands run in the mirror order of enabling: stopped
  first, then out of the runlevel, because a service left in its runlevel is
  back after a reboot having reported itself stopped.
- The tree can hold a pair of opposed operations in a single row. One row
  rather than two because "Install Caddy" and "Uninstall Caddy" are not a
  choice an operator makes — exactly one of them is meaningful at any moment,
  and offering both makes the reader work out which. Two *tasks* rather than
  one task with a verb, because a task's identity is its id: the worker thread
  re-resolves it, `initd run` names it, and `docs/cli.md` documents it. An id
  meaning two things depending on the host is one the worker cannot resolve and
  the contract file cannot describe. Nothing builds a pair yet; what exists is
  the seam and the nine decisions the compiler demanded at every site that
  walks the tree — the count beside a category promises rows, so a pair counts
  once, while search and the task lookup see both members, so every invariant
  already asserted over the tree covers an inverse the moment one arrives.
- Every task that changes the machine asks before it runs. It was nine of
  twenty-eight, because the rule read "irreversible enough to warrant a prompt"
  and was applied as "could lock you out" — so `ssh.install` put an SSH server
  on the machine and enabled it in silence. Twenty-five ask now; the three that
  do not are the ones that only read, and each says so about itself. Asking is
  what a task gets for saying nothing, so none can go quiet by omission the way
  those nineteen had.
- The confirmation has two levels, and the difference is what keeps either
  worth reading. A change that can end the session applying it keeps the red
  frame and the lockout warning; everything else asks plainly. A red border
  around every task marks none of them, and the dialog it would teach people to
  dismiss is `users.lock-root`'s.
- `users.create` takes an optional password, masked as it is typed and applied
  through `chpasswd` on stdin — never `useradd -p`, whose argument
  `/proc/<pid>/cmdline` publishes to every account on the box. Empty means no
  password: the field being optional *is* the answer, rather than a second
  field asking whether to use the first. That second field existed for a while
  and asked for the word `yes`.
- A form field states what the host already says about its value: one naming an
  account to create refuses a name that exists (`root already exists`), one
  naming an account to act on refuses a name that does not. The form drew `✓`
  over a name `users.create` was about to reject, so the mistake the field
  invites was the one live validation did not catch.
- `y` sends the output pane's whole transcript to the terminal's clipboard.
  The mouse cannot do this: the terminal owns the selection and copies
  rectangles of screen, so dragging over the pane takes its border and the
  tree's flags with it, and takes only what the pane was wide enough to draw —
  every line longer than the pane arrives cut. Sent as an OSC 52 sequence
  rather than through a clipboard library or `xclip`, because the machine
  being administered usually has no display server and its clipboard would be
  the wrong one anyway: the operator is at the other end of an SSH connection.
  The message says what was *sent*, never that it was copied — OSC 52 has no
  reply, and terminals that refuse it are real.
- Account and shell fields offer what the host already records, stepped
  through with `↑↓` or listed in full with `Ctrl-L`. The source is declared per
  parameter rather than derived from the field's type: a type describes the
  shape of a value, and `users.create` collects a username that must *not*
  exist — offering the host's accounts there suggested precisely the values it
  refuses. `wireguard.add-peer` collects a label validated by the username
  rules and has nothing to suggest either; `ssh.allow-users` holds a list, and
  taking a suggestion would delete the names already typed.

### Security
- `ssh.authorize-key` refuses a `~/.ssh` or an `authorized_keys` that is a
  symbolic link. `install -d`, `chown` and `tee` all act on a link's target, and
  the directory sits inside a home its own account controls — so replacing
  `~/.ssh` with a link elsewhere had root apply the mode, the ownership and the
  key over there instead. Reproduced on `debian:13` before it was fixed: a
  directory owned by `root` came back owned by the unprivileged account that
  planted the link, with a file written inside it. The refusal names the path,
  because a link into shared storage is something an administrator may have set
  up deliberately.
- A configuration file is written beside itself and moved into place, rather
  than written into. `tee` truncates and then writes, so a process that died
  between the two — a full disk, an OOM kill, the power going — left
  `sshd_config` empty or half a file: a third state neither the change nor the
  backup describes, on the file that decides whether anybody can log in. A
  rename within a directory is atomic, so a reader sees the old file or the new
  one. The staging file sits beside the target rather than in `/tmp`, because a
  rename across filesystems is not a rename and SELinux labels a new file from
  its parent.
- A rewritten file keeps its own mode. The staging file is created with the
  process umask, so moving it over a `0600` file would have published it at
  `0644`. The mode is read with `stat -c` and applied with `chmod` before the
  move — not with `chmod --reference` or `cp --preserve=mode`, which are GNU
  extensions that both fail on busybox. Measured on `alpine:3.23` rather than
  assumed, which is the same lesson `diff`, `cmp` and `pgrep` each taught once.
- The firewall survives a reboot. `nft` speaks only to the kernel, so every
  rule `firewall.enable` and `firewall.allow-port` wrote was gone at the next
  restart — on Debian, Arch and Alpine, and on a RHEL host whose administrator
  removed firewalld. The task reported `inbound denied except 22/tcp` in the
  present tense and the server came back with every port open, reporting
  nothing. The `FirewallManager` trait grew `persist`/`is_persisted`: nftables
  writes the whole ruleset where the boot replays it and turns that replay on,
  firewalld answers that it already does both through `--permanent` and
  `enable --now`. This is the mistake the sysctl tasks had already made and
  fixed — a value that is right for reasons that do not outlive a restart —
  applied to the state where it costs more. Which file the boot reads was
  measured rather than assumed: `/etc/nftables.conf` under systemd on
  `debian:13` and `archlinux:latest`, `/etc/nftables.nft` under OpenRC on
  `alpine:3.23`, resolved by asking the host which init it runs rather than by
  naming a family.
- The escalation helper is looked for in the system's own binary directories
  rather than in `PATH`, and the path it was found at is what gets spawned.
  This process is unprivileged and escalates command by command, so it inherits
  the operator's environment: a `sudo` planted in a directory earlier in their
  `PATH` — `~/.local/bin`, a version manager installed with loose permissions —
  was found first and then wrapped every privileged command of the session.
  `secure_path` never applied, because the real `sudo` was never reached.
  Resolving the name and then spawning that same name also resolved twice, and
  the second resolution was `execvp`'s against the same `PATH`, so the binary
  that was checked need not have been the binary that ran.
- Every child runs under `LC_ALL=C`. Backends read what these programs print,
  and most of what they read is language-invariant — an exit code, a field of
  `/etc/passwd` — but `chage -l` renders through gettext: under a Spanish
  locale its line reads `La cuenta expira`, so a parser looking for `Account
  expires` found nothing, and nothing read as `never`, which read as "this
  account is not locked". Silent, and in the guard deciding whether root may be
  locked out. Set at the choke point so the next backend to parse human output
  inherits it rather than having to remember.
- `users.lock-root` reads the expiry out of `/etc/shadow` instead of out of
  `chage -l`, so the answer no longer depends on a locale being pinned two
  layers away. Alpine already did this for want of `chage`; the reading is now
  shared by both account suites, which is where the divergence came from —
  expiry is *applied* differently by each and stored identically.

### Changed
- `zellij.install` opens on a version instead of on an empty field. The form
  arrives filled with the newest release this build carries a digest for and
  offers the rest through `↑↓` or `Ctrl-L`, and `initd run zellij.install`
  needs no `version=` at all. The field used to be blank under a hint reading
  "a version this build can verify", which named none of them — so the value
  had to be known in advance or guessed, and a guess is refused only after the
  form is submitted. What it deliberately does not offer is whatever upstream
  released this morning: the digest that makes a download trustworthy is
  compiled in, so a newer version has none and the task refuses it. Suggesting
  it would be proposing the refusal.
- The tasks' progress narration goes through the i18n catalogue. Ninety lines
  of it were English literals in `src/tasks/`, so the claim that user-facing
  text lives in the catalogue held for errors and for the interface's chrome
  and stopped one layer short — a second language would have produced an output
  pane with translated headings above `installing wireguard-tools`. `report`
  now takes a `Msg`, which puts the rendering at the one point every such line
  already passed through: threading a `Lang` into `Task::run` would be a
  parameter twenty-eight implementations carry and one forgets. What the lines
  say is unchanged, and the tests that read them needed no edit. The WireGuard
  client configuration a peer copies goes through `report_verbatim` instead,
  being data rather than language: translating `[Interface]` would produce a
  file `wg-quick` cannot read.

### Added
- A scenario that loses the session for real. `SIGHUP` is what a dropped
  connection delivers and the case the verification window exists for, and it
  was covered only by unit tests asserting that a raised flag is seen — which
  says nothing about whether a live process holding a live window puts the file
  back before it exits. `tests/integration_tui.rs` now hardens SSH under
  systemd, confirms the change landed, signals the process from outside tmux,
  and compares the restored `sshd_config` byte for byte. Verified able to fail
  by breaking the handler first: with the revert removed, Debian and Arch both
  reported `PermitRootLogin no` still in place. The signal goes through `kill`
  with a pid read from `/proc` rather than through `pkill`, which `debian:13`
  does not ship — the same shape as the `pgrep` finding already recorded.

### Security
- A password does not outlive the task that used it. The interface keeps the
  values a task ran with so it can report what that task invalidated, and
  nothing reads them again until another task replaces them — so on a host
  where an account is created and nothing else, the password stayed in a
  root-owned process for the rest of the session, on a machine whose core dumps
  this tool does not disable. The secrets are overwritten and dropped when the
  task finishes, on the failure path too, since a task that failed held the
  same value and reported nothing that needed it. This is not a claim that the
  value is gone from memory: four other copies are made on the way to
  `chpasswd` and a growing `Vec<char>` leaves fragments behind — measured, three
  reallocations for twenty-eight characters. Those are short-lived; the one
  removed here was not.

### Fixed
- Installing a tool from a release archive works at all. The line checking the
  download against its digest wrote both inside one pair of single quotes —
  `echo '<digest>  $dir/archive'` — so the shell never expanded `$dir`,
  `sha256sum` looked for a file of that literal name, and it answered `FAILED
  open or read`. The caller classifies a failure mentioning `sha256sum` as a
  mismatch, so every download failed as tampering whatever the archive
  contained, and the message sent the operator looking for an attack rather
  than for a quoting mistake. It affected `zellij.install`, `mise.install` and
  `caddy.install` on every family. The digest stays quoted and the path does
  not, which is the whole of the line's correctness. Verified by installing
  zellij on `debian:13` and caddy on `rockylinux:9` and running both binaries.
- Text is fitted to the screen by the cells it occupies rather than by the
  characters it contains. A CJK ideograph and most emoji take two cells, so
  `admin@東京サーバー本番` is fourteen characters and twenty-two: a pane twenty
  wide was told it fitted, wrote no ellipsis, and let ratatui cut the tail off
  when it drew — losing content and the mark that says content was lost. It is
  reachable rather than hypothetical, since a public key's comment is never
  validated beyond being non-control. Measured through `Span::width`, the same
  number ratatui uses to draw, so no dependency was added: `unicode-width` was
  already in the tree beneath it, and asking the drawing layer is what keeps
  the two from disagreeing.
- `initd run users.create user=deploy` runs. The command line treated "has no
  initial value" as "is required", so the optional password made it exit 2 with
  `needs: password` — refusing a value the field beside it in the interface
  describes as "leave empty for none", and making the account task unreachable
  from a script without supplying the one thing `docs/cli.md` warns against
  putting in an argument. Being optional is now declared on the parameter, so
  both interfaces read the same claim; a default and a skippable value are
  separate things and are stated separately.
- Every task that edits `sshd_config` says so when the daemon will not honour
  what was written. `sshd -t` reports that a file parses, not that it wins:
  Debian 12, Ubuntu 22.04 and RHEL 9 all ship `Include
  /etc/ssh/sshd_config.d/*.conf` as the first line, and sshd takes the first
  occurrence of a directive, so a drop-in left by a provider image beats
  everything below it. Reproduced on `debian:13`: with `PasswordAuthentication
  yes` in `50-cloud-init.conf`, `ssh.harden` wrote `PasswordAuthentication no`,
  `sshd -t` approved, the task reported success, and `sshd -T` answered
  `passwordauthentication yes`. The effective configuration is now read back
  and any directive the daemon disagrees with is named. Warned rather than
  refused, and nothing is rolled back — what was written is correct, and an
  administrator who put the drop-in there meant to. Only the global section is
  compared: what follows a `Match` belongs to that block, so comparing it would
  report the block working as designed. Until now this was mitigated for one
  task on one family, by excluding `ssh.harden-strict` on RHEL.
- A command that stops producing output no longer strands the task waiting on
  it. Cancellation is checked between commands, so it cannot reach one already
  running: a child that neither exits nor speaks — blocked on a prompt
  inherited from a terminal nobody is looking at, or on an unreachable mount —
  left the task thread waiting forever while the interface reported it as
  running and the stop key did nothing. Silence is measured rather than total
  runtime, since installing a kernel is allowed to take an hour and does not go
  quiet for an hour while doing it. The child is left running rather than
  killed, and the message says so: stopping a task part-way leaves half its
  work applied, which is the same reason cancellation refuses the next command
  instead of interrupting this one.
- `ssh.change-port` names the backup before the three steps that can fail
  after the file is already written — the socket check, the SELinux probe and
  the labelling. A task that fails there returns an error rather than an
  outcome, so the backup never reaches the operator through `revertible`: the
  one change documented as able to cost the session its own way back in
  reported a failed command over a modified `sshd_config` without saying what
  to restore. `ssh.harden` and `ssh.allow-users` already said it here; this
  was the sibling that did not.
- A failed restore no longer swallows the rejection that caused it.
  `write_validated` puts the original back when `sshd -t` refuses the new
  file, and the restore's own failure travelled out through `?` — replacing
  the error naming the bad syntax with one naming a `cp` that did not run.
  Both halves are needed and neither implies the other: the rejection says
  what to fix, and only the restore's failure says the rejected file is still
  the one on disk. They are now reported together, with the path to the copy.
- `users.lock-root` accepts a usable password as a way back in, not only an
  authorised key. Expiry is applied through PAM, so it bars every channel
  including the provider's rescue console — which never consults
  `authorized_keys`, and where a password is exactly what gets an administrator
  in. The guard measured SSH when the question was about every route, and
  refused the account a distribution's installer had made while telling the
  operator it had been "created without a password".
- The lockout warning is measured rather than given a fixed two rows, so its
  second line is no longer drawn over the rule beneath it once the dialog is
  wide enough to fit the sentence differently.
- The help overlay leaves room for its own frame. At exactly the height of the
  terminal it is measured against, its top border was drawn off screen and the
  list appeared to have no dialog around it.
- The tree pane fits the longest title it has to draw. It was 34 cells and
  nine of the twenty-eight titles did not fit, so rows read `Create an
  administrative us…`. The width is now measured rather than chosen — 40 cells
  for the longest title plus six for a row's marker, flag, separator and
  borders — and a test compares the constant against the tree, so a task added
  with a longer name is a failing build rather than a screen nobody can read.
- `g` in the output pane no longer crashes the interface. It scrolls to the
  top by asking for `usize::MAX` lines, and the pane added that to its current
  offset before clamping the result — so the addition overflowed and panicked
  in debug. Release was the worse half: `+` wraps silently there, so the same
  key would have jumped to an arbitrary position without saying anything, in a
  program that runs as root. The clamp was already there and could not help;
  an addition that has overflowed cannot be brought back by bounding it
  afterwards.
- `users.lock-root` asks the account database where a home is, instead of
  assuming `/home/{user}`. It carried its own copy of `has_authorized_key`,
  and the copy predated the fix that `ssh::has_authorized_key` documents and
  pins with a test — so an administrator whose home is elsewhere held a key the
  guard could not see. That failed safe (the lock was refused rather than
  granted), but the two answers were drifting apart in front of the one
  operation whose recovery is the provider's rescue console. The copy also
  counted any line that was neither blank nor a comment as a key, so a file
  holding `garbage` satisfied it; the shared one parses the key. The fixture in
  that file changed for the same reason — the short placeholder was never a
  valid key, and only the lax criterion admitted it.

### Changed
- The help overlay is built once instead of on every frame. Nothing it reads
  can change while the program runs — its table of sections is a `const` and
  the locale is resolved once at startup — yet each redraw rebuilt forty-odd
  catalogue renders and twice as many allocations, ten times a second, for a
  list that could not have differed. It is the same waste the interface
  already avoids by holding a resolved `Lang` rather than calling `from_env`
  per message; the overlay was the one place still paying it.
- The parameter form takes the shared dialog width rather than declaring its
  own. The four modals were unified on one number and this one kept a second
  `72` beside it, agreeing by coincidence rather than by construction — which
  is the arrangement the three widths before it also had. Its rendered width
  is now asserted against the shared constant, as the confirmation's already
  was.
- Five comments that stated a number the code contradicts now state the right
  one, and the two that could be tied to their subject are. The safe hardening
  tier was described as sixteen directives in two places while the array held
  seventeen — a figure stated in three files and checked in none, so a test now
  pins it. `App`'s field count was given as twenty in three module headers
  after a field took it to twenty-one, and the counts of how many each module
  reaches had drifted too. The key-bar comment listed `w`, removed with the
  wrap toggle, and omitted `y`, added for the clipboard a dozen lines below it.
  The catalogue's note on why a resolved `Lang` is held said sixty frames a
  second where `POLL_INTERVAL` makes it ten. A doc link pointed at a function
  name that never existed, which `cargo doc` had been warning about.
- `command -v` is written once. Four call sites had built the same `sh -c`
  invocation, each carrying the decision to prefer it over `which` — absent on
  some of these families, disagreeing about exit codes on others — and only
  one carrying the reason, so the other three read like a line somebody could
  simplify.
- The four modal dialogs share one set of rules — width, gutter, inset, and a
  rule above the footer. They had three widths between them (72, 70 and 64),
  each defensible alone and none chosen against the others, and the
  confirmation sized itself as a share of the screen: a 40%-tall block around
  two lines of text, which mattered little while nine tasks confirmed and
  matters now that all but three do.
- A form field is two rows and a separator rather than five: a header carrying
  its label on the left and its verdict on the right, and the value indented
  beneath. Three of the four rows a boxed field spent were drawing a frame
  around a single line of text, and the note under it sat as close to the field
  below as to the value it judged.
- A field holding an acceptable value is marked `✓` rather than described.
  Words are kept for the two states a mark cannot carry — an error, and
  `optional, may be left empty` for a field that is empty and may stay so,
  whose value reads `(unset)`. A green mark over an untouched field said "done"
  about something nobody had typed into.
- The output pane moves the view and hands over the transcript, and does
  nothing else. `w` toggled wrapping and `Esc` returned focus; both were
  bindings to remember in front of no decision they helped make, and the wrap
  now stays on so no line is ever cut at the right edge.
- The status gives up its own row and rides the bottom border of the pane on
  the right, the way the tree's census rides its own — so the row it cost goes
  to the body, which on the 24-row terminal this interface is measured against
  is one more task visible without scrolling. The pill goes with the row: a
  word on a filled background cannot sit on a border without painting over it,
  so the state's word is drawn in the state's colour instead, and the
  `STATUS_*` roles set a foreground only. `READY` is no longer drawn at all —
  it is the state the tool is in whenever it is in no other, so a border
  reading it for most of a session says only that the program is running and
  teaches the eye to skip the one place a failure will appear.
- Running a task no longer moves the focus to the output. That was true of the
  pane, which streams either way, and not of the cursor: what it did was take
  the arrow keys off the tree, so moving on to the next task meant pressing
  `Tab` first to undo something nobody had asked for. `Tab` is the only thing
  that moves focus.
- Where two titles share a pane's bottom border, the pane's own indicator
  yields whole rather than being cut. Ratatui draws both rather than
  arbitrating, which rendered the tree's census as `6 ca FAILED …` and the
  output pane's `following` as `f`. Neither is the only place its information
  appears; the status may be the only report of a task that failed.
- `src/tui/app.rs` gives up the key handlers, the run's life and the privilege
  request: `dispatch.rs`, `execution.rs` and `auth.rs`. Its production code
  drops from 1295 lines to ~495, leaving the struct, the constructor, the event
  loop and the trivial navigation. Worth stating plainly, since the file sizes
  suggest otherwise: only `auth` is genuinely decoupled — it reaches three of
  `App`'s twenty fields and owns `pending_auth`. `dispatch` reaches fourteen and
  `execution` twelve, sharing seven between them, so those two are as coupled to
  `App` as they ever were; what changed is that a reader looking for what `Esc`
  does has one place to look. The module docs say so rather than implying a
  separation that is not there. Nothing moved at any call site: Rust allows a
  type's methods across several `impl` blocks, so `self.on_key(..)` still works
  from `run`.
- The interface's shared test fixtures live in `tui::fixtures`. `test_app`
  builds the whole `App` and belongs to no single module. Two test blocks moved
  with the code they exercise — navigation, which needs no keys, no rendering
  and no running task, and the one auth test that had been buried among the
  render ones. The dispatch, execution and render tests stay together
  deliberately: they share `press`, `render_to_rows`, `select_task` and two
  more between them — `press` alone is used by 53 tests across all three — and
  a fixture that drifts between two copies is worse than a long file.
- The SSH tasks each live in a file of their own, and `src/tasks/ssh/mod.rs`
  drops from 2065 lines to 211. Only ~520 of those were production code; the
  rest was a single `mod tests` covering five groups — two of which were
  orphans. `harden.rs` and `keys.rs` had been extracted as modules earlier, and
  both times the production code moved while its tests stayed behind: neither
  file had a `mod tests` at all, so 25 of the 56 tests belonged to files that
  already existed. The three tasks still defined there now get the same
  treatment: `install.rs`, `port.rs` and `allow_users.rs`.
  `warn_if_socket_activated` and `DEFAULT_SSH_PORT` travel to `port.rs`, their
  only caller, and stop being surface of the module. What stays is what more
  than one task needs, plus the three tests that compare tasks against each
  other — `destructive_tasks_are_marked_as_such` asserts that harden and port
  are destructive *and* that install is not, and splitting it would have kept
  the assertions while losing the comparison. Verified as a pure move by
  diffing the sorted output of `cargo nextest list`: the same 678 names before
  and after, rather than the same count, since a test dropped and another
  renamed would leave the total unchanged.
- `report` is defined once rather than in each of the seven task modules that
  use it. What the copies duplicated was not the four lines but the decision:
  the shape of an output line could be changed in none of them alone.
- `selinux` and `firewalls` are answered by defaults on the `Backend` trait.
  Debian, Arch and Alpine gave identical answers — the first byte for byte,
  comment included — and only RHEL diverges, in both. The trait already used
  this shape for four other capabilities.
- `/etc/shells` and `id -nG` are read from `backend::posix_accounts` rather
  than once per account suite. shadow-utils and busybox differ in how they
  *write* accounts, which is why both modules exist; these two questions were
  not among the differences, diverging only in whether a constant was called
  `SHELLS` or `SHELLS_FILE`. The whole-word group comparison now has tests of
  its own: it was covered only through its callers, and the `sudo`/`sudoers`
  substring case is the one that reports an ordinary account as an
  administrator.
- The confirmation dialog's title is drawn with a style role. It was the one
  panel title in the interface drawn with none, which left the dialog shown
  before a destructive change looking less deliberate than the form that asks
  for a port.

### Removed
- `docs/sudo-timestamp-findings.md` and `docs/tui-specification.html`, and the
  nine references that pointed at them. Four were in code and one in a probe
  script, so the deletion alone would have left doc comments citing files that
  are not there — the drift this project treats as worse than no documentation.
  The sudo measurements are cited through `tests/fixtures/validate-sudo-*.sh`
  instead, which still exist and are what produced them; the claim stays
  measured rather than becoming an assertion. `docs/ui.md` stops calling itself
  a summary of a fuller specification and is now the visual contract outright,
  which is what it had effectively become. Both files remain in git history.

### Documentation
- `CLAUDE.md` says RHEL is implemented, because it is: `Family::Rhel` is in
  `Family::ALL`, `rockylinux:9` is in the container matrix, and 22 of the 28
  tasks run there. Two sections claimed otherwise, one of them listing it under
  "deliberately not built yet — absent by decision". That entry predicted that
  adding a family would mean adding a module and editing no task; RHEL is the
  measurement that confirms it, so it is now cited as evidence rather than
  deleted. Only SUSE remains admitted-but-absent.
- The structure map lists the six backend modules and three domain traits it
  had fallen behind on — `firewalld`, `semanage`, `rpm_repositories`,
  `apt_periodic`, `openrc`, `busybox_accounts`, and the SELinux, repository and
  automatic-update traits. Three of those predate RHEL, so the list had been
  stale since Alpine.
- The minisign claim was measured instead of counted. It said "packaged on all
  three families"; there are four, and on `rockylinux:9` minisign is in no base
  repository — it installs only after EPEL, a third-party repository, is
  enabled. Which strengthens the reason for declining to require it: the cost
  is not the same everywhere.
- `docs/conventions.md` describes this project. It was a mirror of the
  template's generic rules — SQL injection, uploaded files, constant-time
  comparison, `npm audit`, "don't trust the client" — none of which apply here,
  while the prohibitions that do (no distro branching inside a task, no
  `Command` outside `src/exec/`, no `unwrap` in production) appeared nowhere.
  It exists for the reader who only sees `docs/`, which is exactly the reader
  who could not have known any of them.
- The four dead references to `backend.md` in `conventions.md` and
  `user-stories.md` name `cli.md`, and the exit code those two interactive-only
  tasks return is documented. `2`, not `1` — verified against the binary — and
  a script that retries on `1` must not retry them.
- The conventions are pointed at `~/.claude/rules/`, where they actually live.
  `CLAUDE.md`, `docs/README.md` and `docs/conventions.md` all named
  `.claude/rules/`, a path that does not exist in this repository — the four
  files are global Claude Code config, applied to every project. So the three
  documents that exist to tell a newcomer where the rules are sent them to an
  empty directory, and `docs/conventions.md` sent them there *as the source of
  truth over itself*, which is precisely backwards for the reader it was
  written for: someone who only sees `docs/` cannot open `~/.claude/rules/` at
  all. The precedence is now stated per reader — canonical for the maintainer,
  who has them loaded; the mirror is the reference for everyone else — and a
  project-local `.claude/rules/` is noted as an addition on top, not the
  canonical set.

### Added
- Seventeen more tasks run as tasks in a container. Eleven of twenty-eight
  reached one before; the account, sysctl, firewall and WireGuard scenarios are
  joined by the firewall, hardening, developer-environment and lockout tasks,
  each run and then read back through a different mechanism than the one that
  wrote it. Three assumptions did not survive contact with a container and are
  recorded rather than smoothed over: `users.lock-root` and `ssh.allow-users`
  exit **2** rather than 1, since the CLI refuses them as requests that were
  never going to run — the distinction `docs/cli.md` sells to scripts;
  `firewall.allow-port` names the *program* it could not find rather than the
  abstraction, which is the more useful message; and every image ships root
  already password-less, so the scenario compares the account database before
  and after instead of matching a pattern that was never true.
- `tests/integration_privileged.rs`, for what an ordinary container withholds.
  Docker mounts `/proc/sys` read-only and grants no `CAP_NET_ADMIN`, so
  `integration_tasks` can only pin those tasks as the refusals they are — which
  leaves the half they exist for unobserved. This is where `sysctl.ip-forward`
  is watched applying a value the kernel is running, where the drop-in is read
  back, and where `firewall.enable` loads a ruleset that is then queried through
  the front-end's own tool rather than through this one. It skips rather than
  fails where the host will not grant `--privileged`, for the reason
  `integration_systemd` already skips: a rootless Docker has not found a bug.
  Unlike that binary it needs no `--cgroupns=host` — nothing here boots an init.
  Whether the host grants the capability is asked as its own question first,
  by writing a namespaced sysctl in a throwaway container and restoring it. The
  first version inferred it from the scenario's own stderr instead, which cannot
  work: that stream carries the container's shell as well as Docker, and one of
  the tasks under test is named `sysctl.unprivileged-ports` — so a scenario
  failing while naming the task it ran would have been read as a host refusing
  the flag, and a real regression would have reported itself as a skip. Caught
  in review rather than by a run, since every run so far was on a host that
  grants it.
- The selected row says it cannot run, rather than only the pill saying so.
  `selection_disabled` was declared in `style.rs` and drawn nowhere: the
  ordinary blue cursor reads as "press Enter", and pressing it on an unsupported
  task does nothing, which looks like the interface dropping the key rather than
  the host refusing the task. The pill and the detail pane both say so — after
  the eye has moved off the row. Colour is not carrying it alone; the same row
  already shows `·` in its flag column.

### Fixed
- A container that never started is reported as such rather than as a violated
  exit-code contract. `exit_code_of` returned `-1` where no code came back, and
  the caller compared that against a number from `docs/cli.md` — so a Docker
  daemon too busy to start a container failed
  `the_documented_exit_codes_hold`, which reads as the CLI having broken its
  promise to scripts and sends whoever sees it to `main.rs` for a defect that is
  not there. Observed once in a full run of 1033 tests and never in isolation,
  which is the shape of the problem rather than a coincidence: this branch adds
  around eighty containers to the suite, so it made an existing latent fault
  likelier rather than introducing one. It now panics naming the image, the
  arguments and both streams. A test that could not ask its question has not
  answered it.

### Changed
- Every user-facing string in the interface goes through the message catalogue.
  `src/i18n/mod.rs` and `CLAUDE.md` both claimed this already, and it was true
  of errors and consequences and not of the interface's own chrome — pill words,
  key-bar labels, the help overlay, the verification banner were literals in the
  rendering code. A second language would have produced a half-translated
  screen, which is worse than an untranslated one. All eight TUI modules
  resolve through the catalogue now, in 183 variants. Key glyphs (`Tab`, `↑ k`)
  and drawing symbols stay out, as do the tasks' own ids and titles: none is a
  word in a language. Modules that draw every frame hold a resolved `Lang`
  instead of reading the environment per message. Verified by dumping 736
  rendered frames before and after and diffing them byte for byte — 21,252
  lines identical — because a migration that changes what is on screen is a
  regression nothing in the suite was watching for. `docs/ui.md` now says which
  locale its tables document, and `integration_tui.rs` pins `LC_ALL`, being a
  test that greps a real screen for `VERIFY`.
- Drawing moved out of `app.rs` into `src/tui/render.rs`, as free functions
  taking `&App` — the shape `search.rs` already used, which makes "drawing does
  not mutate" something the compiler checks rather than a convention. Production
  code in `app.rs` drops by roughly a third. Two exceptions survive and are the
  interesting part: `render_tree` needs `&mut` because `render_stateful_widget`
  is where ratatui *writes* the scroll offset, which the scrollbar drawn
  immediately afterwards reads back — both orders compile and draw a plausible
  scrollbar, so the dependency is now named at the call site instead of being
  invisible. `render_right` was declared `&mut self` and mutated nothing.

### Added
- `initd version`, also accepted as `--version` and `-V`. The tool had no way
  to say which build it was, so a bug report against it could not be acted on.
- A `LICENSE` file. `Cargo.toml` declared MIT and the repository shipped no
  grant, which for a binary distributed to run as root is part of the contract
  rather than paperwork.
- A `README.md` at the root. The install one-liner existed only in a comment
  inside `install.sh`, so a visitor saw a file listing and no explanation.
- `cargo deny check` runs in CI, on push and on the existing schedule.
  `deny.toml` described itself as the automated half of the dependency policy
  and was automated nowhere — it ran when somebody remembered. The schedule is
  the half that matters: a new advisory lands against an unchanged
  `Cargo.lock`, which no push-triggered run would ever notice.
- CI checks `aarch64-unknown-linux-musl` and the release profile. Both were
  first compiled on the day a tag was cut, which is the worst moment to find a
  cross-build or an LTO failure.
- `ci.yml` declares `permissions: contents: read` and cancels superseded runs.
  The permissions were whatever the repository defaulted to, and each container
  job pulls four distribution images.

### Added
- The output pane shows what the task is actually doing. `docs/ui.md` promised
  output "streamed line by line as it is produced" and `user-stories.md`
  promised it "appears as the task produces it"; neither was true. Commands
  were run through `wait_with_output()`, which captures at the end, and no task
  forwarded any of it — so `apt install` could take two minutes behind a single
  hand-written line, and a failure was a one-line status row carrying a stderr
  cut off mid-sentence. `LocalExecutor` now drains both pipes on their own
  threads and hands each line to an `OutputObserver` as it arrives, still
  collecting both streams so callers that classify a failure by its stderr are
  unaffected. Each command is announced with a `$` prefix first, rendered as
  the task asked for it rather than wrapped in whichever escalation helper the
  host resolved, and never carrying stdin — which is what keeps a WireGuard
  private key out of the pane. A failed task's error goes to the pane as well
  as the status row, where it can be scrolled and pasted into a bug report.
  This restores the shape removed in `813b690`, which went not because it was
  wrong but because nothing called it; it is a property of the executor now
  rather than a second `run` method that can fall out of use unnoticed.

### Changed
- `integration_accounts` and `integration_services` expand through
  `for_each_image!` instead of looping over `IMAGES`. The macro's own
  documentation already argued against the loop — it makes four families into
  one test, so the first to fail hides the rest and the failure names a line
  rather than a distribution — and these two files were the ones not following
  it. Fifteen scenarios become sixty tests, named per family and run in
  parallel. Verified by breaking one scenario for Alpine alone: `::alpine`
  fails and the other three still run and pass, where the loop would have
  abandoned every family after the first. The one `continue` became a `return`,
  which now skips a single image rather than the remainder of the matrix.

### Added
- Tasks run as tasks in a container, on all four families. Five of twenty-eight
  reached one before; eleven scenarios now cover the account, sysctl, firewall
  and WireGuard tasks end to end — running the task and then reading the system
  through a different mechanism, since asking the tool whether the tool
  succeeded is how a mock agrees with itself. It found the sysctl persistence
  bug fixed above on its first run. What a plain container cannot settle is
  stated rather than skipped: sysctls are the host's and `/proc/sys` is mounted
  read-only, so the refusal path is what is asserted, with the measured note
  that `--privileged` does make the success path work.
- Container scenarios for `firewalld`, `openrc` and `semanage`, the three
  backends a whole family each depends on and that had only ever answered to a
  mock — the arrangement `integration_systemd` exists because of. What each can
  honestly claim differs, and was measured rather than assumed: firewalld works
  fully offline, so its port and service queries are asserted against real zone
  state; OpenRC enables and lists without an init, so the enable half is real
  while `status` refuses because the container was booted by something else.
  `semanage` labels a port and reports it back, without `--privileged`: managing
  the policy store is a matter of writing files under `/etc/selinux` rather than
  of enforcing anything. Two measurements were wrong before they were right,
  both concluding less than was true — piping the refusals through `head`
  reported the pipeline's exit code rather than the command's, and installing
  `policycoreutils-python-utils` without `selinux-policy-targeted` gave a
  semanage with no policy to manage, which read as a container that could not
  manage one. The second correction turned an asserted impossibility into two
  real scenarios.
- `semanage port -a` on a port already labelled does not fail: it prints
  "already defined, modifying instead" and exits 0, doing the fallback itself.
  The comment beside the add-then-modify sequence claimed the opposite. The
  sequence stays — the outcome is right either way, and an older policycoreutils
  may well fail where this one recovers — but both paths are now pinned by a
  scenario rather than by a premise.

### Changed
- `tasks::ssh` becomes a directory module. It was 992 lines of production code
  holding six tasks, and two of them formed subjects of their own: everything
  about `authorized_keys` — the file that decides who may log in, where a mode
  matters as much as a content — and the two hardening tiers, which share a
  shape nothing else there has, writing a table of directives wholesale and
  rolling them back together. `mod.rs` keeps 520 lines and the tasks that edit
  one value at a time. That `algorithms` stopped being reachable from the
  parent is the evidence the cut followed a real seam rather than a line count.
- A task declares support as an exhaustive `match` on the family, carrying the
  reason when it refuses. `supported_families` returned a `&[Family]`, which
  the compiler cannot check for exhaustiveness — so adding a family and
  forgetting a task produced a task that was *silently* unsupported, and the
  tool would start on the new distribution and grey out every row. A test
  inverted that default to catch it, at the cost of a table of twelve
  exceptions kept in sync by hand. Verified rather than assumed: adding a fifth
  family now produces 31 compile errors naming the exact tasks that must
  decide, where before it produced none. The fourteen `SUPPORTED` consts are
  gone, and a `supported_everywhere!` macro covers the twenty-one tasks that
  work on all four, so the ones that do not are the ones you see.
- The reasons those twelve tasks are refused now reach the operator. They were
  measured — which repository has never carried fail2ban, which shipped
  `Include` wins on RHEL, which installer publishes no digest — and they lived
  in a test table, invisible in the binary, while the code above the tree
  claimed unsupported tasks stayed visible *with their reason*. Selecting one
  now shows it in the detail panel. Dimming a row says a task is refused; only
  the reason separates a missing package from a policy from a bug worth
  reporting.
- Tree navigation moves to `tui::cursor::TreeCursor`. It depended on none of
  what the rest of `app.rs` does — no executor, no backend, no terminal — which
  made it the one part of the interface that could be tested without building
  an interface, and was not being. It also holds the two stacks that have to
  move together (`path` and the row left behind at each level), so the code
  able to desynchronise them is now confined to the file whose job they are; a
  test pins that, and was confirmed to fail when a push is dropped. The status
  row stays out of it: `leave_category` at the root answers that it could not
  move, and the interface phrases the refusal, because a cursor that knew about
  the status row would be a cursor that knew about the interface.
- Which modal state owns the keyboard is decided in one place. The interface
  holds six independent `Option`s, and four separate sites decided precedence
  by testing the same fields in their own order — two of which had already
  drifted: `pill` asked about `confirm` before `running` and would have named a
  dialog during a task, while `render` drew `confirm` and `form` with
  independent `if`s, so both would have appeared at once with the answering key
  going to only one. No bug today, since the transitions never build those
  states; the correctness simply rested on four readings agreeing. `App::mode`
  now states the order once and `dispatch`, `render`, `pill` and the key bar
  match on the answer, so a state added later fails to compile until each has
  answered for it. Derived rather than replacing the fields, which would touch
  every site that reads or sets one for the same guarantee.
- The key bar is derived from that mode too, so it cannot advertise a key the
  state would refuse, and it now names search's keys while a search is open.
- A consequence's check is phrased by the firewall front-end that holds the
  host's ruleset, so `Task::consequences` now takes the backend. Three tasks
  built `nft list table inet initd` themselves — a distro branch wearing a
  string literal, correct on the three families driven through nftables and
  wrong on RHEL, where the tool writes the rule through firewalld and that
  table is never created. The check would have answered "still to do" forever
  for a port already open, and a warning nobody can resolve is one an
  administrator learns to scroll past, which costs every warning beside it.
  `FirewallManager::open_port_check` returns the command and the needle
  together, since the two are one claim asked at different times; nftables
  builds its needle from the same `rule` helper `allow` writes, so they cannot
  drift. Nothing executes checks yet, which is why this was invisible — and
  why it was worth fixing before something does.
- `MockExecutor` can be strict about commands nobody scripted, and the tests
  whose subject is the *sequence* now are. An unscripted command previously
  answered `Reply::default()` — success with empty output — so a task that grew
  a step got a fabricated success from every test written before that step
  existed: not merely unasserted, but asserted to have worked by a test that
  had never heard of it. It found real drift immediately. The WireGuard secret
  test scripted eleven commands against a task that runs fourteen, because each
  `write` is a `test -e`, a `cp -p` and a `tee`; three were being absorbed
  silently and the comments naming which reply belonged to which command had
  drifted onto the wrong ones. `write_validated`'s rollback test was worse: only
  a comment tied its failing reply to `sshd -t`, and a command inserted anywhere
  ahead of it would have slid that failure onto `tee` — validation would then
  "pass", nothing would roll back, and the test would go on asserting a rollback
  it had caused by accident. `unused_replies()` covers the other direction, a
  task that stopped running a command the script still claims.

### Fixed
- A kernel parameter already holding its value is still persisted. The task
  asked `holds`, which reads the *running* value, and returned early when it
  matched — writing no drop-in and reporting success. A kernel can hold the
  right value for reasons that do not outlive a reboot: another tool set it,
  the image ships it that way, a container inherits it. The task promises "now
  and after a reboot" and delivered only the first half, on exactly the hosts
  where the second half was the only part still needed. `SysctlManager` gains
  `is_persisted`, and the early return now requires both. Found by running the
  real task in Docker, where `net.ipv4.ip_forward` is already `1` in every
  container — the mock had been agreeing that there was nothing to do.
- A key is written where the passwd database says the home is, rather than at
  a guessed `/home/<user>`. The guess had `/root` as its one exception, which
  is a convention rather than a rule: system accounts live under `/var/lib`
  and `/srv`, and a site can relocate an ordinary account. The failure was
  silent in the direction that matters — the task reported success, sshd never
  read the file, and `ssh.harden` could then disable passwords for an account
  whose key had not landed where it was needed. `AccountReader::home_dir`
  reads the field `getent passwd` was already returning and discarding;
  Alpine's implementation reads `/etc/passwd` directly, as its existence check
  already did. The guard that asks whether a named account holds a key uses it
  too, so `ssh.allow-users` stops looking in the wrong place for the same
  reason.
- Losing the session puts an unconfirmed change back, which is the case the
  verification window exists for rather than an edge of it. The countdown lived
  only in this process, so `ssh.harden` severing the administrator's own
  connection killed the interface with `SIGHUP` and left in place the very
  configuration that locked them out — the screen having promised that silence
  would restore it. `SIGHUP` and `SIGTERM` are now caught, the event loop reads
  a flag rather than the handler doing the work (a handler may only touch
  async-signal-safe things, and reverting spawns `cp` through an executor that
  takes locks), and the change goes back before the process exits. `SIGKILL`
  and a power cut cannot be covered by any program, so the banner states the
  limit — "Reverts while this session lives." — rather than implying otherwise:
  a promise with a silent exception teaches people to disbelieve all of it.
  `signal-hook` becomes a direct dependency; it was already in the tree through
  crossterm, so this adds a name to audit rather than new code.
- A panic restores the terminal before it prints. `run` restored on both the
  `Ok` and the `Err` path, but a panic unwinds past that match, so the message
  was drawn into the alternate screen in raw mode — scrolling without carriage
  returns and vanishing with the screen, leaving an unusable shell and no
  explanation of why.
- An address is validated as an address rather than as four numbers.
  `validate_ip` parsed each octet with `str::parse`, which admits what the
  integer parser admits: a leading `+`, and leading zeros without limit. So
  `010.0.0.1`, `+1.0.0.1` and `0000000010.0.0.1` were all accepted and written
  verbatim into `wg0.conf` — where a leading zero reads as octal to some
  tooling, making the address reviewed and the address in effect different
  addresses. `Ipv4Addr::from_str` refuses all three, costs no dependency, and
  the four-part count is still checked first so the message can name the actual
  mistake. Table-driven tests now cover `Ip`, `Cidr`, `Endpoint`, `Version` and
  `Protocol`, five kinds that had no validation test at all; the `Cidr` table
  pins `/8` and `/30` because an off-by-one at either edge of the documented
  range was invisible to a test that only tried `/24`.
- A new `authorized_keys` is restricted before it holds a key. The file was
  written and *then* chmodded, which is the pattern `wg0.conf` was already
  fixed for: `tee` creates a file with the shell's umask, so the key sat
  world-readable for as long as the two privileged commands took. Brief, and
  long enough for a local account to read it — or to hold it open and influence
  which keys sshd honours. A new file is now created empty, restricted, and
  only then written; an existing one is appended to and never truncated, since
  the keys already in it are other people's access. Pinned by a test asserting
  the *order*, because one asserting the final mode passes against both.
- Ctrl-C stops the task it says it stops. The flag the interface raised was
  never read: `Running::start` built it, cloned it, and dropped the clone, so
  the task ran to completion while the interface reported `CANCELLED` — the
  precise failure the code beside it warns about, since a tool claiming to have
  stopped before it has is how half-configured servers happen. The flag now
  travels to `LocalExecutor`, which refuses the next command rather than
  interrupting the running one: a task stopped between two commands has
  completed whole steps only, which is the granularity the interface promises,
  and tasks are not idempotent so killing mid-step would leave one half
  applied. Routing it through the executor rather than through `Task::run` is
  what keeps the obligation off the twenty-eight tasks — the one that forgot to
  check would be the one that could not be stopped. The check precedes
  authentication, so a stopped task does not go on to ask for a password.
- `CANCELLED` is reported from what the task did rather than from the operator
  having asked. The request lands between two commands, so a task already on
  its last one finishes; the status now names the command it stopped *before*,
  and a task that beat the keypress is reported as done with the near miss said
  out loud instead of dropped. The test that pinned the old behaviour asserted
  a finished task be shown as cancelled — it now asserts the opposite.

### Added
- Third-party package repositories, and the one rule that makes them
  defensible: a repository cannot be expressed without a fingerprint published
  independently of the key it verifies. `Repository::fingerprint` is a required
  field, so "register this and trust whatever key arrives" is not representable
  — the key is fetched, its fingerprint derived on the host, compared with a
  value compiled into this build, and a mismatch refuses rather than warns.
  Order matters as much as the check: nothing is written until the key is
  established, so a wrong key leaves the machine as it found it.
- Rootless Docker on RHEL, which is what the capability was built for and the
  only thing that passes its test. Red Hat ships Podman and packages no Docker;
  Docker Inc publishes a repository for RHEL 8-10 whose RPM signing key's
  fingerprint appears on docs.docker.com and on two keyservers — three hosts
  with different operators, none of them the one serving the key. CrowdSec's
  packagecloud repository and Caddy's COPR both fail the same test and stay
  out: their keys are served by the hosts serving their packages and appear on
  no keyserver.
- The fingerprint is pinned by a test that writes the value out rather than
  comparing the constant with itself. It is the whole security property, so a
  typo in it would fail nowhere else — it would refuse every legitimate key, or
  accept a wrong one. The test also names the mistake it guards against: the
  `.deb` and `.rpm` archives are signed by different keys, and Docker's Debian
  documentation publishes the other fingerprint.
- `for_distro` alongside `for_family`, because Docker publishes a repository
  per distribution rather than per family: Rocky and AlmaLinux are served by
  `linux/centos` where Red Hat's own is `linux/rhel`, and pointing a host at
  the wrong one yields a repository whose `$releasever` resolves to nothing it
  carries. That is a URL rather than a behaviour, so the backend resolves it
  like any other name — tasks still cannot ask which distribution they run on.
- SELinux, as a domain trait rather than a check inside a task. It is not a
  different spelling of anything the other families have — it is a second
  authority that can refuse what the first permitted, and its failure has the
  shape this project treats as worst: a daemon told to listen on an unlabelled
  port does not report a permission problem, it fails to start, from a file
  that is valid, was written successfully, and that `sshd -t` approved. So
  `ssh.change-port` labels the port through `semanage` *before* the reload —
  labelling afterwards would be labelling a port nothing is listening on, which
  a test pins by failing when the two are swapped. Whether anything enforces is
  asked of the host rather than answered from the family, since RHEL ships it
  enabled and administrators disable it; the three families without a policy
  answer from a constant and run no command at all.
- Caddy and mise reach RHEL through the release table, which needed no family
  dimension to do it: Caddy is Go and mise is musl, so one artefact per
  architecture serves every family, and the digests were computed from those
  archives on 2026-08-05 rather than copied from a page. `mise.install` needed
  code as well as a table — it called the package manager unconditionally, so
  on a family whose package name is empty it would have asked `dnf` to install
  nothing at all. Zellij needed neither: only the list saying which families
  may run it.
- A Caddy installed from a release enables no service, and says so. A package
  brings a unit with it and an archive is a binary; writing a unit here would
  invent one the distribution does not know about and will not replace when
  Caddy is eventually packaged.
- RHEL enters the container matrix, through Rocky, and the backend written
  against a mock is observed for the first time. Every command in its image
  entry was run against the base image before being written down, which
  corrected three that had looked obvious: the image ships neither `systemctl`
  nor an init, so systemd is genuinely installed rather than declared present;
  `nft` is absent despite nftables being the subsystem firewalld drives; and
  the client package is `openssh-clients`, plural, where the other families
  spell it singular or ship one package for both. `/etc/sysctl.d` is owned by
  `systemd-udev` here rather than by `systemd` — asked of `dnf provides` rather
  than assumed, after a scenario found the directory missing.
- Three of the four SSH tasks held back from RHEL are returned to it, because
  the Include was measured rather than reasoned about. `50-redhat.conf` names
  only `SyslogFacility`, `UsePAM`, GSSAPI, X11 forwarding, `PrintMotd` and —
  through a nested include — the crypto policies. `PermitRootLogin`,
  `PasswordAuthentication`, `Port` and `AllowUsers` are named nowhere in it and
  were each read back from `sshd -T` as the daemon's effective value after
  being written to the main file. Only `ssh.harden-strict` remains unsupported,
  and now for a reason that was seen rather than inferred: a drop-in numbered
  below 50 does beat the shipped one and is deliberately not used, since on
  RHEL the cryptography a daemon accepts belongs to `update-crypto-policies`
  system-wide rather than to one application contradicting it in silence.
- firewalld, the front-end RHEL installs and runs out of the box, and with it
  the recognition that a family may present more than one. `Backend::firewall`
  became `firewalls`, a list tried in order, and which of them holds a host's
  ruleset is asked of the host rather than answered from the family — a RHEL
  server runs firewalld, and one where the administrator removed it drives
  `nft` directly, and both are ordinary states of the same distribution. The
  backends stay `const fn`: nothing about their construction changed, only what
  the firewall accessor returns.
- Three things about firewalld have no equivalent in the nftables
  implementation, and each is read from its documentation rather than inferred.
  There is no turning filtering on — it filters whenever it runs, and its
  default zone already rejects what it was not told to admit — so `enable`
  writes the ports with `firewall-offline-cmd` and starts the daemon after,
  which is why it cannot lock anybody out. A port may be open without being a
  port: RHEL admits SSH as the *service* `ssh`, so an implementation asking
  `--query-port` alone would answer "closed" for a reachable port on a stock
  machine, and this asks about services too, honouring ranges. And
  `--complete-reload` is never issued, because it drops connection state and
  ends established sessions; the runtime-and-permanent pair avoids even
  `--reload`, which would discard what was never persisted.
- RHEL and its rebuilds — Rocky, AlmaLinux, CentOS Stream, Fedora — as the
  fourth family. Mechanically it is the closest to Arch: systemd, `wheel`, the
  shadow suite, so every shared implementation applies unchanged and the module
  is names plus `dnf`. What makes it a third kind of family is provenance
  rather than naming. Red Hat's repositories are narrower than the other
  families', so fourteen of the twenty-eight tasks declare themselves
  unsupported, each naming the reason it could not be reached: EPEL is a
  repository Red Hat does not support and this tool will not enable, Caddy's
  own COPR keeps its signing key on the host serving the packages, CrowdSec
  publishes releases without checksums, and Docker's repository is verifiable
  but needs a capability to register one. Zellij and mise are absent for now
  and cheaply: their musl releases are the same artefacts Debian already
  installs.
- The names were read from Red Hat's documentation and the projects' own rather
  than assumed from the other families, which corrected three of them:
  WireGuard is in AppStream and not EPEL, `rust-toolset` is a compiler where
  `rustup` is a toolchain manager, and `dnf-automatic` changed name and timer
  layout between RHEL 9 and 10 — one the backend cannot express, since it
  resolves a family and not a release.
- The SSH tasks split by whether they write to `sshd_config`. Installing the
  daemon and authorising a key run on RHEL; the four that edit the file do not,
  because RHEL 9 reads `/etc/ssh/sshd_config.d/*.conf` from an Include at the
  top and sshd honours the first occurrence of a directive — so a shipped
  drop-in applying the crypto policies beats anything appended below it. That
  is a configuration which validates, applies, reloads and changes nothing,
  which this project treats as worse than an error, so the tasks wait on a real
  daemon rather than on reasoning about the parser.
- A guard that makes a family a task forgot fail rather than go quiet. Support
  is declared as `&[Family]`, which the compiler cannot check for
  exhaustiveness, so adding a family and missing a declaration produced a task
  that was silently unsupported — the one gap in "adding a distribution means
  adding one module" that nothing caught. The default is now inverted: every
  task supports every family unless it appears in a list that names the task,
  the family and the reason, and a second test deletes an exception once the
  limitation behind it is gone, so a stale entry cannot hide a real omission.
  Confirmed by adding a fourth family and watching all twenty-eight tasks be
  named; before, that produced no output at all.
- A release pipeline: a tag builds both static binaries, confirms each is
  actually statically linked, and publishes them with their checksums. The
  static check is asserted rather than assumed — a dynamically linked binary
  would run on the machine that built it and fail on every older server the
  project exists to reach, which is the failure musl is chosen to avoid and
  one no test on the runner would notice.
- An install script that verifies before it installs, and a scenario that
  proves it: a release is served, the binary is replaced after its digest was
  computed, and the script must refuse it. Reading the script for `sha256sum`
  would pass whether or not the result was acted on. The control case — an
  intact release installing — is there so a script that refused everything
  could not look like a working check.
- Both the script and the release notes state what checksums do not cover:
  anyone able to publish a release writes the binary and its digest alike.
  Signing would close that and is not implemented, so it is named rather than
  implied.
- Alpine, the third family — and the one that proves the abstraction, because
  it diverges in more than names. OpenRC instead of systemd, busybox instead of
  the shadow suite, `apk` instead of `apt` or `pacman`. Where the first two
  disagree over whether a unit is called `ssh` or `sshd`, Alpine has no units
  at all: `ServiceManager` there drives `rc-update` and `rc-service`, two
  programs where systemd has one.
- busybox implementations of both account capabilities. It ships no `getent`,
  so the passwd database is read directly; `adduser` takes different flags from
  `useradd` rather than the same ones spelled differently; and it carries
  neither `usermod` nor `chage`, so the shadow package is installed on demand
  the first time one is needed — verified in a container rather than assumed.
- `initd run` takes `name=value` pairs, so every task is reachable from a
  script rather than only the two that had a subcommand of their own. Values
  are validated against what the task declared, using the same rules the
  interactive form applies — a CLI argument never passes through the keystroke
  filter, so this is the only barrier between an argument and a system file. A
  task run with no values prints what it accepts, with defaults and hints.
- `ssh.allow-users` and `users.lock-root` are refused there whatever arguments
  are given. Both apply a change that can end the session applying it, and the
  interactive interface holds such a change open until the administrator proves
  from a second session that they can still get in. The CLI exits immediately,
  so it has no window to offer and nothing rolls a mistake back.
- A task that stops to ask for parameters now says so before it is run: the `…`
  marker on its row, and an `INPUT` pill while the form is open. The styles for
  both had been defined since the table was written and drawn nowhere, so a
  task that opens a form looked exactly like one that runs on Enter — the one
  thing the row flags exist to distinguish. Only one flag fits the column, and
  destructive outranks input in it for the same reason `CONFIRM` outranks
  `INPUT` in the pill: a destructive task collects its parameters first and
  confirms after, so the warning is what the operator must not miss and the
  confirmation is the live question once both are up. Both orderings are pinned
  by tests that were watched to fail when the branches are swapped.

### Fixed
- A helper asking for a password mid-session prompted where nobody could
  answer it. Authenticating once at startup covers `sudo` while its timestamp
  lasts — five minutes on Arch, which a long task outlives — and covers `doas`
  and `run0` not at all, since neither has one to establish; on an Alpine box
  carrying `doas` and no `sudo`, the *first* privileged command already
  prompted. Reproduced rather than reasoned about: the prompt is written into
  the alternate screen in raw mode, so the interface simply appears to hang.
  The executor now asks whether a prompt is coming before each privileged
  command — `sudo -n -v` and `doas -n true` answer without raising one, and
  `run0` or an unknown helper answers "assume so", because guessing wrong in
  that direction is what strands somebody at a prompt they cannot see — and
  requests the terminal when the answer is yes. `with_terminal_released` had
  been sitting unused since the interface moved tasks onto a thread; it is
  what lends the terminal back. Detecting the failure afterwards was rejected:
  `doas` without `persist` does not fail, it blocks, so there is nothing to
  detect. So was re-running the task, which for a non-idempotent one would
  double-apply what already ran.
- `doas`'s exit codes were measured on alpine:3.23 rather than assumed — 0
  under `permit nopass`, 1 when a password is wanted — because the probe is
  only worth having if it answers the question it claims to. A first reading of
  them was wrong in the safe direction and caught: `exit=0` was the `head` at
  the end of the pipe, not `doas`. `tests/integration_doas.rs` pins both
  answers on a real Alpine, along with the premise underneath them — that a
  host carrying `doas` and no `sudo` resolves `doas` — since each is a claim
  about what that program does rather than about what this repository does.
- `run0` is probed rather than assumed to prompt. It was classed as
  unaskable on the reasoning that polkit owns its prompt, which was true and
  beside the point: `run0 --no-ask-password` refuses instead of asking, exiting
  1 as an unprivileged user and 0 as root. Measured on Arch with systemd as
  PID 1 *and* polkit running, because without both `run0` never reaches the bus
  and every answer looks identical. The old classification cost a needless
  teardown of the interface before every privileged command on a systemd host.

### Removed
- `Executor::run_streaming`, both its implementations, and the `spawn_reader`
  it existed to drive. Nothing called it: the live output pane is fed by the
  `Progress` callback each task writes its own steps to, not by lines drained
  from a process's pipes, and its doc-comment claimed the opposite. It survived
  because a trait method is never reported as dead — the implementations count
  as uses of it — so the compiler was not going to raise this one. The stdin
  helpers beside it stay: `run` uses them.
- `SPEC.md`. What it specified is built, and `docs/` carries the contract now —
  a second description of the same system is one that drifts from it.

### Fixed
- Four comments that described the code as it no longer was: the layout module
  named `centred` among the geometry nothing draws yet, though six call sites
  do; the style table listed dialog borders among the entries the interface
  does not draw, though both are drawn; and `status_input` was documented, in
  the code and in `docs/ui.md`, as serving a `SEARCH` pill that has never
  existed, while the same table omitted `CANCELLED` from the error pill. Each
  was the kind of stale note that makes the next reader mistrust the rest, and
  the first two were what hid a drawn-nowhere style behind a plausible excuse.
- The three shared test helpers that carry a file-level `allow(dead_code)` now
  say why they need one: each integration binary compiles `tests/common` whole,
  so a module only one of them drives is dead in the other nine by
  construction. Without the note the attribute reads as a warning silenced
  rather than a fact about how Rust builds test binaries.
- The confirmation dialog could lose its answers. Body, warning and choice were
  one stacked paragraph, so a description long enough to fill the dialog pushed
  `Yes` and `No` past the bottom border, where they were not truncated but
  simply not drawn — leaving a destructive operation asking a question with no
  visible way to answer it, and looking otherwise normal. The warning is the
  other casualty and outranks the description: by the time the dialog is up the
  operator has chosen the task, but the risk of losing the machine is stated
  only there. Both now have bands of their own and the description yields
  instead. Found on Rocky, whose longer `PRETTY_NAME` wrapped `ssh.harden`'s
  description one line further, but any family was one terminal size away from
  it — a comment in the TUI harness had recorded the symptom and worked around
  it by enlarging the terminal.
- The privileged systemd containers mounted the glibc build regardless of what
  the image could execute. Alpine's scenarios skip before that line, having no
  systemd to boot, so the static path was never exercised there; Rocky boots
  and carries an older glibc, so every command died with `version GLIBC_2.39
  not found` and surfaced as units that were never enabled rather than as a
  binary that could not start. The helper that picks the right build already
  existed and is now used.
- The TUI harness asked tmux for a 120x40 pane and did not check it got one.
  `-x`/`-y` are a request: with no client attached tmux may clamp a detached
  session to the terminal that created it, and Rocky's does, yielding 80x23 —
  one row below the height at which the interface draws a key bar at all. The
  scenarios then read a screen with no key bar and reported missing output for
  an interface that had shed it exactly as designed. The window is resized after
  creation and the size asserted, so a pane smaller than asked for fails where
  it happens rather than as a puzzle further down.
- The two firewall front-ends are now alternatives rather than layers, which
  they had to become before RHEL could enable a firewall at all. nftables
  evaluates every chain registered on a hook, and while `accept` passes a packet
  along, `drop` takes effect at once — so this tool's own table with a drop
  policy overrides whatever firewalld admits. An administrator would open a port
  with `firewall-cmd`, be told it succeeded, and find it closed: the tool
  contradicting the system's own, in silence. Confirmed by inverting the
  resolution order and watching the test name the wrong front-end.
- The unsupported-distribution message named two families where there are four.
- A username of `.` or `..` reached a filesystem path. `ssh.authorize-key`
  derives `/home/{user}/.ssh` from the value, so `..` resolved to `/home/.ssh`
  and had root create a directory nobody asked for. The `/` that would allow a
  longer traversal was already excluded; these two were what remained. Paths
  reject a `..` segment for the same reason — nothing here canonicalises, so
  the path written would not be the one an administrator read back.
- `is_locked` on busybox no longer interpolates a username into an `sh -c`
  string. It was not reachable — the only callers pass the constant `root` —
  but that safety depended on every future caller validating first, which is a
  guarantee a backend cannot make about callers it cannot see. The shadow entry
  is now fetched whole through argv and split in Rust.
- `users.lock-root` re-reads the administrator's key immediately before locking
  root. Several privileged commands separate the prerequisite checks from the
  lock, and a second administrator — or another session of this tool — could
  remove the key in between. Every other task can afford that window; recovery
  from this one is the hosting provider's rescue console.
- WireGuard's server configuration is created with its mode set before the
  private key is written into it. Writing first and tightening afterwards left
  a window in which the key sat in a world-readable file — brief, but long
  enough for any account on the box. Found in a container, from `wg genkey`
  warning about the same mistake in a test's own redirect; no mock would have
  said anything.

### Added
- Zellij's release table carries real digests, computed on 2026-08-04 from the
  archives at the URLs it holds. Two versions, so this project's release
  cadence does not decide which upstream version an administrator may install.
- A release names one artefact per architecture rather than one digest. The
  digest belongs to the *artefact*: the aarch64 and x86_64 builds of one
  release hash differently, so a single digest would have failed verification
  on whichever of the two machines this project targets it was not computed
  from — and failed looking like tampering rather than like a modelling
  mistake. The architecture is read from the host with `uname -m` rather than
  resolved at compile time, since a remote executor would administer a machine
  that is not this one.
- A `rust-toolchain.toml` pinning what CLAUDE.md already promised: the stable
  version and both musl targets. It notes that rustup installs no C linker,
  which is this project's most common first-build failure and the one thing a
  toolchain file cannot fix.
- Brute-force protection and unattended security updates. Defence in depth
  rather than a gap being plugged: `ssh.harden` already writes `MaxAuthTries 3`
  and `LoginGraceTime 30`, and with key-only authentication a password cannot
  be brute-forced at all — so neither banner is required for a hardened host,
  and neither is installed by default.
- fail2ban and CrowdSec both ship, each declaring the other as a `Conflicts`.
  The choice is the administrator's because the trade-off is theirs: one parses
  local logs and reports nothing anywhere, the other consults a reputation
  network and in exchange reports what this host sees. Running both is a host
  that bans twice and unbans unpredictably, since neither observes the other's
  rules — which is what the variant exists to say.
- The fail2ban jail names the SSH port explicitly. `port = ssh` resolves
  through `/etc/services` and therefore means 22 whatever the daemon is
  actually listening on, so a moved port leaves the jail watching one nobody
  knocks on.
- CrowdSec says plainly that its agent decides and does not block: without a
  bouncer nothing enforces, which reads as a working install right up until an
  attack is not stopped. Installing it is confirmed first, since it sends data
  off the machine.
- `updates.unattended-security` never reboots on its own. A tool that reboots a
  server on its own schedule is one nobody can plan around, so the need for one
  is declared as a consequence instead. Writing the policy is not treated as
  success either — the package ships a debconf question whose answer decides
  whether the timer runs at all, so the timer is confirmed enabled.
- Unattended upgrades declare Debian only. Arch is a rolling release with no
  equivalent, and inventing a different operation under the same task id would
  make the two families silently disagree about what the task does.
- A developer environment area: fish, Zellij, mise and the Rust toolchain.
  Installing a tool is a system operation and takes no account — only changing
  a login shell and activating a version manager are per-user, and those are
  separate tasks. The split also keeps the destructive flag honest: putting a
  binary on the box is not destructive, changing someone's login shell is.
- `BinaryInstaller`, a capability for installing from a verified release. The
  gap it covers is a different installation *mechanism*, not a different
  package name: Arch packages Zellij and no Debian or Ubuntu suite does, so
  `PackageManager` cannot express it. `Backend::has_package_for` is how a task
  asks which mechanism applies without asking which distribution it is on.
- Checksums are compiled into this build rather than fetched with the archive.
  A digest served by the host serving the artefact proves only that the
  transfer completed — an attacker who can replace one can replace the other.
  A version this build carries no digest for is not installable, which is the
  intended limit, and the archive is verified before it is extracted: one
  unpacked and then checked has already written whatever it contained.
- The Zellij release table ships empty. Every entry is a promise that this
  project verified that artefact, and a plausible-looking wrong digest would be
  worse than none — so the Debian path refuses to install anything until real
  digests are filled in.
- `fish.install` registers the shell at the path the system resolves rather
  than a compiled-in one, since fish lives at different paths across
  distributions and releases, and compares `/etc/shells` line by line —
  `/bin/fish` is a substring of `/usr/bin/fish`.
- `rust.install` warns that rustup installs no C linker. It is the most common
  first-build failure and it surfaces at link time, long after the toolchain
  reported itself installed.
- `mise.install` warns that shell activation is a prompt hook, so a deploy
  script or a systemd unit sees none of the versions mise manages — the tool
  appears to work everywhere except where it matters.
- Rootless Docker and Caddy, as a Services area. Both stop short of describing
  an application: the engine is provisioned and runs no containers, and Caddy
  is installed, validated and hardened without site configuration being
  written. A `reverse_proxy` block describes an application topology, which is
  where the self-hosting panels live and where this tool deliberately does not.
- `UserServiceManager`, a capability for services belonging to an account
  rather than to the system. The two managers cannot see each other, so a
  rootless engine is not reachable through the existing `ServiceManager` at
  all. Lingering is enabled before the engine starts: without it the engine
  stops when the account's last session ends, and a user unit wanted by
  `default.target` is not brought back by anything at boot.
- The engine is confirmed running rather than assumed. `enable --now` exiting
  zero says the command ran, and a rootless engine that cannot map its ids or
  reach its runtime directory fails after that point — reporting success there
  would send the administrator to look at their containers.
- An account with no subordinate id range is refused before anything is
  installed, since a rootless engine maps container users onto that range and
  without one no container starts.
- The rootless package diverges: Debian's distribution package does not carry
  `dockerd-rootless-setuptool.sh` at all, while Arch's `docker` does. A single
  name would leave one family with an install that has nothing to run.
- Caddy's security headers are a snippet to import rather than a global block.
  Applying headers to every site silently would change how an application
  already deployed here behaves, and this tool does not edit site
  configuration. `X-Forwarded-*` is left alone: Caddy sets those itself and
  overwriting them breaks client-IP detection downstream.
- The Caddyfile is validated by asking Caddy rather than by reading the file —
  directive order in a Caddyfile is not its source order — and a snippet that
  does not parse is rolled back, since a broken configuration takes every site
  down at the next reload.
- WireGuard: install a server, add peers, and report the tunnel's state. Sits
  under Remote Access beside SSH, which is what that category was named for —
  SSH grants shell access and WireGuard grants network access.
- `WireguardTools`, a capability for key material and interface state. Private
  keys are fed on stdin and never as arguments: `/proc/<pid>/cmdline` is
  readable by every account on the host, so an argument publishes the key for
  as long as the process lives.
- Keys are length-checked on the way out of `wg`. A key short by one character
  — the `=` padding lost to an over-eager trim — produces a configuration that
  parses and against which no handshake ever completes, so the failure appears
  as a tunnel that silently does not work.
- Client configurations route `0.0.0.0/0, ::/0` together. Routing only IPv4
  leaves the device's own IPv6 route in place, so traffic to a dual-stack
  destination leaves outside the tunnel while the tunnel reports itself up.
  This was a real leak in the scripts this task was sourced from.
- Peers are authorised for a single `/32`. On the server `AllowedIPs` is the
  set of addresses a peer may send *from*, so a subnet mask there lets any peer
  impersonate every other.
- The server configuration carries no `PostUp`. The masquerade rule usually
  written there is spelled differently for nftables and iptables, and guessing
  wrong leaves a tunnel that connects and routes nothing — the firewall is a
  capability precisely so this does not have to guess.
- Installing over an existing configuration is refused rather than overwriting
  it: a fresh server key invalidates every peer configured against the old one,
  and each stops connecting with no indication why. Adding a peer reloads
  rather than restarts, since a restart drops every established tunnel
  including the administrator's own.
- Firewall and kernel parameters, as their own top-level area. They belong to
  no component and every component needs them: WireGuard needs forwarding and
  an open UDP port, rootless Docker needs unprivileged ports, Caddy needs 80
  and 443, SSH needs whichever port it was moved to.
- `FirewallManager` and `SysctlManager` capabilities, with `nftables` and
  `sysctl` implementations. `ufw` is deliberately not a sibling implementation:
  it wraps whichever backend is installed, so driving both it and `nft` on one
  host is how a rule becomes invisible to the tool that did not write it.
- Enabling the firewall admits the SSH port in the same ruleset that installs
  the default-deny policy. Applying the policy first and the rule second leaves
  a window in which everything is denied, and the session issuing the second
  command does not survive it. Established connections and loopback are kept
  for the same reason: without them the host cannot reach its own package
  mirror or talk to itself.
- Rules live in a table named for this tool rather than in `filter`, which the
  distribution also writes to, and cover `inet` rather than `ip` — a rule added
  only to IPv4 leaves the same port reachable over IPv6.
- Kernel parameters are written to a drop-in of this tool's own rather than
  appended to `/etc/sysctl.conf`. A repeated setting replaces its line instead
  of accumulating contradictory ones whose winner is whichever is read last.
  The runtime value is applied first, so a parameter this kernel does not have
  fails before a file is written that would make every subsequent boot log an
  error.
- `ssh.change-port` now carries a verifiable consequence rather than a bare
  warning: `firewall.allow-port` exists, so the ruleset can be asked whether it
  names the new port. The needle is the whole rule — `2222` is a substring of
  `22220`.
- Account administration: create an administrative user, change a login shell,
  and lock the root account. First area outside SSH, and first entry under a
  second top-level category, since the rest of the tool depends on there being
  a safe way in before anything is hardened.
- `AccountWriter`, a capability for creating and modifying accounts, alongside
  the existing read-only `AccountReader`. Split because the two differ in
  privilege and in what implements them: reading the passwd database is
  unprivileged and universal, while the shadow suite that creates and expires
  accounts is absent from busybox.
- The backend resolves the group that grants sudo — `sudo` on Debian, `wheel`
  on Arch. `usermod -aG sudo` on Arch exits zero against a group the system
  does not have, so asking for the wrong name costs nothing at the time and
  produces an account that looks provisioned and cannot escalate. Membership is
  read back after it is granted for the same reason.
- `users.lock-root` expires the account rather than locking its password. A
  `!`-prefixed hash is checked in PAM's auth phase and public-key
  authentication never reaches it — `sshd` reads `authorized_keys` without
  calling `pam_authenticate`, and OpenSSH's own locked-account check is
  compiled behind `!UsePAM` while `UsePAM yes` is the default. So `passwd -l
  root`, which is what this task is usually written as, reports success and
  leaves root logging in with a key.
- `users.lock-root` refuses to run unless another account exists, is in the
  administrative group, and holds a non-empty `authorized_keys`. The only task
  in the tool that blocks rather than warning: every other change here is
  recoverable, and this one can require the provider's rescue console. A file
  holding only comments does not count as a key, since it authorises nobody
  while passing a check for its own existence.
- `ParamKind::Path` for absolute paths, rejecting relative ones rather than
  resolving them — what they resolve against depends on the working directory
  of whatever runs the command, and a login shell is recorded verbatim.
- Tasks declare what they invalidate elsewhere, and the interface states it
  after the task succeeds. `src/tasks/revert.rs` already named the case in a
  comment — "a firewall that was never opened on the new port" — as a reason
  the verification window exists; the tool could say to wait, but not what had
  just been invalidated. `ssh.change-port` is the first to declare any, since
  it is the change that motivated the mechanism.
- The warnings separate what the tool can inspect from what it cannot. A
  firewall rule on this host is readable; a hosting provider's edge firewall is
  not, and neither is a DNS record that has to resolve before a certificate can
  be issued. The second kind carries its own marker and says in its text that
  nothing checked it — reporting both alike would imply a check that never ran.
  Nothing is acted on either way: the administrator decides.
- Re-running a task with the value it already had declares nothing. A warning
  raised every time is one that gets dismissed unread, which costs the warnings
  that mattered.
- The interface keeps the values a task was started with. They are moved onto
  the worker thread when it launches, so reporting from the ones the form held
  found them empty — every consequence would have been computed from nothing
  and silently reported none. Caught by wiring the reporting up rather than by
  the task's own tests, which call `consequences` directly and cannot see the
  path in between; there is now a test that drives the interface instead.

### Changed
- Configuration paths resolve through the backend, like package and unit names
  already did. `SSHD_CONFIG` was a constant in the task layer, which worked
  only because the two families implemented today agree on
  `/etc/ssh/sshd_config` — an agreement between two distributions rather than a
  property of the capability. A path held in a task is a path no backend can
  correct, and it was the last system-specific name living above that line. The
  tests ask the backend for the path they assert on, so they follow whatever it
  resolves rather than restating a second copy of it.

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
- The exit-code contract in `docs/cli.md` is verified against the binary.
  Twelve documented cases across the three codes, none of which anything
  checked — and the contract exists for automation, where a script that retries
  on `1` and gives up on `2` depends entirely on the difference. Confirmed to
  catch a violation by introducing one: changing the unknown-subcommand exit
  from `2` to `1` fails the scenario, naming the case.
- The documented port range is checked at both ends, with the values just
  inside them, since an off-by-one in the comparison shows at exactly one of
  the four. The valid ports are asserted by their message rather than their
  exit code: with no openssh installed there is no `sshd_config` to edit, so
  they fail afterwards for a reason unrelated to the range — reading the code
  alone reported the tool as rejecting port 1, which it does not.
- Detection is exercised against `/etc/os-release` files no image provides, by
  mounting the existing fixtures over the real path. The unit tests parse those
  same files and prove the parser; what they cannot prove is that the binary
  reads the real path and resolves a backend from what it finds. Ubuntu is the
  case that matters — its `ID` is not a family, so only `ID_LIKE` says which
  backend to use, and getting it wrong makes every Ubuntu server unsupported.
  Gentoo covers the other side: an unsupported distribution must be refused
  naming what it found, since guessing a backend would run `apt` on a system
  that has none.
- Tests that drive the terminal interface as a user drives it, through tmux.
  ratatui needs a real terminal; a pipe renders nothing and `script(1)`
  captures nothing readable, because the interface lives in the alternate
  screen and that is discarded on exit. tmux allocates the pty *and* dumps a
  live pane, so the screen is asserted on while it is drawn — and it is a shell
  tool rather than a crate, so nothing was added to audit.
- Coverage of `Revert`, which was reachable from nowhere a test could get to.
  There is no `initd revert` subcommand — deliberately, since a revert without
  a verification window is what the CLI keeps out — so the interface is the
  only route, and its three unit tests ran against a mock that cannot say
  whether the restored file is the one that was there before. The scenarios
  reach the verification window, press `R`, and compare the configuration byte
  for byte with what preceded it; a second presses `K` and confirms the change
  survives.
- The verification window needs systemd, which is why this could not have been
  written earlier. Without it `ssh.harden` writes the file, fails at
  `systemctl reload`, and the task ends FAILED — and a failed task offers
  nothing to keep or revert, so the window never opens.
- Coverage of the `ssh.socket` warning, as Debian-specific behaviour rather
  than a shared invariant. Socket activation moves the listening port out of
  `sshd_config` into the socket unit, so the `Port` the task writes has no
  effect until that unit is reconfigured; silence there would be the worst
  outcome available — success reported, the file reading 2222, the daemon still
  answering on 22. Written first as a matrix scenario and moved after it failed
  on Arch: that package ships `sshd.service`, `sshd@.service` and
  `sshdgenkeys.service`, and no socket unit at all, so the situation cannot
  arise there. The warning is driven by the unit being active, which is why it
  had never been exercised.
- `initd list` and `initd privileges` are covered in the shared matrix. Both
  had none: `list` prints the identifiers a script would call, and
  `privileges` must answer `none` as root, since naming a mechanism there would
  mean the resolution ignored the effective user.
- Container tests that boot systemd as PID 1, so `systemctl` means what it
  means on a host. `ssh.install` enables a unit and the ordinary containers
  cannot run that step at all — they assert the package landed and let the
  enable fail — so a task that installed correctly and enabled the wrong unit,
  or none, passed every test there. The unit names diverge (`ssh.service`
  against `sshd.service`) and that divergence had only ever been checked
  against a mock. They also cover what a reload does: hardening must leave the
  service running, not merely leave a file that parses.
- `--cgroupns=host` alongside `--privileged`, found empirically: without it
  systemd exits 255 immediately and logs nothing, which reads like a broken
  image rather than a missing flag. These scenarios live in their own binary
  and skip where a host will not grant those capabilities, since a rootless
  Docker has not found a bug.
- Tests that log in from a client older than the server — Debian 11's OpenSSH
  8.4 against 10.0 and 10.4 — across two containers on a private network. The
  single-container scenarios take client and server from one image and so from
  one release, which leaves the question `ssh.harden-strict` actually raises
  unanswered: an algorithm the server now insists on is one an older client may
  never have learned. The strict tier is allowed to refuse such a client, since
  refusing is that tier working; what is asserted is that the daemon *answers*,
  rather than hanging or dying mid-handshake.
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
- Centring a dialog on a proportion of the screen is `layout::centred_percent`,
  beside the fixed-size `layout::centred` the form and the help overlay use.
  The confirmation dialog had its own copy, which left the module that declares
  it owns every inner split not owning this one.
- The parameter form resolves which field method a key means before touching
  the form, instead of repeating the same focus guard around twelve editing
  keys.
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
- The socket scenario recreates `/run/sshd` after stopping the service rather
  than before, with explicit ownership and mode. The unit declares
  `RuntimeDirectory=sshd` and `RuntimeDirectoryPreserve=no`, so systemd deletes
  that directory on stop and a `mkdir` beforehand is undone by the stop itself;
  recreated afterwards it needs 0755 root-owned or `sshd -t` rejects it as
  group-writable. Both failures abort the port change before it can warn about
  anything, which is how the scenario failed twice while looking like a missing
  warning.
- The two-host harness waits on sshd's pid file rather than calling `pgrep`,
  which procps provides and Debian's base image does not ship. The call never
  matched, so the loop ran to its limit and the wait was silently a fixed
  thirty-second sleep that happened to be long enough. Found by checking every
  external tool the scenarios invoke against both images, after two of them had
  already turned out to be missing.
- File comparisons in the interface scenarios compare hashes rather than
  calling `diff` or `cmp`. Both live in diffutils, which Debian pulls in and
  Arch's base image does not — so each failed the same way in turn: the missing
  tool reports "differs", which failed the revert scenario whose revert had
  actually worked, and *passed* the keep scenario, which asserts the files
  differ and got that for free. Substituting one tool for another repeated the
  bug; `sha256sum` is in coreutils and present in both. A scenario now pins the
  comparison itself against a copy and a change, since a comparator that is
  wrong in either direction is invisible in the scenarios that use it.
- The systemd scenarios compare `systemctl` output line by line rather than by
  substring. Written as a substring check, `is-active` reporting `inactive`
  satisfied a test looking for `active`, and one passed against a container
  where the package had failed to install — the precise case it existed to
  catch. The states systemd reports are words that contain one another.
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
- `Error::FileIo` and its catalogue entry. Every file operation reaches the
  system through an `Executor` command, so failures surface as `CommandFailed`
  or `CommandIo`; the variant was left over from a design that used `std::fs`
  directly, and was constructed only by its own test. The test that covered it
  now exercises `OsReleaseUnreadable`, which carries the same `#[source]` and
  is raised in production, so the error chain stays covered.
- Three `allow(dead_code)` attributes that no longer suppressed anything, on
  `State::Cancelled`, `Stream` and `OutputLine`. Each carried a comment saying
  the item was declared ahead of its consumer, which had stopped being true:
  cancellation is bound to `Ctrl-C`, and the output pane styles both streams.

### Fixed
- Centring a dialog on a proportion of the screen no longer overflows `u16`.
  The multiplication ran at `u16`, so a terminal 1093 columns wide exceeded the
  type at 60% — a panic in debug, and a silently wrapped width in release, the
  profile this ships as. A wide terminal is what a proportional dialog is for,
  so the overflow sat on the path the function exists to serve, and the dialog
  it corrupts is the one gating destructive operations.
- The confirmation dialog's proportions are measured on a rendered buffer
  rather than asserted against the constants that produce them. Comparing a
  constant with its own literal passes whatever `render` does, including
  ignoring the constants altogether.
- The output pane styles only the rows the viewport shows, rather than the
  whole retained history on every frame. The loop redraws ten times a second
  whether or not output arrived, so a full buffer meant cloning up to 5,000
  strings per redraw to display about twenty rows — work proportional to the
  backlog, on exactly the path a package installation exercises. Wrapped lines
  keep the previous behaviour, since one logical line then occupies several
  rows and only the widget can say which rows fall inside the viewport.
- The confirmation dialog draws its border with `dialog_border_danger`, the
  role `docs/ui.md` assigns it, rather than the yellow it built inline. It was
  the one module that constructed styles at the call site instead of naming
  them in `style.rs`, which is the drift the style table exists to prevent —
  `choice_selected` and `choice_normal` were declared for this dialog and had
  no callers.

### Security
- A directive absent from `sshd_config` is written before the first `Match`
  block rather than appended. Everything after a `Match` line belongs to that
  block, so a file ending in one — a common hardening pattern, jailing an
  `sftp-only` group — silently scoped the new directive to whoever the block
  matched. Measured against OpenSSH 10.0: `PermitRootLogin no` appended after
  `Match User deployer` leaves `sshd -T` reporting `without-password` for every
  other user. The task reported success and the server was not hardened, which
  is the failure mode the tool exists to prevent. Replacing a directive that
  already exists was already correct and is unchanged.
- A public key containing a line break is rejected. `split_whitespace` treats
  one like any other separator, so a value carrying it validated as a single
  key and was then written verbatim into `authorized_keys` as two entries — the
  second never approved. `AuthorizeKey` only trims the outer whitespace, and
  the CLI hands its argument straight to the check without passing through the
  interface's per-keystroke filter, so this was the only barrier. The sibling
  check on usernames already rejected the same characters for the same reason.
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
