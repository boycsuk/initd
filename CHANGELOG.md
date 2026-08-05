# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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

### Changed
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
