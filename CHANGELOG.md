# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
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

### Fixed
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
