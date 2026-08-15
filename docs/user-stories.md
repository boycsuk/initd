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
    version and the resolved family (`debian`, `arch`, `alpine`, `rhel` or
    `suse`).
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
- As an **administrator**, I can see whether something is already installed
  before I decide to act, so that I am not offered work the machine has already
  done.
  - Acceptance: a row offering to install something the host already has
    instead offers to remove it, and the reverse. One row, one verb, decided by
    the machine rather than by me.
  - Acceptance: the answer is measured in the background rather than making me
    wait for the interface to open, and a row that has not been settled yet
    says so instead of silently showing a guess.
  - Acceptance: the answer is taken again after a task finishes, including one
    that failed — a task that installed a package and then could not enable the
    unit leaves a state nobody knows.
  - Platform exception: TUI only. The CLI measures nothing and lists both the
    install and the uninstall, since it is a catalogue of what can be run rather
    than a report on this host.
- As an **administrator**, I can restore the display after something else has
  written over it, so that kernel console messages do not leave me reading a
  broken screen on the console my provider gives me.
  - Acceptance: one key repaints every cell, from any state — including the
    verification window, where an unreadable screen would be worst.
  - Acceptance: nothing machine-global is changed to achieve it. Kernel
    messages are not suppressed: they are what an administrator wants to see
    while hardening SSH or changing a firewall, and silencing them would
    outlive the session that did it.
  - Acceptance: the tool states that it cannot prevent the damage, only repair
    it — messages arriving between two repaints are still drawn over.
  - Platform exception: TUI only. The CLI writes a line at a time and needs no
    repair.
- As an **administrator**, I can browse the tasks grouped by area rather than
  as one flat list, so that I can find what I need as the tool grows.
  - Acceptance: tasks are organised into categories that may themselves contain
    categories, to any depth.
  - Acceptance: a task's identifier does not change when it is regrouped, so
    scripts calling it keep working.
  - TUI exception: categories are opened one level at a time, with a breadcrumb
    showing the current location and a way back to the parent. The arrow keys
    walk both directions — into a category and back out — so descending does not
    need the key that also runs tasks.
  - Acceptance: the key that walks *into* a level never starts a task. Reaching
    a task and reaching for the next arrow are one keystroke apart, and a
    movement key that sometimes changes the machine is one nobody can press
    quickly.
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
    `sudo` on Debian, `wheel` on Arch, Alpine, RHEL and openSUSE — and the
    membership is read back rather than assumed, because the command reports
    success either way.
  - Acceptance: the group is created first where the distribution does not
    ship one. openSUSE takes `wheel` from a package only its desktop patterns
    require, so a minimally installed server has none, and adding an account to
    a missing group fails outright.
  - Acceptance: where membership alone does not confer escalation, the grant is
    written as well. openSUSE ships the rule for `wheel` commented out, so an
    account can be in the right group and still be unable to escalate; a
    drop-in under `sudoers.d` supplies it, and the result is validated, since a
    sudoers file that does not parse disables sudo entirely.
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
- As an **administrator**, I can delete an account, so that someone who has
  left keeps no way in.
  - Acceptance: its home directory is kept unless I ask for it to go. Both
    answers are defensible — a home holding dotfiles is residue, one holding a
    year of someone's work is not — which is why neither is safe as a default
    nobody stated.
  - Acceptance: when I do ask for it to go, the confirmation names the
    directory **and how much is in it** before anything happens. "Also delete
    the home directory?" is a question answered by habit; "so will
    /home/deploy — 2.4 GiB of files this tool did not create and cannot put
    back" is one that gets read.
  - Acceptance: a directory whose size could not be read says so rather than
    reporting zero. Unreadable and empty are different facts, and "0 B"
    understates the stake by exactly the amount that matters.
  - Acceptance: it warns that keys authorised for that account, and any
    allow-list naming it, now refer to something that does not exist — a list
    naming a deleted account admits nobody under that name while going on
    looking correct.
  - Acceptance: I cannot delete the account I am administering the machine as.
    Doing so would end the session mid-task and remove whatever grants it root,
    with nothing left to undo it from. Refused where the escalation says which
    account it acted for; where nothing says — a root console, `su -` — the
    confirmation warns instead, because refusing an unanswerable question would
    stop a root console from deleting anything.
  - Platform exception: TUI only. The interactive confirmation is the only
    place the path and its size are stated before it happens, and with the home
    directory deleted there is nothing to put back afterwards.
- As an **administrator**, I can change an account's login shell, so that a
  user gets the shell they prefer.
  - Acceptance: a shell absent from `/etc/shells` is refused before anything is
    written, since the system would refuse it afterwards.
  - Acceptance: an account this host does not have is refused as I type it,
    the mirror of the rule that stops me creating one it already has. Every
    field naming an account states which it expects, so neither mistake waits
    for the task to run.
- As an **administrator**, I can lock the root account, so that it cannot be
  logged into at all — and unlock it again from the same place.
  - Acceptance: one row covers both directions, and which one it offers is read
    from the host when the confirmation opens rather than guessed at. Where the
    account's state cannot be read — that answer needs administrator access,
    which a session loses once its authentication expires — neither direction
    is offered, and the dialog says so instead of proposing the wrong one.
  - Acceptance: unlocking lifts the expiry and sets no password, which the tool
    states plainly: an account holding no usable credential still cannot log in
    afterwards.
  - Acceptance: unlocking is not refused for want of another administrator. The
    scan below guards the direction that can strand somebody; restoring access
    can strand nobody, and a host with no other administrator is exactly where
    it matters most.
  - Acceptance: I am not asked which account keeps access. The tool scans every
    account the host has and answers that itself — the question had one right
    answer the machine already held, and the account I would have named was
    only ever checked, never locked or modified.
  - Acceptance: refused unless *some* account is in the administrative group
    and can authenticate — by an authorised key or by a usable password. Either
    counts, because expiry is applied through PAM and so bars every channel
    including the provider's rescue console, which never consults
    `authorized_keys`; demanding a key measured SSH when the question was about
    every way in, and refused the account a distribution's installer made. A
    `!` or `*` hash is not a password: neither can be produced by any input.
  - Acceptance: the refusal is about the host rather than about a name — "no
    account here can get back in" — and says how many were examined, so it
    asserts no more than it measured.
  - Acceptance: each account that does not qualify is reported with the reason
    it was set aside. One of those reasons is a fact about the distribution
    rather than the account: on openSUSE the administrative group grants
    nothing on its own, so membership reads back true on an account that still
    cannot escalate — and what I am given is the shipped rule to uncomment
    rather than an absent membership the system would contradict.
  - Acceptance: every account below the conventional uid threshold is scanned
    too. That threshold orders the search and never limits it, so a site that
    numbers a real administrator below it is not reported as having no way out.
  - Acceptance: I am told that root will no longer log in by any route,
    including the rescue console, and shown **every** account that keeps
    access, each with the credential it gets in by — so I can check that mine
    is among them rather than having to know the answer in advance. The list
    scrolls where it is longer than the dialog, so no account is hidden.
  - Acceptance: where nothing says which account I am connected as — a root
    console, `su -`, `run0` — the dialog says so rather than marking a row it
    cannot justify. It never refuses on that basis: the signal is set by
    whoever is already root, and refusing on an unanswerable question would
    strand the rescue console this task exists for.
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
  - Platform exception: Debian only, and the other four decline for four
    different reasons rather than one. Arch is a rolling release, where
    upgrading unattended means pulling whatever landed today. Alpine ships no
    equivalent at all. RHEL packages one under a name that moved between
    releases, and SUSE's depends on how the host was installed rather than on
    the family — so in both of those the backend, which resolves a family,
    cannot name the right mechanism. Each is shown unsupported rather than
    doing something different under the same name.
- As an **administrator**, I can remove a banner or stop applying updates
  automatically, so that I can swap one protection for another or take the
  machine back under manual control.
  - Acceptance: removing a banner says plainly that nothing now rate-limits
    repeated authentication failures — the window between removing one and
    installing the other is a window where neither watches.
  - Acceptance: stopping automatic updates says that they now need applying by
    hand. It is the one removal here with no visible effect: nothing stops
    working, updates simply stop arriving, and a host left this way looks
    healthy for as long as it takes to matter.

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
  - Acceptance: they are named *before* the choice as well as after it. The
    field opens on the newest release this build can verify and offers the
    rest, rather than opening empty under a hint that says "a version this
    build can verify" without saying which — the refusal above was the only
    way to find out, and it arrives after the form is submitted.
  - Acceptance: what is offered is what the tool will accept. A version
    published upstream after this binary was built has no compiled-in digest,
    so suggesting it would be proposing the refusal.
  - Acceptance: the archive is verified before it is extracted — and where the
    artefact is an installer rather than the tool, before it is *run*. Running
    an unverified binary as root is the worse half of the same mistake.
  - Acceptance: a host that already has the binary downloads nothing.
  - Acceptance: where the tool belongs to an account rather than to the machine,
    it is installed as that account. A toolchain manager resolves its home from
    the environment at run time, so one installed by root belongs to root
    however the request was phrased.
- As an **administrator**, I can give an account a git identity, so that commits
  made on this box are attributed to somebody.
  - Acceptance: git refuses to commit without one — it exits 128 saying *"Please
    tell me who you are"* — so the row that installs git says so rather than
    reporting success on a tool that cannot yet do its job.
  - Acceptance: the identity is written per account, never machine-wide. One
    `user.email` for the host would attribute everybody's commits to one person.
  - Acceptance: everything already in that account's config file survives.
    Aliases, editor choices and comments are the operator's, and a tool that
    tidied them into its own shape would destroy work while reporting success.
  - Acceptance: setting an identity twice replaces it rather than appending a
    second one. git reads the last of a repeated key, so a duplicate leaves the
    operator looking at two values unable to tell which is in effect.
- As an **administrator**, I can let git read a repository owned by another
  account, so that a deploy checkout works without weakening the check for
  everything else.
  - Acceptance: paths are added, not replaced. A host with three checkouts needs
    three entries, and replacing would un-trust one that worked yesterday — a
    failure that surfaces later and somewhere else.
  - Acceptance: a relative path is refused where it is typed. git matches this
    setting literally, so a relative one is not a near miss: it never matches,
    and would read as applied.
  - Acceptance: trusting one path is offered; opting out of the check entirely
    is not.
- As an **administrator**, I can install the GitHub CLI, so that I can work with
  repositories from the server.
  - Acceptance: it is installed from the distribution where the distribution has
    it, under whichever name that distribution uses, and from a checksum-verified
    release where it does not.
  - Acceptance: the tool says how to authenticate on a machine with no browser,
    naming the command, because the default flow cannot work there.
  - Acceptance: no token is asked for, stored or handled by this tool. It is the
    operator's credential, and gh has its own storage for it.
- As an **administrator**, I can remove a tool I installed, so that a box I use
  for one thing does not accumulate the tools I tried for another.
  - Acceptance: I choose whether its configuration goes with it. The default
    keeps it, so a reinstall finds what was there.
  - Acceptance: removing a shell leaves its `/etc/shells` entry, since an
    account still set to it would otherwise have a login shell no file admits.
  - Acceptance: removing a tool that came from a release deletes the binary
    this tool installed and nothing else. A copy of the same program found
    elsewhere — from `cargo install`, or a vendor script — is named and left
    where it is.
  - Acceptance: toolchains and versions the tool managed under an account's own
    directory stay, where the distribution packaged the manager. This tool
    installed the manager, not what was built with it.
  - Acceptance: where the manager was installed for one account instead, it is
    removed by its own uninstaller, which takes those directories with it — and
    the tool says so rather than repeating a promise that holds on the other
    route. An uninstaller that deletes somebody's work while reporting that it
    kept it is worse than one that warns.

### Containers and web server

- As an **administrator**, I can install a container engine for the machine, so
  that it can run containers at all.
  - Acceptance: the engine is installed the way the distribution's own
    documentation says. Where Docker publishes a repository for it, that
    repository is registered and every package upstream's page lists is
    installed in one transaction — a host left holding some of them is one
    where the daemon or the client may be missing without anything saying so.
    Where Docker publishes no repository, the distribution's own package is
    used rather than a third-party one.
  - Acceptance: the engine is confirmed running *and* enabled at boot, rather
    than assumed from a command that exited zero.
  - Acceptance: I am told that adding an account to the `docker` group makes it
    equivalent to root, since that is the usual next step and nothing about the
    command announces what it grants. The tool states it and does not do it.

- As an **administrator**, I can then have that engine run as an ordinary
  account rather than as root, so that a container escape lands in a user
  instead of on the machine.
  - Acceptance: this is a separate step from installing the engine, because the
    two have different scopes: an engine belongs to the machine and a rootless
    setup belongs to one account. Asking for it on a host with no engine is
    refused in words naming the step that installs one.
  - Acceptance: the account is allowed to keep services running with no session
    open. Without that the engine stops at logout and nothing restarts it after
    a reboot.
  - Acceptance: where my distribution ships no rootless setup script in any
    official package, I am told before anything runs that the script will be
    fetched from upstream and that there is no digest to check it against.
    Every other route the tool takes verifies what it downloads; this one
    cannot, and says so rather than staying quiet about the one exception.
  - Acceptance: an account with no subordinate id range is refused before
    anything is installed, since no container could start.
  - Acceptance: an account whose own service manager cannot be reached is
    refused, and told so in words that name the cause. The engine runs under
    that manager, so there is nothing to install it into — and the underlying
    message, about two unset environment variables, names no cause and suggests
    a flag for a different problem.
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
- As an **administrator**, I can remove the web server or take a container
  engine off one account, so that a box repurposed for something else is not
  still serving.
  - Acceptance: removing the web server stops it and disables it at boot, not
    one or the other — a service stopped but left enabled is running again
    after a reboot, having reported itself stopped.
  - Acceptance: removing the container engine from an account leaves its
    containers, images and volumes alone: they are that account's data, not
    this tool's. The engine itself also stays, since the machine and other
    accounts may still be using it.
  - Acceptance: removing the engine from the machine leaves `/var/lib/docker`
    alone for the same reason — images and volumes are my data, and nothing
    here could put them back.
  - Acceptance: removal stops rather than half-completing when the account's
    service manager cannot be reached, and says which account and why. Running
    on regardless would remove the engine's files while leaving a unit nothing
    stopped, and report that as success.
  - Acceptance: naming an account that does not exist says exactly that, rather
    than reporting its service manager unreachable — true of an account that is
    not there, and it sends the reader after the wrong thing over a typo.

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
- As an **administrator**, I can remove WireGuard, so that a host that no
  longer needs a tunnel is not still listening for one.
  - Acceptance: it carries the same lockout warning as the changes that can end
    my session, because it can: if I am connected *over* the tunnel, it goes
    down with the server. It is offered anyway, unlike removing the SSH server,
    because reaching a host over WireGuard is a choice a console can undo.
  - Acceptance: `wg0.conf` and the server keys are left on disk whichever
    removal I choose. They cannot be regenerated to match peers that already
    hold the public key, so deleting them is a decision for whoever knows those
    peers are gone — not one taken by a field whose two values sit a character
    apart.
  - Acceptance: it says that every configured peer now points at a tunnel that
    is down, and that the firewall rule admitting the port now admits nothing.
    Neither is visible from here — the peers are elsewhere, and an open port
    with nothing behind it is exactly the residue a removal should not leave.

### Firewall and kernel parameters

- As an **administrator**, I can see whether the firewall is filtering and which
  ports it admits, so that I know what is reachable before I change anything.
  - Acceptance: "not filtering" and "filtering nothing" are reported
    differently. They look alike in a listing and mean opposite things.
  - Acceptance: and so is "could not be read", which is a third state rather
    than a shade of the first. Listing a ruleset needs administrator access,
    and a session loses that once its authentication expires — so a firewall
    that is running is never reported as off on the strength of a question the
    tool was refused. The row says the state is unknown, and the port table
    declines to open rather than opening empty: it is declarative, so an empty
    table confirmed is a request to close every port, the session's included.
  - Acceptance: the status says whether the rules come back after a restart.
    The running ruleset cannot be read for it — `nft` holds its rules in the
    kernel — so a host filtering perfectly now can return from a reboot with
    every port open, and a status that stopped at "denied by default" would be
    true and misleading in the same sentence.
  - Acceptance: a host with no firewall front-end installed is told which ones
    were looked for, rather than being shown the front-end's own command
    failing. "nft --version — FAILED" reads as a broken tool; "none of these is
    installed: firewalld, nftables" is the answer to the question that was
    asked.
- As an **administrator**, I can turn on default-deny inbound filtering without
  losing the session I am running it from.
  - Acceptance: the SSH port is admitted by the same ruleset that installs the
    policy, not by a second command afterwards.
  - Acceptance: the port defaults to the one the daemon is **actually** serving,
    read from the host rather than assumed to be 22, in both interfaces. A
    compiled-in default is not a neutral guess here: on a host whose SSH was
    moved it admits a port nothing listens on and closes the one carrying the
    session, so the field meant to prevent a lockout would be the thing causing
    one. A value given explicitly still wins.
  - Acceptance: the task says what it *closes* before it says what it opens, and
    the port field says why it is being asked. "Enable the firewall" reads as
    an operation that needs no argument, so a field labelled only "SSH port"
    invites skipping past the one value keeping the session alive.
  - Acceptance: established connections and loopback keep working, so the host
    can still reach its own package mirror and talk to itself.
  - Acceptance: applied *and* kept, on the same terms the kernel parameters
    already promise. A ruleset that only exists in the kernel is gone at the
    next restart, and a server that comes back with every port open reports
    nothing about it.
  - Acceptance: where the host has nothing to replay the rules at boot — a
    container, a chroot — the rules are still applied and saved, and the task
    says that is what happened rather than claiming they will return.
  - Acceptance: the front-end is installed if it is not there. `nft` is
    packaged separately on every family, so going straight to enabling fails
    with a missing binary over a host whose only problem is a package nobody
    installed yet.
- As an **administrator**, I can see every port the host admits and declare
  which of them should stay open — adding ports, removing ports, or both at
  once.
  - Acceptance: a set is a *declaration*, so anything listed is opened and
    anything the host admits and the list omits is closed. Running it twice
    with the same set changes nothing the second time. This replaces the
    earlier "open one port" task, which could add a rule and never remove one;
    `firewall.allow-port` no longer exists.
  - Acceptance: a rule for TCP does not admit UDP. WireGuard is UDP, and a
    TCP rule for its port admits none of its traffic.
  - Acceptance: ports are opened before any is closed, so a set that moves a
    service from one port to another does not drop the session in the window
    between the two commands.
  - Acceptance: the changes survive a restart, and declaring a set while
    nothing is being filtered is refused — against no policy every port is
    already reachable, so "open" would read as "only this is admitted".
  - Acceptance: a port the front-end admits by a route this tool cannot undo is
    shown and refused rather than hidden, naming what admits it. firewalld
    admits SSH on a stock RHEL host as the *service* `ssh`, where removing the
    port succeeds and closes nothing — so a tool that accepted the removal
    would report a closed port over a session that is still reachable.
  - Acceptance: a port that appeared after the set was read — opened by
    somebody else while the operator was deciding — is reported and left alone
    rather than silently closed.
  - Acceptance: the confirmation names the ports about to close, and says
    plainly when one of them is the port this host's sshd is listening on.
    Where none of them is, it still declines to promise safety: `sshd -T` says
    what the daemon serves, not how the operator reached it, and a jump host or
    a forwarded port arrives by a route nothing here can see.
  - TUI: the set is edited as a table, one row per port.
  - CLI: `ports="22/tcp 443/tcp"`, which defaults to what the host currently
    admits — so an invocation naming nothing changes nothing, while an
    explicitly empty set closes everything.
- As an **administrator**, I can enable IP forwarding and unprivileged port
  binding, so that a VPN can route and a rootless container engine can serve.
  - Acceptance: applied immediately *and* across reboots. Either alone reports
    success over a system that does not behave as described.
  - Acceptance: a parameter already holding the value says so rather than
    silently doing nothing.
  - Acceptance: a host with no `sysctl` gets it installed rather than being told
    the program is missing. It is a separate package on four of the five
    families and absent from a freshly provisioned RHEL, so "program sysctl"
    reads as a broken tool rather than a package nobody installed. Where the
    tool cannot be missing — Alpine, where it is a busybox applet — nothing is
    installed and the refusal says so instead.
  - Acceptance: the directory holding the persistent setting is created if the
    distribution does not ship it, rather than the write failing over a
    temporary filename.

### SSH server

- As an **administrator**, I can install and enable the SSH server so that the
  machine accepts remote connections after a reboot.
  - Acceptance: the correct package for the distribution is installed
    (`openssh-server` on Debian, `openssh` on Arch and Alpine) and the correct
    service is enabled — `ssh.service`, `sshd.service`, or the `sshd` init
    script where there are no units at all.
  - Acceptance: running it again on a machine that already has SSH does not
    reinstall the package.
  - Acceptance: the version of OpenSSH the host runs is reported, whether it
    was just installed or was already there. "already installed" says nothing
    about *what* is installed, and the version is what decides which hardening
    tier is safe to apply — the strict tier insists on algorithms an older
    client may never have learned.
  - Acceptance: removing it **is** offered, and it is the one operation here
    with no route back. Run over SSH it ends the session that asked for it
    mid-removal, and the hold-open-and-revert mechanism cannot help: the
    process that would put it back is being torn down by the disconnection, and
    putting it back means reinstalling a package over a network path that no
    longer exists. Recovery is the provider's console.
  - Acceptance: that reasoning is why it carries the strongest confirmation the
    interface has, and why it was absent by design until it was asked for. The
    reasoning did not change — the answer to it did. This entry read "there is
    no way to uninstall it from here, deliberately and permanently" for as long
    as `ssh.uninstall` has existed.
- As an **administrator**, I can harden the SSH configuration so that the
  server refuses root logins, password authentication, forwarding and
  tunnelling, limits how long and how often a client may try to authenticate,
  and records which key each login used.
  - Acceptance: the previous configuration is copied aside before anything is
    written.
  - Acceptance: the operation is refused, with an explanation, when no account
    that survives the change holds an authorised key — otherwise it would lock
    everyone out. Root does not count, since this task disables root logins.
  - Acceptance: before applying, I am shown which accounts keep SSH access, so
    I can check that mine is among them.
  - Acceptance: a configuration rejected by `sshd -t` is rolled back and the
    service is not reloaded.
  - Acceptance: a directive this version of OpenSSH does not recognise is
    skipped and reported, rather than written and taking every other directive
    down with it when the file is rejected.
  - Acceptance: a directive the daemon will not honour is named. Validation
    says the file parses, not that it wins: Debian, Ubuntu and RHEL read
    `/etc/ssh/sshd_config.d/` before the main file, and the first occurrence of
    a directive is the one that applies — so a drop-in left by a provider image
    can leave the hardening written, valid, reloaded and without effect.
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
  - Acceptance: a write cursor marks where the next line will land, so a quiet
    command is distinguishable from a screen that has stopped updating.
  - Acceptance: the header names the running task beside a turning throbber and
    the time it has run, so a command that has gone quiet is distinguishable
    from a session that has stopped answering — and I can tell *which* task is
    the one taking the time. The write cursor neither moves nor counts, which is
    why it is not the only signal.
  - Known limit: the count is elapsed time, not progress. A task's command count
    is not known before it runs, so a percentage would be invented; what the
    screen offers is evidence that something is still happening, not an estimate
    of when it will end.
  - Acceptance: I am asked for my password once, before the interface starts,
    rather than each time a task needs root.
  - TUI exception: the CLI prints output to the terminal as it arrives and has
    no interface to keep responsive.
- As an **administrator**, I can ask what the keys are from wherever I am stuck,
  so that not knowing which key to press is never the thing that traps me.
  - Acceptance: `?` opens the key list from anywhere, including on top of a
    dialog asking me to confirm a change, the window counting down to revert
    one, and the list of recorded changes. Those are the states where a wrong
    guess costs the most and where the keys are least familiar.
  - Acceptance: the overlay draws over what I was looking at rather than
    replacing it, so I do not lose my place, and closing it returns me to the
    same state.
  - Acceptance: it also explains the marks the rows carry, in the colours they
    are drawn in. A mark is the one thing on screen with no word beside it, so
    it is the one thing I can see and have no way to look up — and the answer
    being in a document is no answer on a server that does not have it.
  - TUI exception: the CLI answers the same question with `--help`.
- As an **administrator**, I can stop a running task without leaving the
  machine half-configured.
  - Acceptance: stopping takes effect between two commands, never in the middle
    of one.
  - Acceptance: until the current step finishes, the tool says it is *stopping*
    rather than claiming it has stopped — on screen, from the moment I ask. The
    key I pressed stops being offered and the bar reads `stopping after this
    command`, so the wait is not mistaken for a keypress that never landed.
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
    a machine losing power both leave the change applied. The sentence saying so
    is on screen — it was written, and drawn outside the banner at every
    terminal size, so the tool promised more than it could keep for as long as
    the banner's height was fixed independently of its content.
  - Acceptance: the window is on screen whatever the size of my terminal and
    whichever pane I was reading. On a narrow one — a phone client, a split
    pane — the panes are shown one at a time, and the window used to be reachable
    only by pressing the key that switches them: I would have had to already know
    a change was pending in order to find out that one was.
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
  - Acceptance: a field that needs explaining carries its explanation beside the
    label. Enabling the firewall asks for an "SSH port" for a reason only the
    hint gives — that port is kept open so the session asking survives the
    default-deny policy — and without it the question reads as arbitrary.
    Others resolve an ambiguity the label cannot: whether removing an account
    keeps or deletes its files, that a shell must appear in `/etc/shells`.
  - Acceptance: where the row is too narrow for the hint it is dropped whole
    rather than cut, and the field's verdict keeps its place. Half a sentence
    reads as a defect, and the verdict is the part of the row I cannot work
    without.
  - Acceptance: cancelling a form I have typed into asks before discarding it,
    and says so — the hint changes to `again to discard`, so the first `Esc` is
    not mistaken for a key that was dropped and answered by pressing it again.
  - Acceptance: I can paste a value rather than typing it. A pasted public key
    fills the field whole, including when what I pasted ends in a newline, which
    does not submit the form.
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

- As an **administrator**, I can put a configuration change back in a later
  session, not only in the one that made it, so that a decision I regret
  tomorrow is not one I have to undo by hand.
  - Acceptance: the previous version is copied somewhere the next change to the
    same file cannot reach. Without that, the second edit destroys the copy the
    first one left, and the state worth going back to is the older of the two.
  - Acceptance: the task says whether the change was recorded — either way. A
    host where the record could not be kept still applies the change correctly,
    and being told today is better than assuming an undo exists and finding
    none tomorrow.
  - Acceptance: restoring refuses if the file has changed since this tool wrote
    it. A day is long enough for me to have edited it myself, and putting the
    copy over that would discard my work while reporting success. The refusal
    names both digests, since "the file changed" alone cannot tell my own edit
    from a package upgrade replacing a conffile.
  - Acceptance: restoring also refuses if the copy itself is damaged. A backup
    truncated by a full disk is a file that exists and is readable, and putting
    half a configuration over a working one is worse than leaving the change.
  - Acceptance: a file that could not be read at all is reported as that, not
    as a file that changed. The two call for different actions, and reporting
    the second as the first sends me looking for an edit nobody made.
  - Acceptance: the record holds no secrets and never can — it names paths,
    times and digests, and there is no field a password could be put in.
  - Acceptance: the two files whose copies would be dangerous are never
    recorded: the WireGuard configuration, which holds the server's private key
    and every peer's preshared key, and `authorized_keys`, whose restoration
    *removes* an authorised key rather than restoring access.
- As an **administrator**, I can see what this tool has changed and put any one
  of it back, so that a configuration I regret is not one I have to reconstruct
  from memory.
  - Acceptance: the list names the task that made each change as well as the
    time. Ten recorded states of one file are ten indistinguishable timestamps
    without it, and choosing between them is the whole point of the list.
  - Acceptance: restoring asks first, with the same warning as any other change
    that can end the session — restoring an `sshd_config` is exactly as able to
    lock me out as writing one was.
  - Acceptance: confirming a restore restores; it never starts whatever task
    the tree's cursor happened to be on.
  - Acceptance: a refusal — the file edited since, the copy damaged — is
    reported as *not restored* rather than as a failure, because the machine is
    left exactly as it was.
  - Acceptance: a host where nothing has been recorded says so, rather than
    showing an empty list that looks like a view which failed to load.
  - Platform exception: TUI only. Choosing among recorded states is a
    selection, and the CLI has no cursor; `initd` prints the index's path in
    the task output for anybody who wants to read it with ordinary tools.
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
  - Acceptance: I read what the program printed, not the codes it printed it
    with. A script that colours its own output unconditionally — and they do,
    pipe or no pipe — would otherwise put `[101m[97m[ERROR]` on my screen and
    into anything I paste elsewhere.
  - Acceptance: when the task ends, its report is on screen. A task that
    narrates more lines than the pane is tall would otherwise finish with the
    outcome below the last visible row, showing me the middle of the run.
  - Acceptance: the header tells me the task is still alive independently of
    what it prints — a throbber that turns, the task's id, and how long it has
    been going. Over a slow link a quiet command and a stalled session no longer
    look the same.
  - Platform exception: the TUI shows it in a scrollable pane; the CLI prints
    it as it arrives.
- As an **administrator**, I can install a task's dependencies on a host whose
  package index has never been fetched, so that a freshly provisioned machine
  is not refused over a package name that is correct.
  - Acceptance: the index is refreshed before a name is resolved against it, on
    the families whose package manager does not do it itself. Otherwise the
    failure is `Unable to locate package` or `target not found` — which reads
    as the tool naming the package wrong, when what is empty is the index.
  - Acceptance: installing one package does not upgrade the system. A tool
    asked for a firewall front-end has no business deciding that this is the
    moment to replace the kernel: a full upgrade has its own reboot and its own
    timing, and neither belongs to the task that was run.
- Known limit, across the interface: **a refused keystroke produces no
  message.** Pressing `Enter` on a task this host cannot run, or `q` while a
  task is running, is declined silently — the screen does not change, which is
  indistinguishable from a key that never arrived. For the unsupported case the
  row is dimmed and flagged and the detail pane says why; the others say
  nothing. Accepted deliberately when the status line was removed: a word in a
  corner describing a dialog that fills the middle of the screen was judged the
  larger cost.
- As an **administrator**, I can read back through a task's output while it runs
  without the arriving lines dragging me away from what I am reading.
  - Acceptance: scrolling up detaches from the newest output and stays there.
  - Acceptance: reaching the bottom again resumes following, with no separate
    key to press — having caught up is the same thing as wanting to follow.
  - Platform exception: TUI only. The CLI's output is the terminal's own
    scrollback, which the terminal already does this for.
- As an **administrator**, I am told **why** a task failed and not only that it
  did, so that I can act on it instead of guessing.
  - Acceptance: I get the command that failed, the code it exited with, and what
    it wrote to stderr — each on its own line, under its own label. One sentence
    holding all three buries the exit code in the middle of it and loses the
    stderr to the width of whatever was drawing it.
  - Acceptance: the report is where the task's own output is, beside the
    commands that led to it. I am not asked to read a corner of the screen and a
    pane at the same time, and nothing has to be pressed to see it.
  - Acceptance: an error whose whole content is one sentence keeps that
    sentence. A label over an empty column would tell me less than the sentence
    it replaced.
  - Acceptance: a task I stopped is reported distinctly from one that broke, and
    names the command it stopped *before* — what ran and what did not is the
    thing I need before running it again.
  - Acceptance: a **revert** that failed says so in its own words: the machine
    is in neither state, which is worse than a task that did not run, and it is
    not reported as though it were the same thing.
  - Acceptance: the report goes with the transcript when I copy it.
  - Platform exception: the TUI writes it into the output pane; the CLI prints
    it to stderr and exits non-zero, where the exit code is the contract.
- As an **administrator**, I can read what a task *does* while a previous task's
  output is still on screen, so that choosing the next one does not mean losing
  the record of the last.
  - Acceptance: the description and the transcript are both visible. The pane
    used to show one or the other, so after the first task ran, every task
    selected afterwards had its description displaced by output from a task I
    had already finished with.
  - Acceptance: I can fold the output away when a long transcript is worth the
    whole pane, and unfold it with the same key. Folding keeps the transcript —
    a key pressed to make room must not discard what a finished task said.
  - Acceptance: folding does not leave the arrow keys addressing a pane that is
    no longer drawn.
  - Platform exception: the TUI only. The CLI prints a task's output as it runs
    and its description is `run --help`.
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
