//! English message catalogue — the default and fallback language.

use super::{ErrorField, Msg, SysctlHolding};

/// Width the field labels are padded to, in columns.
///
/// The values line up in a column only if every label occupies the same width,
/// and the widest English label is `architecture`. A locale with longer words
/// sets its own: the padding belongs to the language, not to the caller.
const FIELD_LABEL_WIDTH: usize = 12;

/// Renders a message in English.
///
/// Exhaustive by construction: a new [`Msg`] variant fails to compile here
/// rather than falling through to a placeholder at runtime.
pub(super) fn render(message: &Msg) -> String {
    match message {
        // --- Distro detection ---
        Msg::OsReleaseUnreadable { path, source } => {
            format!("could not read {path}: {source}")
        }
        Msg::OsReleaseMissingId { path } => {
            format!("{path} does not declare an ID field")
        }
        Msg::UnsupportedDistro { id, id_like } => {
            let like = id_like.as_deref().unwrap_or("(none)");
            // Derived from `Family::ALL` rather than written out. The literal
            // that stood here said "debian, arch, alpine, rhel" and was never
            // updated when SUSE landed, so an operator on SLES whose
            // `/etc/os-release` did not resolve — a derivative, an unexpected
            // `ID_LIKE` — read that their distribution was unsupported when the
            // backend, two container images and the whole test matrix say
            // otherwise. A list of what a program supports is exactly the kind
            // of sentence that cannot be maintained by hand.
            let families = crate::distro::Family::ALL
                .iter()
                .map(ToString::to_string)
                .collect::<Vec<_>>()
                .join(", ");

            format!(
                "unsupported distribution: ID={id}, ID_LIKE={like}. \
                 Supported families: {families}"
            )
        }
        Msg::RepositoryKeyMismatch {
            repository,
            expected,
            found,
        } => {
            format!(
                "the signing key served for {repository} is not the one this \
                 build expects, so it was not registered. Expected \
                 {expected}, got {found}"
            )
        }
        Msg::RepositoryKeyUnverifiable { repository } => {
            format!(
                "the signing key for {repository} could not be fetched or read, \
                 so the repository was not registered"
            )
        }
        Msg::RepositoryUnknownSuite { repository } => {
            format!(
                "this host declares no VERSION_CODENAME in /etc/os-release, so \
                 there is no suite to fetch from {repository} and it was not \
                 registered. APT expands no variable for the suite, and a \
                 guessed one would register a repository serving nothing"
            )
        }
        // Says why it matters rather than only that it is required: git matches
        // this setting literally, so a relative path is not a near miss — it
        // never matches anything, and the setting would look applied.
        Msg::PathNotAbsolute { path } => format!(
            "{path} is not an absolute path. git matches safe.directory \
             literally, so a relative one would be written and never match"
        ),
        Msg::NoFirewallFrontEnd => {
            "no inbound filtering front-end is installed on this host".to_owned()
        }
        // Names the task that fixes it, because this refusal is one step short
        // of an operation the operator plainly wants and the step is not
        // guessable from "the firewall is not enabled". Says why rather than
        // only what: against no default-deny policy every port is already
        // reachable, so a rule admitting one would filter nothing while looking
        // like a firewall that had been configured.
        Msg::FirewallNotEnabled => {
            "nothing is being filtered, so opening a port would admit nothing it \
             does not already admit — run firewall.enable first"
                .to_owned()
        }
        // --- Command execution ---
        Msg::ProgramNotFound { program } => {
            format!("executable {program} was not found in PATH")
        }
        Msg::CommandFailed {
            command,
            code,
            stderr,
        } => {
            format!("`{command}` failed with exit code {code}: {stderr}")
        }
        Msg::CommandTerminatedBySignal { command } => {
            format!("`{command}` was terminated by a signal, with no exit code")
        }
        // Says the process is still running, because it is: waiting stopped,
        // the child did not. An operator told only that something "timed out"
        // would reasonably assume the machine is back to where it started.
        Msg::CommandSilent { command, seconds } => {
            format!(
                "`{command}` produced no output for {seconds} seconds and is still \
                 running; it was left alone rather than killed, since stopping it \
                 part-way through would leave half of its work applied"
            )
        }
        Msg::CommandIo { command, source } => {
            format!("I/O error while running `{command}`: {source}")
        }
        Msg::Cancelled { before } => {
            format!("stopped at the operator's request, before running `{before}`")
        }
        // --- Privileges ---
        Msg::NoPrivilegeEscalator => "this operation requires root privileges, but no escalation \
             mechanism (sudo, doas or run0) was found in PATH"
            .to_owned(),
        Msg::AuthenticationRefused { mechanism } => {
            format!("{mechanism} was not given a valid password, so nothing was run")
        }
        Msg::AuthenticationUnavailable { mechanism } => {
            format!("nothing answered the request to authenticate with {mechanism}")
        }
        Msg::AuthenticationRequested { mechanism } => {
            format!("{mechanism} needs a password — the interface is standing aside for it")
        }
        Msg::AuthenticationGranted => "authenticated; carrying on".to_owned(),
        // --- SSH ---
        Msg::InvalidSshdConfig { details } => {
            format!("the sshd configuration is invalid: {details}")
        }
        Msg::InvalidPublicKey { reason } => {
            format!("invalid public key: {reason}")
        }
        Msg::InvalidPort { port } => {
            format!("invalid port: {port} (must be between 1 and 65535)")
        }
        Msg::InvalidAllowUsers { reason } => {
            format!("invalid list of allowed users: {reason}")
        }
        Msg::LockoutNoKeyForRoot => "no authorised key found for root; disabling password \
             authentication now would lock you out. Add a key with `ssh.authorize-key` first"
            .to_owned(),
        Msg::LockoutUnknownUser { user } => {
            format!(
                "no account named {user} exists on this host; restricting SSH to it would \
                 refuse every login. Check the spelling, or create the account first"
            )
        }
        Msg::LockoutNoKeyForAllowedUsers { users } => {
            format!(
                "none of these accounts has an authorised key: {users}. Password \
                 authentication may already be disabled, which would leave no way to log \
                 in. Authorise a key for one of them with `ssh.authorize-key` first"
            )
        }
        Msg::MissingParameter { name } => {
            format!("the task was run without a value for {name}")
        }
        Msg::TaskVanished { task } => {
            format!("{task} stopped without reporting what it did")
        }
        // --- Tasks ---
        Msg::TaskUnsupported { task, family } => {
            format!("task {task} is not supported on {family}")
        }
        // Names the group, because the answer is almost always that this
        // distribution calls it something else: Debian grants sudo through
        // `sudo`, Arch and RHEL through `wheel`.
        Msg::MissingGroup { group } => {
            format!("the group {group} does not exist on this system")
        }
        Msg::UnknownSysctl { key } => {
            format!("this kernel has no parameter named {key}")
        }
        Msg::InvalidWireguardKey { reason } => {
            format!("invalid WireGuard key: {reason}")
        }
        // Says what overwriting would cost, since the file looks replaceable.
        Msg::WireguardAlreadyConfigured { path } => {
            format!(
                "{path} already exists; replacing it would generate a new server key \
                 and every existing peer would stop connecting"
            )
        }
        Msg::WireguardNotConfigured => {
            "WireGuard has no server configuration; run wireguard.install first".to_owned()
        }
        // Names the files, because the fix is to add a line to them and the
        // usual cause is an account created before the convention existed.
        Msg::NoSubordinateIds { user } => {
            format!(
                "{user} has no subordinate id range in /etc/subuid and /etc/subgid, \
                 so rootless containers cannot map their users"
            )
        }
        // Names the task that installs it. The rootless setup needs an engine
        // already on the host, and upstream's script fails in terms that name
        // neither this tool nor what to run first.
        Msg::DockerEngineAbsent => {
            "the docker engine is not installed on this host — run docker.install first".to_owned()
        }
        Msg::CaddyAbsent => {
            "caddy is not installed on this host — run caddy.install first".to_owned()
        }
        // Names the task rather than the binary: `sshd` missing from `PATH` is
        // what the tool saw, and "install the SSH server" is what the operator
        // has to do about it.
        Msg::SshdAbsent => "the SSH server is not installed on this host, so there is no \
             configuration to change — run ssh.install first"
            .to_owned(),
        // Says there is nothing to validate rather than that validation failed:
        // the file may never have been written, and "invalid" would send the
        // operator to edit something that is not there.
        Msg::CaddyfileAbsent { path } => {
            format!("there is no Caddy configuration at {path}, so nothing was validated")
        }
        // Names systemd-logind, because that is what has to be working and
        // systemd's own message names neither it nor any cause — it reports two
        // unset variables and suggests `--machine=<user>@.host`, which is advice
        // for reaching another host's bus rather than for a session that was
        // never created.
        Msg::NoUserSession { user } => {
            format!(
                "{user}'s own service manager cannot be reached: no session was \
                 established, so XDG_RUNTIME_DIR is unset and systemctl --user has \
                 no bus to address. Check that systemd-logind is running"
            )
        }
        // Stated as tampering rather than as a download problem, because that
        // is what a mismatch means once the digest is pinned in this binary.
        Msg::ChecksumMismatch { program, version } => {
            format!(
                "the {program} {version} archive did not match the checksum this build \
                 expects; it was not installed"
            )
        }
        // Names the architecture, since the usual cause is a host this
        // project has not published a build for rather than a mistake.
        Msg::UnsupportedArchitecture {
            program,
            version,
            arch,
        } => {
            format!("this build has no verified {program} {version} for {arch}")
        }
        Msg::UnknownRelease { version, known } => {
            format!("this build cannot verify {version}; it knows: {known}")
        }
        Msg::CapabilityUnavailable { capability } => {
            format!("this distribution has no mechanism for {capability}")
        }
        Msg::TimerNotEnabled { timer } => {
            format!(
                "{timer} is not enabled, so the policy was written and nothing \
                 will apply it"
            )
        }
        Msg::InvalidCaddyfile { details } => {
            format!("the Caddy configuration is invalid: {details}")
        }
        // Names where to look, since a user service's log is not where an
        // administrator would look first.
        Msg::ServiceDidNotStart { service, user } => {
            format!(
                "{service} was enabled but is not running for {user}; see \
                 `journalctl --user -u {service}` as that account"
            )
        }
        Msg::WireguardAddressTaken { address } => {
            format!("another peer already uses {address}")
        }
        Msg::InvalidSubnet { subnet } => {
            format!("{subnet} is not a subnet in CIDR notation")
        }
        Msg::AccountExists { user } => {
            format!("the account {user} already exists")
        }
        Msg::NoSuchAccount { user } => {
            format!("there is no account named {user}")
        }
        // Names the path rather than the account: a link here is something an
        // administrator may have set up on purpose, and the one thing they need
        // in order to judge that is which path was refused.
        Msg::UnsafeSymlink { path } => {
            format!(
                "{path} is a symbolic link, and writing through it would apply \
                 this change somewhere else; remove it or point the task at the \
                 real directory"
            )
        }
        Msg::GroupMembershipFailed { user, group } => {
            format!("{user} was not added to {group}, though the command reported success")
        }
        // The count rather than a name, because there is no name to report: the
        // host was scanned and none of what it holds can get back in. Says how
        // many were looked at so the claim asserts no more than was measured —
        // and points at the report, which carries the reason for each one.
        Msg::NoWayBackIn { examined } => {
            format!(
                "no account on this host can log in and escalate once root is locked \
                 — {examined} were examined, and the report above says why each was \
                 set aside. Give one of them a key or a password, and membership of \
                 the administrative group, before locking root"
            )
        }
        Msg::CannotDeleteRoot => "root cannot be deleted. Locking it is offered instead, \
             which refuses unless another account can still get in — a machine \
             with no root is not one this tool can put back"
            .to_owned(),
        // Both digests, because the difference is the evidence: "the file
        // changed" alone cannot tell an administrator's own edit from a
        // package upgrade that replaced a conffile.
        Msg::FileChangedSinceBackup {
            path,
            expected,
            found,
        } => format!(
            "{path} has changed since initd wrote it, so restoring the backup \
             would discard whatever changed it. Expected {expected}, found \
             {found}. Reverting by hand from the recorded copy is the way \
             forward if that is what you want."
        ),
        Msg::BackupCorrupt { copy } => format!(
            "{copy} is not the copy that was recorded — it was truncated or \
             replaced after being taken. Restoring it would put an incomplete \
             file over a working one, so nothing was changed."
        ),
        Msg::RevertUnverifiable { path } => format!(
            "{path} could not be read, so nothing can be proven about it \
             either way. This is not the same as the file having changed: \
             nothing was restored, and nothing is claimed."
        ),
        // Names the account and what it is: an operator who typed it deliberately
        // needs to know the tool is not confused, and one who typed it by
        // mistake needs to know which name was wrong.
        Msg::CannotDeleteOwnAccount { user } => format!(
            "{user} is the account this session is being administered as. \
             Deleting it would end the session and remove whatever grants it \
             root, with nothing left to undo it from. Do it from another \
             account, or from a root console."
        ),
        Msg::ShellNotListed { shell } => {
            format!("{shell} is not listed in /etc/shells, so the system will refuse it")
        }
        // --- Consequences ---
        Msg::ConsequencePortChanged { task, from, to } => {
            format!("{task} still refers to port {from}, not {to}")
        }
        Msg::ConsequenceRequiresSetting { task, setting } => {
            format!("{task} requires {setting}, which is not set")
        }
        Msg::ConsequenceNeedsRestart { task, service } => {
            format!("{service} must be restarted before {task} observes this")
        }
        Msg::ConsequenceAccountNotListed { task, user } => {
            format!("{task} does not name the account {user}")
        }
        Msg::ConsequenceAccountRemoved { task, user } => {
            format!("{task} still refers to {user}, which no longer exists")
        }
        Msg::ConsequenceConflictsOverBanRules { task } => {
            format!(
                "{task} also writes ban rules through the firewall; running \
                 both bans twice and unbans unpredictably"
            )
        }
        // Says plainly that this one cannot be checked from here. An
        // administrator who opens a port locally and still cannot reach it has
        // usually hit exactly this, and the tool has no way to see it.
        // Says what closes before it says what to check. The warning named only
        // the provider's firewall, which is the second thing an operator needs
        // to know — the first is that everything except this port is about to
        // stop answering, and that a wrong number here is what ends the session
        // running the task.
        Msg::ConsequenceProviderFirewall { port, protocol } => {
            format!(
                "every inbound port except {port}/{protocol} stops answering, \
                 including anything else this host serves — and if that is not \
                 the port your session is on, this ends it. Your hosting \
                 provider's firewall is a separate layer, and this tool cannot \
                 see it"
            )
        }
        Msg::ConsequenceDnsMustResolve => {
            "the name must resolve to this host before a certificate can be \
             issued — this tool cannot see it"
                .to_owned()
        }
        Msg::ConsequenceDockerGroupIsRoot => {
            "adding an account to the `docker` group makes it equivalent to \
             root: the daemon socket takes commands that mount any file on \
             this host"
                .to_owned()
        }
        Msg::ConsequenceUnverifiedRootlessInstaller => {
            "no official package here ships the rootless setup script, so it \
             is fetched from get.docker.com — which publishes no digest to \
             check it against"
                .to_owned()
        }
        // --- Terminal ---
        Msg::Terminal { source } => {
            format!("terminal error: {source}")
        }

        // --- Interface: help ---
        Msg::HelpTitle => " Keys ".to_owned(),
        Msg::HelpSectionAnywhere => "Anywhere".to_owned(),
        Msg::HelpSectionTree => "Task tree".to_owned(),
        Msg::HelpSectionMarkers => "Row markers".to_owned(),
        Msg::HelpSectionSearch => "Search".to_owned(),
        Msg::HelpSectionRunning => "While a task runs".to_owned(),
        Msg::HelpSectionOutput => "Output".to_owned(),
        Msg::HelpSectionForms => "Forms".to_owned(),
        Msg::HelpSectionConfirmation => "Confirmation".to_owned(),
        Msg::HelpSectionLockout => "After a change that could lock you out".to_owned(),
        Msg::HelpMoveFocus => "move focus between the tree and the output".to_owned(),
        // Named for the problem rather than the mechanism: somebody reaching
        // for this is looking at a screen the kernel has written over, and
        // "redraw" is what the program does about it rather than what they see.
        Msg::HelpRedraw => "repaint the screen (after console messages)".to_owned(),
        Msg::HelpThisHelp => "this help".to_owned(),
        Msg::HelpQuit => "quit".to_owned(),
        Msg::HelpPreviousRow => "previous row".to_owned(),
        Msg::HelpNextRow => "next row".to_owned(),
        Msg::HelpFirstLastRow => "first / last row".to_owned(),
        Msg::HelpOpenOrRun => "open a category, or run a task".to_owned(),
        Msg::HelpOpenCategory => "open a category, never run a task".to_owned(),
        Msg::HelpHistory => "recorded changes, with any one restorable".to_owned(),
        Msg::HelpFind => "find a task anywhere in the tree".to_owned(),
        Msg::HelpBack => "back to the parent level".to_owned(),
        Msg::HelpMarkerDanger => "can lock you out of this machine".to_owned(),
        Msg::HelpMarkerInput => "asks for values before it runs".to_owned(),
        Msg::HelpMarkerUnsupported => "not supported here — select it to see why".to_owned(),
        // "waiting on" rather than "blocked": the row is not broken, and the
        // thing it waits for is a task the operator can run.
        Msg::HelpMarkerBlocked => "waiting on another task — select it to see which".to_owned(),
        Msg::HelpMarkerPresent => "this host already has it".to_owned(),
        Msg::HelpMarkerProbing => "still checking what this host has".to_owned(),
        Msg::HelpFilter => "filter by title or task id".to_owned(),
        Msg::HelpBetweenResults => "move between results".to_owned(),
        Msg::HelpGoToTask => "go to the task, without running it".to_owned(),
        Msg::HelpCloseSearch => "close, leaving the cursor where it was".to_owned(),
        Msg::HelpStopAfterCommand => "stop after the current command".to_owned(),
        Msg::HelpScrollOutput => "scroll the output".to_owned(),
        Msg::HelpFocusOutput => "move focus to the output".to_owned(),
        // Says which half goes, since the pane holds two things and folding
        // either would be a plausible reading of one word.
        Msg::HelpFoldOutput => {
            "fold the task description away, giving the pane to the output".to_owned()
        }
        Msg::HelpScrollLine => "scroll a line".to_owned(),
        Msg::HelpScrollPage => "scroll a page".to_owned(),
        Msg::HelpOldestLine => "oldest retained line".to_owned(),
        Msg::HelpNewestLine => "newest output, and follow it".to_owned(),
        Msg::HelpCopy => "send the whole transcript to the terminal's clipboard".to_owned(),
        Msg::HelpNextField => "next field".to_owned(),
        Msg::HelpNextFieldOrSubmit => "next field, or submit on the last".to_owned(),
        // Both say "where the host offers any", because in a field with none
        // the arrows still move between fields and the list key does nothing
        // — and a help entry that does not say so reads as a broken binding.
        Msg::HelpStepOptions => {
            "step through what this host offers, where it offers any".to_owned()
        }
        Msg::HelpListOptions => "list everything this host offers for the field".to_owned(),
        Msg::HelpFieldEnds => "start / end of the value".to_owned(),
        Msg::HelpClearAround => "clear before / after the cursor".to_owned(),
        Msg::HelpDeleteWord => "delete the previous word".to_owned(),
        Msg::HelpCancelForm => "cancel (twice, if anything is typed)".to_owned(),
        Msg::HelpApply => "apply".to_owned(),
        Msg::HelpCancel => "cancel".to_owned(),
        Msg::HelpBetweenAnswers => "move between the answers".to_owned(),
        Msg::HelpKeep => "keep the change".to_owned(),
        Msg::HelpRevert => "put the previous configuration back".to_owned(),
        Msg::HelpAutoRevert => "puts it back on its own after 60s".to_owned(),
        // These two sit in the key column but are words rather than key names,
        // which is why they are in the catalogue while `Tab` and `↑ k` are not.
        Msg::HelpTypeGlyph => "(type)".to_owned(),
        Msg::HelpWaitGlyph => "(wait)".to_owned(),
        Msg::HelpMoreBelow { percent } => {
            format!(" ↑↓ more · any other key closes  ({percent}%) ")
        }
        Msg::HelpAnyKeyCloses => " any key closes ".to_owned(),

        // --- Interface: confirm ---
        //
        // Padded because each is drawn as a highlighted badge: the spaces are
        // the badge's inside edge, not separation between words.
        Msg::ConfirmYes => " Yes ".to_owned(),
        Msg::ConfirmNo => " No ".to_owned(),
        // Spelled out beside the answers rather than left to the key bar. This
        // is the dialog a destructive operation opens, and `Tab` selecting
        // while `Enter` commits is the one place in the interface where the
        // two differ — guessing wrong here applies the change.
        Msg::ConfirmKeyHint => "      (Tab to switch, Enter to confirm, Esc to cancel)".to_owned(),
        Msg::ConfirmScrollHint => "  ↑↓ to scroll the list".to_owned(),

        // --- Interface: output ---
        Msg::OutputTitle => "output".to_owned(),
        Msg::TranscriptRedacted => {
            "<secret omitted from the copy — shown on screen only>".to_owned()
        }

        // --- Interface: forms ---
        //
        // Trailing spaces separate the counter from the label beside it, and
        // each key hint from the next: they are drawn as adjacent spans on one
        // line, so the gap has to travel with the words.
        // Framed by spaces because it rides the dialog's border, where the
        // rule would otherwise run into the words.
        Msg::FormFieldCounter { index, total } => format!(" field {index} of {total} "),
        // Leading spaces separate this from the validation note it sits
        // beside. The arrows are drawn rather than named for the reason the
        // key bar states: a glyph on a keyboard is not a word in a language.
        Msg::FormOptionCount { position, total } => match position {
            Some(position) => format!("   ↑↓ {position}/{total} on this host"),
            None => format!("   ↑↓ {total} on this host"),
        },
        Msg::FormFieldOptional => "optional, may be left empty".to_owned(),
        Msg::FormFieldUnset => "(unset)".to_owned(),
        Msg::FormKeyList => "list".to_owned(),
        Msg::FormOptionsTitle { label } => format!(" {label} on this host "),
        Msg::FormOptionsChoose => "choose".to_owned(),
        Msg::FormKeyField => "field".to_owned(),
        Msg::FormKeyContinue => "continue".to_owned(),
        // Parenthesised because it stands where `continue` stands: it names
        // what is missing rather than announcing a refusal, which is what an
        // operator who has just pressed Enter is looking for.
        Msg::FormKeyIncomplete => "(fill every field)".to_owned(),
        Msg::FormKeyCancel => "cancel".to_owned(),
        Msg::KeyCancelArmed => "again to discard".to_owned(),

        // --- Interface: the ports table ---
        Msg::PortsOpenCount { count } => format!(" {count} open "),
        Msg::PortsColumnPort => "PORT".to_owned(),
        Msg::PortsColumnProtocol => "PROTOCOL".to_owned(),
        Msg::PortsColumnSource => "SOURCE".to_owned(),
        Msg::PortsSourceService { service } => format!("service {service}"),
        Msg::PortsSourceAdded => "added".to_owned(),
        // Names the service and what to do about it. "Cannot be removed" would
        // be true and leave the operator with nowhere to go, and the reason is
        // the part that says which tool to reach for instead.
        Msg::PortsRowFromService { spec, service } => format!(
            "{spec} is admitted by the service {service}, which removing the port does not undo"
        ),
        Msg::PortsRowIncomplete => "this row needs a port and a protocol".to_owned(),
        // Names the spec rather than saying "duplicate", because the protocol
        // is half the answer: 443/tcp and 443/udp are two different rules, and
        // an operator told only "already listed" would look for the number.
        Msg::PortsRowDuplicate { spec } => format!("{spec} is already in the table"),
        Msg::PortsKeyAdd => "add".to_owned(),
        Msg::PortsKeyRemove => "remove".to_owned(),
        Msg::PortsKeyEdit => "edit".to_owned(),
        Msg::PortsKeyApply => "apply".to_owned(),
        Msg::PortsKeyCommit => "done".to_owned(),
        Msg::PortsKeyNextCell => "next".to_owned(),
        Msg::PortsKeyDiscard => "discard".to_owned(),

        // --- Interface: search ---
        //
        // The query is interpolated untranslated — it is what the operator
        // typed. `▌` after it is the write cursor, the same glyph the output
        // pane uses, so the field reads as one being typed into rather than as
        // a title that happens to contain text.
        Msg::SearchTitle { query } => format!(" search: {query}▌ "),
        Msg::SearchNoMatches => " no matches · Esc closes ".to_owned(),
        // English does not inflect anything in this line, so `total` is used
        // only as a number. A language that does inflect resolves it here,
        // which is the reason the count is carried rather than pre-rendered.
        Msg::SearchFooter { position, total } => {
            format!(" {position} of {total} · ↑↓ move · Enter goes there · Esc closes ")
        }

        // --- Interface: header ---
        //
        // The leading space is the header's own inset: this is the first span
        // on a borderless row, so nothing else provides one.
        Msg::HeaderTitle => " initd".to_owned(),
        Msg::HeaderPaneTree => "tasks".to_owned(),
        Msg::HeaderPaneOutput => "output".to_owned(),
        Msg::HeaderPrivilege { mechanism } => format!("root via {mechanism}"),
        Msg::HeaderRunning { task, elapsed } => format!("{task}  {elapsed}"),
        // The `?` is the key to press, so it leads: the hint is read as an
        // instruction rather than as a label for a key named elsewhere.
        Msg::HeaderHelpHint => "? help".to_owned(),

        // --- Interface: detail pane ---
        //
        // Both sit under the task's own description, separated from it by a
        // blank line the call site writes: the description is the task's
        // words, and running the two together would read as one sentence.
        // "not yet" rather than "cannot": the difference from an unsupported
        // task is that this one becomes possible, and the sentence says how.
        Msg::DetailRequires { task } => {
            format!("Not ready yet: run {task} first.")
        }
        Msg::DetailUnsupported { family, reason } => {
            format!("Not available on {family}: {reason}.")
        }
        // English inflects only the noun here. A language that also inflects
        // the verb or the number resolves both in this one arm, which is why
        // the count arrives as a number rather than as a rendered phrase.
        Msg::DetailCategoryContents { title, count } => {
            let noun = if *count == 1 { "task" } else { "tasks" };
            format!("{title} — {count} {noun} inside.\n\nPress Enter to open.")
        }
        Msg::DetailTitle => "Detail".to_owned(),

        // --- Interface: tree census ---
        Msg::CensusCategories { count } => {
            let noun = if *count == 1 {
                "category"
            } else {
                "categories"
            };
            format!("{count} {noun}")
        }
        Msg::CensusTasks { count } => {
            let noun = if *count == 1 { "task" } else { "tasks" };
            format!("{count} {noun}")
        }

        // --- Interface: verification banner ---
        //
        // Padded like the status pill, whose badge this mirrors: the spaces
        // are the badge's inside edge rather than separation between words.
        Msg::VerifyBadge => " VERIFY ".to_owned(),
        // "applied" and "not yet kept" are two spans so the second can be
        // emphasised; the trailing space is the join between them.
        Msg::VerifyApplied => "applied, ".to_owned(),
        // Not "pending", not "awaiting confirmation": the operative fact is
        // that this *will* be undone unless answered.
        Msg::VerifyNotYetKept => "not yet kept".to_owned(),
        // A statement of what happens, not an offer. The countdown follows it.
        Msg::VerifyRevertingIn => "reverting in ".to_owned(),
        // Padded to sit against the `K` and `R` glyphs beside them, and to
        // separate the first pair from the second on one line.
        Msg::VerifyKeepKey => "keep".to_owned(),
        Msg::VerifyRevertKey => "revert now".to_owned(),
        // Wrapped by hand across two lines to the banner's width. Says what to
        // do, not just that a decision is due: the tool cannot check this
        // itself, and a countdown alone tells nobody how to spend the time.
        Msg::VerifyCheckSecondSessionLine1 => "Open a second session and check you".to_owned(),
        Msg::VerifyCheckSecondSessionLine2 => "can still log in.".to_owned(),
        // The limit of the promise above. `SIGKILL` and a power cut run no
        // code, so the change would stay — stating that is what makes the
        // sentence above believable, and dropping this line in a translation
        // breaks the banner rather than shortening it.
        Msg::VerifySessionScopeCaveat => "Reverts while this session lives.".to_owned(),

        // --- Interface: key bar ---
        //
        // One verb each, in the imperative: the bar is scanned rather than
        // read, and a label longer than a word crowds out the next pair.
        Msg::KeyBarOpen => "open".to_owned(),
        Msg::KeyBarRun => "run".to_owned(),
        Msg::KeyBarMove => "move".to_owned(),
        Msg::KeyBarFind => "find".to_owned(),
        Msg::KeyBarHistory => "history".to_owned(),
        Msg::KeyBarBack => "back".to_owned(),
        Msg::KeyBarOutput => "output".to_owned(),
        // Named for what the key does next rather than for what it toggles: a
        // bar reading "detail" beside a visible description says nothing about
        // which way pressing it goes.
        Msg::KeyBarHideDetail => "hide detail".to_owned(),
        Msg::KeyBarShowDetail => "show detail".to_owned(),
        Msg::KeyBarStop => "stop".to_owned(),
        Msg::KeyBarStopping => "stopping after this command".to_owned(),
        Msg::KeyBarScroll => "scroll".to_owned(),
        Msg::KeyBarCopy => "copy".to_owned(),
        Msg::KeyBarKeys => "keys".to_owned(),
        Msg::KeyBarKeep => "keep".to_owned(),
        Msg::KeyBarRevert => "revert".to_owned(),
        Msg::KeyBarGo => "go".to_owned(),
        Msg::KeyBarRestore => "restore".to_owned(),
        Msg::KeyBarClose => "close".to_owned(),
        Msg::KeyBarFollow => "follow".to_owned(),
        Msg::KeyBarTree => "tree".to_owned(),
        Msg::KeyBarQuit => "quit".to_owned(),

        // --- Interface: status messages ---
        //
        // Lower case and unpunctuated: they are read as a continuation of the
        // line above them, not as sentences of their own.
        Msg::StatusCopyFailed => "the terminal did not accept the copy".to_owned(),
        Msg::StatusFinishedBeforeItCouldStop => {
            "the task finished before it could be stopped".to_owned()
        }
        Msg::OutputConsequencesHeading => "Consequences:".to_owned(),
        // The task id is in the heading because the pane outlives the border:
        // a transcript read back an hour later has to say which task the
        // fields below belong to.
        Msg::OutputFailedHeading { task } => format!("FAILED — {task}"),
        Msg::OutputCancelledHeading { task } => format!("STOPPED — {task}"),
        // "neither state" rather than "failed": the change was applied and
        // putting it back did not work, which is worse than a task that did
        // not run and is the one sentence the operator must not misread.
        Msg::OutputRevertFailedHeading { task } => {
            format!("COULD NOT RESTORE — {task} is in neither state")
        }
        // Padded to a common width so the values line up in a column. The
        // labels are English words here and a locale with longer ones pads to
        // its own width, which is why the padding is applied at render time
        // rather than baked into the label.
        Msg::OutputErrorField { label, value } => {
            let name = match label {
                ErrorField::Command => "command",
                ErrorField::ExitCode => "exit code",
                ErrorField::Stderr => "stderr",
                ErrorField::Seconds => "waited",
                ErrorField::Path => "path",
                ErrorField::Expected => "expected",
                ErrorField::Found => "found",
                ErrorField::Repository => "repository",
                ErrorField::Service => "service",
                ErrorField::User => "user",
                ErrorField::Group => "group",
                ErrorField::Program => "program",
                ErrorField::Version => "version",
                ErrorField::Architecture => "architecture",
                ErrorField::Cause => "cause",
                ErrorField::Examined => "examined",
                ErrorField::Count => "count",
                ErrorField::Port => "port",
                ErrorField::Address => "address",
                ErrorField::Interface => "interface",
                ErrorField::Task => "task",
                ErrorField::Directive => "directive",
                ErrorField::Value => "value",
                ErrorField::Distribution => "distribution",
                ErrorField::Kind => "kind",
                ErrorField::Shell => "shell",
                ErrorField::Digest => "digest",
                ErrorField::Url => "url",
            };

            format!("{name:FIELD_LABEL_WIDTH$}  {value}")
        }

        // --- Interface: confirmation warning ---
        //
        // Two sentences: what this can cost, then what to do about it. The
        // second is the one the operator can act on.
        Msg::ConfirmLockoutWarning => "This operation can lock you out of a server you reach \
             over SSH. Make sure you have another way in before continuing."
            .to_owned(),
        // Names the port and says whether it is the right one, which the generic
        // sentence above cannot: "make sure you have another way in" is true
        // here and unactionable, and this dialog is the last place the value can
        // still be changed.
        //
        // The agreeing case still warns rather than reassuring. `sshd -T` says
        // what the daemon serves, not how the operator reached it — a jump host,
        // a forwarded port or a provider console all end up here — so "these
        // match, you are safe" would be a promise made on evidence that does not
        // support it.
        Msg::ConfirmFirewallLockout {
            port,
            listening,
            agrees,
        } => {
            if *agrees {
                format!(
                    "Everything except {port}/tcp stops answering the moment this runs, \
                     including anything else this host serves.\n\n\
                     If you are connected over SSH, {port} is the port keeping that \
                     connection alive — this host's sshd is listening on it, which is \
                     why it is filled in. Changing it to a port sshd does not serve \
                     ends your session, and only a console can undo that."
                )
            } else {
                format!(
                    "Everything except {port}/tcp stops answering the moment this runs, \
                     including anything else this host serves.\n\n\
                     This host's sshd is listening on {listening}, not {port}. If you \
                     are connected over SSH, this closes the port carrying your session \
                     and leaves open one nothing answers on — and only a console can \
                     undo that. Use {listening} unless you know why not."
                )
            }
        }
        // Names the ports rather than counting them, unlike the applied
        // message: this is the last screen where the set can still be changed,
        // and a count gives the operator nothing to check it against.
        Msg::ConfirmPortsClosing {
            specs,
            listening,
            closes_ssh,
        } => {
            if *closes_ssh {
                format!(
                    "This closes {specs}.\n\n\
                     {listening}/tcp is the port this host's sshd is listening on. If you \
                     are reading this over SSH, applying it ends your session the moment \
                     it runs, and only a console can undo that."
                )
            } else {
                format!(
                    "This closes {specs}, and anything reaching this host on them stops \
                     answering the moment it runs.\n\n\
                     This host's sshd is listening on {listening}, which is not among \
                     them — but sshd's own port is not the only way a session arrives. A \
                     jump host, a forwarded port or a provider console each reach this \
                     machine by a route nothing here can see."
                )
            }
        }
        Msg::ConfirmPortsOpeningOnly { opening } => format!(
            "This opens {opening} port(s) and closes none, so nothing that answers now \
             stops answering.\n\n\
             Opening a port here says nothing about whether the provider's edge firewall \
             admits it, which is the layer most often forgotten."
        ),
        // The path and the size are the whole point. "Also delete the home
        // directory?" is a question answered by habit; a sentence naming
        // /home/deploy and 2.4 GB is one that gets read.
        // Each of these ends on the same sentence, which is the one the
        // operator can act on. This tool cannot tell which account is running
        // it — nothing here resolves the invoking user — so it says what it
        // knows and names the account rather than implying a check it did not
        // make. root is refused outright and never reaches this dialog.
        Msg::ConfirmDeleteHome { user, path, size } => {
            format!(
                "{user} will be deleted, and so will {path} — {size} of files \
                 this tool did not create and cannot put back. If {user} is the \
                 account you are administering this machine as, this ends your \
                 access to it."
            )
        }
        Msg::ConfirmDeleteHomeUnmeasured { user, path } => {
            format!(
                "{user} will be deleted, and so will {path}. Its size could not \
                 be read, so how much is in there is unknown — which is not the \
                 same as nothing. If {user} is the account you are administering \
                 this machine as, this ends your access to it."
            )
        }
        Msg::ConfirmKeepHome { user, path } => {
            format!(
                "{user} will be deleted. {path} stays on disk, owned by a user \
                 id nothing claims any more. If {user} is the account you are \
                 administering this machine as, this ends your access to it."
            )
        }
        // Heads a list rather than naming one account, because the host was
        // scanned rather than asked about. The operator's decision is whether
        // their own account is among what follows — which is a thing they can
        // check, unlike the name they used to be asked to supply.
        Msg::ConfirmRootLockout { keeping } => {
            let accounts = if *keeping == 1 { "account" } else { "accounts" };

            format!(
                "root will no longer log in by any route, including the provider's \
                 rescue console. {keeping} {accounts} can still get in and administer \
                 this machine — check that yours is one of them:"
            )
        }
        // The credentials in one line, because this is a list the operator
        // scans for their own name and an account spread over two rows is one
        // that pushes another off the bottom.
        Msg::ConfirmKeepsAccess {
            user,
            key,
            password,
        } => format!("  {user} — {}", credentials(*key, *password)),
        // Said rather than left out. Nothing on the host answers which account
        // escalated into this session — every command describes the process,
        // which by then is root — so the dialog states the limit instead of
        // marking a row it cannot justify.
        Msg::ConfirmSessionAccountUnknown => {
            "Which of these you are connected as could not be determined, so none \
             is marked. If your account is not listed above, this will end your \
             access to this machine."
                .to_owned()
        }

        // --- Interface: terminal too small ---
        //
        // Both sizes, so the operator can see by how much the window has to
        // grow rather than resizing until the refusal disappears.
        Msg::TerminalTooSmall {
            min_width,
            min_height,
            width,
            height,
        } => {
            format!(
                "initd needs at least {min_width}×{min_height} .\nThis terminal is {width}×{height}."
            )
        }

        // What the tasks say as they work. The wording is what these lines
        // already said as literals in the task modules; moving them here
        // changed where they live rather than what they read.
        Msg::TaskInstalling { what } => format!("Installing {what}..."),
        Msg::TaskAlreadyInstalled { what } => format!("{what} is already installed"),
        Msg::TaskRemoving { what } => format!("Removing {what}, keeping its configuration..."),
        Msg::TaskPurging { what } => format!("Removing {what} and its configuration..."),
        // Names what survives rather than only that purging was declined: an
        // operator who asked for it wants to know where their configuration
        // now is, and `.rpmsave` is not a thing anybody guesses.
        Msg::TaskPurgeUnavailable => {
            "This distribution's package manager has no purge: rpm does not \
             track configuration as separately removable, so an edited file is \
             kept as <name>.rpmsave. Removing it by hand is the only way."
                .to_owned()
        }
        // Names where the configuration is rather than only that the depth was
        // ignored: an operator who asked to purge wants to know what survived,
        // and a release-installed program keeps nothing this tool wrote.
        Msg::TaskDepthNotApplicable { what } => {
            format!(
                "This distribution packages no {what}, so it was installed as a \
                 verified release and removing it deletes that binary. There is \
                 no package manager here to keep or discard configuration, so \
                 remove and purge do the same thing; anything under your own \
                 home directory is untouched either way."
            )
        }
        Msg::TaskNotInstalled { what } => format!("{what} is not installed"),
        Msg::TaskInstalledElsewhere { what, at } => {
            format!("{what} is installed at {at}, which initd did not put there — leaving it alone")
        }
        Msg::TaskDisabling { unit } => format!("Stopping and disabling {unit}..."),
        Msg::TaskBinaryRemoved { path } => format!("Removed {path}"),
        // Framed by spaces like every other pane title — `HelpTitle` and
        // `SearchTitle` carry theirs the same way. Without them the words sit
        // against the border's corner while the panes beside it have air.
        Msg::HistoryTitle { count } => format!(" Recorded changes ({count}) "),
        Msg::HistoryRestored { path } => {
            format!("{path} was put back to its recorded state and the service reloaded")
        }
        Msg::ConfirmRestoreTitle { path } => format!("Restore {path}"),
        // Names the task as well as the file, because the file alone does not
        // say which of its recorded states this is — the reason the list shows
        // the task in the first place.
        Msg::ConfirmRestoreBody { task, path } => format!(
            "{path} goes back to what it held before {task} changed it. If it \
             has been edited since, nothing is restored and you are told so."
        ),
        // A sentence rather than an empty list, and it says why there is
        // nothing rather than only that there is nothing: an operator who has
        // never run a configuration task should not read this as a fault.
        Msg::HistoryEmpty => "No changes have been recorded on this host yet. A task that edits \
             a configuration file copies the previous version aside, and what \
             it copied appears here."
            .to_owned(),
        Msg::TaskChangeRecorded => {
            "The previous configuration was copied aside, so this can be put \
             back in a later session"
                .to_owned()
        }
        // Names the consequence rather than the cause: which of the two steps
        // failed is a detail, and what the operator needs to know is that
        // coming back tomorrow will not offer an undo.
        Msg::TaskChangeNotRecorded => {
            "The previous configuration could not be recorded, so this change \
             cannot be put back from a later session"
                .to_owned()
        }
        Msg::TaskHomeKept { path } => format!("{path} was left on disk"),
        Msg::TaskHomeDeleted { path } => format!("{path} was deleted"),
        Msg::TaskEnabling { unit } => format!("Enabling {unit}..."),
        Msg::TaskUnitEnabled { unit } => format!("{unit} is enabled"),
        // The daemon's own word for itself, `OpenSSH_10.0p2`, passed through
        // rather than reformatted: it is what `sshd -V` prints and what an
        // operator will match against a release note.
        Msg::TaskSshVersion { version } => format!("running {version}"),
        Msg::TaskUnitState {
            unit,
            active,
            enabled,
        } => {
            format!(
                "{unit}: {}, {}",
                if *active { "active" } else { "inactive" },
                if *enabled { "enabled" } else { "disabled" }
            )
        }
        Msg::TaskNothingToDo { what } => format!("{what}; nothing to do"),

        Msg::TaskScanningAccounts => "Scanning accounts for a way back in...".to_owned(),
        Msg::TaskAccountKeepsAccess {
            user,
            key,
            password,
        } => format!(
            "  {user} — {} -> KEEPS ACCESS",
            credentials(*key, *password)
        ),
        Msg::TaskAccountNotAnAdministrator { user, group } => {
            format!("  {user} — not in {group}")
        }
        // Deliberately not the line above: this account *is* in the group, and
        // saying otherwise would send the operator to `usermod` for a problem
        // that command cannot fix. The cause is the distribution's own sudoers,
        // so it names the file and the line to uncomment.
        // `/usr/etc/sudoers`, not `/etc/sudoers`: openSUSE's `/usr/etc` split
        // is the whole reason this state exists, and this message is only ever
        // shown there. Naming the wrong path sends the operator to a file whose
        // commented line is not in it — the failure the message exists to
        // prevent, committed by the message itself.
        Msg::TaskAccountGroupGrantsNothing { user, group } => format!(
            "  {user} — in {group}, but {group} grants nothing here: \
             \"%{group} ALL=(ALL:ALL) ALL\" is commented out in \
             /usr/etc/sudoers. Creating an administrator with initd writes a \
             drop-in instead, which is the route that survives an upgrade"
        ),
        // Names sudo as the thing that answered, because that is what makes the
        // claim checkable: an operator who disagrees can run the same question.
        Msg::TaskAccountSudoGrantsNothing { user } => format!(
            "  {user} — in the administrative group, but sudo grants it nothing \
             on this host: check `sudo -l -U {user}` and the rules in \
             /etc/sudoers"
        ),
        Msg::TaskAccountCannotAuthenticate { user } => {
            format!("  {user} — no authorised key and no usable password")
        }
        Msg::TaskCreatingUser { user } => format!("Creating {user}..."),
        Msg::TaskUserCreated { user } => format!("{user} created"),
        Msg::TaskAddingToGroup { user, group } => format!("Adding {user} to {group}..."),
        Msg::TaskUserInGroup { user, group } => format!("{user} is in {group}"),
        Msg::TaskSettingShell { user, shell } => format!("setting {user} shell to {shell}"),
        Msg::TaskShellSet { user, shell } => format!("{user} now uses {shell}"),
        Msg::TaskRootAlreadyLocked => "root is already locked".to_owned(),
        Msg::TaskLockingRoot => "locking root".to_owned(),
        Msg::TaskRootLocked { admin } => {
            format!("root is locked; {admin} is the way in from now on")
        }
        Msg::TaskUserHasPassword { user } => format!("{user} has a password"),
        Msg::TaskUserHoldsKey { user } => format!("{user} holds an authorised key"),

        Msg::TaskSshKeyAlreadyAuthorised => {
            "The key is already authorised; nothing to do".to_owned()
        }
        Msg::TaskSshAddingKey { path } => format!("Adding the key to {path}..."),
        Msg::TaskSshKeyAuthorised => "Key authorised".to_owned(),
        Msg::TaskSshPortUnchanged { port } => {
            format!("The port is already {port}; nothing to do")
        }
        Msg::TaskSshChangingPort { from, to } => {
            format!("Changing the port from {from} to {to}...")
        }
        Msg::TaskSshBackupSaved { path } => format!("Previous configuration saved to {path}"),
        Msg::TaskSshLabellingPort { port } => format!("Labelling port {port} for SELinux..."),
        Msg::TaskSshPortSet { port } => {
            format!(
                "Port set to {port}. If a firewall is active, the new port may \
                 need to be opened before it can be reached."
            )
        }
        Msg::TaskSshReloading { unit } => format!("Reloading {unit}..."),
        Msg::TaskSshApplyingDirectives { count } => {
            format!("Applying {count} hardening directives...")
        }
        Msg::TaskSshNarrowingAlgorithms => "Narrowing the accepted algorithms...".to_owned(),
        Msg::TaskSshAlgorithmClass { directive, value } => format!("{directive}: {value}"),
        Msg::TaskSshAlgorithmsNarrowed { count } => {
            format!("{count} algorithm lists narrowed to what this daemon supports")
        }
        Msg::TaskSshHardening => "Applying the hardening...".to_owned(),
        Msg::TaskSshHardened { tier } => format!("{tier} applied"),
        Msg::TaskSshAllowingUsers { users } => format!("Restricting SSH to {users}..."),
        Msg::TaskSshUsersAllowed { users } => format!("SSH now admits only {users}"),

        Msg::TaskFirewallNoneInstalled { tried } => {
            format!("none of these is installed: {tried}")
        }
        Msg::TaskFirewallInactive => "inbound filtering is not active".to_owned(),
        // Says what is now true rather than that a command ran: "the firewall
        // is off" leaves an operator wondering what that means for the ports
        // their host serves.
        Msg::TaskFirewallDisabled => {
            "inbound filtering removed — every port this host serves is reachable again".to_owned()
        }
        Msg::TaskFirewallDefaultDeny => "inbound denied by default".to_owned(),
        Msg::TaskFirewallNoOpenPorts => "no ports are open".to_owned(),
        Msg::TaskFirewallPortOpen { port, admitted_by } => match admitted_by {
            Some(source) => format!("  {port} is open (admitted by {source})"),
            None => format!("  {port} is open"),
        },
        Msg::TaskFirewallPersisted => "the rules are restored at boot".to_owned(),
        Msg::TaskFirewallNotPersisted => {
            "the rules are not restored at boot — they end at the next restart".to_owned()
        }
        Msg::TaskFirewallInstalling { front_end } => format!("installing {front_end}"),
        Msg::TaskFirewallUsing { front_end } => format!("using {front_end}"),
        Msg::TaskFirewallEnabled { port } => {
            format!("inbound denied except {port}/tcp, now and after a reboot")
        }
        // Counts rather than a list: the ports themselves were on the screen
        // the operator just left, and a batch repeating them says less than the
        // two numbers that changed.
        // Named rather than counted, and said before the closing half runs: if
        // that half fails, this line is the only record that the firewall
        // already admits these.
        Msg::TaskFirewallPortsOpened { specs } => format!("opened: {specs}"),
        Msg::TaskFirewallPortsApplied { opened, closed } => match (opened, closed) {
            (0, 0) => "the open ports already matched what was declared".to_owned(),
            (opened, 0) => format!("opened {opened} port(s), now and after a reboot"),
            (0, closed) => format!("closed {closed} port(s), now and after a reboot"),
            (opened, closed) => {
                format!("opened {opened} port(s) and closed {closed}, now and after a reboot")
            }
        },
        // Names them, unlike the counts above: this is the half that did not do
        // what was asked, and the operator has to know which ports to go and
        // deal with by another route.
        Msg::TaskFirewallPortsStillOpen { specs } => {
            format!(
                "still open: {specs} — admitted by a service rather than by name, \
                 which removing the port does not undo"
            )
        }
        Msg::TaskFirewallPortsAppearedSince { specs } => {
            format!(
                "left alone: {specs} — opened by something else after this list \
                 was read, so closing it was never asked for"
            )
        }
        Msg::TaskFirewallPortsNotPersisted => {
            "saved, but this host has no service manager to replay it at boot".to_owned()
        }
        // Says what is missing rather than only that something is: the rules
        // are applied and saved, and what this host has nowhere to register is
        // the replay. Claiming "after a reboot" here would be the false promise
        // the persistence work exists to remove.
        Msg::TaskFirewallEnabledNotPersisted { port } => {
            format!(
                "inbound denied except {port}/tcp — saved, but this host has no \
                 service manager to replay it at boot"
            )
        }
        Msg::TaskFirewallNotFilteringYet => {
            "nothing is being filtered yet: run firewall.enable for this to mean anything"
                .to_owned()
        }
        Msg::TaskSysctlAlready { key, value } => format!("{key} is already {value}"),
        // Says what is now true rather than that a line was deleted, and the
        // two cases differ in a way that matters: a parameter still holding the
        // value is the common outcome, because something else on the host is
        // usually also asking for it. Reporting "removed" flat would be true
        // about the file and false about the machine.
        Msg::TaskSysctlUnset { key, holding } => match holding {
            SysctlHolding::Yes => format!(
                "{key} is no longer declared here, and still holds its value — \
                 something else on this host is setting it"
            ),
            SysctlHolding::No => format!("{key} is no longer declared here"),
            // Says what was done and what could not be checked, rather than
            // borrowing either of the answers above. The declaration is gone
            // either way; what is unknown is what the kernel does now.
            SysctlHolding::Unknown => format!(
                "{key} is no longer declared here — whether the kernel still \
                 holds its value could not be read back"
            ),
        },
        Msg::TaskSysctlSet { key, value } => format!("{key} = {value}, now and after a reboot"),

        Msg::TaskCaddyValidating { path } => format!("Validating {path}..."),
        Msg::TaskCaddyParses { path } => format!("{path} parses"),
        Msg::TaskCaddySnippetDefined => "the snippet is already defined".to_owned(),
        Msg::TaskCaddySnippetWritten { name, path } => format!("{name} is defined in {path}"),
        Msg::TaskCaddyNoUnit => {
            "no service was enabled: this family has no Caddy package, so there \
             is no unit to enable and nothing here invents one"
                .to_owned()
        }
        Msg::TaskCaddyInstalledAt { version } => {
            format!("caddy {version} is installed at /usr/local/bin")
        }
        Msg::TaskLingerEnabled { user } => {
            format!("{user} may now keep services running between logins")
        }

        Msg::TaskFishInstalledAt { path } => format!("fish is installed at {path}"),
        Msg::TaskFishNotForRoot => "never make it root's shell: a shell that is not POSIX breaks \
             recovery scripts that assume one"
            .to_owned(),
        Msg::TaskMiseUseShims => {
            "on a server, reach it through shims or `mise exec --` rather than \
             shell activation"
                .to_owned()
        }
        // The home is read from passwd rather than assumed: `/home/<user>` is a
        // convention this project already refuses to rely on elsewhere, and a
        // hint naming the wrong directory is worse than none.
        // Measured rather than paraphrased: git 2.47.3 exits 128 with
        // `*** Please tell me who you are.` A freshly installed git is not a
        // working git, and the row that installed it should say so.
        Msg::TaskGitNeedsIdentity => {
            "git will refuse to commit until an account has a name and an email \
             — set them with git.identity"
                .to_owned()
        }
        // States what was written and what is missing, in that order: the
        // setting is real and will be read, and the reason nothing happens yet
        // is that there is nothing to read it.
        Msg::TaskGitNotInstalledYet => {
            "git is not installed on this host, so nothing reads this yet — \
             run git.install"
                .to_owned()
        }
        // The headless flow, named exactly, because the default one cannot work
        // here: `gh auth login` without arguments wants a browser. Upstream
        // documents `--with-token` and the environment variables as "most
        // suitable for headless use", which is what a server is.
        Msg::TaskGithubCliNeedsToken => {
            "gh does almost nothing until it has a token. On a server there is \
             no browser, so authenticate as the account that will use it: \
             `gh auth login --with-token < token.txt`, or set GH_TOKEN. \
             Minimum scopes are repo, read:org and gist"
                .to_owned()
        }
        Msg::TaskGitIdentitySet { user, email } => {
            format!("{user} commits as {email}")
        }
        Msg::TaskGitDirectoryTrusted { path } => {
            format!("{path} is trusted system-wide; git will read it whoever owns it")
        }
        Msg::TaskGitDefaultBranchSet { branch } => {
            format!("new repositories start on {branch}")
        }
        Msg::TaskRustPathHint { home } => format!(
            "the toolchain is in {home}/.cargo/bin, which no shell has been \
             told about — add it to PATH in that account's own profile, or run \
             `. \"{home}/.cargo/env\"`"
        ),
        // Says what went with it, because it is more than the operator asked
        // for and they should hear it from the tool rather than discover it.
        // `rustup self uninstall` prints "removing rustup home" and "removing
        // cargo home" and means both — measured on `debian:13`, where the two
        // directories are gone afterwards. There is no flag that spares them.
        Msg::TaskRustManagerRemoved { user } => format!(
            "removed rustup for {user}, and with it that account's ~/.rustup \
             and ~/.cargo — rustup's own uninstaller takes the toolchains it \
             installed, and offers no way to keep them"
        ),
        Msg::TaskRustAvailableTo { user } => format!("rust is available to {user}"),
        Msg::TaskToolchainInstalled { tool, user } => format!("{tool} is installed for {user}"),

        Msg::TaskWatchingForFailures { service } => {
            format!("watching {service} for repeated failures")
        }
        Msg::TaskUpgradesNoReboot => "reboots stay yours to schedule".to_owned(),
        Msg::TaskServiceRunning { service } => format!("{service} is running"),

        Msg::TaskCrowdsecDetectsOnly => {
            "it detects and decides; install a bouncer to make it block".to_owned()
        }
        Msg::TaskUpgradesAutomatic => "security updates will be applied automatically".to_owned(),
        Msg::TaskZellijFromDistribution => "zellij installed from the distribution".to_owned(),
        Msg::TaskZellijDownloading { version } => format!("downloading zellij {version}"),
        Msg::TaskZellijVerified => "zellij installed and its checksum verified".to_owned(),
        Msg::TaskCaddyPorts { http, https } => {
            format!("it will answer on {http} and {https} once the firewall admits them")
        }
        Msg::TaskCaddyImportHint { name } => {
            format!("add `import {name}` to a site block to apply it")
        }
        Msg::TaskDockerInstalling { user } => format!("installing docker for {user}"),
        Msg::TaskDockerEngineInstalling => "installing the docker engine".to_owned(),
        Msg::TaskDockerFetchingInstaller => {
            "fetching the rootless installer from get.docker.com".to_owned()
        }
        Msg::TaskDockerConnectHint { user } => {
            format!("connect with DOCKER_HOST=unix:///run/user/$(id -u {user})/docker.sock")
        }
        Msg::TaskRepositoryRegistering { repository } => {
            format!("registering the {repository} repository")
        }
        Msg::TaskServiceRunningAs { service, user } => format!("{service} is running as {user}"),

        Msg::TaskWireguardNotConfigured => "WireGuard is not configured".to_owned(),
        Msg::TaskWireguardUp { interface } => format!("{interface} is up"),
        Msg::TaskWireguardDown { interface } => format!("{interface} is configured but down"),
        Msg::TaskWireguardInstallingTools => "installing wireguard-tools".to_owned(),
        Msg::TaskWireguardGeneratingKeys => "generating the server keys".to_owned(),
        Msg::TaskWireguardWrote { path } => format!("wrote {path}"),
        Msg::TaskWireguardServerKey { key } => format!("server public key: {key}"),
        Msg::TaskWireguardPeerAdded { name, address } => format!("{name} added at {address}"),
        Msg::TaskWireguardPeerCount { count } => format!("{count} peer(s) configured"),
        Msg::TaskWireguardInterface { interface, address } => {
            format!("{interface} is at {address}")
        }
    }
}

/// What an account authenticates with, as one phrase.
///
/// Inside this module rather than in the catalogue because it *is* English: the
/// conjunction joining two credentials is a word, and a language that joins
/// them differently renders this its own way. Both are named when both hold
/// rather than reporting the first found — "holds a key" and "has a password"
/// send an operator to different places if locking root turns out to have been
/// the wrong call.
///
/// Called only where at least one holds, which is what makes the last arm
/// unreachable in practice; it answers anyway rather than panicking, since this
/// runs as root on somebody's server.
fn credentials(key: bool, password: bool) -> &'static str {
    match (key, password) {
        (true, true) => "key + password",
        (true, false) => "key",
        (false, true) => "password",
        (false, false) => "no credential",
    }
}
