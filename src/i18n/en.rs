//! English message catalogue — the default and fallback language.

use super::{Msg, RevertReason};

/// Renders a message in English.
///
/// Exhaustive by construction: a new [`Msg`] variant fails to compile here
/// rather than falling through to a placeholder at runtime.
pub(super) fn render(message: &Msg) -> String {
    match message {
        Msg::OsReleaseUnreadable { path, source } => {
            format!("could not read {path}: {source}")
        }
        Msg::OsReleaseMissingId { path } => {
            format!("{path} does not declare an ID field")
        }
        Msg::UnsupportedDistro { id, id_like } => {
            let like = id_like.as_deref().unwrap_or("(none)");
            format!(
                "unsupported distribution: ID={id}, ID_LIKE={like}. \
                 Supported families: debian, arch, alpine, rhel"
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
        Msg::NoFirewallFrontEnd => {
            "no inbound filtering front-end is installed on this host".to_owned()
        }
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
        // Names the group, since the usual cause is that this distribution
        // calls it something else.
        Msg::NotAnAdministrator { user, group } => {
            format!("{user} is not in {group}, so it cannot escalate once root is locked")
        }
        Msg::NoWayBackIn { user } => {
            format!(
                "{user} has neither an authorised key nor a usable password, so it \
                 cannot log in anywhere — give it one before locking root"
            )
        }
        Msg::AdminCannotBeRoot => "root cannot be the account that stays usable: it is the \
             one being locked"
            .to_owned(),
        Msg::ShellNotListed { shell } => {
            format!("{shell} is not listed in /etc/shells, so the system will refuse it")
        }
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
        Msg::ConsequenceConflictsOverBanRules { task } => {
            format!(
                "{task} also writes ban rules through the firewall; running \
                 both bans twice and unbans unpredictably"
            )
        }
        // Says plainly that this one cannot be checked from here. An
        // administrator who opens a port locally and still cannot reach it has
        // usually hit exactly this, and the tool has no way to see it.
        Msg::ConsequenceProviderFirewall { port, protocol } => {
            format!(
                "check your hosting provider's firewall allows {port}/{protocol} \
                 — this tool cannot see it"
            )
        }
        Msg::ConsequenceDnsMustResolve => {
            "the name must resolve to this host before a certificate can be \
             issued — this tool cannot see it"
                .to_owned()
        }
        Msg::Terminal { source } => {
            format!("terminal error: {source}")
        }

        // --- Interface: status pills ---
        //
        // Upper case because the pill is a fixed-width badge read at a glance
        // from the left edge, not a sentence. A translation should keep them
        // short for the same reason: the pill's cells are budgeted by the
        // longest word here.
        Msg::PillReady => "READY".to_owned(),
        Msg::PillRunning => "RUNNING".to_owned(),
        Msg::PillDone => "DONE".to_owned(),
        Msg::PillFailed => "FAILED".to_owned(),
        Msg::PillCancelled => "CANCELLED".to_owned(),
        Msg::PillVerify => "VERIFY".to_owned(),
        Msg::PillConfirm => "CONFIRM".to_owned(),
        Msg::PillInput => "INPUT".to_owned(),
        Msg::PillUnsupported => "UNSUPPORTED".to_owned(),

        // --- Interface: help ---
        Msg::HelpTitle => " Keys ".to_owned(),
        Msg::HelpSectionAnywhere => "Anywhere".to_owned(),
        Msg::HelpSectionTree => "Task tree".to_owned(),
        Msg::HelpSectionSearch => "Search".to_owned(),
        Msg::HelpSectionRunning => "While a task runs".to_owned(),
        Msg::HelpSectionOutput => "Output".to_owned(),
        Msg::HelpSectionForms => "Forms".to_owned(),
        Msg::HelpSectionConfirmation => "Confirmation".to_owned(),
        Msg::HelpSectionLockout => "After a change that could lock you out".to_owned(),
        Msg::HelpMoveFocus => "move focus between the tree and the output".to_owned(),
        Msg::HelpThisHelp => "this help".to_owned(),
        Msg::HelpQuit => "quit".to_owned(),
        Msg::HelpPreviousRow => "previous row".to_owned(),
        Msg::HelpNextRow => "next row".to_owned(),
        Msg::HelpFirstLastRow => "first / last row".to_owned(),
        Msg::HelpOpenOrRun => "open a category, or run a task".to_owned(),
        Msg::HelpFind => "find a task anywhere in the tree".to_owned(),
        Msg::HelpBack => "back to the parent level".to_owned(),
        Msg::HelpFilter => "filter by title or task id".to_owned(),
        Msg::HelpBetweenResults => "move between results".to_owned(),
        Msg::HelpGoToTask => "go to the task, without running it".to_owned(),
        Msg::HelpCloseSearch => "close, leaving the cursor where it was".to_owned(),
        Msg::HelpStopAfterCommand => "stop after the current command".to_owned(),
        Msg::HelpScrollOutput => "scroll the output".to_owned(),
        Msg::HelpFocusOutput => "move focus to the output".to_owned(),
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

        // --- Interface: output ---
        Msg::OutputTitle => "output".to_owned(),
        // A pane that has silently stopped updating and one that is following a
        // quiet command look identical, so the title says which it is.
        Msg::OutputFollowing => "follow".to_owned(),
        Msg::OutputDetached => "detached".to_owned(),

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
        Msg::FormKeyList => " list   ".to_owned(),
        Msg::FormOptionsTitle { label } => format!(" {label} on this host "),
        Msg::FormOptionsChoose => " choose   ".to_owned(),
        Msg::FormKeyField => " field   ".to_owned(),
        Msg::FormKeyContinue => " continue   ".to_owned(),
        // Parenthesised because it stands where `continue` stands: it names
        // what is missing rather than announcing a refusal, which is what an
        // operator who has just pressed Enter is looking for.
        Msg::FormKeyIncomplete => " (fill every field)   ".to_owned(),
        Msg::FormKeyCancel => " cancel".to_owned(),

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
        // The `?` is the key to press, so it leads: the hint is read as an
        // instruction rather than as a label for a key named elsewhere.
        Msg::HeaderHelpHint => "? help".to_owned(),

        // --- Interface: detail pane ---
        //
        // Both sit under the task's own description, separated from it by a
        // blank line the call site writes: the description is the task's
        // words, and running the two together would read as one sentence.
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
        Msg::VerifyKeepKey => " keep   ".to_owned(),
        Msg::VerifyRevertKey => " revert now".to_owned(),
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
        Msg::KeyBarBack => "back".to_owned(),
        Msg::KeyBarOutput => "output".to_owned(),
        Msg::KeyBarStop => "stop".to_owned(),
        Msg::KeyBarScroll => "scroll".to_owned(),
        Msg::KeyBarCopy => "copy".to_owned(),
        Msg::KeyBarKeys => "keys".to_owned(),
        Msg::KeyBarKeep => "keep".to_owned(),
        Msg::KeyBarRevert => "revert".to_owned(),
        Msg::KeyBarGo => "go".to_owned(),
        Msg::KeyBarClose => "close".to_owned(),
        Msg::KeyBarFollow => "follow".to_owned(),
        Msg::KeyBarTree => "tree".to_owned(),
        Msg::KeyBarQuit => "quit".to_owned(),

        // --- Interface: status messages ---
        //
        // Lower case and unpunctuated: they sit beside the pill as a
        // continuation of it, not as sentences of their own.
        Msg::StatusTaskRunningQuitRefused => {
            "a task is running — Ctrl-C to stop it first".to_owned()
        }
        Msg::StatusTaskAlreadyRunning => "a task is already running".to_owned(),
        Msg::StatusAlreadyStopping => "already stopping — waiting for the current step".to_owned(),
        // The ellipsis is the point: the task has been asked and has not yet
        // finished the step it was on.
        Msg::StatusStoppingAfterCurrentStep => "stopping after the current step...".to_owned(),
        Msg::StatusAlreadyAtTopLevel => "already at the top level".to_owned(),
        // Names both keys rather than saying the key was wrong: this is the
        // one window where doing nothing has consequences.
        Msg::StatusVerifyKeysOnly => "K keeps this change, R puts it back".to_owned(),
        Msg::StatusCancelled => "cancelled".to_owned(),
        // "sent to the terminal" rather than "copied": the tool cannot see
        // whether the terminal honoured it, and a claim it cannot check is one
        // the operator learns to disbelieve.
        Msg::StatusCopied { lines } => {
            let line = if *lines == 1 { "line" } else { "lines" };
            format!("{lines} {line} sent to the terminal's clipboard")
        }
        Msg::StatusCopyFailed => "the terminal did not accept the copy".to_owned(),
        Msg::StatusNothingToCopy => "there is no output to copy".to_owned(),
        Msg::StatusPressEscAgainToDiscard => "press Esc again to discard what you typed".to_owned(),
        Msg::StatusFillEveryFieldFirst => "fill in every field first".to_owned(),
        Msg::StatusFinishedBeforeItCouldStop => {
            "the task finished before it could be stopped".to_owned()
        }
        Msg::StatusTaskNotSupported { task, family } => {
            format!("{task} is not supported on {family}")
        }
        Msg::StatusTaskFailed { task } => format!("{task} — failed"),
        // Backticks around the command, as everywhere a command is named: it
        // is something to type rather than something to read.
        Msg::StatusStoppedBefore { task, before } => {
            format!("{task} — stopped before `{before}`")
        }
        Msg::StatusAppliedNotYetKept { task } => format!("{task} — applied, not yet kept"),
        Msg::StatusKept { task } => format!("{task} — kept"),
        Msg::StatusReverted { task, reason } => {
            let why = match reason {
                RevertReason::Requested => "reverted",
                RevertReason::SessionEnded => "the session ended",
                RevertReason::NoConfirmation => "no confirmation",
            };

            format!("{task} — {why}, previous configuration restored")
        }
        Msg::StatusRevertFailed { task, error } => {
            format!("{task} — could not restore: {error}")
        }
        Msg::OutputConsequencesHeading => "Consequences:".to_owned(),

        // --- Interface: confirmation warning ---
        //
        // Two sentences: what this can cost, then what to do about it. The
        // second is the one the operator can act on.
        Msg::ConfirmLockoutWarning => "This operation can lock you out of a server you reach \
             over SSH. Make sure you have another way in before continuing."
            .to_owned(),
        Msg::ConfirmRootLockout { admin } => {
            format!(
                "root will no longer log in by any route, including the provider's \
                 rescue console. From here on this machine is administered as \
                 {admin} — check that name is right."
            )
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
        Msg::TaskEnabling { unit } => format!("Enabling {unit}..."),
        Msg::TaskUnitEnabled { unit } => format!("{unit} is enabled"),
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

        Msg::TaskUserExists { user } => format!("{user} exists"),
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
        Msg::TaskFirewallDefaultDeny => "inbound denied by default".to_owned(),
        Msg::TaskFirewallNoOpenPorts => "no ports are open".to_owned(),
        Msg::TaskFirewallPortOpen { port } => format!("  {port} is open"),
        Msg::TaskFirewallPersisted => "the rules are restored at boot".to_owned(),
        Msg::TaskFirewallNotPersisted => {
            "the rules are not restored at boot — they end at the next restart".to_owned()
        }
        Msg::TaskFirewallInstalling { front_end } => format!("installing {front_end}"),
        Msg::TaskFirewallUsing { front_end } => format!("using {front_end}"),
        Msg::TaskFirewallEnabled { port } => {
            format!("inbound denied except {port}/tcp, now and after a reboot")
        }
        Msg::TaskFirewallPortAllowed { port, protocol } => {
            format!("{port}/{protocol} is open inbound, now and after a reboot")
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
        Msg::TaskFirewallPortAllowedNotPersisted { port, protocol } => {
            format!(
                "{port}/{protocol} is open inbound — saved, but this host has no \
                 service manager to replay it at boot"
            )
        }
        Msg::TaskFirewallNotFilteringYet => {
            "nothing is being filtered yet: run firewall.enable for this to mean anything"
                .to_owned()
        }
        Msg::TaskSysctlAlready { key, value } => format!("{key} is already {value}"),
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
        Msg::TaskDockerRootlessReady { user } => {
            format!("rootless docker is running for {user}")
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
