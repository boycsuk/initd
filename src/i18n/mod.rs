//! Message catalogue and locale resolution.
//!
//! Every user-facing string in `initd` goes through this module — errors,
//! consequences, and the interface's own chrome. Nothing else embeds display
//! text, so adding a language means adding one catalogue module and one `match`
//! arm, never touching call sites.
//!
//! Two kinds of string deliberately stay out, and both are the same
//! distinction: they are not words in a language.
//!
//! - **Key glyphs and drawing symbols** — `Tab`, `↑ k`, `│`, `✓`. Translating
//!   `Tab` would describe a keyboard the operator does not have.
//! - **Task data** — ids, titles, descriptions, and the reasons a task gives
//!   for refusing a family. These belong to the task rather than to the
//!   interface; they reach the screen through `Task`, which the catalogue does
//!   not sit behind.
//!
//! The design is deliberately dependency-free. The catalogue is a closed enum
//! rendered by an exhaustive `match`, so a message that lacks a translation is
//! a compile error rather than a runtime lookup miss.
//!
//! Callers that render on every frame resolve the locale once and hold it —
//! `App` keeps a `Lang` field — rather than calling [`Lang::from_env`] per
//! message. An error reaches the catalogue rarely; a key bar is a dozen labels
//! ten times a second, which is what `POLL_INTERVAL` makes the redraw ceiling.

mod en;

use std::env;

/// A language `initd` can render messages in.
///
/// [`Lang::En`] is both the default and the fallback for unrecognised locales.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Lang {
    #[default]
    En,
}

impl Lang {
    /// Resolves the language from the environment, honouring the POSIX
    /// precedence `LC_ALL` > `LC_MESSAGES` > `LANG`.
    ///
    /// Unset, empty, or unrecognised values fall back to [`Lang::En`], so this
    /// never fails.
    pub fn from_env() -> Self {
        ["LC_ALL", "LC_MESSAGES", "LANG"]
            .iter()
            .find_map(|var| env::var(var).ok().filter(|value| !value.is_empty()))
            .map_or(Self::default(), |value| Self::from_locale(&value))
    }

    /// Parses a POSIX locale string such as `es_ES.UTF-8` or `en`.
    ///
    /// Only the language part before `_` or `.` is significant; the territory
    /// and encoding are ignored.
    fn from_locale(locale: &str) -> Self {
        let code = locale
            .split(['_', '.', '@'])
            .next()
            .unwrap_or_default()
            .to_ascii_lowercase();

        match code.as_str() {
            // "C" and "POSIX" are not real languages; they mean "no locale".
            "en" | "c" | "posix" => Self::En,
            _ => Self::default(),
        }
    }

    /// Renders a message in this language.
    pub fn render(self, message: &Msg) -> String {
        match self {
            Self::En => en::render(message),
        }
    }
}

/// A user-facing message, as structured data rather than text.
///
/// Variants carry the values to interpolate; the wording lives in the
/// per-language catalogues.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Msg {
    // --- Distro detection ---
    OsReleaseUnreadable {
        path: String,
        source: String,
    },
    OsReleaseMissingId {
        path: String,
    },
    UnsupportedDistro {
        id: String,
        id_like: Option<String>,
    },

    RepositoryKeyMismatch {
        repository: String,
        expected: String,
        found: String,
    },
    RepositoryKeyUnverifiable {
        repository: String,
    },
    RepositoryUnknownSuite {
        repository: String,
    },
    PathNotAbsolute {
        path: String,
    },

    NoFirewallFrontEnd,

    // --- Command execution ---
    ProgramNotFound {
        program: String,
    },
    CommandFailed {
        command: String,
        code: i32,
        stderr: String,
    },
    CommandTerminatedBySignal {
        command: String,
    },
    CommandSilent {
        command: String,
        seconds: u64,
    },
    CommandIo {
        command: String,
        source: String,
    },

    Cancelled {
        before: String,
    },

    // --- Privileges ---
    NoPrivilegeEscalator,
    AuthenticationRefused {
        mechanism: String,
    },
    AuthenticationUnavailable {
        mechanism: String,
    },
    /// Written to the output pane just before the terminal is handed over, so
    /// the gap the prompt leaves in the transcript is explained.
    AuthenticationRequested {
        mechanism: String,
    },
    AuthenticationGranted,

    // --- SSH ---
    InvalidSshdConfig {
        details: String,
    },
    InvalidPublicKey {
        reason: String,
    },
    InvalidPort {
        port: u32,
    },
    InvalidAllowUsers {
        reason: String,
    },
    LockoutNoKeyForRoot,
    LockoutUnknownUser {
        user: String,
    },
    LockoutNoKeyForAllowedUsers {
        users: String,
    },
    MissingParameter {
        name: String,
    },
    TaskVanished {
        task: String,
    },
    MissingGroup {
        group: String,
    },
    UnknownSysctl {
        key: String,
    },
    InvalidWireguardKey {
        reason: String,
    },
    WireguardAlreadyConfigured {
        path: String,
    },
    WireguardNotConfigured,
    NoSubordinateIds {
        user: String,
    },
    NoUserSession {
        user: String,
    },
    InvalidCaddyfile {
        details: String,
    },
    CapabilityUnavailable {
        capability: String,
    },
    TimerNotEnabled {
        timer: String,
    },
    ChecksumMismatch {
        program: String,
        version: String,
    },
    UnknownRelease {
        version: String,
        known: String,
    },
    UnsupportedArchitecture {
        program: String,
        version: String,
        arch: String,
    },
    ServiceDidNotStart {
        service: String,
        user: String,
    },
    WireguardAddressTaken {
        address: String,
    },
    InvalidSubnet {
        subnet: String,
    },
    AccountExists {
        user: String,
    },
    NoSuchAccount {
        user: String,
    },
    UnsafeSymlink {
        path: String,
    },
    GroupMembershipFailed {
        user: String,
        group: String,
    },
    NoWayBackIn {
        examined: usize,
    },
    CannotDeleteRoot,
    CannotDeleteOwnAccount {
        user: String,
    },
    FileChangedSinceBackup {
        path: String,
        expected: String,
        found: String,
    },
    BackupCorrupt {
        copy: String,
    },
    RevertUnverifiable {
        path: String,
    },
    ShellNotListed {
        shell: String,
    },

    // --- Tasks ---
    TaskUnsupported {
        task: String,
        family: String,
    },

    // --- Consequences ---
    ConsequencePortChanged {
        task: String,
        from: String,
        to: String,
    },
    ConsequenceRequiresSetting {
        task: String,
        setting: String,
    },
    ConsequenceNeedsRestart {
        task: String,
        service: String,
    },
    ConsequenceAccountNotListed {
        task: String,
        user: String,
    },
    ConsequenceAccountRemoved {
        task: String,
        user: String,
    },
    ConsequenceConflictsOverBanRules {
        task: String,
    },
    ConsequenceProviderFirewall {
        port: String,
        protocol: String,
    },
    ConsequenceDnsMustResolve,

    // --- Terminal ---
    Terminal {
        source: String,
    },

    // --- Interface: help ---
    //
    // Section titles and the description beside each key. The key glyphs
    // themselves stay literals: `Tab` and `↑ k` name keys on a keyboard rather
    // than words in a language, and translating them would describe a keyboard
    // the operator does not have.
    HelpTitle,
    HelpSectionAnywhere,
    HelpSectionTree,
    HelpSectionSearch,
    HelpSectionRunning,
    HelpSectionOutput,
    HelpSectionForms,
    HelpSectionConfirmation,
    HelpSectionLockout,
    HelpMoveFocus,
    HelpRedraw,
    HelpThisHelp,
    HelpQuit,
    HelpPreviousRow,
    HelpNextRow,
    HelpFirstLastRow,
    HelpOpenOrRun,
    HelpFind,
    HelpHistory,
    HelpBack,
    HelpFilter,
    HelpBetweenResults,
    HelpGoToTask,
    HelpCloseSearch,
    HelpStopAfterCommand,
    HelpScrollOutput,
    HelpFocusOutput,
    HelpScrollLine,
    HelpScrollPage,
    HelpOldestLine,
    HelpNewestLine,
    /// What `y` does in the output pane, in the help overlay.
    HelpCopy,
    HelpNextField,
    HelpNextFieldOrSubmit,
    /// What `↑↓` do in a field the host can offer values for.
    HelpStepOptions,
    /// What the key that opens the full list of those values does.
    HelpListOptions,
    HelpFieldEnds,
    HelpClearAround,
    HelpDeleteWord,
    HelpCancelForm,
    HelpApply,
    HelpCancel,
    HelpBetweenAnswers,
    HelpKeep,
    HelpRevert,
    HelpAutoRevert,
    HelpTypeGlyph,
    HelpWaitGlyph,
    HelpMoreBelow {
        percent: u16,
    },
    HelpAnyKeyCloses,

    // --- Interface: confirm ---
    //
    // The two answers and the line telling the operator how to give one. The
    // answers carry their own padding in the catalogue rather than at the call
    // site: they are drawn as highlighted badges, and a translation whose word
    // needs different spacing to sit inside one has no way to say so from here.
    ConfirmYes,
    ConfirmNo,
    ConfirmKeyHint,
    /// Appended to the hint above where the warning has rows below the fold.
    ///
    /// Shown only when scrolling moves something, which today is one dialog:
    /// `users.lock-root` lists every account that keeps access, and a host with
    /// a dozen administrators has more than the band can hold. A hint for a key
    /// that does nothing is how a bar stops being read.
    ConfirmScrollHint,

    // --- Interface: output ---
    //
    // The pane's title, payload-free: it names one pane.
    OutputTitle,

    // --- Interface: forms ---
    //
    // The dialog's own chrome. What a field is called, what it currently holds
    // and what is wrong with it all come from the task's `Param`, so none of
    // that is here: those are the task's data, and a form that renamed them
    // would be describing a different task.
    /// Which of several fields the cursor is on. Carries both numbers rather
    /// than a rendered `2 of 3`, since a language that words the pair
    /// differently — or orders it the other way — cannot say so from the call
    /// site.
    FormFieldCounter {
        index: usize,
        total: usize,
    },
    /// How many values the host offers for a field, and which one is on
    /// screen.
    ///
    /// `position` is `None` where the value is not one of them — typed by
    /// hand, or not yet typed at all — so the count is still offered without
    /// claiming the field is sitting on an option it is not. Carries the
    /// numbers rather than a rendered `2/6` for the same reason as
    /// [`Msg::FormFieldCounter`].
    FormOptionCount {
        position: Option<usize>,
        total: usize,
    },
    /// A field that is empty and may stay that way.
    ///
    /// The only verdict still spelled out for a value that passes. A field
    /// holding something acceptable is marked `✓` and says nothing, because
    /// words there were the bulk of the small text scattered across the
    /// dialog; an empty optional field has no value to mark, and silence over
    /// one reads as "not reached yet" rather than "nothing needed here".
    FormFieldOptional,
    /// Stands in for the value of an empty optional field.
    ///
    /// A blank space says the operator has not got there yet. Naming the state
    /// says the field is answered by leaving it alone — which is what stops an
    /// untouched field from looking unfinished, without the green that would
    /// make it look completed.
    FormFieldUnset,
    /// What the key that opens the full list of options does.
    FormKeyList,
    /// Title of the overlay listing everything the host offers for a field.
    FormOptionsTitle {
        label: String,
    },
    /// What `Enter` does in the options overlay.
    FormOptionsChoose,
    FormKeyField,
    /// What `Enter` does once every field would be accepted.
    FormKeyContinue,
    /// What `Enter` does while a field would still be rejected. Stated as the
    /// remedy rather than as a refusal: it sits where `continue` sits, and the
    /// operator reading it is looking for what to do next.
    FormKeyIncomplete,
    FormKeyCancel,

    // --- Interface: search ---
    //
    // The chrome around the query. The query itself is never rendered through
    // the catalogue: it is what the operator typed, and translating it would
    // change what they are searching for.
    SearchTitle {
        query: String,
    },
    /// Said rather than left to be inferred from an empty list: "no matches"
    /// and "the tree is empty" look alike otherwise.
    SearchNoMatches,
    /// Position in the results, with the keys that act on them. `total` is
    /// carried so the language can agree its own plural — English does not
    /// here, but a catalogue that only received the rendered pair could not
    /// start.
    SearchFooter {
        position: usize,
        total: usize,
    },

    // --- Interface: header ---
    //
    // The one-line band naming the tool and the machine. The hostname, the
    // distribution's display name and the version are interpolated
    // untranslated: they are what the machine calls itself, and a header that
    // renamed them would be describing a different host.
    /// The tool's own name, leading the header. Carries its leading space
    /// because it is the first span on the row and nothing else insets it.
    HeaderTitle,
    /// Which pane is showing, on a terminal narrow enough that only one fits.
    /// Two variants rather than one with a payload: they are drawn as separate
    /// spans so the showing one can be emphasised, and a single rendered pair
    /// could not be styled apart.
    HeaderPaneTree,
    HeaderPaneOutput,
    /// How root is obtained, stated in the header rather than when a task
    /// fails: "this will need a password" is worth knowing before starting.
    HeaderPrivilege {
        mechanism: String,
    },
    /// The right-aligned hint pointing at the help overlay. Carries its key
    /// glyph, unlike the key bar's labels, because it is drawn as one span
    /// rather than as a glyph and a label styled apart — and it is measured
    /// before it is drawn, so the width has to include the glyph.
    HeaderHelpHint,

    // --- Interface: detail pane ---
    //
    // What the selected row would do, before anything has run. A task's title
    // and description are the task's own data and never come from here; only
    // the sentences the pane wraps around them do.
    /// Why a task the host cannot run is refused. The reason is the task's,
    /// measured per family, and is interpolated as written.
    DetailUnsupported {
        family: String,
        reason: String,
    },
    /// What a category holds, since a category has no description of its own.
    /// `count` is carried rather than a rendered `3 tasks`, so the language
    /// agrees its own plural.
    DetailCategoryContents {
        title: String,
        count: usize,
    },
    /// The pane's title where the cursor is on a category, which lends no
    /// title of its own.
    DetailTitle,

    // --- Interface: tree census ---
    //
    // What the level on screen holds, riding the tree's bottom border. Two
    // messages rather than one joined line: which of the two appears depends
    // on what the level contains, and a language that joins them differently
    // resolves that where the parts are still separate.
    CensusCategories {
        count: usize,
    },
    CensusTasks {
        count: usize,
    },

    // --- Interface: verification banner ---
    //
    // The highest-risk copy in the interface: it stands over a change that can
    // sever the administrator's own connection, and what it promises is what
    // decides whether they trust the countdown.
    //
    // Three things are said in order, and a translation must keep the order:
    // that the change is applied but *not* permanent, how long is left, and
    // what to press. Anything that reads as "done" belongs to `keep`, never
    // here — a banner that sounds settled is one nobody answers.
    /// The banner's own badge. Padded because it is drawn as a highlighted
    /// pill like the status one, and the spaces are the pill's inside edge.
    VerifyBadge,
    /// Split from `VerifyNotYetKept` rather than one sentence: the second half
    /// is emphasised and the first is not, and a single span could not be.
    VerifyApplied,
    /// The half that carries the meaning, which is why it is the emphasised
    /// one. A translation must not soften it into "pending" or "awaiting
    /// confirmation": the operative fact is that this will be undone.
    VerifyNotYetKept,
    /// Precedes the countdown, which is styled as danger because it is the one
    /// number on screen that acts on its own. Reads as a statement of what
    /// will happen, not as an offer.
    VerifyRevertingIn,
    /// The two keys' labels, padded to sit against their key glyph. `K` and
    /// `R` themselves are keys on a keyboard and stay literal.
    VerifyKeepKey,
    VerifyRevertKey,
    /// The instruction that matters, over two lines because it is wrapped by
    /// hand to the banner's width. The tool cannot check this itself, so the
    /// one thing the administrator must actually do is stated outright rather
    /// than implied by the countdown — a window that only counts down does not
    /// tell anyone what to do with the time.
    VerifyCheckSecondSessionLine1,
    VerifyCheckSecondSessionLine2,
    /// The limit of the promise, said rather than left implied. A dropped
    /// connection and an ordinary kill both revert, because those signals are
    /// caught; `SIGKILL` and a power cut run no code at all, so the change
    /// would stay. Stating that is what makes the line above trustworthy — a
    /// promise with a silent exception teaches people to disbelieve the whole
    /// banner, which costs the warnings beside it too. A translation that
    /// drops this line breaks the banner rather than shortening it.
    VerifySessionScopeCaveat,

    // --- Interface: key bar ---
    //
    // The labels beside each key glyph along the bottom row. The glyphs
    // themselves — `↑↓`, `Enter`, `Esc`, `Tab`, `Ctrl-C`, `?`, `K`, `R`, `G`,
    // `y`, `q`, `/` — stay literals for the same reason the help overlay's do:
    // they name keys on a keyboard rather than words in a language.
    //
    // Each label is a verb naming what the key does *here*, so `KeyBarOpen`
    // and `KeyBarRun` are separate messages even though one key produces both:
    // `Enter` opens a category and runs a task, and which it is has to be said.
    KeyBarOpen,
    KeyBarRun,
    KeyBarMove,
    KeyBarFind,
    /// What `H` opens from the tree.
    ///
    /// A noun where its neighbours are verbs, because the key opens a view
    /// rather than acting: "restore" is what `Enter` does once inside, and
    /// promising it here would name an action this key does not perform.
    KeyBarHistory,
    KeyBarBack,
    KeyBarOutput,
    KeyBarStop,
    KeyBarScroll,
    /// What `y` does in the output pane.
    KeyBarCopy,
    KeyBarKeys,
    KeyBarKeep,
    KeyBarRevert,
    KeyBarGo,
    KeyBarRestore,
    KeyBarClose,
    KeyBarFollow,
    KeyBarTree,
    KeyBarQuit,

    // --- Interface: status messages ---
    //
    // What the interface says about a task's own progress. Task ids and command
    // names are interpolated as written: they are what the operator would type
    // or search for, and translating them would name something that does not
    // exist.
    /// The copy sequence could not be written to the terminal at all.
    StatusCopyFailed,
    /// Said out loud rather than silently dropped: the operator pressed a key
    /// and is owed an answer, even when the answer is that it arrived late.
    StatusFinishedBeforeItCouldStop,
    /// Heads the consequences a finished task declared, written into the
    /// output pane where there is room to read them.
    OutputConsequencesHeading,
    /// Heads the failure block in the output pane, naming the task that failed.
    ///
    /// The pane is where a failure is read, so the heading carries the task id
    /// that used to sit on the border: a transcript scrolled back to hours
    /// later has to say which task the block below it belongs to, and the
    /// border says nothing about a task that is no longer the current one.
    OutputFailedHeading {
        task: String,
    },
    /// Heads the same block for a task that was stopped rather than one that
    /// broke. Distinct from [`Msg::OutputFailedHeading`] because the two call
    /// for different actions: a cancelled task is re-run, a failed one is
    /// diagnosed first.
    OutputCancelledHeading {
        task: String,
    },
    /// Heads the block for a revert that itself failed.
    ///
    /// Distinct from a failed task because the machine is in neither state —
    /// the change was applied and putting it back did not work — which is a
    /// worse position than a task that simply did not run.
    OutputRevertFailedHeading {
        task: String,
    },
    /// One field of a structured error, as a label and its value.
    ///
    /// The label is a word from the catalogue and the value is data the error
    /// carried, which is why they are rendered together here rather than
    /// concatenated at the call site: a language that puts the label after the
    /// value has nowhere else to say so.
    OutputErrorField {
        label: ErrorField,
        value: String,
    },

    // --- Interface: confirmation warning ---
    //
    /// The lockout warning on a destructive task's confirmation. Names the
    /// remedy — have another way in — rather than only the risk, because by
    /// the time this is on screen the operator has already decided to proceed
    /// and the useful sentence is the one they can act on.
    ConfirmLockoutWarning,
    /// The lockout warning for `users.lock-root`, heading the accounts that
    /// keep access.
    ///
    /// Separate from the generic one because this is the only task that has
    /// something to *show*: the host was scanned, and the operator's decision
    /// is whether their own account is among what the scan found. It named a
    /// single account while the task asked for one — an echo of what had just
    /// been typed. Nothing is typed now, so what follows this sentence is the
    /// list, and the count is in it because "3 accounts keep access" and "1
    /// account keeps access" are different decisions.
    ConfirmRootLockout {
        keeping: usize,
    },
    /// One line of that list: an account, and what it gets in with.
    ///
    /// Rendered per account rather than joined into the sentence above, because
    /// the dialog scrolls them — a paragraph cannot be scrolled a line at a
    /// time, and hiding one of these is hiding the reason the operator is
    /// about to say yes.
    ConfirmKeepsAccess {
        user: String,
        key: bool,
        password: bool,
    },
    /// About to delete an account and the directory it owns.
    ///
    /// Carries the measured size because that is what makes the question
    /// answerable. "Also delete the home directory?" is answered by habit;
    /// "delete /home/deploy (2.4 GB)" is read.
    ConfirmDeleteHome {
        user: String,
        path: String,
        size: String,
    },
    /// About to delete an account, leaving the directory it owns.
    ConfirmKeepHome {
        user: String,
        path: String,
    },
    /// About to delete an account whose home could not be measured.
    ///
    /// Distinct from a size of zero. A directory nobody could read and one that
    /// is genuinely empty are different facts, and "(0 B)" would understate the
    /// stake by exactly the amount that matters.
    ConfirmDeleteHomeUnmeasured {
        user: String,
        path: String,
    },

    // --- Interface: terminal too small ---
    //
    /// A stated requirement rather than a partial interface: a garbled layout
    /// on a production server is worse than a clear refusal, so both the
    /// minimum and the actual size are given and the operator can see by how
    /// much the window must grow.
    TerminalTooSmall {
        min_width: u16,
        min_height: u16,
        width: u16,
        height: u16,
    },

    // What the tasks say as they work. These reach the same output pane as the
    // errors above and were English literals in the task modules until now, so
    // a second language would have translated the headings around them and
    // left the narration itself untouched.
    //
    // The generic ones come first: "installing X" is the same sentence
    // whichever task says it, and a variant per task would be thirty-nine
    // spellings of one string to keep in step.
    /// A package or program is being installed.
    TaskInstalling {
        what: String,
    },
    /// A package or program was already there.
    TaskAlreadyInstalled {
        what: String,
    },
    /// A package or program is being removed, keeping its configuration.
    TaskRemoving {
        what: String,
    },
    /// A package is being removed along with its configuration.
    TaskPurging {
        what: String,
    },
    /// Purging was asked for on a family that cannot do it.
    TaskPurgeUnavailable,
    /// A depth was asked for on a host where the capability is not a package.
    ///
    /// Distinct from [`TaskPurgeUnavailable`](Self::TaskPurgeUnavailable),
    /// which is about a package manager that cannot purge. Here there is no
    /// package at all: the undo deletes the binary this tool installed, and
    /// neither depth means anything. The interface no longer asks, so this is
    /// for the CLI, where the argument is still accepted — a script written
    /// against a host that packages this should not quietly mean something
    /// else on one that does not.
    TaskDepthNotApplicable {
        what: String,
    },
    /// There was nothing here to remove.
    TaskNotInstalled {
        what: String,
    },
    /// The program is present, but not where this tool installs one.
    ///
    /// Carries the path because "installed elsewhere" without saying where
    /// sends the operator looking for something already located.
    TaskInstalledElsewhere {
        what: String,
        at: String,
    },
    /// A unit is being stopped and disabled.
    TaskDisabling {
        unit: String,
    },
    /// A binary this tool installed has been deleted.
    TaskBinaryRemoved {
        path: String,
    },
    /// Title of the history overlay, carrying how much it holds.
    HistoryTitle {
        count: usize,
    },
    /// Nothing has been recorded on this host.
    HistoryEmpty,
    /// A recorded state was put back.
    HistoryRestored {
        path: String,
    },
    /// Heading of the confirmation before a recorded state is put back.
    ConfirmRestoreTitle {
        path: String,
    },
    /// What restoring the selected record would do.
    ConfirmRestoreBody {
        task: String,
        path: String,
    },
    /// The previous contents were copied aside and written down.
    TaskChangeRecorded,
    /// Nothing could be recorded, so no later revert will be offered.
    TaskChangeNotRecorded,
    /// A deleted account's home directory was left on disk.
    TaskHomeKept {
        path: String,
    },
    /// A deleted account's home directory went with it.
    TaskHomeDeleted {
        path: String,
    },
    /// A unit is being enabled and started.
    TaskEnabling {
        unit: String,
    },
    /// A unit is enabled.
    TaskUnitEnabled {
        unit: String,
    },
    /// A unit's state, as the host reports it.
    TaskUnitState {
        unit: String,
        active: bool,
        enabled: bool,
    },
    /// The task found the machine already in the state it exists to reach.
    TaskNothingToDo {
        what: String,
    },

    // Accounts.
    //
    /// `users.lock-root` has begun asking the host who can still get in.
    ///
    /// Said before the scan rather than after it, because the scan is a
    /// privileged command per account — 17 on a stock `debian:13` — and a pane
    /// that went quiet for them reads as a tool that has hung.
    TaskScanningAccounts,
    /// One account that keeps access, and what it authenticates with.
    ///
    /// Both credentials in one line rather than a line each: this reaches a
    /// list the operator scans for their own name, and one account occupying
    /// two rows is one that pushes another off the bottom.
    TaskAccountKeepsAccess {
        user: String,
        key: bool,
        password: bool,
    },
    /// One account that does not keep access, because it cannot escalate.
    TaskAccountNotAnAdministrator {
        user: String,
        group: String,
    },
    /// One account in the administrative group that still cannot escalate.
    ///
    /// The reason this is its own line rather than folded into the one above:
    /// it describes a decision the distribution made — openSUSE ships `%wheel`
    /// commented out — and no amount of `usermod` addresses it. What the
    /// operator needs is the file and the line to uncomment.
    TaskAccountGroupGrantsNothing {
        user: String,
        group: String,
    },
    /// One account that can escalate and holds no credential at all.
    TaskAccountCannotAuthenticate {
        user: String,
    },
    /// Nothing said who escalated into this session, so nothing is marked.
    ///
    /// A warning rather than a refusal, and the distinction is the whole of it:
    /// no command answers who a `sudo` process was started by — `whoami`,
    /// `id -un` and `logname` all describe the process, which by then is root —
    /// and the environment variables that do answer are set by the subject
    /// itself. Refusing on a question that cannot be answered would leave the
    /// provider's rescue console, which arrives as root directly, unable to run
    /// the one task it exists for.
    ConfirmSessionAccountUnknown,
    TaskCreatingUser {
        user: String,
    },
    TaskUserCreated {
        user: String,
    },
    TaskAddingToGroup {
        user: String,
        group: String,
    },
    TaskUserInGroup {
        user: String,
        group: String,
    },
    TaskSettingShell {
        user: String,
        shell: String,
    },
    TaskShellSet {
        user: String,
        shell: String,
    },
    TaskRootAlreadyLocked,
    TaskLockingRoot,
    TaskRootLocked {
        admin: String,
    },
    TaskUserHasPassword {
        user: String,
    },
    TaskUserHoldsKey {
        user: String,
    },

    // SSH.
    TaskSshKeyAlreadyAuthorised,
    TaskSshAddingKey {
        path: String,
    },
    TaskSshKeyAuthorised,
    TaskSshPortUnchanged {
        port: String,
    },
    TaskSshChangingPort {
        from: String,
        to: String,
    },
    TaskSshBackupSaved {
        path: String,
    },
    TaskSshLabellingPort {
        port: u32,
    },
    TaskSshPortSet {
        port: u32,
    },
    TaskSshReloading {
        unit: String,
    },
    TaskSshApplyingDirectives {
        count: usize,
    },
    TaskSshNarrowingAlgorithms,
    TaskSshAlgorithmClass {
        directive: String,
        value: String,
    },
    TaskSshAlgorithmsNarrowed {
        count: usize,
    },
    TaskSshHardening,
    TaskSshHardened {
        tier: String,
    },
    TaskSshAllowingUsers {
        users: String,
    },
    TaskSshUsersAllowed {
        users: String,
    },

    // Firewall and kernel parameters.
    TaskFirewallNoneInstalled {
        tried: String,
    },
    TaskFirewallInactive,
    TaskFirewallDefaultDeny,
    TaskFirewallNoOpenPorts,
    TaskFirewallPortOpen {
        port: String,
    },
    TaskFirewallPersisted,
    TaskFirewallNotPersisted,
    TaskFirewallInstalling {
        front_end: String,
    },
    TaskFirewallUsing {
        front_end: String,
    },
    TaskFirewallEnabled {
        port: u32,
    },
    TaskFirewallPortAllowed {
        port: u32,
        protocol: String,
    },
    TaskFirewallEnabledNotPersisted {
        port: u32,
    },
    TaskFirewallPortAllowedNotPersisted {
        port: u32,
        protocol: String,
    },
    TaskFirewallNotFilteringYet,
    TaskSysctlAlready {
        key: String,
        value: String,
    },
    TaskSysctlSet {
        key: String,
        value: String,
    },

    // Services and the web server.
    TaskCaddyValidating {
        path: String,
    },
    TaskCaddyParses {
        path: String,
    },
    TaskCaddySnippetDefined,
    TaskCaddySnippetWritten {
        name: String,
        path: String,
    },
    TaskCaddyNoUnit,
    TaskCaddyInstalledAt {
        version: String,
    },
    TaskDockerRootlessReady {
        user: String,
    },
    TaskLingerEnabled {
        user: String,
    },

    // The developer environment.
    TaskFishInstalledAt {
        path: String,
    },
    TaskFishNotForRoot,
    TaskMiseUseShims,
    TaskGitNeedsIdentity,
    TaskGithubCliNeedsToken,
    TaskGitIdentitySet {
        user: String,
        email: String,
    },
    TaskGitDirectoryTrusted {
        path: String,
    },
    TaskGitDefaultBranchSet {
        branch: String,
    },
    TaskRustPathHint {
        home: String,
    },
    TaskRustManagerRemoved {
        user: String,
    },
    TaskRustAvailableTo {
        user: String,
    },
    TaskToolchainInstalled {
        tool: String,
        user: String,
    },

    // Hardening.
    TaskWatchingForFailures {
        service: String,
    },
    TaskUpgradesNoReboot,
    TaskServiceRunning {
        service: String,
    },

    TaskCrowdsecDetectsOnly,
    TaskUpgradesAutomatic,
    TaskZellijFromDistribution,
    TaskZellijDownloading {
        version: String,
    },
    TaskZellijVerified,
    TaskCaddyPorts {
        http: u32,
        https: u32,
    },
    TaskCaddyImportHint {
        name: String,
    },
    TaskDockerInstalling {
        user: String,
    },
    TaskDockerConnectHint {
        user: String,
    },
    TaskRepositoryRegistering {
        repository: String,
    },
    TaskServiceRunningAs {
        service: String,
        user: String,
    },

    // WireGuard.
    TaskWireguardNotConfigured,
    TaskWireguardUp {
        interface: String,
    },
    TaskWireguardDown {
        interface: String,
    },
    TaskWireguardInstallingTools,
    TaskWireguardGeneratingKeys,
    TaskWireguardWrote {
        path: String,
    },
    TaskWireguardServerKey {
        key: String,
    },
    TaskWireguardPeerAdded {
        name: String,
        address: String,
    },
    TaskWireguardPeerCount {
        count: usize,
    },
    TaskWireguardInterface {
        interface: String,
        address: String,
    },
}

/// The name of one field in a structured error.
///
/// A closed set rather than a string, for the reason the whole catalogue is
/// one: a field label is a word in the operator's language, and a `&str` at
/// the call site is a word that no locale can reach. It also keeps the labels
/// consistent between variants — `Expected` reads the same above a digest as
/// above a repository key, because it is the same variant both times.
///
/// Deliberately smaller than the set of fields the errors carry. Several
/// variants hold a value whose meaning is the sentence around it rather than a
/// label above it; those keep their rendered sentence and never reach here.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ErrorField {
    /// The command as it was run, including its arguments.
    Command,
    /// The exit status a command answered with.
    ExitCode,
    /// What a command wrote to its standard error.
    Stderr,
    /// How long a silent command was waited on.
    Seconds,
    /// The file a failure is about.
    Path,
    /// What this tool recorded, in a comparison of two values.
    ///
    /// Paired with [`Self::Found`]: neither is worth showing alone, since the
    /// difference between them is the evidence.
    Expected,
    /// What the host actually holds, against what was recorded.
    Found,
    /// The package repository a failure is about.
    Repository,
    /// The service or unit a failure is about.
    Service,
    /// The account a failure is about.
    User,
    /// The group a failure is about.
    Group,
    /// The program a failure is about.
    Program,
    /// A version string, of a program or a release.
    Version,
    /// A machine architecture.
    Architecture,
    /// The underlying cause, where the error carried one from the system.
    ///
    /// Rendered last wherever it appears: it is the most specific thing on
    /// screen and the least likely to be understood without the fields above
    /// it for context.
    Cause,
    /// How many accounts a scan examined.
    Examined,
    /// The count of something the error measured, where no field above names it.
    Count,
    /// A network port.
    Port,
    /// A network address.
    Address,
    /// A network interface.
    Interface,
    /// The task a failure names, where it is not the one that ran.
    Task,
    /// A configuration directive or key.
    Directive,
    /// A value that was rejected, where the error is about the value itself.
    Value,
    /// A distribution family or release.
    Distribution,
    /// The kind or category a failure falls into.
    Kind,
    /// A shell.
    Shell,
    /// A digest, where only one is carried rather than a pair.
    Digest,
    /// A URL a failure is about.
    Url,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unknown_locale_falls_back_to_english() {
        assert_eq!(Lang::from_locale("de_DE.UTF-8"), Lang::En);
        assert_eq!(Lang::from_locale(""), Lang::En);
    }

    #[test]
    fn parses_language_ignoring_territory_and_encoding() {
        assert_eq!(Lang::from_locale("en_US.UTF-8"), Lang::En);
        assert_eq!(Lang::from_locale("en"), Lang::En);
        assert_eq!(Lang::from_locale("EN_GB"), Lang::En);
    }

    #[test]
    fn c_and_posix_locales_resolve_to_english() {
        assert_eq!(Lang::from_locale("C"), Lang::En);
        assert_eq!(Lang::from_locale("POSIX"), Lang::En);
    }

    #[test]
    fn renders_interpolated_values() {
        let rendered = Lang::En.render(&Msg::InvalidPort { port: 70_000 });
        assert!(rendered.contains("70000"), "port must appear: {rendered}");
    }
}
