//! Command execution — the single choke point for running processes.
//!
//! `std::process::Command` appears nowhere else in the codebase. The trait
//! exists so that remote execution over SSH can be added later as a second
//! implementation without touching any call site.
//!
//! The signature supports streaming rather than only capturing at the end,
//! because the TUI renders command output live as it arrives.

pub mod local;
pub mod privilege;

#[cfg(test)]
pub mod mock;

use std::fmt;

use crate::error::Result;

/// Where a program lookup searches, whoever is running this tool.
///
/// `initd` is unprivileged and escalates command by command, so it inherits the
/// operator's environment rather than root's — `src/exec/privilege.rs` states
/// this and is the accurate account. A non-root login on Debian 13 gets
/// `/usr/local/bin:/usr/bin:/bin:/usr/local/games:/usr/games`, and **`/usr/sbin`
/// is not in it**, which is where `sshd` and `nft` live. So a lookup asked of
/// the bare inherited `PATH` reported a preinstalled SSH server absent on a host
/// plainly serving SSH, and greyed out all four `sshd_config` tasks with it.
///
/// The doc comment on `tasks::consequence::program_check` used to claim the
/// opposite — that the probe "inherits the environment of a process that did"
/// escalate. Nothing creates such a process: `docs/cli.md` and the README both
/// document the invocation as bare `initd`. That comment also carried its own
/// correction, unacted on for as long as it stood: "a future caller running
/// these checks from an unprivileged context would need to look on disk
/// instead". This is that caller, and always was.
///
/// The four system directories come first and **`$PATH` is kept after them**
/// rather than replaced. Dropping it would answer the SSH question and break
/// `location_of` for everything installed from a release — `mise`, `zellij` and
/// this tool's own copies live in `/usr/local/bin`, and a lookup that cannot see
/// them reports a row absent for the opposite reason.
const LOOKUP_PATH: &str = "/usr/sbin:/usr/bin:/sbin:/bin:/usr/local/sbin:/usr/local/bin";

/// A command to run: a program resolved through `PATH` plus its arguments.
///
/// Absolute paths are never hardcoded — binaries live in different locations
/// across distributions, so resolution is left to `PATH`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Command {
    pub program: String,
    pub args: Vec<String>,
    /// Whether the command must run with root privileges.
    pub needs_root: bool,
    /// Data fed to the process on stdin, if any.
    ///
    /// File contents travel through here rather than through arguments: an
    /// argument would have to be shell-escaped, and any mistake in that
    /// escaping is a command injection on a tool that runs as root.
    pub stdin: Option<String>,
    /// Whether what the process prints is itself a secret.
    ///
    /// The output pane is a transcript an administrator scrolls, pastes into a
    /// bug report and copies to the clipboard, so a command whose stdout *is*
    /// the secret cannot be observed the way every other command is. `stdin`
    /// above keeps a secret out of `argv`; this keeps one out of the pane, and
    /// the two are needed together because `wg pubkey` reads a key the safe way
    /// while `wg genkey` writes one the other way.
    ///
    /// Only the observer is withheld. `Output` still carries both streams, so
    /// the caller that asked for the key still receives it — what changes is
    /// that nobody is watching over its shoulder.
    pub secret_output: bool,
    /// Environment this command needs beyond what the process inherits.
    ///
    /// Per-command rather than global, which is the difference from
    /// `INVARIANT_LOCALE`: that one is true of every command this tool runs, and
    /// this is true of the one that asks it. Only [`locating`](Self::locating)
    /// sets anything today, and what it sets is a `PATH` — see there for why.
    ///
    /// Kept out of [`Display`](std::fmt::Display) on purpose. The pane is a
    /// transcript an operator reads to see *what was asked*, and a lookup
    /// prefixed by four directories reads as noise at exactly the moment it is
    /// being read — when the program was not found.
    pub env: Vec<(String, String)>,
}

impl Command {
    /// Builds an unprivileged command.
    pub fn new(program: impl Into<String>) -> Self {
        Self {
            program: program.into(),
            args: Vec::new(),
            needs_root: false,
            stdin: None,
            secret_output: false,
            env: Vec::new(),
        }
    }

    /// Builds the command that asks the host where a program is.
    ///
    /// `command -v` rather than `which`, which is not installed everywhere and
    /// whose exit codes differ between implementations. Stated once because
    /// five call sites had written it out, each carrying the same decision and
    /// only one of them carrying the reason — so the three that did not read
    /// like a shell invocation somebody could simplify.
    ///
    /// The exit code answers "is it there" and stdout answers "where", which is
    /// why this returns the command rather than either: callers want different
    /// halves of the same answer.
    ///
    /// `program` reaches a shell here, unlike every other command in this
    /// codebase: `sh -c` would read a value carrying `;` or a backtick as more
    /// of the script.
    ///
    /// `&'static str` is what keeps that from being a rule somebody has to
    /// remember. Every call site passes a literal today, so the bound costs
    /// nothing and none of them changed — but a `String` built from a form
    /// field or a CLI argument now fails to compile rather than reaching the
    /// shell. The same trade the task tree makes with an exhaustive `match`:
    /// let the compiler hold the invariant, since a comment saying "must stay a
    /// literal" is only as good as the next person's attention.
    #[must_use]
    pub fn locating(program: &'static str) -> Self {
        Self::new("sh")
            .args(["-c", &format!("command -v {program}")])
            .with_env("PATH", LOOKUP_PATH)
    }

    /// Adds one environment variable to what this command runs with.
    #[must_use]
    pub fn with_env(mut self, key: &str, value: impl Into<String>) -> Self {
        self.env.push((key.to_owned(), value.into()));
        self
    }

    /// Feeds the given data to the process on stdin.
    #[must_use]
    pub fn stdin(mut self, data: impl Into<String>) -> Self {
        self.stdin = Some(data.into());
        self
    }

    /// Withholds the process's output from whoever is observing.
    ///
    /// For the command that *prints* a secret, as `wg genkey` prints a private
    /// key. Its counterpart is [`Command::stdin`], which keeps a secret out of
    /// `argv`; a key is generated one way and consumed the other, so a command
    /// needs whichever half matches the direction its secret travels.
    #[must_use]
    pub const fn secret_output(mut self) -> Self {
        self.secret_output = true;
        self
    }

    /// Appends a single argument.
    #[must_use]
    pub fn arg(mut self, arg: impl Into<String>) -> Self {
        self.args.push(arg.into());
        self
    }

    /// Appends several arguments.
    #[must_use]
    pub fn args<I, S>(mut self, args: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.args.extend(args.into_iter().map(Into::into));
        self
    }

    /// Marks the command as requiring root.
    #[must_use]
    pub const fn privileged(mut self) -> Self {
        self.needs_root = true;
        self
    }
}

impl fmt::Display for Command {
    /// Renders the command as a readable line, for logs and error messages.
    ///
    /// A `sh -c` script is summarised rather than printed. One of them is
    /// thirteen lines, and this line is announced in the output pane before the
    /// command runs and carried into `CommandFailed` if it does not — so
    /// spelling it out would bury the transcript under a program the operator
    /// did not write and put the same wall of text inside the error. The
    /// arguments after it are the part that varies and the part worth reading.
    ///
    /// The same reasoning that keeps `stdin` out: this line is for somebody
    /// working out what the tool did, and a faithful transcription that nobody
    /// can read serves that worse than a summary.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.program)?;

        let mut args = self.args.iter();

        // `sh -c <script> <argv0> <args…>`: the script is one argument, and
        // `-c` is what identifies it. A one-line script is printed as it is —
        // `command -v fish` reads perfectly well and five call sites rely on
        // being able to see it.
        if self.program == "sh"
            && self.args.first().is_some_and(|arg| arg == "-c")
            && let Some(script) = self.args.get(1)
            && script.contains('\n')
        {
            let lines = script.lines().count();
            write!(f, " -c <{lines}-line script>")?;

            // `argv0` is the conventional `sh` and says nothing.
            args.nth(2);
        }

        for arg in args {
            write!(f, " {arg}")?;
        }

        Ok(())
    }
}

/// Which stream a line of output came from.
///
/// Consumed by the TUI's live output pane, which styles stderr apart from
/// stdout so warnings stand out from progress.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Stream {
    Stdout,
    Stderr,
    /// Not a stream of the process: the command line itself, announced before
    /// it runs.
    ///
    /// Carried here rather than as a separate kind of update because the pane
    /// renders one sequence, and a command has to appear in order with the
    /// output it produced. It is what makes the pane a transcript somebody can
    /// paste into a bug report rather than a wall of unattributed lines.
    Command,
}

/// Why a line stands out, where its stream does not say so.
///
/// Not a style: `exec` has no opinion about colour, and the command line
/// renders these as plain text. It names *what a line is*, and the interface
/// decides what that looks like — the same split the catalogue makes between a
/// message and its wording.
///
/// Its one use today is the consequences a finished task reports, where the
/// distinction is load-bearing rather than decorative: a warning the tool can
/// verify and one the administrator has to chase elsewhere must not read alike.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Emphasis {
    /// A consequence on this machine, which the tool can inspect.
    Consequence,
    /// A consequence beyond it, which nothing here can check.
    ConsequenceExternal,
}

/// A single line of output, tagged with its origin.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OutputLine {
    pub stream: Stream,
    pub text: String,
    /// Why the line stands out, where its stream does not already say.
    ///
    /// `None` for everything a process prints: the stream is the answer there.
    /// Set only by the interface's own lines, which is why this is an `Option`
    /// rather than a variant of [`Stream`] — a process has no way to produce
    /// one, and `main.rs` matches `Stream` exhaustively to decide between
    /// stdout and stderr, a question emphasis has no bearing on.
    pub emphasis: Option<Emphasis>,
    /// Whether the line holds a secret, so the clipboard must not carry it.
    ///
    /// Separate from [`Emphasis`], which says why a line stands out on screen:
    /// a line can be sensitive without being emphasised and the reverse, and
    /// folding the two would make a styling decision able to widen disclosure.
    ///
    /// The pane still draws it. What this bounds is the *copy*: the peer
    /// configuration exists to be read off the screen, while
    /// [`OutputPane::transcript`](crate::tui::output::OutputPane::transcript)
    /// sends whatever it holds to the operator's own machine over OSC 52, where
    /// it lands in clipboard history and anything syncing it. The task that
    /// produces such a line already refuses to let a copy of the same key reach
    /// `/var/lib/initd` or a `.initd.bak` sidecar; a copy travelling the other
    /// way, across the SSH hop, is the same disclosure through a different door.
    pub sensitive: bool,
}

impl OutputLine {
    /// A line of a process's output.
    pub fn new(stream: Stream, text: impl Into<String>) -> Self {
        Self {
            stream,
            text: text.into(),
            emphasis: None,
            sensitive: false,
        }
    }

    /// The same line, marked for why it stands out.
    #[must_use]
    pub const fn emphasised(mut self, emphasis: Emphasis) -> Self {
        self.emphasis = Some(emphasis);
        self
    }

    /// The same line, marked as holding a secret the clipboard must not carry.
    ///
    /// Opt-in rather than inferred from the text. A rule guessing at what looks
    /// like a key would have to be right about every format a task might print,
    /// and the one it did not recognise would be disclosed silently — whereas a
    /// line wrongly marked is merely absent from a copy, which is visible.
    #[must_use]
    pub const fn sensitive(mut self) -> Self {
        self.sensitive = true;
        self
    }
}

/// The result of a finished command.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Output {
    pub code: i32,
    pub stdout: String,
    pub stderr: String,
}

impl Output {
    /// Whether the command reported success.
    pub const fn success(&self) -> bool {
        self.code == 0
    }
}

/// Runs commands. The only path to process execution in `initd`.
pub trait Executor {
    /// Runs a command to completion, capturing its output.
    fn run(&self, command: &Command) -> Result<Output>;
}

/// Somewhere a command's output goes as it is produced.
///
/// Deliberately *not* a second `Executor` method. A `run_streaming` beside
/// `run` existed once and was removed for having no caller: two ways to run a
/// command means one of them is the one nobody wires up, and its doc-comment
/// went on describing an arrangement that had stopped being true. There is one
/// way to run a command; whether anybody is watching is a property of the
/// executor, not of the call.
///
/// `Send` because the lines are read on the reader threads, and the observer
/// outlives none of them.
pub trait OutputObserver: Send + Sync {
    /// Called for each line, from either stream, in arrival order.
    fn line(&self, line: OutputLine);
}

/// A flag the interface raises to ask a running task to stop.
///
/// Deliberately *not* a parameter of [`Executor::run`], and not a method on the
/// trait: a task is stopped between its commands, and the executor is already
/// the only place every command passes through. Threading a token through all
/// fifty-two tasks would put the obligation to check it on each of them, and
/// the one that forgot would be the one that could not be stopped.
///
/// Cloning shares the flag rather than copying its value — the interface holds
/// one end and the worker thread the other.
#[derive(Debug, Clone, Default)]
pub struct CancelToken(std::sync::Arc<std::sync::atomic::AtomicBool>);

impl CancelToken {
    /// A token nobody has cancelled yet.
    pub fn new() -> Self {
        Self::default()
    }

    /// Asks whatever holds the other end to stop at its next command.
    pub fn cancel(&self) {
        self.0.store(true, std::sync::atomic::Ordering::SeqCst);
    }

    /// Whether cancellation has been asked for.
    pub fn is_cancelled(&self) -> bool {
        self.0.load(std::sync::atomic::Ordering::SeqCst)
    }
}

/// Somewhere the terminal can be borrowed from so a helper may prompt.
///
/// Deliberately *not* a method on [`Executor`]. The interface owns the
/// terminal and runs tasks on another thread, so the executor cannot restore
/// it itself; it has to ask. Putting that on `Executor` would oblige the mock
/// and the future SSH implementation to answer a question neither has — an SSH
/// executor authenticates over the transport, not by clearing a local screen.
///
/// `Send` because the implementation crosses into the worker thread. That is a
/// bound on this trait alone: what travels is the program and its arguments,
/// never the escalator or the executor, both of which stay where they were
/// built.
pub trait TerminalBroker: Send {
    /// Runs an authentication command with the terminal handed back.
    ///
    /// Answers whether authentication succeeded. `Ok(false)` is an operator
    /// who declined or typed the wrong password — ordinary, and not an error
    /// in the sense the caller should retry.
    fn authenticate(&self, program: &str, args: &[String]) -> Result<bool>;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn builds_command_with_args() {
        let cmd = Command::new("apt-get").arg("install").arg("-y");

        assert_eq!(cmd.program, "apt-get");
        assert_eq!(cmd.args, ["install", "-y"]);
        assert!(!cmd.needs_root);
    }

    #[test]
    fn locating_asks_the_shell_where_a_program_is() {
        // Pinned because five call sites now share this one line, and the
        // choice inside it is load-bearing: `which` is absent on some of the
        // families this runs on and disagrees about exit codes on others.
        let cmd = Command::locating("fish");

        assert_eq!(cmd.program, "sh");
        assert_eq!(cmd.args, ["-c", "command -v fish"]);
        assert!(
            !cmd.needs_root,
            "asking where a program is needs no privilege"
        );
    }

    #[test]
    fn a_lookup_searches_where_system_daemons_live() {
        // The defect this exists for: `initd` runs unprivileged and inherits
        // the operator's `PATH`, which on a non-root Debian login has no
        // `/usr/sbin` — so `sshd` and `nft` were invisible and four SSH tasks
        // refused on a host plainly serving SSH.
        let (key, value) = Command::locating("sshd")
            .env
            .first()
            .cloned()
            .expect("a lookup must carry a PATH of its own");

        assert_eq!(key, "PATH");

        for directory in ["/usr/sbin", "/usr/bin", "/sbin", "/bin"] {
            assert!(
                value.split(':').any(|entry| entry == directory),
                "{directory} must be searched: {value}"
            );
        }
    }

    #[test]
    fn a_lookup_still_finds_what_this_tool_installs_itself() {
        // The half a narrower fix would have broken. Capabilities installed
        // from a release live in `/usr/local/bin`, and `location_of` names the
        // copy it found — a lookup blind to that directory reports `mise` and
        // `zellij` absent, which is the same bug pointing the other way.
        let (_, value) = Command::locating("zellij")
            .env
            .first()
            .cloned()
            .expect("a lookup must carry a PATH of its own");

        assert!(
            value.split(':').any(|entry| entry == "/usr/local/bin"),
            "a release-installed binary must still be found: {value}"
        );
    }

    #[test]
    fn a_lookups_path_is_not_spelled_into_the_pane() {
        // The environment is deliberately outside `Display`. What an operator
        // reads when a program was not found is the question that was asked,
        // and six directories in front of it is noise at the one moment the
        // line is being read closely.
        let rendered = Command::locating("sshd").to_string();

        assert_eq!(rendered, "sh -c command -v sshd");
        assert!(
            !rendered.contains("/usr/sbin"),
            "the search path must stay out of the transcript: {rendered}"
        );
    }

    #[test]
    fn every_shell_bearing_call_names_a_program_the_binary_was_built_knowing() {
        // The real guarantee is the `&'static str` bound, which no runtime
        // assertion can observe — a value from a form is a `String` and fails
        // to compile rather than reaching `sh -c`. A `compile_fail` doctest
        // would state it, but this crate has no library target, so doctests
        // never run and it would be a comment pretending to be a test.
        //
        // What is checked here is the other half: that the script this builds
        // is a lookup and nothing else, whatever it is handed.
        for program in ["fish", "cc", "usermod", "zellij"] {
            let cmd = Command::locating(program);

            assert_eq!(cmd.args[0], "-c");
            assert_eq!(
                cmd.args[1],
                format!("command -v {program}"),
                "the script must stay one lookup: anything appended to it runs"
            );
        }
    }

    #[test]
    fn display_renders_a_readable_line() {
        let cmd = Command::new("systemctl").args(["enable", "ssh.service"]);

        assert_eq!(cmd.to_string(), "systemctl enable ssh.service");
    }

    #[test]
    fn the_rendered_line_never_carries_stdin() {
        // Secrets travel on stdin precisely so they stay out of argv, where
        // `/proc/<pid>/cmdline` would publish them. The rendered line goes into
        // error messages and the output pane, so it must not undo that — a
        // WireGuard private key is fed this way.
        let command = Command::new("wg")
            .arg("pubkey")
            .stdin("PRIVATE_KEY_THAT_MUST_NOT_APPEAR");

        assert_eq!(command.to_string(), "wg pubkey");
        assert!(!command.to_string().contains("PRIVATE_KEY"));
    }

    #[test]
    fn a_multi_line_script_is_summarised_rather_than_printed() {
        // This line is announced in the output pane before the command runs and
        // carried into `CommandFailed` if it fails. The owned-directory write is
        // a thirteen-line script, so printing it would bury a transcript under a
        // program the operator did not write, twice.
        let script = "set -eu\nif [ -L \"$1\" ]; then exit 9; fi\nmv -f \"$2\" \"$1\"\n";
        let command = Command::new("sh").args([
            "-c",
            script,
            "sh",
            "/root/.ssh",
            "700",
            "/root/.ssh/authorized_keys",
        ]);

        let rendered = command.to_string();

        assert_eq!(
            rendered,
            "sh -c <3-line script> /root/.ssh 700 /root/.ssh/authorized_keys"
        );
        assert!(
            !rendered.contains("exit 9"),
            "the script body must not be spelled out: {rendered}"
        );
    }

    #[test]
    fn a_one_line_script_is_still_shown_in_full() {
        // `Command::locating` builds `sh -c 'command -v fish'`, which reads
        // perfectly well and is the thing worth seeing when a program is not
        // found. Summarising by program name rather than by length would have
        // hidden it.
        assert_eq!(
            Command::locating("fish").to_string(),
            "sh -c command -v fish"
        );
    }

    #[test]
    fn privileged_marks_the_command() {
        assert!(Command::new("pacman").privileged().needs_root);
    }

    #[test]
    fn output_reports_success_only_on_zero() {
        let ok = Output {
            code: 0,
            stdout: String::new(),
            stderr: String::new(),
        };
        let failed = Output {
            code: 1,
            ..ok.clone()
        };

        assert!(ok.success());
        assert!(!failed.success());
    }
}
