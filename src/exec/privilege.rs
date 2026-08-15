//! Privilege escalation, resolved at runtime.
//!
//! `sudo` is not universal: Alpine ships `doas`, and modern systemd offers
//! `run0`, which authenticates through polkit but is a symlink to
//! `systemd-run` and does not exist without systemd. The mechanism is
//! therefore discovered at runtime behind a trait, never hardcoded.
//!
//! **Discovered in a fixed list of directories rather than in `PATH`.** This
//! process is unprivileged and escalates command by command, so it inherits
//! the operator's environment — including a `PATH` that may begin with a
//! directory somebody else can write to (`~/.local/bin` and a version manager
//! with loose permissions are the ordinary cases). A `sudo` planted there is
//! found first, and from then on every privileged command in the session goes
//! through it: `secure_path` never gets to run, because the real `sudo` is
//! never reached. The helper is therefore looked up where the system keeps
//! its own binaries, which is the same reasoning `sudo` applies to the
//! commands it runs.
//!
//! The resolved absolute path is then *kept*. Looking a name up and spawning
//! it by that name resolves twice, and the second resolution — performed by
//! `execvp` against the same untrusted `PATH` — need not answer what the
//! first one checked.

use std::fmt;
use std::path::{Path, PathBuf};

use super::Command;
use crate::error::{Error, Result};

/// Directories a helper may be found in, in the order they are searched.
///
/// The system's own binary directories, and nothing the operator's profile can
/// prepend. `/usr/bin` before `/bin` because the split is historical and the
/// latter is a symlink to the former on every family implemented here; both
/// are listed so a host that kept them separate still resolves.
const TRUSTED_DIRECTORIES: [&str; 4] = ["/usr/sbin", "/usr/bin", "/sbin", "/bin"];

/// Escalation mechanisms, in the order they are preferred.
///
/// `sudo` comes first as the most widely deployed; `run0` last because it
/// requires systemd and behaves differently enough (polkit agent, separate
/// TTY) that it is a fallback rather than a default.
const CANDIDATES: [&str; 3] = [SUDO, DOAS, RUN0];

/// The one helper that can authenticate ahead of the work.
const SUDO: &str = "sudo";

/// Alpine's helper, which authenticates per invocation unless `doas.conf`
/// carries `persist`.
const DOAS: &str = "doas";

/// systemd's helper, which defers to polkit for both prompt and caching.
///
/// Named for the candidate list rather than matched on: it takes the same
/// branch as an unknown helper, since neither can be asked whether it will
/// prompt.
const RUN0: &str = "run0";

/// The do-nothing command a probe runs to ask a helper a question.
///
/// `doas` and `run0` have no validate flag, so the probe needs *some* command
/// to carry; the answer is in the exit code, not in what runs.
const NO_OP: &str = "true";

/// Where `true` is if the trusted directories do not have it.
///
/// They always do — it is coreutils on four families and busybox on Alpine —
/// but a probe that fell back to a bare name would reintroduce exactly the
/// lookup this module exists to avoid, so the fallback is absolute too.
const NO_OP_FALLBACK: &str = "/bin/true";

/// The absolute path of the no-op a probe runs.
///
/// **Resolved here rather than passed as a bare name**, which is the module's
/// own rule applied one argument to the right. The helper resolves its command
/// against the *caller's* `PATH` — this process inherits the operator's — so
/// `doas -n true` ran whatever `true` came first there, as root: measured on
/// `alpine:3.21` under `permit nopass`, a planted `true` wrote to `/root` and
/// read `/etc/shadow`. `sudo` is not exposed, since `secure_path` replaces the
/// `PATH` before the lookup, but the probe must not depend on which helper it
/// happens to be talking to.
pub(super) fn no_op_command() -> String {
    find_trusted(NO_OP).map_or_else(
        || NO_OP_FALLBACK.to_owned(),
        |path| path.to_string_lossy().into_owned(),
    )
}

/// Whether a mechanism will prompt before a privileged command runs.
///
/// The distinction exists because a prompt drawn while the interface holds the
/// terminal is unusable: raw mode disables echo and the alternate screen hides
/// it. Knowing *before* spawning lets the caller hand the terminal over first.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuthNeed {
    /// Never prompts. The process is already root, or nothing can escalate.
    Never,
    /// Ask this command; success means no prompt is coming.
    Probe { program: String, args: Vec<String> },
    /// Cannot be asked, so the terminal is handed over regardless.
    Always,
}

/// Wraps a command so it runs with root privileges.
pub trait PrivilegeEscalator: fmt::Debug {
    /// Returns the program and arguments to spawn for a privileged command.
    fn wrap(&self, command: &Command) -> Result<(String, Vec<String>)>;

    /// Name of the mechanism, for display in the UI.
    fn name(&self) -> &str;

    /// The command that authenticates ahead of time, if this mechanism has one.
    ///
    /// `sudo -v` establishes a timestamp that later commands reuse, which is
    /// what lets the interface run a task without handing the terminal over
    /// for each command. Returning `None` means every privileged command has
    /// to authenticate on its own.
    ///
    /// `doas` has no equivalent, and `run0` authenticates through polkit,
    /// which owns its own prompt and its own caching — neither is ours to
    /// drive.
    fn preauth_command(&self) -> Option<(String, Vec<String>)> {
        None
    }

    /// Whether a privileged command is about to prompt.
    ///
    /// Defaults to [`AuthNeed::Never`] only for mechanisms that genuinely
    /// cannot prompt. A mechanism that might is answered [`AuthNeed::Always`]
    /// instead: claiming "will not prompt" for something that does is the
    /// error that strands an operator at an invisible password prompt, so the
    /// safe direction is to hand the terminal over needlessly.
    fn auth_need(&self) -> AuthNeed {
        AuthNeed::Never
    }
}

/// No escalation: the process already runs as root, or the command does not
/// need privileges.
#[derive(Debug, Clone, Copy)]
pub struct NoEscalation;

impl PrivilegeEscalator for NoEscalation {
    fn wrap(&self, command: &Command) -> Result<(String, Vec<String>)> {
        Ok((command.program.clone(), command.args.clone()))
    }

    fn name(&self) -> &str {
        "none (already root)"
    }
}

/// Escalation through an external helper.
///
/// Carries both the helper's name, which is what the interface displays and
/// what selects its behaviour, and the absolute path it was found at, which is
/// what gets spawned. Keeping the two apart is what stops a `sudo` earlier in
/// the operator's `PATH` from answering for the one that was checked.
#[derive(Debug, Clone)]
pub struct HelperEscalation {
    program: String,
    path: String,
}

impl HelperEscalation {
    /// Wraps a helper found at a known absolute path.
    pub fn new(program: impl Into<String>, path: impl Into<String>) -> Self {
        Self {
            program: program.into(),
            path: path.into(),
        }
    }

    /// Wraps a helper by name, spawning it by that name.
    ///
    /// For tests and for a caller naming a helper it has already resolved.
    /// Production detection goes through [`detect`], which keeps the path.
    #[cfg(test)]
    pub fn by_name(program: impl Into<String>) -> Self {
        let program = program.into();

        Self {
            path: program.clone(),
            program,
        }
    }
}

impl PrivilegeEscalator for HelperEscalation {
    fn wrap(&self, command: &Command) -> Result<(String, Vec<String>)> {
        let mut args = Vec::with_capacity(command.args.len() + 1);
        args.push(command.program.clone());
        args.extend(command.args.iter().cloned());

        Ok((self.path.clone(), args))
    }

    fn name(&self) -> &str {
        &self.program
    }

    fn preauth_command(&self) -> Option<(String, Vec<String>)> {
        // Only sudo has a validate flag. doas authenticates per invocation with
        // no client-side refresh, and run0 defers to polkit.
        (self.program == SUDO).then(|| (self.path.clone(), vec!["-v".to_owned()]))
    }

    fn auth_need(&self) -> AuthNeed {
        match self.program.as_str() {
            // `sudo -n -v` answers whether the timestamp is still valid without
            // prompting, which is *most* of the question: Arch expires it after
            // five minutes and a long task outlives that.
            //
            // Not all of it, and the gap is worth naming rather than leaving
            // for the next reader to find. `-v` reports on the user's
            // credential cache, not on the command about to run, so a sudoers
            // granting `NOPASSWD` for one command and requiring a password for
            // others answers 0 here and then asks. Measured: with
            // `op ALL=(ALL) NOPASSWD: /usr/bin/id` and nothing else, `sudo -n -v`
            // exits 0 while `sudo -n cat /etc/shadow` reports `a password is
            // required`.
            //
            // Not covered, and the honest statement of what that costs is that
            // the terminal is not handed over: `wrap` builds `sudo <program>`
            // with no `-n`, so on such a host the prompt is raised under the
            // alternate screen — the outcome this probe exists to prevent, for
            // a sudoers shape it cannot see.
            //
            // Left alone because the fix is worse than the gap. Probing the
            // actual command means `sudo -n -l <program> <args>` before every
            // privileged call, doubling the invocations, and `-l` answers about
            // a command line rather than about what running it will do. A host
            // configured this way is also one where `sudo -v` at startup
            // already establishes nothing.
            SUDO => AuthNeed::Probe {
                program: self.path.clone(),
                args: vec!["-n".to_owned(), "-v".to_owned()],
            },
            // Alpine's opendoas takes `-n` — confirmed against its usage line,
            // and its exit codes measured on alpine:3.23: 0 under `permit
            // nopass`, 1 when a password is wanted. There is no validate flag,
            // so the probe runs a no-op rather than nothing — by absolute path,
            // for the reason [`no_op_command`] records.
            DOAS => AuthNeed::Probe {
                program: self.path.clone(),
                args: vec!["-n".to_owned(), no_op_command()],
            },
            // polkit owns run0's prompt, but run0 can still be asked whether
            // one is coming: `--no-ask-password` exits non-zero rather than
            // prompting. Measured on an Arch container with systemd as PID 1
            // and polkit active — 1 as an unprivileged user, 0 as root — which
            // needed both, since without them run0 fails to reach the bus and
            // every answer looks the same.
            RUN0 => AuthNeed::Probe {
                program: self.path.clone(),
                args: vec!["--no-ask-password".to_owned(), no_op_command()],
            },
            // An unrecognised helper cannot be asked, so the terminal is
            // handed over regardless: a wrong "will not prompt" is what
            // strands an operator at a prompt they cannot see.
            _ => AuthNeed::Always,
        }
    }
}

/// Refuses to escalate: nothing suitable was found in `PATH`.
///
/// Constructed instead of failing at detection time so that unprivileged
/// commands still run on a system with no escalation helper; the error only
/// surfaces when a command actually needs root.
#[derive(Debug, Clone, Copy)]
pub struct UnavailableEscalation;

impl PrivilegeEscalator for UnavailableEscalation {
    fn wrap(&self, _command: &Command) -> Result<(String, Vec<String>)> {
        Err(Error::NoPrivilegeEscalator)
    }

    fn name(&self) -> &str {
        "unavailable"
    }
}

/// Picks an escalation mechanism for the current process.
///
/// Running as root needs none. Otherwise the first candidate found in the
/// trusted directories wins, and the path it was found at is what will be
/// spawned; if none is present, escalation fails later with a clear error
/// rather than at startup.
pub fn detect() -> Box<dyn PrivilegeEscalator> {
    if is_root() {
        return Box::new(NoEscalation);
    }

    CANDIDATES
        .iter()
        .find_map(|program| Some((*program, find_trusted(program)?)))
        .map_or_else(
            || Box::new(UnavailableEscalation) as Box<dyn PrivilegeEscalator>,
            |(program, path)| {
                Box::new(HelperEscalation::new(
                    program,
                    path.to_string_lossy().as_ref(),
                )) as Box<dyn PrivilegeEscalator>
            },
        )
}

/// Whether the effective user is root.
///
/// Reads `/proc/self/status` rather than calling `geteuid`, which would mean a
/// `libc` dependency for a single value.
fn is_root() -> bool {
    let Ok(status) = std::fs::read_to_string("/proc/self/status") else {
        return false;
    };

    status
        .lines()
        .find_map(|line| line.strip_prefix("Uid:"))
        .and_then(|uids| {
            // Format: "Uid:\treal\teffective\tsaved\tfilesystem"
            uids.split_whitespace().nth(1)
        })
        .is_some_and(|effective| effective == "0")
}

/// Looks a program up in the trusted directories, in their declared order.
///
/// `PATH` is deliberately not consulted: see the module documentation. A
/// helper installed somewhere else is not found, and the operator gets the
/// "no escalation mechanism" error rather than a silent lookup in a directory
/// somebody else can write to.
fn find_trusted(program: &str) -> Option<PathBuf> {
    TRUSTED_DIRECTORIES
        .iter()
        .map(|dir| Path::new(dir).join(program))
        .find(|candidate| is_executable(candidate))
}

/// Whether the path is an existing executable file.
fn is_executable(path: &std::path::Path) -> bool {
    use std::os::unix::fs::PermissionsExt;

    std::fs::metadata(path)
        .is_ok_and(|meta| meta.is_file() && meta.permissions().mode() & 0o111 != 0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn no_escalation_passes_the_command_through() {
        let cmd = Command::new("systemctl").arg("status");
        let (program, args) = NoEscalation.wrap(&cmd).expect("passthrough cannot fail");

        assert_eq!(program, "systemctl");
        assert_eq!(args, ["status"]);
    }

    #[test]
    fn helper_prepends_itself_to_the_command() {
        let cmd = Command::new("apt-get").args(["install", "-y", "openssh-server"]);
        let (program, args) = HelperEscalation::by_name("sudo")
            .wrap(&cmd)
            .expect("wrapping cannot fail");

        assert_eq!(program, "sudo");
        assert_eq!(args, ["apt-get", "install", "-y", "openssh-server"]);
    }

    #[test]
    fn helper_works_for_any_mechanism() {
        // doas and run0 take the same "helper then command" shape.
        let cmd = Command::new("pacman").args(["-S", "openssh"]);

        for helper in ["doas", "run0"] {
            let (program, args) = HelperEscalation::by_name(helper)
                .wrap(&cmd)
                .expect("wrapping cannot fail");

            assert_eq!(program, helper);
            assert_eq!(args, ["pacman", "-S", "openssh"]);
        }
    }

    #[test]
    fn unavailable_escalation_errors_instead_of_panicking() {
        let err = UnavailableEscalation
            .wrap(&Command::new("apt-get").privileged())
            .expect_err("no mechanism means no escalation");

        assert!(matches!(err, Error::NoPrivilegeEscalator), "{err:?}");
    }

    #[test]
    fn finds_a_program_that_exists_in_a_trusted_directory() {
        assert!(
            find_trusted("sh").is_some(),
            "sh must live in /bin or /usr/bin"
        );
    }

    #[test]
    fn does_not_find_a_nonexistent_program() {
        assert!(find_trusted("initd-nonexistent-binary").is_none());
    }

    #[test]
    fn a_helper_is_only_looked_for_in_trusted_directories() {
        // The attack this closes: an unprivileged process inherits the
        // operator's PATH, so a `sudo` planted in a directory somebody else can
        // write to would be found first and would then wrap every privileged
        // command of the session. Every directory searched must be one only
        // root can write to.
        for directory in TRUSTED_DIRECTORIES {
            assert!(
                std::path::Path::new(directory).is_absolute(),
                "{directory} must be absolute: a relative entry resolves against \
                 the working directory, which the operator chooses"
            );
        }
    }

    #[test]
    fn a_planted_helper_earlier_in_path_is_not_found() {
        // PATH is not consulted at all, so a directory prepended to it cannot
        // introduce a candidate. Asserted against a real executable placed in a
        // temporary directory, rather than against the absence of a lookup.
        let dir = std::env::temp_dir().join(format!("initd-path-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("temp dir");

        let planted = dir.join(SUDO);
        std::fs::write(&planted, "#!/bin/sh\nexit 0\n").expect("write planted helper");

        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(&planted, std::fs::Permissions::from_mode(0o755))
            .expect("make it executable");

        let found = find_trusted(SUDO);

        std::fs::remove_dir_all(&dir).ok();

        assert_ne!(
            found.as_deref(),
            Some(planted.as_path()),
            "a helper outside the trusted directories must never be chosen"
        );
    }

    #[test]
    fn a_probe_never_carries_a_bare_command_name() {
        // The same rule as `a_planted_helper_earlier_in_path_is_not_found`, one
        // argument to the right. A helper resolves its command against the
        // *caller's* PATH, and the caller is this process with the operator's
        // environment — so a bare `true` runs whatever comes first there, as
        // root. Measured on alpine:3.21 under `permit nopass`: a planted `true`
        // wrote to /root and read /etc/shadow.
        for program in [DOAS, RUN0] {
            let helper = HelperEscalation::new(program, format!("/usr/bin/{program}"));

            let AuthNeed::Probe { args, .. } = helper.auth_need() else {
                panic!("{program} is probeable and must answer with a probe");
            };

            let carried = args.last().expect("a probe carries a command");

            assert!(
                carried.starts_with('/'),
                "{program}'s probe must name an absolute path, got {carried:?}"
            );
        }
    }

    #[test]
    fn the_resolved_path_is_what_gets_spawned() {
        // Resolving a name and then spawning that name resolves twice, and the
        // second resolution answers to `execvp` against the untrusted PATH. The
        // path found is therefore what `wrap` returns.
        let helper = HelperEscalation::new(SUDO, "/usr/bin/sudo");
        let (program, _) = helper
            .wrap(&Command::new("apt-get").privileged())
            .expect("wrapping cannot fail");

        assert_eq!(program, "/usr/bin/sudo");
        assert_eq!(helper.name(), SUDO, "the display name stays the bare name");
    }

    #[test]
    fn the_probe_and_the_preauth_use_the_resolved_path_too() {
        // Both spawn the helper independently of `wrap`, so both would resolve
        // by name again if they carried the name.
        let helper = HelperEscalation::new(SUDO, "/usr/bin/sudo");

        assert_eq!(
            helper.auth_need(),
            AuthNeed::Probe {
                program: "/usr/bin/sudo".to_owned(),
                args: vec!["-n".to_owned(), "-v".to_owned()],
            }
        );

        let (program, args) = helper.preauth_command().expect("sudo pre-authenticates");

        assert_eq!(program, "/usr/bin/sudo");
        assert_eq!(args, ["-v"]);
    }

    #[test]
    fn detection_always_yields_a_mechanism() {
        // Never panics regardless of environment: worst case it is the
        // Unavailable variant, which fails only when root is actually needed.
        assert!(!detect().name().is_empty());
    }

    #[test]
    fn sudo_is_asked_whether_its_timestamp_is_still_valid() {
        let need = HelperEscalation::by_name(SUDO).auth_need();

        assert_eq!(
            need,
            AuthNeed::Probe {
                program: SUDO.to_owned(),
                args: vec!["-n".to_owned(), "-v".to_owned()],
            }
        );
    }

    #[test]
    fn doas_is_probed_rather_than_assumed_to_be_silent() {
        // The case this mechanism exists for: Alpine ships doas and no sudo,
        // so nothing authenticates at startup and the first privileged command
        // is the one that prompts. Its exit codes were measured on alpine:3.23
        // — 0 under `permit nopass`, 1 when a password is wanted.
        let need = HelperEscalation::by_name(DOAS).auth_need();

        // The no-op's path is resolved rather than spelled, so this asserts the
        // flag and leaves the path to
        // `a_probe_never_carries_a_bare_command_name`.
        assert_eq!(
            need,
            AuthNeed::Probe {
                program: DOAS.to_owned(),
                args: vec!["-n".to_owned(), no_op_command()],
            }
        );
    }

    #[test]
    fn run0_is_asked_rather_than_assumed_to_prompt() {
        // polkit owns the prompt, but run0 still answers whether one is
        // coming: `--no-ask-password` refuses instead of asking. Measured on
        // Arch with systemd as PID 1 and polkit active.
        let need = HelperEscalation::by_name(RUN0).auth_need();

        assert_eq!(
            need,
            AuthNeed::Probe {
                program: RUN0.to_owned(),
                args: vec!["--no-ask-password".to_owned(), no_op_command()],
            }
        );
    }

    #[test]
    fn an_unknown_helper_hands_the_terminal_over_regardless() {
        // The dangerous direction is claiming a mechanism will not prompt when
        // it will, so anything unrecognised errs towards a needless handoff.
        assert_eq!(
            HelperEscalation::by_name("something-else").auth_need(),
            AuthNeed::Always
        );
    }

    #[test]
    fn a_mechanism_that_cannot_prompt_is_never_asked() {
        assert_eq!(NoEscalation.auth_need(), AuthNeed::Never);
        assert_eq!(UnavailableEscalation.auth_need(), AuthNeed::Never);
    }

    #[test]
    fn every_candidate_reports_a_need() {
        // Guards the table against a candidate being added to the list and
        // forgotten in `auth_need`, which would silence the handoff for it.
        for candidate in CANDIDATES {
            assert_ne!(
                HelperEscalation::by_name(candidate).auth_need(),
                AuthNeed::Never,
                "{candidate} must not claim it will never prompt"
            );
        }
    }
}
