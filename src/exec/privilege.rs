//! Privilege escalation, resolved at runtime.
//!
//! `sudo` is not universal: Alpine ships `doas`, and modern systemd offers
//! `run0`, which authenticates through polkit but is a symlink to
//! `systemd-run` and does not exist without systemd. The mechanism is
//! therefore discovered through `PATH` at runtime behind a trait, never
//! hardcoded.

use std::fmt;
use std::path::PathBuf;

use super::Command;
use crate::error::{Error, Result};

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

/// Escalation through an external helper found in `PATH`.
#[derive(Debug, Clone)]
pub struct HelperEscalation {
    program: String,
}

impl HelperEscalation {
    /// Wraps a specific helper by name.
    pub fn new(program: impl Into<String>) -> Self {
        Self {
            program: program.into(),
        }
    }
}

impl PrivilegeEscalator for HelperEscalation {
    fn wrap(&self, command: &Command) -> Result<(String, Vec<String>)> {
        let mut args = Vec::with_capacity(command.args.len() + 1);
        args.push(command.program.clone());
        args.extend(command.args.iter().cloned());

        Ok((self.program.clone(), args))
    }

    fn name(&self) -> &str {
        &self.program
    }

    fn preauth_command(&self) -> Option<(String, Vec<String>)> {
        // Only sudo has a validate flag. doas authenticates per invocation with
        // no client-side refresh, and run0 defers to polkit.
        (self.program == SUDO).then(|| (self.program.clone(), vec!["-v".to_owned()]))
    }

    fn auth_need(&self) -> AuthNeed {
        match self.program.as_str() {
            // `sudo -n -v` answers whether the timestamp is still valid without
            // prompting, which is the question, since Arch expires it after
            // five minutes and a long task outlives that.
            SUDO => AuthNeed::Probe {
                program: self.program.clone(),
                args: vec!["-n".to_owned(), "-v".to_owned()],
            },
            // Alpine's opendoas takes `-n` — confirmed against its usage line,
            // and its exit codes measured on alpine:3.23: 0 under `permit
            // nopass`, 1 when a password is wanted. There is no validate flag,
            // so the probe runs `true` rather than nothing.
            DOAS => AuthNeed::Probe {
                program: self.program.clone(),
                args: vec!["-n".to_owned(), "true".to_owned()],
            },
            // polkit owns run0's prompt, but run0 can still be asked whether
            // one is coming: `--no-ask-password` exits non-zero rather than
            // prompting. Measured on an Arch container with systemd as PID 1
            // and polkit active — 1 as an unprivileged user, 0 as root — which
            // needed both, since without them run0 fails to reach the bus and
            // every answer looks the same.
            RUN0 => AuthNeed::Probe {
                program: self.program.clone(),
                args: vec!["--no-ask-password".to_owned(), "true".to_owned()],
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
/// Running as root needs none. Otherwise the first candidate found in `PATH`
/// wins; if none is present, escalation fails later with a clear error rather
/// than at startup.
pub fn detect() -> Box<dyn PrivilegeEscalator> {
    if is_root() {
        return Box::new(NoEscalation);
    }

    CANDIDATES
        .iter()
        .find(|program| find_in_path(program).is_some())
        .map_or_else(
            || Box::new(UnavailableEscalation) as Box<dyn PrivilegeEscalator>,
            |program| Box::new(HelperEscalation::new(*program)) as Box<dyn PrivilegeEscalator>,
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

/// Looks a program up in `PATH`, returning the first executable match.
fn find_in_path(program: &str) -> Option<PathBuf> {
    let path = std::env::var_os("PATH")?;

    std::env::split_paths(&path)
        .map(|dir| dir.join(program))
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
        let (program, args) = HelperEscalation::new("sudo")
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
            let (program, args) = HelperEscalation::new(helper)
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
    fn finds_a_program_that_exists_in_path() {
        assert!(find_in_path("sh").is_some(), "sh must exist in PATH");
    }

    #[test]
    fn does_not_find_a_nonexistent_program() {
        assert!(find_in_path("initd-nonexistent-binary").is_none());
    }

    #[test]
    fn detection_always_yields_a_mechanism() {
        // Never panics regardless of environment: worst case it is the
        // Unavailable variant, which fails only when root is actually needed.
        assert!(!detect().name().is_empty());
    }

    #[test]
    fn sudo_is_asked_whether_its_timestamp_is_still_valid() {
        let need = HelperEscalation::new(SUDO).auth_need();

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
        let need = HelperEscalation::new(DOAS).auth_need();

        assert_eq!(
            need,
            AuthNeed::Probe {
                program: DOAS.to_owned(),
                args: vec!["-n".to_owned(), "true".to_owned()],
            }
        );
    }

    #[test]
    fn run0_is_asked_rather_than_assumed_to_prompt() {
        // polkit owns the prompt, but run0 still answers whether one is
        // coming: `--no-ask-password` refuses instead of asking. Measured on
        // Arch with systemd as PID 1 and polkit active.
        let need = HelperEscalation::new(RUN0).auth_need();

        assert_eq!(
            need,
            AuthNeed::Probe {
                program: RUN0.to_owned(),
                args: vec!["--no-ask-password".to_owned(), "true".to_owned()],
            }
        );
    }

    #[test]
    fn an_unknown_helper_hands_the_terminal_over_regardless() {
        // The dangerous direction is claiming a mechanism will not prompt when
        // it will, so anything unrecognised errs towards a needless handoff.
        assert_eq!(
            HelperEscalation::new("something-else").auth_need(),
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
                HelperEscalation::new(candidate).auth_need(),
                AuthNeed::Never,
                "{candidate} must not claim it will never prompt"
            );
        }
    }
}
