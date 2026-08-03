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
const CANDIDATES: [&str; 3] = [SUDO, "doas", "run0"];

/// The one helper that can authenticate ahead of the work.
const SUDO: &str = "sudo";

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
}
