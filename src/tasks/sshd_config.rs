//! `sshd_config` editing and validation.
//!
//! Shared by the hardening and port tasks: both set directives, both must
//! validate before reloading, and both must restore their backup if the new
//! configuration is rejected.

use crate::backend::Backend;
use crate::domain::files::Backup;
use crate::error::{Error, Result};
use crate::exec::{Command, Executor};

/// Location of the server configuration. Identical across both families —
/// unlike the package and unit names.
pub const SSHD_CONFIG: &str = "/etc/ssh/sshd_config";

/// Outcome of validating a configuration with `sshd -t`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Validation {
    /// The configuration parses.
    Valid,
    /// The configuration is syntactically wrong.
    Invalid { details: String },
    /// Validation could not reach a verdict for a reason unrelated to syntax.
    ///
    /// Verified empirically on a fresh Arch container: `sshd -t` fails with
    /// `no hostkeys available -- exiting` on a valid file simply because host
    /// keys have not been generated yet. Treating that as invalid would make
    /// the task refuse a perfectly good configuration.
    Inconclusive { reason: String },
}

/// Markers that mean "sshd could not run", not "the config is wrong".
const NON_SYNTAX_FAILURES: [&str; 2] = ["no hostkeys available", "unable to load host key"];

/// Runs `sshd -t` and classifies the outcome.
pub fn validate(executor: &dyn Executor) -> Result<Validation> {
    // `-t` is test mode: parse the config and exit without serving.
    let command = Command::new("sshd").arg("-t").privileged();

    classify(executor, &command)
}

/// Whether this sshd recognises a directive at all.
///
/// `-o` applies an override on top of the live configuration, so the daemon
/// parses the keyword without anything being written first. `Inconclusive`
/// counts as recognised: missing host keys say nothing about whether the
/// keyword is known, and on a freshly installed system that is the answer
/// every probe would get.
///
/// This exists because a keyword sshd does not know is not a warning — it is a
/// rejected configuration, and `write_validated` responds by restoring the
/// backup, discarding every other directive set alongside it. Probing costs
/// one command and protects the whole change.
pub fn accepts_directive(executor: &dyn Executor, directive: &str, value: &str) -> Result<bool> {
    let command = Command::new("sshd")
        .args(["-t", "-o", &format!("{directive}={value}")])
        .privileged();

    Ok(!matches!(
        classify(executor, &command)?,
        Validation::Invalid { .. }
    ))
}

/// Runs a validation command and classifies what it reports.
///
/// Shared so that a probe and a full validation agree on what counts as a
/// syntax error: both distinguish "sshd rejected this" from "sshd could not
/// run", and the second must never be read as the first.
fn classify(executor: &dyn Executor, command: &Command) -> Result<Validation> {
    let output = executor.run(command)?;

    if output.success() {
        return Ok(Validation::Valid);
    }

    let stderr = output.stderr.trim().to_owned();
    let lowered = stderr.to_ascii_lowercase();

    if NON_SYNTAX_FAILURES
        .iter()
        .any(|marker| lowered.contains(marker))
    {
        return Ok(Validation::Inconclusive { reason: stderr });
    }

    Ok(Validation::Invalid { details: stderr })
}

/// Sets a directive, replacing any existing definition.
///
/// Existing lines for the directive are commented out rather than deleted, so
/// the previous value stays visible to whoever reads the file later. A
/// commented-out original is also what an administrator expects to find.
pub fn set_directive(contents: &str, directive: &str, value: &str) -> String {
    let mut result = String::with_capacity(contents.len() + 64);
    let mut replaced = false;

    for line in contents.lines() {
        if is_directive_line(line, directive) {
            // Keep the original as a comment, then write the new value in its
            // place so ordering relative to Match blocks is preserved.
            result.push_str("# ");
            result.push_str(line.trim_end());
            result.push('\n');

            if !replaced {
                result.push_str(&format!("{directive} {value}\n"));
                replaced = true;
            }
        } else {
            result.push_str(line);
            result.push('\n');
        }
    }

    if !replaced {
        result.push_str(&format!("{directive} {value}\n"));
    }

    result
}

/// Reads the effective value of a directive, ignoring commented-out lines.
pub fn directive_value(contents: &str, directive: &str) -> Option<String> {
    contents
        .lines()
        .rfind(|line| is_directive_line(line, directive) && !line.trim_start().starts_with('#'))
        .and_then(|line| line.split_once(char::is_whitespace))
        .map(|(_, value)| value.trim().to_owned())
}

/// Whether a line defines the given directive, commented out or not.
///
/// `sshd_config` keywords are case-insensitive, and a commented line still
/// counts here so that replacing a directive also neutralises its commented
/// variants rather than leaving a confusing duplicate.
fn is_directive_line(line: &str, directive: &str) -> bool {
    let trimmed = line.trim_start().trim_start_matches('#').trim_start();

    trimmed
        .split_once(char::is_whitespace)
        .is_some_and(|(keyword, _)| keyword.eq_ignore_ascii_case(directive))
}

/// Writes new configuration contents, validating before committing.
///
/// The order is what makes a rejected configuration recoverable: back up,
/// write, validate, and restore the backup if validation rejects the result.
/// Validating before writing would say nothing about the file the daemon will
/// actually read. The service is only reloaded by the caller once this returns
/// successfully.
pub fn write_validated(
    executor: &dyn Executor,
    backend: &dyn Backend,
    contents: &str,
) -> Result<Option<Backup>> {
    let backup = backend.files().write(executor, SSHD_CONFIG, contents)?;

    match validate(executor)? {
        Validation::Valid | Validation::Inconclusive { .. } => Ok(backup),
        Validation::Invalid { details } => {
            // Never leave a broken config in place: put the original back
            // before returning, and do not reload.
            if let Some(ref backup) = backup {
                backend.files().restore(executor, backup)?;
            }

            Err(Error::InvalidSshdConfig { details })
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::exec::mock::{MockExecutor, Reply};

    #[test]
    fn appends_a_directive_that_is_absent() {
        let result = set_directive("Port 22\n", "PermitRootLogin", "no");

        assert_eq!(result, "Port 22\nPermitRootLogin no\n");
    }

    #[test]
    fn replaces_an_existing_directive_and_keeps_the_original_commented() {
        let result = set_directive("PermitRootLogin yes\n", "PermitRootLogin", "no");

        assert_eq!(result, "# PermitRootLogin yes\nPermitRootLogin no\n");
    }

    #[test]
    fn replaces_a_commented_out_directive() {
        // A default config ships the directive commented out; writing a new
        // value must not leave a confusing pair of lines.
        let result = set_directive(
            "#PermitRootLogin prohibit-password\n",
            "PermitRootLogin",
            "no",
        );

        assert!(result.contains("PermitRootLogin no\n"));
        assert_eq!(result.matches("PermitRootLogin no").count(), 1);
    }

    #[test]
    fn matches_directives_case_insensitively() {
        // sshd_config keywords are case-insensitive.
        let result = set_directive("permitrootlogin yes\n", "PermitRootLogin", "no");

        assert!(result.contains("# permitrootlogin yes"));
        assert!(result.contains("PermitRootLogin no"));
    }

    #[test]
    fn collapses_duplicate_definitions_into_one() {
        // Two active definitions must become one, with both originals kept as
        // comments so the previous state stays readable.
        let result = set_directive("Port 22\nPort 2222\n", "Port", "2022");

        assert_eq!(
            result.lines().filter(|l| l.starts_with("Port ")).count(),
            1,
            "only one active definition may remain: {result}"
        );
        assert!(result.contains("Port 2022"));
        assert!(result.contains("# Port 22"));
        assert!(result.contains("# Port 2222"));
    }

    #[test]
    fn does_not_touch_a_directive_with_a_similar_name() {
        let result = set_directive("PermitRootLoginExtra yes\n", "PermitRootLogin", "no");

        assert!(result.contains("PermitRootLoginExtra yes"));
    }

    #[test]
    fn reads_the_effective_value_ignoring_comments() {
        let contents = "# Port 22\nPort 2222\n";

        assert_eq!(directive_value(contents, "Port").as_deref(), Some("2222"));
    }

    #[test]
    fn reports_no_value_when_the_directive_is_absent() {
        assert_eq!(directive_value("Port 22\n", "PermitRootLogin"), None);
    }

    #[test]
    fn validation_accepts_a_clean_run() {
        let mock = MockExecutor::with_replies([Reply::ok("")]);

        assert_eq!(validate(&mock).expect("runs"), Validation::Valid);
    }

    #[test]
    fn missing_host_keys_are_inconclusive_not_invalid() {
        // Verified on a fresh Arch container: this failure says nothing about
        // the syntax of the file.
        let mock =
            MockExecutor::with_replies([Reply::failure(1, "no hostkeys available -- exiting.")]);

        assert!(
            matches!(
                validate(&mock).expect("runs"),
                Validation::Inconclusive { .. }
            ),
            "missing host keys must not be reported as a syntax error"
        );
    }

    #[test]
    fn a_syntax_error_is_invalid() {
        let mock = MockExecutor::with_replies([Reply::failure(
            255,
            "/etc/ssh/sshd_config: line 3: Bad configuration option: Prt",
        )]);

        assert!(matches!(
            validate(&mock).expect("runs"),
            Validation::Invalid { .. }
        ));
    }

    #[test]
    fn a_directive_this_sshd_parses_is_accepted() {
        let mock = MockExecutor::with_replies([Reply::ok("")]);

        assert!(
            accepts_directive(&mock, "KbdInteractiveAuthentication", "no").expect("the probe runs")
        );
    }

    #[test]
    fn an_unknown_directive_is_rejected() {
        // Measured: the probe reports this on stderr rather than through the
        // exit code, which is 1 here and not the 255 a file with the same
        // error produces.
        let mock = MockExecutor::with_replies([Reply::failure(
            1,
            "command-line: line 0: Bad configuration option: KbdInteractiveAuthentication",
        )]);

        assert!(!accepts_directive(&mock, "KbdInteractiveAuthentication", "no").expect("runs"));
    }

    #[test]
    fn missing_host_keys_do_not_make_a_directive_look_unknown() {
        // On a freshly installed system `sshd -t` always fails this way, so
        // reading it as "unknown keyword" would skip every probed directive on
        // exactly the machines this tool is pointed at.
        let mock = MockExecutor::with_replies([Reply::failure(
            1,
            "sshd: no hostkeys available -- exiting.",
        )]);

        assert!(
            accepts_directive(&mock, "KbdInteractiveAuthentication", "no").expect("runs"),
            "an unrunnable sshd says nothing about the keyword"
        );
    }

    #[test]
    fn the_probe_overrides_rather_than_writing() {
        // The keyword must be tested without the file being touched first: a
        // probe that wrote would be the very rollback it exists to avoid.
        let mock = MockExecutor::with_replies([Reply::ok("")]);

        accepts_directive(&mock, "PermitTunnel", "no").expect("runs");

        let command = mock.single_command();
        assert!(
            command.to_string().contains("-o PermitTunnel=no"),
            "got: {command}"
        );
    }

    #[test]
    fn an_invalid_config_is_rolled_back_and_never_committed() {
        // Replies: test -e (exists), cp (backup), tee (write), sshd -t (fails),
        // cp (restore).
        let mock = MockExecutor::with_replies([
            Reply::ok(""),
            Reply::ok(""),
            Reply::ok(""),
            Reply::failure(255, "Bad configuration option: Prt"),
            Reply::ok(""),
        ]);
        let backend = crate::backend::for_family(crate::distro::Family::Debian);

        let err = write_validated(&mock, backend.as_ref(), "Prt 22\n")
            .expect_err("an invalid config must fail");

        assert!(matches!(err, Error::InvalidSshdConfig { .. }), "{err:?}");

        let commands = mock.recorded_lines();
        let restore = format!("cp -p {SSHD_CONFIG}.initd.bak {SSHD_CONFIG}");
        assert!(
            commands.contains(&restore),
            "the backup must be restored: {commands:?}"
        );
    }

    #[test]
    fn a_valid_config_is_kept() {
        let mock = MockExecutor::with_replies([
            Reply::ok(""),
            Reply::ok(""),
            Reply::ok(""),
            Reply::ok(""),
        ]);
        let backend = crate::backend::for_family(crate::distro::Family::Debian);

        write_validated(&mock, backend.as_ref(), "Port 22\n").expect("a valid config must commit");

        let restore = format!("cp -p {SSHD_CONFIG}.initd.bak {SSHD_CONFIG}");
        assert!(
            !mock.recorded_lines().contains(&restore),
            "a valid config must not be rolled back"
        );
    }

    #[test]
    fn missing_host_keys_do_not_roll_back_a_valid_file() {
        // The Arch case: the write must survive an inconclusive validation.
        let mock = MockExecutor::with_replies([
            Reply::ok(""),
            Reply::ok(""),
            Reply::ok(""),
            Reply::failure(1, "no hostkeys available -- exiting."),
        ]);
        let backend = crate::backend::for_family(crate::distro::Family::Arch);

        write_validated(&mock, backend.as_ref(), "Port 22\n")
            .expect("an inconclusive validation must not fail the write");

        let restore = format!("cp -p {SSHD_CONFIG}.initd.bak {SSHD_CONFIG}");
        assert!(!mock.recorded_lines().contains(&restore));
    }
}
