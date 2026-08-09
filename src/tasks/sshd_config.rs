//! `sshd_config` editing and validation.
//!
//! Shared by the hardening and port tasks: both set directives, both must
//! validate before reloading, and both must restore their backup if the new
//! configuration is rejected.

use crate::backend::{Backend, Capability};
use crate::domain::files::Backup;
use crate::error::{Error, Result};
use crate::exec::{Command, Executor, OutputLine, Stream};
use crate::tasks::Progress;

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
///
/// A directive absent from the file is written before the first `Match` line
/// rather than at the end. Everything following a `Match` belongs to that
/// block, so appending would scope the directive to whoever the block matches
/// instead of to the server. Measured against OpenSSH 10.0: `PermitRootLogin
/// no` written after `Match User deployer` leaves `sshd -T` reporting
/// `without-password` for every other user, so a task that reported success
/// would have hardened nobody but `deployer`.
pub fn set_directive(contents: &str, directive: &str, value: &str) -> String {
    let mut result = String::with_capacity(contents.len() + 64);
    let mut replaced = false;

    for line in contents.lines() {
        // The first `Match` ends the global section. A directive not seen by
        // now has to be written here, while it still applies to everyone.
        if !replaced && is_match_line(line) {
            result.push_str(&format!("{directive} {value}\n"));
            replaced = true;
        }

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

/// Whether a line opens a `Match` block.
///
/// Keywords are case-insensitive, and a commented-out `Match` opens nothing.
fn is_match_line(line: &str) -> bool {
    let trimmed = line.trim_start();

    trimmed
        .split_whitespace()
        .next()
        .is_some_and(|keyword| keyword.eq_ignore_ascii_case("match"))
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

/// Warns about directives the daemon will not honour as written.
///
/// `sshd -t` says the file parses; it does not say the file wins. Debian 12,
/// Ubuntu 22.04 and RHEL 9 all ship `Include /etc/ssh/sshd_config.d/*.conf` as
/// the first line, and sshd takes the *first* occurrence of a directive — so a
/// drop-in put there by a provider image (`50-cloud-init.conf` is the ordinary
/// one) beats everything written below it.
///
/// Reproduced on `debian:13`: with that drop-in holding `PasswordAuthentication
/// yes`, writing `PasswordAuthentication no` into the main file leaves `sshd -T`
/// reporting `passwordauthentication yes`, and `sshd -t` approves. The task
/// reported hardening that had not happened.
///
/// `sshd -T` is what settles it, being the daemon's own account of its
/// effective configuration after every `Include` and `Match` is resolved.
/// Warned rather than refused, and not rolled back: what was written is
/// correct, and an administrator who put the drop-in there on purpose is not
/// making a mistake. The two sibling situations are treated the same way —
/// `ssh.socket` owning the port, and this.
fn warn_if_overridden(
    executor: &dyn Executor,
    contents: &str,
    progress: Progress<'_>,
) -> Result<()> {
    // Asked once and read for every directive: `sshd -T` is a whole daemon
    // startup, so one call answers what a call per directive would.
    let command = Command::new("sshd").arg("-T").privileged();
    let output = executor.run(&command)?;

    if !output.success() {
        // The same reasoning as `NON_SYNTAX_FAILURES`: a host with no host keys
        // cannot answer this, and that is not a finding about the file.
        return Ok(());
    }

    let effective: Vec<(String, String)> = output
        .stdout
        .lines()
        .filter_map(|line| line.split_once(' '))
        .map(|(key, value)| (key.to_ascii_lowercase(), value.trim().to_ascii_lowercase()))
        .collect();

    for (directive, wanted) in written_directives(contents) {
        let key = directive.to_ascii_lowercase();

        // Only directives sshd reports back. A keyword it does not know about
        // is already handled by `accepts_directive` before anything is written.
        let Some((_, actual)) = effective.iter().find(|(name, _)| *name == key) else {
            continue;
        };

        if *actual != wanted.to_ascii_lowercase() {
            progress(OutputLine {
                stream: Stream::Stderr,
                text: format!(
                    "warning: {directive} was written as {wanted}, but this daemon \
                     reports {actual}. Something read earlier wins — most often a \
                     file in /etc/ssh/sshd_config.d/, which the Include at the top \
                     of sshd_config reads before anything below it."
                ),
            });
        }
    }

    Ok(())
}

/// The directives a written file sets, outside any `Match` block.
///
/// Stops at the first `Match` for the same reason [`set_directive`] writes
/// before it: what follows belongs to that block, and comparing it against the
/// daemon's global configuration would report a difference that is the point of
/// the block rather than a fault.
fn written_directives(contents: &str) -> Vec<(String, String)> {
    contents
        .lines()
        .take_while(|line| !is_match_line(line))
        .filter_map(|line| {
            let line = line.trim();

            if line.is_empty() || line.starts_with('#') {
                return None;
            }

            line.split_once(char::is_whitespace)
                .map(|(key, value)| (key.to_owned(), value.trim().to_owned()))
        })
        .collect()
}

/// Writes new configuration contents, validating before committing.
///
/// The order is what makes a rejected configuration recoverable: back up,
/// write, validate, and restore the backup if validation rejects the result.
/// Validating before writing would say nothing about the file the daemon will
/// actually read. The service is only reloaded by the caller once this returns
/// successfully.
///
/// A file that parses is then checked for whether it *wins*, which is a
/// separate question — see [`warn_if_overridden`].
pub fn write_validated(
    executor: &dyn Executor,
    backend: &dyn Backend,
    contents: &str,
    progress: Progress<'_>,
) -> Result<Option<Backup>> {
    let path = backend.path_for(Capability::Ssh);
    let backup = backend.files().write(executor, path, contents)?;

    match validate(executor)? {
        Validation::Valid | Validation::Inconclusive { .. } => {
            // After the file is in place, because what is being asked is what
            // the daemon would do with it — and only warned about, since the
            // write itself is correct.
            warn_if_overridden(executor, contents, progress)?;

            Ok(backup)
        }
        Validation::Invalid { details } => {
            // Never leave a broken config in place: put the original back
            // before returning, and do not reload.
            //
            // The restore's own failure is carried alongside the rejection
            // rather than through `?`, which would return it *instead*. Both
            // halves are needed and neither implies the other: the rejection
            // says what is wrong with the file, and only the restore's failure
            // says that the rejected file is still the one on disk — the case
            // where the daemon will not come back after a reload nobody
            // performed. Reported as one message because a task raises one
            // error, and the half that got dropped was the half naming the
            // syntax to fix.
            if let Some(ref backup) = backup
                && let Err(restore) = backend.files().restore(executor, backup)
            {
                return Err(Error::InvalidSshdConfig {
                    details: format!(
                        "{details}; the original could not be put back either \
                         ({restore}), so the rejected file is still at {} and \
                         {} holds the copy",
                        path, backup.copy
                    ),
                });
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
    fn a_new_directive_lands_before_the_first_match_block() {
        // Everything after a `Match` line belongs to that block, so appending a
        // directive to a file ending in one silently scopes it to whoever the
        // block matches. Measured against OpenSSH 10.0: with `PermitRootLogin
        // no` written after `Match User deployer`, `sshd -T` reports
        // `without-password` for every other user — the hardening the task
        // reported as applied does not apply to them.
        let contents = "Port 22\nMatch User deployer\n    X11Forwarding yes\n";
        let result = set_directive(contents, "PermitRootLogin", "no");

        let directive = result
            .lines()
            .position(|line| line.starts_with("PermitRootLogin"))
            .expect("the directive must be written");
        let match_block = result
            .lines()
            .position(|line| line.starts_with("Match "))
            .expect("the Match block must survive");

        assert!(
            directive < match_block,
            "a global directive must precede the first Match block, got:\n{result}"
        );
    }

    #[test]
    fn a_new_directive_is_appended_when_there_is_no_match_block() {
        // Without a block to fall into, the end of the file is global.
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
        // Strict, because the failing reply has to land on `sshd -t` and
        // nothing but a comment used to say that it did. Insert a command
        // anywhere before it under the lenient mock and the failure slides
        // onto `tee` instead: validation then "passes", nothing is rolled
        // back, and this test goes on asserting a rollback it caused by
        // accident. The queue is now the claim.
        let mock = MockExecutor::with_exact_replies([
            Reply::ok(""),                                        // test -e
            Reply::ok(""),                                        // cp -p: backup
            Reply::ok(""),                                        // tee: stage
            Reply::ok("600"),                                     // stat -c %a
            Reply::ok(""),                                        // chmod
            Reply::ok(""),                                        // mv: publish
            Reply::failure(255, "Bad configuration option: Prt"), // sshd -t
            Reply::ok(""),                                        // cp -p: restore
        ]);
        let backend = crate::backend::for_family(crate::distro::Family::Debian);

        let err = write_validated(&mock, backend.as_ref(), "Prt 22\n", &mut |_| {})
            .expect_err("an invalid config must fail");

        assert!(matches!(err, Error::InvalidSshdConfig { .. }), "{err:?}");

        let commands = mock.recorded_lines();
        // Asking the backend rather than a local constant keeps the assertion
        // tied to the path the code under test actually resolves.
        let path = backend.path_for(Capability::Ssh);
        let restore = format!("cp -p {path}.initd.bak {path}");
        assert!(
            commands.contains(&restore),
            "the backup must be restored: {commands:?}"
        );
    }

    #[test]
    fn a_failed_restore_reports_the_rejection_that_caused_it() {
        // Both halves or neither: the rejection names the syntax to fix, and
        // only the restore's failure says the rejected file is still the one
        // on disk. Returning the restore's error on its own — which is what
        // `?` did here — left an operator reading "command failed" over a
        // config that `sshd -t` had refused, with nothing saying why.
        let mock = MockExecutor::with_exact_replies([
            Reply::ok(""),                                        // test -e
            Reply::ok(""),                                        // cp -p: backup
            Reply::ok(""),                                        // tee: stage
            Reply::ok("600"),                                     // stat -c %a
            Reply::ok(""),                                        // chmod
            Reply::ok(""),                                        // mv: publish
            Reply::failure(255, "Bad configuration option: Prt"), // sshd -t
            Reply::failure(1, "cp: cannot create regular file"),  // cp -p: restore
        ]);
        let backend = crate::backend::for_family(crate::distro::Family::Debian);

        let err = write_validated(&mock, backend.as_ref(), "Prt 22\n", &mut |_| {})
            .expect_err("a rejected config must fail");

        let Error::InvalidSshdConfig { details } = &err else {
            panic!("the rejection must survive the failed restore: {err:?}");
        };

        assert!(
            details.contains("Prt"),
            "the syntax error must still be named: {details}"
        );
        assert!(
            details.contains("could not be put back"),
            "the failed restore must be reported too: {details}"
        );

        // The path to the copy is what an operator needs to put the file back
        // by hand, which is the only route left once the restore has failed.
        let path = backend.path_for(Capability::Ssh);
        assert!(
            details.contains(&format!("{path}.initd.bak")),
            "the backup's path must be named: {details}"
        );
    }

    #[test]
    fn a_directive_the_daemon_overrides_is_reported() {
        // Reproduced on debian:13 before this existed: with
        // `PasswordAuthentication yes` in a /etc/ssh/sshd_config.d/ drop-in —
        // `50-cloud-init.conf` on any provider image — writing
        // `PasswordAuthentication no` into the main file leaves `sshd -T`
        // saying `passwordauthentication yes`, and `sshd -t` approves. The
        // task reported hardening that had not happened.
        let mock = MockExecutor::with_replies([
            Reply::ok(""),                             // test -e
            Reply::ok(""),                             // cp -p
            Reply::ok(""),                             // tee
            Reply::ok("600"),                          // stat
            Reply::ok(""),                             // chmod
            Reply::ok(""),                             // mv
            Reply::ok(""),                             // sshd -t
            Reply::ok("passwordauthentication yes\n"), // sshd -T: the drop-in won
        ]);
        let backend = crate::backend::for_family(crate::distro::Family::Debian);

        let mut warnings = Vec::new();

        write_validated(
            &mock,
            backend.as_ref(),
            "PasswordAuthentication no\n",
            &mut |line| {
                if line.stream == Stream::Stderr {
                    warnings.push(line.text);
                }
            },
        )
        .expect("a file that parses must still commit");

        assert!(
            warnings
                .iter()
                .any(|line| line.contains("PasswordAuthentication")
                    && line.contains("sshd_config.d")),
            "the operator must be told the write had no effect: {warnings:?}"
        );
    }

    #[test]
    fn a_directive_the_daemon_agrees_with_is_not_reported() {
        // The warning has to be rare to be read. A daemon reporting what was
        // written is the ordinary case and must stay silent — including across
        // the case differences `sshd -T` introduces, since it lowercases every
        // keyword it prints.
        let mock = MockExecutor::with_replies([
            Reply::ok(""),
            Reply::ok(""),
            Reply::ok(""),
            Reply::ok("600"),
            Reply::ok(""),
            Reply::ok(""),
            Reply::ok(""),
            Reply::ok("passwordauthentication no\n"),
        ]);
        let backend = crate::backend::for_family(crate::distro::Family::Debian);

        let mut warnings = Vec::new();

        write_validated(
            &mock,
            backend.as_ref(),
            "PasswordAuthentication no\n",
            &mut |line| {
                if line.stream == Stream::Stderr {
                    warnings.push(line.text);
                }
            },
        )
        .expect("a valid config must commit");

        assert!(warnings.is_empty(), "nothing to warn about: {warnings:?}");
    }

    #[test]
    fn a_directive_inside_a_match_block_is_not_compared() {
        // What follows a `Match` applies to whoever it matches, so comparing it
        // against the daemon's global configuration would report the block
        // working as designed.
        let written = written_directives(
            "PermitRootLogin no\nMatch User deployer\n    PermitRootLogin yes\n",
        );

        assert_eq!(
            written,
            [("PermitRootLogin".to_owned(), "no".to_owned())],
            "only the global section is the server's own configuration"
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

        write_validated(&mock, backend.as_ref(), "Port 22\n", &mut |_| {})
            .expect("a valid config must commit");

        // Asking the backend rather than a local constant keeps the assertion
        // tied to the path the code under test actually resolves.
        let path = backend.path_for(Capability::Ssh);
        let restore = format!("cp -p {path}.initd.bak {path}");
        assert!(
            !mock.recorded_lines().contains(&restore),
            "a valid config must not be rolled back"
        );
    }

    #[test]
    fn missing_host_keys_do_not_roll_back_a_valid_file() {
        // The Arch case: the write must survive an inconclusive validation.
        let mock = MockExecutor::with_replies([
            Reply::ok(""),    // test -e
            Reply::ok(""),    // cp -p: backup
            Reply::ok(""),    // tee: stage
            Reply::ok("600"), // stat -c %a
            Reply::ok(""),    // chmod
            Reply::ok(""),    // mv: publish
            Reply::failure(1, "no hostkeys available -- exiting."),
        ]);
        let backend = crate::backend::for_family(crate::distro::Family::Arch);

        write_validated(&mock, backend.as_ref(), "Port 22\n", &mut |_| {})
            .expect("an inconclusive validation must not fail the write");

        // Asking the backend rather than a local constant keeps the assertion
        // tied to the path the code under test actually resolves.
        let path = backend.path_for(Capability::Ssh);
        let restore = format!("cp -p {path}.initd.bak {path}");
        assert!(!mock.recorded_lines().contains(&restore));
    }
}
