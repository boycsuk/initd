//! `sshd_config` editing and validation.
//!
//! Shared by the hardening and port tasks: both set directives, both must
//! validate before reloading, and both must restore their backup if the new
//! configuration is rejected.

use crate::backend::backup_index;
use crate::backend::{Backend, Capability};
use crate::domain::FileEditor;
use crate::domain::files::Backup;
use crate::error::{Error, Result};
use crate::exec::{Command, Executor, OutputLine, Stream};
use crate::tasks::Progress;
use crate::tasks::ssh::DEFAULT_SSH_PORT;

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

/// The port the daemon is actually listening on.
///
/// Asked of `sshd -T` rather than read from the file, because the file answers
/// a different question. A host that has never been reconfigured has **no**
/// `Port` line at all — measured on `debian:13`, where `grep -c '^Port'`
/// answers 0 while the daemon serves 22 — so a reader that only parsed the
/// file would find nothing in the commonest case, and would also miss a value
/// set in an `Include`d drop-in. `sshd -T` resolves includes and defaults and
/// prints `port 2222` for a moved daemon.
///
/// Falls back to the file, then to [`DEFAULT_SSH_PORT`], because `sshd -T`
/// fails on a host with no host keys — `no hostkeys available -- exiting`,
/// which this project already records for a freshly installed Arch. That is a
/// daemon that has never run, so the file is the better authority there.
///
/// Returns a value rather than an error on every path: this fills in a form
/// field, and a form that refused to open because a probe failed would be
/// worse than one that opens on the default.
pub fn effective_port(executor: &dyn Executor, config_path: &str) -> u32 {
    let query = Command::new("sshd").arg("-T");

    if let Ok(output) = executor.run(&query)
        && output.success()
        && let Some(port) = port_in_dump(&output.stdout)
    {
        return port;
    }

    // The file, for the host whose daemon cannot answer for itself.
    let files = crate::backend::unix_files::UnixFiles::new();

    if let Ok(contents) = files.read(executor, config_path)
        && let Some(port) = directive_value(&contents, "Port")
        && let Ok(port) = port.parse()
    {
        return port;
    }

    DEFAULT_SSH_PORT
}

/// The `port` line in an `sshd -T` dump.
///
/// The dump lowercases every keyword and prints one setting per line, so the
/// match is exact rather than a prefix: `port` and `portforwarding` would both
/// answer a `starts_with`, and only one of them is a port.
fn port_in_dump(dump: &str) -> Option<u32> {
    dump.lines()
        .filter_map(|line| line.split_once(char::is_whitespace))
        .find(|(keyword, _)| *keyword == "port")
        .and_then(|(_, value)| value.trim().parse().ok())
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
            progress(OutputLine::new(
                Stream::Stderr,
                format!(
                    "warning: {directive} was written as {wanted}, but this daemon \
                     reports {actual}. Something read earlier wins — most often a \
                     file in /etc/ssh/sshd_config.d/, which the Include at the top \
                     of sshd_config reads before anything below it."
                ),
            ));
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
    task: &'static str,
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

            // Only once the configuration is known good, and only where there
            // was a previous version to keep: a file this task created has no
            // earlier state, and a record claiming one would offer to restore
            // an empty file.
            //
            // Said either way rather than only on success. An operator who
            // assumes tomorrow's revert is available and finds none is worse
            // off than one told today, and silence produces the first.
            let Some(mut backup) = backup else {
                return Ok(None);
            };

            let kept = backup_index::record_and_report(
                executor,
                backend.files(),
                task,
                Some(&backup),
                backend.service_for(Capability::Ssh),
                progress,
            );

            // The returned `Backup` names where the copy *is*, not where it
            // was made. Both hardening tasks and the port task print this path
            // so that an operator who has locked themselves out knows what to
            // restore from — and recording moves the file, so returning the
            // original `.initd.bak` would hand them a path that no longer
            // exists, in the one message that matters most.
            if let Some(kept) = kept {
                backup.copy = kept;
            }

            Ok(Some(backup))
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
    fn the_port_comes_from_the_daemon_rather_than_the_file() {
        // The file is the wrong authority for this and the difference is not
        // academic: a host that has never been reconfigured has no `Port` line
        // at all — measured on `debian:13`, where `grep -c '^Port'` answers 0
        // while the daemon serves 22 — so a reader that parsed only the file
        // would find nothing in the commonest case. `sshd -T` resolves
        // includes and defaults.
        let mock = MockExecutor::with_replies([Reply::ok(
            "port 2222\naddressfamily any\npermitrootlogin no\n",
        )]);

        assert_eq!(effective_port(&mock, "/etc/ssh/sshd_config"), 2222);
    }

    #[test]
    fn a_daemon_that_cannot_answer_leaves_the_file_to_say() {
        // `sshd -T` fails with `no hostkeys available -- exiting` on a host
        // where the daemon has never run — recorded for a freshly installed
        // Arch. There the file is the better authority, since it is the only
        // one there is.
        let mock = MockExecutor::with_replies([
            Reply::failure(255, "sshd: no hostkeys available -- exiting."),
            Reply::ok("#Port 22\nPort 2022\nPermitRootLogin no\n"),
        ]);

        assert_eq!(effective_port(&mock, "/etc/ssh/sshd_config"), 2022);
    }

    #[test]
    fn a_host_that_says_nothing_gets_the_default() {
        // Both sources silent. Returns a value rather than an error on every
        // path: this fills in a form field, and refusing to open the form
        // because a probe failed is worse than opening it on 22.
        let mock =
            MockExecutor::with_replies([Reply::failure(1, ""), Reply::failure(1, "no such file")]);

        assert_eq!(
            effective_port(&mock, "/etc/ssh/sshd_config"),
            DEFAULT_SSH_PORT
        );
    }

    #[test]
    fn a_setting_whose_name_merely_starts_with_port_is_not_the_port() {
        // The dump lowercases every keyword and prints one per line, so
        // `portforwarding` sits in the same list as `port` and would answer a
        // prefix match. Only one of them is a port number, and the other is a
        // word — which would parse to nothing and silently fall through to the
        // file, quietly undoing the whole point of asking the daemon.
        assert_eq!(
            port_in_dump("gatewayports no\nportforwarding yes\nport 2222\n"),
            Some(2222)
        );
    }

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

        let err = write_validated(
            &mock,
            backend.as_ref(),
            "ssh.harden",
            "Prt 22\n",
            &mut |_| {},
        )
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

        let err = write_validated(
            &mock,
            backend.as_ref(),
            "ssh.harden",
            "Prt 22\n",
            &mut |_| {},
        )
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
    fn a_change_is_recorded_where_there_was_a_previous_version_to_keep() {
        // The copy `write` already took is moved under /var/lib/initd with a
        // timestamp in its name, rather than a second one being made: the fixed
        // `.initd.bak` is reused by the next write to the same path, so a copy
        // left there is the copy the second change destroys.
        let mock = MockExecutor::with_replies([
            Reply::ok(""),                               // test -e: the file exists
            Reply::ok(""),                               // cp -p (write's own backup)
            Reply::ok(""),                               // tee
            Reply::ok("600"),                            // stat -c %a
            Reply::ok(""),                               // chmod
            Reply::ok(""),                               // mv into place
            Reply::ok(""),                               // sshd -t
            Reply::ok("port 22\n"),                      // sshd -T
            Reply::ok("20260809T142203Z\n"),             // date -u
            Reply::ok(""),                               // install -d /var/lib/initd
            Reply::ok(""),                               // install -d …/backups
            Reply::failure(1, ""),                       // test -e: the name is free
            Reply::ok(""),                               // mv the copy under /var/lib
            Reply::ok(format!("{}  x", "a".repeat(64))), // digest of the copy
            Reply::ok(format!("{}  y", "b".repeat(64))), // digest of the new file
            Reply::ok(""),                               // install -d /var/lib/initd
            Reply::ok(""),                               // install -d …/backups
            Reply::ok(""),                               // append
            Reply::ok(""),                               // chmod 600 on the index
        ]);
        let backend = crate::backend::for_family(crate::distro::Family::Debian);

        write_validated(
            &mock,
            backend.as_ref(),
            "ssh.harden",
            "Port 22\n",
            &mut |_| {},
        )
        .expect("the write must succeed");

        let commands = mock.recorded_lines();

        assert!(
            commands
                .iter()
                .any(|line| line.contains("/var/lib/initd/backups/etc-ssh-sshd_config.")),
            "the copy must be moved somewhere the next write cannot reach: {commands:?}"
        );
        assert!(
            commands.iter().any(|line| line.contains("backups.jsonl")),
            "the record must be appended: {commands:?}"
        );
    }

    #[test]
    fn the_backup_returned_is_where_the_copy_actually_is() {
        // The three tasks that call this print the returned path so an operator
        // who has locked themselves out knows what to restore from. Recording
        // *moves* the copy, so returning the `.initd.bak` it was made at would
        // name a file that no longer exists — in the one message that matters
        // most. Reproduced on alpine:3.23 before it was fixed.
        let mock = MockExecutor::with_replies([
            Reply::ok(""),                               // test -e
            Reply::ok(""),                               // cp -p
            Reply::ok(""),                               // tee
            Reply::ok("600"),                            // stat
            Reply::ok(""),                               // chmod
            Reply::ok(""),                               // mv into place
            Reply::ok(""),                               // sshd -t
            Reply::ok("port 22\n"),                      // sshd -T
            Reply::ok("20260809T142203Z\n"),             // date -u
            Reply::ok(""),                               // install -d
            Reply::ok(""),                               // install -d
            Reply::failure(1, ""),                       // test -e: the name is free
            Reply::ok(""),                               // mv the copy
            Reply::ok(format!("{}  x", "a".repeat(64))), // digest of the copy
            Reply::ok(format!("{}  y", "b".repeat(64))), // digest of the file
            Reply::ok(""),                               // install -d
            Reply::ok(""),                               // install -d
            Reply::ok(""),                               // append
            Reply::ok(""),                               // chmod on the index
        ]);
        let backend = crate::backend::for_family(crate::distro::Family::Debian);

        let backup = write_validated(
            &mock,
            backend.as_ref(),
            "ssh.harden",
            "Port 22\n",
            &mut |_| {},
        )
        .expect("the write must succeed")
        .expect("a file that existed must yield a backup");

        assert!(
            backup.copy.starts_with("/var/lib/initd/backups/"),
            "the path handed to the operator must be where the copy is: {}",
            backup.copy
        );
        assert!(
            !backup.copy.ends_with(".initd.bak"),
            "and not where it was made: {}",
            backup.copy
        );
    }

    #[test]
    fn a_file_that_did_not_exist_records_nothing_to_go_back_to() {
        // `write` reports no backup for a file it created, and a record
        // claiming a previous version would offer to restore an empty file.
        let mock = MockExecutor::with_replies([
            Reply::failure(1, ""),  // test -e: no such file
            Reply::ok(""),          // tee
            Reply::ok("600"),       // stat
            Reply::ok(""),          // chmod
            Reply::ok(""),          // mv
            Reply::ok(""),          // sshd -t
            Reply::ok("port 22\n"), // sshd -T
        ]);
        let backend = crate::backend::for_family(crate::distro::Family::Debian);

        write_validated(
            &mock,
            backend.as_ref(),
            "ssh.harden",
            "Port 22\n",
            &mut |_| {},
        )
        .expect("the write must succeed");

        assert!(
            !mock
                .recorded_lines()
                .iter()
                .any(|line| line.contains("backups.jsonl")),
            "{:?}",
            mock.recorded_lines()
        );
    }

    #[test]
    fn a_rejected_configuration_records_nothing() {
        // The record would name a state the machine deliberately does not
        // have: the file is rolled back, so offering to restore what preceded
        // it is offering to restore what is already there.
        let mock = MockExecutor::with_replies([
            Reply::ok(""),                                        // test -e
            Reply::ok(""),                                        // cp -p
            Reply::ok(""),                                        // tee
            Reply::ok("600"),                                     // stat
            Reply::ok(""),                                        // chmod
            Reply::ok(""),                                        // mv
            Reply::failure(255, "bad configuration option: Prt"), // sshd -t
            Reply::ok(""),                                        // restore
        ]);
        let backend = crate::backend::for_family(crate::distro::Family::Debian);

        write_validated(
            &mock,
            backend.as_ref(),
            "ssh.harden",
            "Prt 22\n",
            &mut |_| {},
        )
        .expect_err("an invalid configuration must be refused");

        assert!(
            !mock
                .recorded_lines()
                .iter()
                .any(|line| line.contains("backups.jsonl")),
            "{:?}",
            mock.recorded_lines()
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
            "ssh.harden",
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
            "ssh.harden",
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

        write_validated(
            &mock,
            backend.as_ref(),
            "ssh.harden",
            "Port 22\n",
            &mut |_| {},
        )
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

        write_validated(
            &mock,
            backend.as_ref(),
            "ssh.harden",
            "Port 22\n",
            &mut |_| {},
        )
        .expect("an inconclusive validation must not fail the write");

        // Asking the backend rather than a local constant keeps the assertion
        // tied to the path the code under test actually resolves.
        let path = backend.path_for(Capability::Ssh);
        let restore = format!("cp -p {path}.initd.bak {path}");
        assert!(!mock.recorded_lines().contains(&restore));
    }
}
