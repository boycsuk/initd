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

/// The daemon's own binary, which is what every task here configures.
///
/// `sshd` rather than `ssh`, for the reason `tui::probe` records about the same
/// name: the client is a separate package on RHEL, so a host with `ssh` on its
/// `PATH` may have no server at all.
const SSHD_BINARY: &str = "sshd";

/// Whether this host has an SSH server to configure.
///
/// Asked of the binary rather than of a package: the daemon may have arrived
/// from the distribution or been built, and `sshd` is what both put on the
/// path. A package query would answer "absent" for a server that is plainly
/// running.
///
/// `is_installed` rather than `is_installed_here`, which is the distinction
/// that matters and the one this first got wrong. The second asks whether the
/// binary is in *this tool's own* install directory, which is the right
/// question before removing something and the wrong one here: `sshd` lives in
/// `/usr/sbin` on every family, so every SSH task refused on a host that plainly
/// had a server. Caught by the container suite, which runs the tasks against a
/// real `openssh-server`.
fn sshd_is_present(executor: &dyn Executor, backend: &dyn Backend) -> Result<bool> {
    backend.binaries().is_installed(executor, SSHD_BINARY)
}

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
    // Already what was asked for: nothing to write, and writing anyway is what
    // made this file grow. A second identical run must leave the bytes alone,
    // which is the property the whole task is judged on — measured before this
    // check existed, the file went from 143 lines to 162 on the second run.
    if directive_value(contents, directive).as_deref() == Some(value) {
        return contents.to_owned();
    }

    // The line the file already carries for this directive, commented out.
    // Uncommenting it in place keeps the file in its own order, where
    // appending would leave the shipped default above a contradicting copy.
    //
    // Only when nothing active precedes it. sshd honours the *first* active
    // line, so rewriting the commented one below an active `PermitRootLogin
    // yes` writes a directive the daemon never reads — and the task reports
    // success over a root login it was asked to close. The loop below is what
    // handles that file: it comments the active line out and writes the new
    // value in its place.
    if !contents
        .lines()
        .any(|line| is_directive_line(line, directive))
        && let Some(index) = commented_directive_line(contents, directive)
    {
        return rewrite_line(contents, index, &format!("{directive} {value}"));
    }

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

/// The commented-out line a directive would be uncommented from.
///
/// Stops at the first `Match`, commented or not, for the reason
/// [`opens_any_match_block`] records: a directive under a commented `Match` is
/// a per-user override rather than the server's, and uncommenting it would
/// change what the block around it means.
fn commented_directive_line(contents: &str, directive: &str) -> Option<usize> {
    contents
        .lines()
        .take_while(|line| !opens_any_match_block(line))
        .position(|line| is_commented_directive(line, directive))
}

/// Replaces one line, leaving every other byte and the trailing newline alone.
///
/// Rebuilt from `lines()` rather than spliced by offset, so a file with `\r\n`
/// or without a final newline comes back in the shape the rest of this module
/// writes — which is what the byte-for-byte round trip depends on.
fn rewrite_line(contents: &str, index: usize, replacement: &str) -> String {
    let mut result = String::with_capacity(contents.len() + 64);

    for (position, line) in contents.lines().enumerate() {
        if position == index {
            result.push_str(replacement);
        } else {
            result.push_str(line);
        }

        result.push('\n');
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
///
/// **The first occurrence wins, not the last.** sshd takes the earliest active
/// line for a keyword and ignores every later one, and `sshd -t` does not
/// complain about the repetition — measured on `debian:13`, where
/// `MaxAuthTries 3` above `MaxAuthTries 9` leaves `sshd -T` reporting `3`, the
/// reverse order reports `9`, and validation exits 0 either way.
///
/// This read the *last* one until that was measured, which mattered most where
/// it is least visible. A file carrying the same directive twice is what an
/// administrator's own edit above this tool's appended line produces, and the
/// value reported was the one the daemon *ignores* — so
/// [`set_directive`]'s idempotence check could compare against it, decide
/// there was nothing to write, and report success over a daemon still doing
/// the opposite.
///
/// The commented case needs no test of its own here: [`is_directive_line`]
/// answers `false` for those, which is the same fix and the reason the
/// `starts_with('#')` guard that stood beside this is gone. Verified in the
/// same container run — a commented duplicate changes nothing whichever side
/// of the active line it sits on.
pub fn directive_value(contents: &str, directive: &str) -> Option<String> {
    contents
        .lines()
        // Split the same line the match was made against. `is_directive_line`
        // trims first, so splitting the raw line hands back the leading
        // whitespace as the keyword and the whole line as the value — and an
        // indented directive is what an `Include`d drop-in and a `Match` block
        // both produce.
        .map(str::trim_start)
        .find(|line| is_directive_line(line, directive))
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

/// Whether a line *sets* the given directive: uncommented, and this keyword.
///
/// `sshd_config` keywords are case-insensitive. A commented line is **not** one
/// of these — that is [`is_commented_directive`], and conflating the two is
/// what made this file grow on every run. The predicate that stood here
/// stripped leading `#` before comparing, so a line already commented out
/// answered `true` and `set_directive` commented it again: measured on
/// `debian:13`, `# X11Forwarding yes` became `# # X11Forwarding yes`, gaining a
/// level per pass and the file 19 lines.
fn is_directive_line(line: &str, directive: &str) -> bool {
    let trimmed = line.trim_start();

    if trimmed.starts_with('#') {
        return false;
    }

    trimmed
        .split_once(char::is_whitespace)
        .is_some_and(|(keyword, _)| keyword.eq_ignore_ascii_case(directive))
}

/// Whether a line is this directive, commented out — the shipped default.
///
/// A stock `sshd_config` is mostly these: 53 commented lines against 7 active
/// on `debian:13`. They are the file's own documentation of what the daemon
/// does without being told, and turning a switch on means uncommenting the one
/// that is already in place rather than appending a second line for the same
/// keyword.
///
/// Separating a commented *directive* from prose that merely mentions one is
/// what this has to get right, and the file itself provides the separator.
/// Line 33 is `#PermitRootLogin prohibit-password`; line 83 is
/// `# the setting of "PermitRootLogin prohibit-password".` inside a paragraph.
/// Every commented directive has `#` immediately against the keyword, and
/// every prose line has `# ` with a space — measured across the shipped file,
/// where the rule matches 52 lines and every one of them is a directive.
///
/// Whitespace *inside* the comment is a different signal and is deliberately
/// not trimmed away before the `#` test: `#\tX11Forwarding no` is indented
/// because it sits inside a commented `Match` block, and the caller uses that.
fn is_commented_directive(line: &str, directive: &str) -> bool {
    let Some(body) = line.trim_start().strip_prefix('#') else {
        return false;
    };

    // Prose. `# ` opens a sentence; `#Keyword` opens a directive.
    if body.starts_with([' ', '\t']) {
        return false;
    }

    body.split_once(char::is_whitespace)
        .is_some_and(|(keyword, _)| keyword.eq_ignore_ascii_case(directive))
}

/// Whether a line opens a `Match` block, commented out or not.
///
/// The commented case is what [`is_match_line`] deliberately excludes and this
/// deliberately includes, and the difference decides whether a line below it
/// is global. Debian ships:
///
/// ```text
/// #Match User anoncvs
/// #    X11Forwarding no
/// ```
///
/// That `X11Forwarding` is not the server's — it is a per-user override that
/// is inert because its header is commented. Uncommenting it would write a
/// directive into a block whose `Match` is still off, changing what every line
/// around it means. So the scan for a line to uncomment stops here, exactly as
/// the scan for where to *insert* stops at a live `Match`.
fn opens_any_match_block(line: &str) -> bool {
    let body = line.trim_start().trim_start_matches('#').trim_start();

    body.split_whitespace()
        .next()
        .is_some_and(|keyword| keyword.eq_ignore_ascii_case("match"))
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
    // Before the write, and the only place it needs to be: all four tasks that
    // edit `sshd_config` reach it through here, which is the shape
    // `ensure_config_present` already records — fixing it in each is where the
    // fifth is the one that forgets.
    //
    // Ordering below rather than above `write` was the defect. The validation
    // that follows is what would have noticed the daemon was missing, and it
    // notices by failing to run a program that is not there: `ProgramNotFound`
    // then travelled past the branch that restores the backup, leaving the host
    // holding an edited configuration nothing had checked, for a daemon it does
    // not have. Writing to `sshd_config` on a machine with no sshd is not a
    // recoverable near miss — it is a file nobody will ever read.
    if !sshd_is_present(executor, backend)? {
        return Err(Error::SshdAbsent);
    }

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

    /// The shape a stock `sshd_config` has, in the parts that matter here.
    ///
    /// Copied from `debian:13` rather than invented: the commented defaults,
    /// a prose paragraph that names a directive, an active line, and the
    /// commented `Match` block the file ends with. Every trap this module has
    /// to avoid is in these fourteen lines.
    const SHIPPED: &str = "Include /etc/ssh/sshd_config.d/*.conf\n\
         \n\
         #PermitRootLogin prohibit-password\n\
         #PasswordAuthentication yes\n\
         KbdInteractiveAuthentication no\n\
         \n\
         # PAM authentication via KbdInteractiveAuthentication may bypass\n\
         # the setting of \"PermitRootLogin prohibit-password\".\n\
         \n\
         X11Forwarding yes\n\
         \n\
         # Example of overriding settings on a per-user basis\n\
         #Match User anoncvs\n\
         #\tX11Forwarding no\n";

    #[test]
    fn the_first_occurrence_of_a_repeated_directive_is_the_effective_one() {
        // sshd takes the earliest active line for a keyword and ignores every
        // later one, and `sshd -t` does not complain about the repetition.
        // Measured on `debian:13`: `MaxAuthTries 3` above `MaxAuthTries 9`
        // leaves `sshd -T` reporting 3, the reverse reports 9, and validation
        // exits 0 both ways.
        //
        // This read the last one until it was measured, and the case it got
        // wrong is the one nobody looks at: a file carrying an administrator's
        // own line above this tool's appended one reported the value the
        // daemon was *ignoring*. `set_directive`'s idempotence check compares
        // against exactly this, so a run could decide there was nothing to
        // write and report success over a daemon still doing the opposite.
        let repeated = "MaxAuthTries 3\nMaxAuthTries 9\n";

        assert_eq!(
            directive_value(repeated, "MaxAuthTries").as_deref(),
            Some("3"),
            "the first active line is the one sshd honours"
        );

        let reversed = "MaxAuthTries 9\nMaxAuthTries 3\n";

        assert_eq!(
            directive_value(reversed, "MaxAuthTries").as_deref(),
            Some("9")
        );
    }

    #[test]
    fn a_commented_duplicate_is_not_an_occurrence() {
        // Verified in the same container run: a commented copy changes nothing
        // whichever side of the active line it sits on.
        let before = "#MaxAuthTries 9\nMaxAuthTries 3\n";
        let after = "MaxAuthTries 3\n#MaxAuthTries 9\n";

        assert_eq!(
            directive_value(before, "MaxAuthTries").as_deref(),
            Some("3")
        );
        assert_eq!(directive_value(after, "MaxAuthTries").as_deref(), Some("3"));
    }

    #[test]
    fn an_indented_directive_reads_back_as_its_value() {
        // The match is made against the trimmed line and the split was made
        // against the raw one, so leading whitespace came back as the keyword
        // and the whole line as the value. An `Include`d drop-in and a `Match`
        // block both indent, and the value fed the idempotence check.
        assert_eq!(
            directive_value("    PermitRootLogin no\n", "PermitRootLogin").as_deref(),
            Some("no")
        );
    }

    #[test]
    fn an_active_line_is_replaced_even_when_a_commented_one_follows() {
        // sshd honours the *first* active line. Rewriting the commented copy
        // below an active one wrote a directive the daemon never reads, and
        // `sshd -t` accepts the repetition — so `ssh.harden` reported success
        // over a root login it had been asked to close. This is what an
        // administrator's own edit above the shipped default produces.
        let contents = "PermitRootLogin yes\n#PermitRootLogin prohibit-password\n";

        let updated = set_directive(contents, "PermitRootLogin", "no");

        let first_active = updated
            .lines()
            .find(|line| {
                let trimmed = line.trim_start();
                !trimmed.starts_with('#') && trimmed.starts_with("PermitRootLogin")
            })
            .unwrap_or("(none)");

        assert_eq!(
            first_active, "PermitRootLogin no",
            "the line sshd honours must be the new one: {updated}"
        );
    }

    #[test]
    fn setting_a_directive_to_what_it_already_says_changes_nothing() {
        // The bug this whole change exists for. `set_directive` commented the
        // old line and wrote a new one without ever asking whether the value
        // was already right, so a task run twice grew its own file — measured
        // on `debian:13` at 143 lines becoming 162, with `# X11Forwarding yes`
        // becoming `# # X11Forwarding yes` and gaining a `#` per pass.
        let once = set_directive(SHIPPED, "X11Forwarding", "no");
        let twice = set_directive(&once, "X11Forwarding", "no");

        assert_eq!(once, twice, "a second identical run must write nothing");
    }

    #[test]
    fn turning_a_directive_on_uncomments_the_line_the_file_already_carries() {
        // A stock file is mostly commented defaults — 53 of them against 7
        // active on `debian:13` — and the value belongs where the file already
        // states it rather than appended below.
        let updated = set_directive(SHIPPED, "PermitRootLogin", "no");

        assert!(
            updated.contains("PermitRootLogin no\n"),
            "the directive must be set: {updated}"
        );
        assert!(
            !updated.contains("#PermitRootLogin"),
            "the commented default must have become the directive: {updated}"
        );
        assert_eq!(
            updated.matches("PermitRootLogin no").count(),
            1,
            "exactly one line may set it: {updated}"
        );
    }

    #[test]
    fn prose_naming_a_directive_is_not_mistaken_for_one() {
        // Line 83 of the shipped file reads `# the setting of
        // "PermitRootLogin prohibit-password".` inside a paragraph. A
        // commented directive has `#` against the keyword; prose has `# `.
        let updated = set_directive(SHIPPED, "PermitRootLogin", "no");

        assert!(
            updated.contains("# the setting of \"PermitRootLogin prohibit-password\"."),
            "the paragraph must survive untouched: {updated}"
        );
    }

    #[test]
    fn a_directive_under_a_commented_match_block_is_left_alone() {
        // The trap, and it ships with Debian: `#\tX11Forwarding no` beneath
        // `#Match User anoncvs` is a per-user override that is inert because
        // its header is commented. Uncommenting it would write a directive
        // into a block whose `Match` is still off.
        let updated = set_directive(SHIPPED, "X11Forwarding", "no");

        assert!(
            updated.contains("#\tX11Forwarding no"),
            "the commented Match block must stay commented: {updated}"
        );
        assert!(
            updated.contains("#Match User anoncvs"),
            "and so must its header: {updated}"
        );
    }

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
    fn no_config_is_written_for_a_daemon_this_host_does_not_have() {
        // The validation that follows the write is what would have noticed the
        // daemon was missing, and it notices by failing to run a program that
        // is not there — `ProgramNotFound`, raised past the branch that
        // restores the backup. So the host was left holding an edited
        // `sshd_config` that nothing had checked, for a server it does not
        // have, under an error naming `PATH`.
        //
        // Exact replies, for the reason the rollback test below records: the
        // refusal has to land on the presence check and nowhere else.
        let mock = MockExecutor::with_exact_replies([Reply::failure(1, "")]);
        let backend = crate::backend::for_family(crate::distro::Family::Debian);

        let err = write_validated(
            &mock,
            backend.as_ref(),
            "ssh.harden",
            "PermitRootLogin no\n",
            &mut |_| {},
        )
        .expect_err("a host with no sshd must be refused");

        assert!(
            matches!(err, Error::SshdAbsent),
            "the refusal must name the missing server: {err:?}"
        );

        // The point of checking before the write rather than after: nothing
        // may reach the file.
        let commands = mock.recorded_lines();
        assert!(
            !commands.iter().any(|line| line.contains("tee")),
            "nothing may be written: {commands:?}"
        );
        assert!(
            !commands.iter().any(|line| line.contains("cp -p")),
            "and no backup taken of a file about to be left alone: {commands:?}"
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
            Reply::ok("/usr/sbin/sshd\n"), // sshd is installed
            Reply::ok(""),                 // test -e
            Reply::ok(""),                 // cp -p: backup
            Reply::ok(""),                 // install the staging file
            Reply::ok(""),                 // tee: stage
            Reply::ok("600"),              // stat -c %a
            Reply::ok(""),                 // chmod
            Reply::ok(""),                 // mv: publish
            Reply::failure(255, "Bad configuration option: Prt"), // sshd -t
            Reply::ok(""),                 // cp -p: restore
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
            Reply::ok("/usr/sbin/sshd\n"), // sshd is installed
            Reply::ok(""),                 // test -e
            Reply::ok(""),                 // cp -p: backup
            Reply::ok(""),                 // install the staging file
            Reply::ok(""),                 // tee: stage
            Reply::ok("600"),              // stat -c %a
            Reply::ok(""),                 // chmod
            Reply::ok(""),                 // mv: publish
            Reply::failure(255, "Bad configuration option: Prt"), // sshd -t
            Reply::failure(1, "cp: cannot create regular file"), // cp -p: restore
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
            Reply::ok("/usr/sbin/sshd\n"),               // sshd is installed
            Reply::ok(""),                               // test -e: the file exists
            Reply::ok(""),                               // cp -p (write's own backup)
            Reply::ok(""),                               // install the staging file
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
            Reply::ok("/usr/sbin/sshd\n"),               // sshd is installed
            Reply::ok(""),                               // test -e
            Reply::ok(""),                               // cp -p
            Reply::ok(""),                               // install the staging file
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
            Reply::ok("/usr/sbin/sshd\n"), // sshd is installed
            Reply::failure(1, ""),         // test -e: no such file
            Reply::ok(""),                 // install the staging file
            Reply::ok(""),                 // tee
            Reply::ok("600"),              // stat
            Reply::ok(""),                 // chmod
            Reply::ok(""),                 // mv
            Reply::ok(""),                 // sshd -t
            Reply::ok("port 22\n"),        // sshd -T
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
            Reply::ok(""),                                        // install the staging file
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
            Reply::ok("/usr/sbin/sshd\n"),             // sshd is installed
            Reply::ok(""),                             // test -e
            Reply::ok(""),                             // cp -p
            Reply::ok(""),                             // install the staging file
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
            Reply::ok("/usr/sbin/sshd\n"), // sshd is installed
            Reply::ok(""),                 // test -e
            Reply::ok(""),                 // cp -p: backup
            Reply::ok(""),                 // install the staging file
            Reply::ok(""),                 // tee: stage
            Reply::ok("600"),              // stat -c %a
            Reply::ok(""),                 // chmod
            Reply::ok(""),                 // mv: publish
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
