//! `sysctl` implementation of [`SysctlManager`].
//!
//! Shared by every family: `sysctl` reads and writes `/proc/sys`, and
//! `/etc/sysctl.d/` is read at boot by both systemd's `systemd-sysctl` and by
//! the `procps` init script that non-systemd distributions use. Nothing here is
//! distribution-specific, which is why it is not folded into a family module.

use super::systemd::run_checked;
use crate::domain::sysctl::{Setting, SysctlManager};
use crate::error::{Error, Result};
use crate::exec::{Command, Executor};

/// Where persistent settings are written.
///
/// A drop-in of this tool's own rather than `/etc/sysctl.conf`: the shared file
/// is also edited by administrators and by packages, and appending to it makes
/// a repeated operation accumulate contradictory lines whose winner is the last
/// one read. A file named for the tool can be rewritten wholesale.
///
/// The `99-` prefix orders it after the distribution's own drop-ins, so a value
/// set here is not silently overridden by one shipped in the base system.
const DROP_IN: &str = "/etc/sysctl.d/99-initd.conf";

/// Mode for the drop-in: readable by anyone, writable only by root.
const DROP_IN_MODE: u32 = 0o644;

/// Manages kernel parameters through `sysctl`.
#[derive(Debug, Clone, Copy, Default)]
pub struct ProcfsSysctl;

impl ProcfsSysctl {
    pub const fn new() -> Self {
        Self
    }

    /// The drop-in's contents with one setting added or replaced.
    ///
    /// Replacing rather than appending is what makes the operation idempotent:
    /// running it twice must leave one line, not two that disagree.
    fn merged(existing: &str, setting: Setting) -> String {
        let mut lines: Vec<String> = existing
            .lines()
            .filter(|line| !Self::declares(line, setting.key))
            .map(str::to_owned)
            .collect();

        lines.push(format!("{} = {}", setting.key, setting.value));

        // A trailing newline: a file whose last line lacks one is still read
        // correctly, but appending to it later would join two settings.
        format!("{}\n", lines.join("\n"))
    }

    /// Whether a line assigns the named key.
    ///
    /// Compares the text before `=` rather than searching for the key anywhere
    /// in the line: `net.ipv4.ip_forward` is a prefix of
    /// `net.ipv4.ip_forward_use_pmtu`, and a substring match would delete the
    /// wrong setting.
    fn declares(line: &str, key: &str) -> bool {
        line.split('=')
            .next()
            .is_some_and(|assigned| assigned.trim() == key)
    }
}

impl SysctlManager for ProcfsSysctl {
    fn get(&self, executor: &dyn Executor, key: &str) -> Result<String> {
        // `-n` prints the value alone, without the `key = ` prefix.
        let command = Command::new("sysctl").args(["-n", key]);
        let output = executor.run(&command)?;

        if !output.success() {
            return Err(Error::UnknownSysctl {
                key: key.to_owned(),
            });
        }

        Ok(output.stdout.trim().to_owned())
    }

    fn set(&self, executor: &dyn Executor, setting: Setting) -> Result<()> {
        // Runtime first: if this fails the parameter does not exist on this
        // kernel, and writing a drop-in naming it would leave a file that makes
        // every subsequent boot log an error.
        let apply = Command::new("sysctl")
            .args(["-w", &format!("{}={}", setting.key, setting.value)])
            .privileged();

        run_checked(executor, &apply)?;

        // Then persistence. Read-modify-write so that settings this tool wrote
        // earlier survive, and so that repeating one replaces its line.
        let files = crate::backend::unix_files::UnixFiles::new();
        let existing = if files.exists(executor, DROP_IN)? {
            files.read(executor, DROP_IN)?
        } else {
            String::new()
        };

        use crate::domain::FileEditor;

        files.write(executor, DROP_IN, &Self::merged(&existing, setting))?;
        files.set_mode(executor, DROP_IN, DROP_IN_MODE)?;

        Ok(())
    }

    fn is_persisted(&self, executor: &dyn Executor, setting: Setting) -> Result<bool> {
        use crate::domain::FileEditor;

        let files = crate::backend::unix_files::UnixFiles::new();

        // No drop-in at all is an answer rather than a failure: this tool has
        // never written here.
        if !files.exists(executor, DROP_IN)? {
            return Ok(false);
        }

        // Only this tool's own drop-in is consulted. A value another file sets
        // may well survive a reboot, but nothing here can promise the two are
        // read in an order that leaves ours winning — and the honest response
        // to "somebody else may have set it" is to write ours anyway, which is
        // what returning false does.
        Ok(files
            .read(executor, DROP_IN)?
            .lines()
            .filter(|line| Self::declares(line, setting.key))
            .any(|line| {
                line.split_once('=')
                    .is_some_and(|(_, value)| value.trim() == setting.value)
            }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::exec::mock::{MockExecutor, Reply};

    #[test]
    fn a_repeated_setting_replaces_its_line() {
        // Appending would leave two lines that disagree, and the value that
        // survives a reboot would be whichever is read last.
        let existing = "net.ipv4.ip_forward = 0\n";

        let merged = ProcfsSysctl::merged(
            existing,
            Setting {
                key: "net.ipv4.ip_forward",
                value: "1",
            },
        );

        assert_eq!(merged, "net.ipv4.ip_forward = 1\n");
    }

    #[test]
    fn an_unrelated_setting_is_kept() {
        // The drop-in holds every parameter this tool set, and forwarding is
        // written by a different task from unprivileged ports.
        let existing = "net.ipv4.ip_unprivileged_port_start = 80\n";

        let merged = ProcfsSysctl::merged(
            existing,
            Setting {
                key: "net.ipv4.ip_forward",
                value: "1",
            },
        );

        assert!(merged.contains("net.ipv4.ip_unprivileged_port_start = 80"));
        assert!(merged.contains("net.ipv4.ip_forward = 1"));
    }

    #[test]
    fn a_key_that_is_a_prefix_of_another_is_not_replaced() {
        // `net.ipv4.ip_forward` is a prefix of `net.ipv4.ip_forward_use_pmtu`.
        // A substring match would delete a setting nobody asked to change.
        let existing = "net.ipv4.ip_forward_use_pmtu = 1\n";

        let merged = ProcfsSysctl::merged(
            existing,
            Setting {
                key: "net.ipv4.ip_forward",
                value: "1",
            },
        );

        assert!(
            merged.contains("net.ipv4.ip_forward_use_pmtu = 1"),
            "the longer key must survive: {merged}"
        );
    }

    #[test]
    fn the_runtime_value_is_applied_before_anything_is_written() {
        // A parameter this kernel does not have must fail here rather than
        // leave a drop-in that makes every subsequent boot log an error.
        let mock = MockExecutor::with_replies([Reply::failure(255, "unknown key")]);

        let err = ProcfsSysctl::new()
            .set(
                &mock,
                Setting {
                    key: "net.ipv4.nonexistent",
                    value: "1",
                },
            )
            .expect_err("an unknown parameter must fail");

        assert!(matches!(err, Error::CommandFailed { .. }), "{err:?}");
        assert_eq!(
            mock.recorded_lines().len(),
            1,
            "nothing must be written: {:?}",
            mock.recorded_lines()
        );
    }

    #[test]
    fn reading_a_value_needs_no_privilege() {
        // /proc/sys is world-readable.
        let mock = MockExecutor::with_replies([Reply::ok("1\n")]);

        let value = ProcfsSysctl::new()
            .get(&mock, "net.ipv4.ip_forward")
            .expect("the read must succeed");

        assert_eq!(value, "1");
        assert!(!mock.any_privileged());
    }

    #[test]
    fn an_unknown_parameter_is_named_in_the_error() {
        let mock = MockExecutor::with_replies([Reply::failure(255, "cannot stat")]);

        let err = ProcfsSysctl::new()
            .get(&mock, "net.ipv4.nonexistent")
            .expect_err("an unknown parameter must fail");

        assert!(matches!(err, Error::UnknownSysctl { .. }), "{err:?}");
    }

    #[test]
    fn a_parameter_already_holding_the_value_is_reported() {
        let mock = MockExecutor::with_replies([Reply::ok("1\n")]);

        assert!(
            ProcfsSysctl::new()
                .holds(
                    &mock,
                    Setting {
                        key: "net.ipv4.ip_forward",
                        value: "1",
                    }
                )
                .expect("the query must succeed")
        );
    }
}
