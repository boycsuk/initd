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

/// The directory holding [`DROP_IN`].
///
/// Named separately because it cannot be assumed to exist: `rockylinux:9` has
/// no `/etc/sysctl.d`, and installing `procps-ng` there does not create one.
const DROP_IN_DIR: &str = "/etc/sysctl.d";

/// Mode for that directory, matching what the families shipping it use.
///
/// Measured rather than chosen: Debian, Arch and Alpine all carry it as
/// `drwxr-xr-x`. A drop-in read at boot has to be traversable by anyone, and
/// writable only by root.
const DROP_IN_DIR_MODE: u32 = 0o755;

/// The parameter read to prove the tool works.
///
/// `kernel.ostype` because every Linux kernel carries it, so a failure is about
/// the tool being absent rather than about this host's configuration — a key
/// that some kernels lack would answer a different question than the one asked.
const AVAILABILITY_KEY: &str = "kernel.ostype";

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

    /// The drop-in's contents with one setting removed.
    ///
    /// The first half of [`merged`](Self::merged) without its second: that
    /// filters the key out before appending the new value, and this stops at
    /// the filter. Written as its own function rather than as a flag on the
    /// other, because a `merged(.., None)` reads as "merge nothing" at every
    /// call site that does not open the definition.
    fn without(existing: &str, key: &str) -> String {
        let lines: Vec<&str> = existing
            .lines()
            .filter(|line| !Self::declares(line, key))
            .collect();

        // An empty result is an empty file rather than a lone newline: the
        // drop-in holding no settings is the state this leaves behind when the
        // last one is removed, and `sysctl` reads it either way.
        if lines.is_empty() {
            return String::new();
        }

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
    fn is_available(&self, executor: &dyn Executor) -> Result<bool> {
        // Unprivileged deliberately, as the firewall's own availability check
        // is: this is asked before the tool knows it will need to write
        // anything, and a question that prompts for a password is the wrong
        // shape for one whose answer may be "there is nothing here to drive".
        //
        // Reading a parameter rather than asking for a version, and the choice
        // is load-bearing. `--version` was written here first and measured
        // before it shipped: busybox rejects it *and* `-V` with exit 1
        // (`sysctl: unrecognized option: version`, measured on `alpine:3.23`
        // against busybox 1.37.0), so the check would have reported the tool
        // absent on the one family where it can never be, and sent the task off
        // to install a package Alpine does not carry. The same trap as the
        // installer's `sha256sum --ignore-missing`, which this project has
        // already paid for once.
        //
        // `kernel.ostype` is what all three accept: it exists on every Linux
        // kernel, so the answer is about the tool rather than about the host,
        // and `-n` is a flag procps and busybox both implement.
        let command = Command::new("sysctl").args(["-n", AVAILABILITY_KEY]);

        // An absent binary answers the question rather than failing to answer
        // it — the same shape `Nftables::is_available` needed, and the reason
        // this method exists at all.
        match executor.run(&command) {
            Ok(output) => Ok(output.success()),
            Err(Error::ProgramNotFound { .. }) => Ok(false),
            Err(other) => Err(other),
        }
    }

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

        use crate::domain::FileEditor;

        // The directory before the file, because `tee` creates neither and one
        // family ships neither. Measured on `rockylinux:9`: `/etc/sysctl.d` is
        // absent from the base image and *stays* absent after `procps-ng` is
        // installed — the package that owns `sysctl` does not own the drop-in
        // directory. Debian's `procps` does create it, Alpine and Arch ship it,
        // so four families hid the fifth. Without this the task reported
        // `tee: /etc/sysctl.d/99-initd.conf.initd.new: No such file or
        // directory` — a write failing for a reason that names a temporary file
        // rather than the missing directory.
        //
        // `create_dir` is idempotent, so the four that already have it are
        // unaffected, and 0755 is the mode all three that ship it use.
        files.create_dir(executor, DROP_IN_DIR, DROP_IN_DIR_MODE)?;

        let existing = if files.exists(executor, DROP_IN)? {
            files.read(executor, DROP_IN)?
        } else {
            String::new()
        };

        files.write(executor, DROP_IN, &Self::merged(&existing, setting))?;
        files.set_mode(executor, DROP_IN, DROP_IN_MODE)?;

        Ok(())
    }

    fn unset(&self, executor: &dyn Executor, setting: Setting) -> Result<()> {
        use crate::domain::FileEditor as _;

        let files = crate::backend::unix_files::UnixFiles::new();

        // No drop-in is nothing to remove, which is success rather than an
        // error: the state being asked for is the one the host is already in.
        if !files.exists(executor, DROP_IN)? {
            return Ok(());
        }

        let existing = files.read(executor, DROP_IN)?;
        let remaining = Self::without(&existing, setting.key);

        // Rewritten rather than deleted even when nothing is left. The file is
        // this tool's own, so an empty one is a true statement — "initd
        // declares no kernel parameters here" — where a missing one says the
        // same thing less clearly to whoever reads the directory next.
        files.write(executor, DROP_IN, &remaining)?;
        files.set_mode(executor, DROP_IN, DROP_IN_MODE)?;

        // The running value is deliberately untouched. See the trait: there is
        // no previous value to restore to, and forcing the opposite would take
        // a setting away from whoever else is relying on it.
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
