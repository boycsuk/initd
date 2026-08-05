//! Mandatory access control capability.
//!
//! Behind a trait for a reason the other capabilities do not share. The rest of
//! this layer abstracts things that differ between distributions — a package
//! name, a unit name, the syntax of a command. SELinux is not a different
//! spelling of anything: it is a second authority that can refuse an operation
//! the first one permitted, present on RHEL and absent from the other families
//! implemented today.
//!
//! What makes it worth a trait rather than a check inside a task is the shape
//! of its failure. A daemon told to listen on a port SELinux has not labelled
//! does not report a permission problem — it fails to start, having been given
//! a configuration that is valid, was written successfully, and that `sshd -t`
//! approves. The tool would have done everything right and left the machine
//! unreachable. So the port has to be labelled before the daemon is asked to
//! use it, and the task cannot ask "am I on RHEL" to decide: it asks whether
//! this host enforces, and the backend answers.
//!
//! Absence is an ordinary answer here, not an error. A RHEL host with SELinux
//! disabled and a Debian host that never had it are the same situation from a
//! task's point of view, and both are far more common than the enforcing case.

use crate::error::Result;
use crate::exec::Executor;

use super::firewall::Protocol;

/// Labels ports so a confined service may bind them.
pub trait SelinuxManager {
    /// Whether this host is enforcing a policy right now.
    ///
    /// Asked of the host rather than answered from the family, because the
    /// question is not which distribution this is. RHEL ships SELinux enabled
    /// and administrators disable it; a container reports it disabled whatever
    /// the image. Both are ordinary states, so neither is an error to report
    /// upwards — the answer is `false` and the caller does nothing.
    fn is_enforcing(&self, executor: &dyn Executor) -> Result<bool>;

    /// Labels a port so the SSH daemon may listen on it.
    ///
    /// Narrow by design. A general "label any port for any service" would need
    /// the caller to name an SELinux type, which is a policy detail no task
    /// here has any business knowing — and the only port this tool moves is
    /// SSH's.
    fn allow_ssh_port(&self, executor: &dyn Executor, port: u32, protocol: Protocol) -> Result<()>;
}
