//! The task tree the TUI exposes.
//!
//! Tasks are native typed Rust rather than embedded shell scripts: they call
//! the domain traits, so they inherit the distro abstraction and are testable
//! without a container. A shell script could not call a trait.

pub mod ssh;
pub mod sshd_config;

use crate::backend::Backend;
use crate::distro::Family;
use crate::error::Result;
use crate::exec::{Executor, OutputLine};

/// Somewhere a task reports its progress to.
///
/// The CLI prints these lines; the TUI streams them into its output pane.
pub type Progress<'a> = &'a mut dyn FnMut(OutputLine);

/// A unit of administration work.
///
/// Implementations must never branch on the distribution. If a task needs to
/// know which distro it runs on, the missing abstraction belongs in a domain
/// trait instead.
pub trait Task {
    /// Stable identifier, used by the CLI and as a key in the TUI.
    fn id(&self) -> &'static str;

    /// Short human-readable title.
    fn title(&self) -> &'static str;

    /// What the task does, shown in the TUI before running it.
    fn description(&self) -> &'static str;

    /// Whether the task changes system state irreversibly enough to warrant a
    /// confirmation prompt.
    fn is_destructive(&self) -> bool {
        false
    }

    /// Families this task supports.
    ///
    /// The TUI shows unsupported tasks greyed out with the reason, rather than
    /// hiding them.
    fn supported_families(&self) -> &'static [Family];

    /// Whether the task runs on the given family.
    fn supports(&self, family: Family) -> bool {
        self.supported_families().contains(&family)
    }

    /// Runs the task.
    fn run(
        &self,
        executor: &dyn Executor,
        backend: &dyn Backend,
        progress: Progress<'_>,
    ) -> Result<()>;
}

/// A named group of tasks, forming one level of the tree.
pub struct TaskGroup {
    pub title: &'static str,
    pub tasks: Vec<Box<dyn Task>>,
}

/// Builds the full task tree.
pub fn tree() -> Vec<TaskGroup> {
    vec![TaskGroup {
        title: "SSH",
        tasks: ssh::tasks(),
    }]
}

/// Finds a task by its identifier, across every group.
pub fn find(id: &str) -> Option<Box<dyn Task>> {
    tree()
        .into_iter()
        .flat_map(|group| group.tasks)
        .find(|task| task.id() == id)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_task_has_a_unique_id() {
        let ids: Vec<_> = tree()
            .into_iter()
            .flat_map(|group| group.tasks)
            .map(|task| task.id().to_owned())
            .collect();

        let mut unique = ids.clone();
        unique.sort_unstable();
        unique.dedup();

        assert_eq!(ids.len(), unique.len(), "duplicate task ids: {ids:?}");
    }

    #[test]
    fn every_task_supports_at_least_one_family() {
        for group in tree() {
            for task in group.tasks {
                assert!(
                    !task.supported_families().is_empty(),
                    "{} supports nothing",
                    task.id()
                );
            }
        }
    }

    #[test]
    fn tasks_can_be_found_by_id() {
        assert!(find("ssh.install").is_some());
        assert!(find("nonexistent").is_none());
    }
}
