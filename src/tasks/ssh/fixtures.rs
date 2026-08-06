//! Fixtures the SSH task tests share.
//!
//! Only what more than one submodule needs. A fixture used by a single task
//! stays with that task, because a shared file is where an unused fixture hides
//! and where a change made for one test silently reaches another.
//!
//! Shaped after [`crate::exec::mock`] — a `#[cfg(test)]` module in a file of its
//! own — rather than a `mod tests` some sibling reaches into. That is the only
//! form of shared test infrastructure this codebase has, and one is enough.

use crate::tasks::params::ParamValues;

/// A valid ed25519 key body, long enough to pass structural validation.
///
/// Every group needs one: hardening and the allow-list both refuse to run
/// without an authorised key, so a scenario that does not intend to test that
/// refusal has to hold a key that survives parsing.
pub const TEST_KEY: &str =
    "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIKj8VQqPmVxOKGVkGYhAaKcHVDkPAeSlZLnQFDKmvXYZ user@host";

/// A passwd entry for root, as `getent` returns it.
///
/// The home directory is read from here rather than assumed, so every scenario
/// that looks for an authorised key has to answer the lookup first.
pub const ROOT_PASSWD: &str = "root:x:0:0:root:/root:/bin/bash";

/// For tasks that declare no parameters.
pub fn no_values() -> ParamValues {
    ParamValues::new()
}
