//! Capability traits the backends implement.
//!
//! Tasks are written against these traits and never learn which distribution
//! they run on. Package names, unit names and command syntax live exclusively
//! in the per-family backends.

pub mod files;
pub mod packages;
pub mod services;

pub use files::FileEditor;
pub use packages::PackageManager;
pub use services::{ServiceManager, ServiceState};
