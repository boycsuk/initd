//! Capability traits the backends implement.
//!
//! Tasks are written against these traits and never learn which distribution
//! they run on. Package names, unit names and command syntax live exclusively
//! in the per-family backends.

pub mod account_writer;
pub mod accounts;
pub mod files;
pub mod firewall;
pub mod packages;
pub mod services;
pub mod sysctl;
pub mod user_services;
pub mod wireguard;

pub use account_writer::AccountWriter;
pub use accounts::AccountReader;
pub use files::FileEditor;
pub use firewall::FirewallManager;
pub use packages::PackageManager;
pub use services::{ServiceManager, ServiceState};
pub use sysctl::SysctlManager;
pub use user_services::UserServiceManager;
pub use wireguard::WireguardTools;
