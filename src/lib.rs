//! Enrollment core for Keymate.
//!
//! Frontends (the CLI and a future desktop app) call into this crate directly
//! rather than parsing terminal output. Device listing and diagnostics are
//! read-only; only a service's setup, signer and nuke steps change anything,
//! each after consent. Each service's code lives in its own module, such as
//! [`github`].

pub mod check;
pub mod devices;
pub mod doctor;
mod error;
mod files;
mod git;
pub mod github;
mod process;
mod service;
mod ssh_config;
pub mod sshkey;
mod tools;
pub mod update;

pub use error::{Error, Result};
pub use service::Service;
