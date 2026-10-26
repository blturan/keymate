//! The services a security key can be set up with.

use std::fmt;

/// A remote service a security key can be enrolled with.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Service {
    GitHub,
}

impl Service {
    /// Every service Keymate supports.
    pub const ALL: [Service; 1] = [Service::GitHub];
}

impl fmt::Display for Service {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Service::GitHub => f.write_str("GitHub"),
        }
    }
}
