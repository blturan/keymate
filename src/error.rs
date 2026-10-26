//! Keymate's error type, and a helper to describe failed file operations.

use std::fmt;
use std::io;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Error {
    /// A required external tool is not installed or not on `PATH`.
    MissingTool {
        name: &'static str,
        install: &'static str,
    },
    /// An external tool failed or timed out.
    ToolFailed { name: &'static str, detail: String },
    /// A step could not be completed.
    Failed(String),
    /// A problem the person can fix, and how.
    Fixable { problem: String, fix: String },
    /// The security key wasn't touched in time (or, when it asks for one, the
    /// PIN was wrong); trying again is fine.
    NotConfirmed,
    /// The security key rejected the PIN; asking again is fine.
    WrongPin,
    /// The person cancelled.
    Cancelled,
}

impl Error {
    pub fn fixable(problem: impl Into<String>, fix: impl Into<String>) -> Self {
        Error::Fixable {
            problem: problem.into(),
            fix: fix.into(),
        }
    }

    /// What the person can do about it, if anything.
    pub fn fix(&self) -> Option<String> {
        match self {
            Error::MissingTool { install, .. } => Some(format!("Install it with `{install}`")),
            Error::Fixable { fix, .. } => Some(fix.clone()),
            _ => None,
        }
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::MissingTool { name, .. } => write!(f, "`{name}` isn't installed"),
            Error::ToolFailed { name, detail } => write!(f, "`{name}` failed: {detail}"),
            Error::Failed(message) => f.write_str(message),
            Error::Fixable { problem, .. } => f.write_str(problem),
            Error::NotConfirmed => f.write_str("Your security key wasn't touched in time"),
            Error::WrongPin => f.write_str("The PIN was wrong"),
            Error::Cancelled => f.write_str("Cancelled"),
        }
    }
}

impl std::error::Error for Error {}

pub type Result<T> = std::result::Result<T, Error>;

/// Turn an I/O error into `Could not <action>: <error>`.
pub(crate) trait Context<T> {
    fn context(self, action: &str) -> Result<T>;
}

impl<T> Context<T> for io::Result<T> {
    fn context(self, action: &str) -> Result<T> {
        self.map_err(|e| Error::Failed(format!("Could not {action}: {e}")))
    }
}
