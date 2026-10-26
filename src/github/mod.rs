//! GitHub: setting up security keys for SSH and commit signing, and showing,
//! switching and removing them.

pub mod api;
mod connection;
pub mod enrollment;
pub mod nuke;
pub mod setup;
pub mod signer;
pub mod status;

/// Where SSH keys are authorized for SAML single sign-on ("Configure SSO")
/// and Keymate's keys can be reviewed.
pub const SSH_SETTINGS_URL: &str = "https://github.com/settings/keys";
