//! Git commit signing with a Keymate key. git signs with one key at a time
//! (`user.signingKey`), so one enrollment signs and the person can switch.

use std::path::{Path, PathBuf};

use super::api::{self, Gh, KeyKind, Session};
use super::enrollment::{self, Enrollment};
use crate::error::Context;
use crate::files;
use crate::git::{
    self, GIT_INCLUDE, find_git, git_global, keymate_gitconfig, run_git, signing_key_name,
};
use crate::tools::{fido_openssh, sanitize};
use crate::{Error, Result};

/// Make git sign commits and tags with `key`, via `~/.ssh/keymate/gitconfig`
/// included from the global git config.
pub(crate) fn sign_with(ssh_dir: &Path, ssh_keygen: &Path, key: &Enrollment) -> Result<()> {
    let git = find_git()?;
    let verifies = update_allowed_signers(ssh_dir)?;
    let gitconfig = keymate_gitconfig(&key.display(), ssh_keygen, verifies);
    files::write_atomic(&ssh_dir.join("keymate/gitconfig"), &gitconfig, 0o644)
        .context("write ~/.ssh/keymate/gitconfig")?;
    let includes = git_global(&git, &["--get-all", "include.path"])?.unwrap_or_default();
    if !includes.lines().any(|l| l.trim() == GIT_INCLUDE) {
        run_git(
            &git,
            &["config", "--global", "--add", "include.path", GIT_INCLUDE],
        )?;
    }
    Ok(())
}

/// List every Keymate key in `~/.ssh/keymate/allowed_signers`, so git
/// verifies commits signed by any of them. Returns `false` (and writes
/// nothing) without a git `user.email`.
pub(crate) fn update_allowed_signers(ssh_dir: &Path) -> Result<bool> {
    let git = find_git()?;
    let Some(email) = git_global(&git, &["--get", "user.email"])? else {
        return Ok(false);
    };
    let email = sanitize(&email);
    let lines: String = enrollment::list(ssh_dir)
        .iter()
        .filter_map(|e| e.public_key.as_ref())
        .map(|key| format!("{email} namespaces=\"git\" {key}\n"))
        .collect();
    files::write_atomic(&ssh_dir.join("keymate/allowed_signers"), &lines, 0o644)
        .context("write ~/.ssh/keymate/allowed_signers")?;
    Ok(true)
}

/// The enrollment git signs with, if Keymate's signing is on.
pub(crate) fn current_signer(ssh_dir: &Path, enrolled: &[Enrollment]) -> Option<Enrollment> {
    let name = signing_key_name(ssh_dir)?;
    enrolled.iter().find(|e| e.file_name() == name).cloned()
}

/// What `keymate signer github` found.
pub struct Signer {
    pub account: String,
    /// Keymate keys on this Mac.
    pub enrollments: Vec<Enrollment>,
    /// The key git signs with now, if any.
    pub current: Option<Enrollment>,
    session: Session,
    gh: Gh,
    ssh_keygen: PathBuf,
    ssh_dir: PathBuf,
}

/// Find Keymate's keys and which one signs. Read-only.
pub fn prepare() -> Result<Signer> {
    let ssh_keygen = fido_openssh("ssh-keygen")?;
    let gh = Gh::find()?;
    let session = gh.signed_in()?;
    let ssh_dir = files::ssh_dir()?;
    let enrolled = enrollment::list(&ssh_dir);
    Ok(Signer {
        account: session.account.clone(),
        current: current_signer(&ssh_dir, &enrolled),
        enrollments: enrolled,
        session,
        gh,
        ssh_keygen,
        ssh_dir,
    })
}

impl Signer {
    /// The GitHub permission needed to register signing keys, if missing.
    pub fn missing_scope(&self) -> Option<&'static str> {
        self.session.missing_scope(KeyKind::Signing)
    }

    pub fn request_scope(&self, scope: &str) -> Result<()> {
        self.gh.request_scope(scope)
    }

    /// Sign with `key` from now on, registering it on GitHub as a signing
    /// key first if needed (so its commits show as Verified).
    pub fn switch_to(&self, key: &Enrollment) -> Result<Vec<String>> {
        let public_key = key
            .public_key
            .as_ref()
            .ok_or_else(|| Error::Failed(format!("{} has no public key file", key.display())))?;
        let mut changes = Vec::new();
        let registered = self
            .gh
            .list_keys(KeyKind::Signing)?
            .iter()
            .any(|k| &k.key == public_key);
        if !registered {
            let title = api::title(
                &key.name().unwrap_or_else(|| "key".into()),
                KeyKind::Signing,
            );
            self.gh
                .add_key(&key.public_path(), &title, KeyKind::Signing)?;
            changes.push(format!("Added to GitHub as {title}"));
        }
        sign_with(&self.ssh_dir, &self.ssh_keygen, key)?;
        changes.push(format!(
            "Signing commits and tags with {}",
            key.short_name()
        ));
        Ok(changes)
    }

    /// Re-list every Keymate key in `allowed_signers` (e.g. after another key
    /// was set up), keeping the current signer.
    pub fn refresh(&self) -> Result<()> {
        if self.current.is_some() {
            update_allowed_signers(&self.ssh_dir)?;
        }
        Ok(())
    }

    /// Stop signing commits with Keymate's settings.
    pub fn turn_off(&self) -> Result<Option<String>> {
        let off = git::remove_signing(&self.ssh_dir)?;
        Ok(off.then(|| "Turned off commit signing".to_owned()))
    }
}
