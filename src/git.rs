//! Git's global configuration, and Keymate's signing settings in
//! `~/.ssh/keymate/gitconfig`, which it includes.

use std::fs;
use std::path::{Path, PathBuf};
use std::time::Duration;

use crate::files;
use crate::process;
use crate::tools::{find_on_path, sanitize};
use crate::{Error, Result};

/// Keymate's gitconfig, as listed in the global `include.path`.
pub(crate) const GIT_INCLUDE: &str = "~/.ssh/keymate/gitconfig";
/// Signing files in `~/.ssh/keymate`, removed when signing is turned off.
const SIGNING_FILES: [&str; 2] = ["gitconfig", "allowed_signers"];
const TIMEOUT: Duration = Duration::from_secs(15);

pub(crate) fn find_git() -> Result<PathBuf> {
    find_on_path("git").ok_or(Error::MissingTool {
        name: "git",
        install: "xcode-select --install",
    })
}

/// `git config --global <args>`; `None` when the setting is absent.
pub(crate) fn git_global(git: &Path, args: &[&str]) -> Result<Option<String>> {
    let mut full = vec!["config", "--global"];
    full.extend_from_slice(args);
    let output = process::run(git, &full, TIMEOUT)
        .map_err(|e| Error::Failed(format!("could not run git: {e}")))?;
    // `git config --get` exits with 1 when the key is not set.
    match output.status.code() {
        Some(0) => Ok(Some(output.stdout.trim().to_owned())),
        Some(1) => Ok(None),
        _ => Err(Error::Failed(format!(
            "git config failed: {}",
            sanitize(output.stderr.trim())
        ))),
    }
}

pub(crate) fn run_git(git: &Path, args: &[&str]) -> Result<()> {
    let output = process::run(git, args, TIMEOUT)
        .map_err(|e| Error::Failed(format!("could not run git: {e}")))?;
    if output.status.success() {
        Ok(())
    } else {
        Err(Error::Failed(format!(
            "git config failed: {}",
            sanitize(output.stderr.trim())
        )))
    }
}

pub(crate) fn keymate_gitconfig(key: &str, ssh_keygen: &Path, allowed_signers: bool) -> String {
    let mut text = format!(
        "# Managed by Keymate (`keymate setup github`). Changes here may be replaced.\n\
         [gpg]\n\
         \tformat = ssh\n\
         [gpg \"ssh\"]\n\
         \tprogram = {}\n",
        ssh_keygen.display()
    );
    if allowed_signers {
        text += "\tallowedSignersFile = ~/.ssh/keymate/allowed_signers\n";
    }
    text += &format!(
        "[user]\n\
         \tsigningKey = {key}.pub\n\
         [commit]\n\
         \tgpgSign = true\n\
         [tag]\n\
         \tgpgSign = true\n"
    );
    text
}

/// The key file git signs with, from `~/.ssh/keymate/gitconfig`.
pub(crate) fn signing_key_name(ssh_dir: &Path) -> Option<String> {
    let text = fs::read_to_string(ssh_dir.join("keymate/gitconfig")).ok()?;
    text.lines().find_map(|line| {
        let value = line.trim().strip_prefix("signingKey = ~/.ssh/")?;
        value.strip_suffix(".pub").map(str::to_owned)
    })
}

/// Turn off Keymate's git signing: drop the include and its files. Returns
/// whether anything was there.
pub(crate) fn remove_signing(ssh_dir: &Path) -> Result<bool> {
    let mut removed = false;
    if let Some(git) = find_on_path("git") {
        let included = git_global(&git, &["--get-all", "include.path"])?
            .is_some_and(|paths| paths.lines().any(|l| l.trim() == GIT_INCLUDE));
        if included {
            run_git(
                &git,
                &[
                    "config",
                    "--global",
                    "--fixed-value",
                    "--unset-all",
                    "include.path",
                    GIT_INCLUDE,
                ],
            )?;
            removed = true;
        }
    }
    for name in SIGNING_FILES {
        let path = ssh_dir.join("keymate").join(name);
        if path.exists() {
            files::remove_file(&path)?;
            removed = true;
        }
    }
    Ok(removed)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn gitconfig_signs_with_key() {
        let text = keymate_gitconfig("~/.ssh/k", Path::new("/opt/homebrew/bin/ssh-keygen"), false);
        assert!(text.contains("\tformat = ssh\n"));
        assert!(text.contains("\tprogram = /opt/homebrew/bin/ssh-keygen\n"));
        assert!(text.contains("\tsigningKey = ~/.ssh/k.pub\n"));
        assert!(!text.contains("allowedSignersFile"));
    }
}
