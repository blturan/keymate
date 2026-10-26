//! `keymate update`: through Homebrew when Homebrew installed Keymate,
//! otherwise by replacing this binary with the one from the GitHub release.

use std::env;
use std::fs;
use std::io;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use crate::error::Context;
use crate::files;
use crate::github::api::Gh;
use crate::process;
use crate::tools::{find_on_path, sanitize};
use crate::{Error, Result};

/// The GitHub repository releases come from.
const REPO: &str = "blturan/keymate";
pub const CURRENT: &str = env!("CARGO_PKG_VERSION");
const TIMEOUT: Duration = Duration::from_secs(120);
/// How often other commands look for a new release.
const CHECK_EVERY: Duration = Duration::from_secs(24 * 60 * 60);
/// The background check must never hold a command up for long.
const CHECK_TIMEOUT: Duration = Duration::from_secs(5);

/// How this copy of Keymate was installed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Install {
    /// By Homebrew, which must also upgrade it.
    Homebrew(PathBuf),
    /// As a plain binary at this path.
    Binary(PathBuf),
}

pub fn install() -> Result<Install> {
    let exe = env::current_exe()
        .and_then(fs::canonicalize)
        .map_err(|e| Error::Failed(format!("could not find the keymate binary: {e}")))?;
    if exe.to_string_lossy().contains("/Cellar/keymate/") {
        let brew = find_on_path("brew").ok_or(Error::MissingTool {
            name: "brew",
            install: "https://brew.sh",
        })?;
        return Ok(Install::Homebrew(brew));
    }
    Ok(Install::Binary(exe))
}

/// `brew upgrade keymate`, with Homebrew's output on the terminal.
pub fn brew_upgrade(brew: &Path) -> Result<()> {
    let status = process::run_interactive(brew, &["upgrade", "keymate"])
        .map_err(|e| Error::Failed(format!("could not run brew: {e}")))?;
    if status.success() {
        Ok(())
    } else {
        Err(Error::Failed("brew upgrade keymate failed".into()))
    }
}

/// A release newer than this one, looked up at most once a day and
/// remembered in `~/Library/Caches/keymate`. Best effort: `None` when up to
/// date, offline, or anything else goes wrong.
pub fn newer_release() -> Option<String> {
    let cache = files::home()?.join("Library/Caches/keymate/latest-version");
    let now = SystemTime::now().duration_since(UNIX_EPOCH).ok()?.as_secs();
    let cached = fs::read_to_string(&cache).ok().and_then(|text| {
        let (checked, version) = text.trim().split_once(' ')?;
        Some((checked.parse::<u64>().ok()?, version.to_owned()))
    });
    let latest = match cached {
        Some((checked, version)) if now.saturating_sub(checked) < CHECK_EVERY.as_secs() => version,
        _ => {
            // Remembered even when the lookup fails, so an offline Mac
            // doesn't try again on every command.
            let latest = lookup(CHECK_TIMEOUT).unwrap_or_else(|_| CURRENT.to_owned());
            if let Some(dir) = cache.parent() {
                let _ = fs::create_dir_all(dir);
            }
            let _ = fs::write(&cache, format!("{now} {latest}\n"));
            latest
        }
    };
    is_newer(&latest, CURRENT).then_some(latest)
}

/// The latest release's version, e.g. `0.2.0`.
pub fn latest() -> Result<String> {
    lookup(TIMEOUT)
}

fn lookup(timeout: Duration) -> Result<String> {
    let output = Gh::find()?
        .run(
            &[
                "api",
                &format!("repos/{REPO}/releases/latest"),
                "--jq",
                ".tag_name",
            ],
            timeout,
        )
        .map_err(|e| match e {
            Error::ToolFailed { detail, .. } if detail.contains("404") => {
                Error::Failed(format!("No Keymate release found on github.com/{REPO}"))
            }
            e => e,
        })?;
    let tag = sanitize(output.trim());
    let version = tag.strip_prefix('v').unwrap_or(&tag).to_owned();
    if parse(&version).is_none() {
        return Err(Error::Failed(format!(
            "the latest release has an unexpected tag `{tag}`"
        )));
    }
    Ok(version)
}

/// Whether `latest` is a newer version than `current`.
pub fn is_newer(latest: &str, current: &str) -> bool {
    matches!((parse(latest), parse(current)), (Some(l), Some(c)) if l > c)
}

fn parse(version: &str) -> Option<(u64, u64, u64)> {
    let mut parts = version.split('.').map(|p| p.parse().ok());
    let parsed = (parts.next()??, parts.next()??, parts.next()??);
    parts.next().is_none().then_some(parsed)
}

/// The release file for this Mac.
fn asset() -> Result<&'static str> {
    match env::consts::ARCH {
        "aarch64" => Ok("keymate-aarch64-apple-darwin"),
        _ => Err(Error::Failed(
            "Keymate only supports Macs with Apple silicon".into(),
        )),
    }
}

/// Download `version` and put it in place of the binary at `exe`. The new
/// binary must report that version before it replaces the running one.
pub fn replace(version: &str, exe: &Path) -> Result<String> {
    let dir = env::temp_dir().join(format!("keymate-upgrade-{}", std::process::id()));
    fs::create_dir_all(&dir).context("create a download folder")?;
    let result = download_and_install(version, exe, &dir);
    let _ = fs::remove_dir_all(&dir);
    result?;
    Ok(format!("Updated to keymate {version}"))
}

fn download_and_install(version: &str, exe: &Path, dir: &Path) -> Result<()> {
    let asset = asset()?;
    let dir_arg = dir.to_string_lossy();
    Gh::find()?.run(
        &[
            "release",
            "download",
            &format!("v{version}"),
            "--repo",
            REPO,
            "--pattern",
            asset,
            "--dir",
            &dir_arg,
        ],
        TIMEOUT,
    )?;
    let new = dir.join(asset);
    fs::set_permissions(&new, fs::Permissions::from_mode(0o755))
        .context("make the download executable")?;
    let output = process::run(&new, &["--version"], Duration::from_secs(15))
        .map_err(|e| Error::Failed(format!("the downloaded keymate does not run: {e}")))?;
    if output.stdout.trim() != format!("keymate {version}") {
        return Err(Error::Failed(
            "the downloaded keymate reports a different version; nothing was changed".into(),
        ));
    }
    match swap(&new, exe) {
        Ok(()) => Ok(()),
        // Installed somewhere only root can write, e.g. /usr/local/bin.
        Err(e) if e.kind() == io::ErrorKind::PermissionDenied => sudo_install(&new, exe),
        Err(e) => Err(Error::Failed(format!(
            "could not replace {}: {e}",
            exe.display()
        ))),
    }
}

/// Copy next to `exe`, then rename over it, so it is never half-written.
fn swap(new: &Path, exe: &Path) -> io::Result<()> {
    let staged = exe.with_file_name(format!(".keymate-upgrade-{}", std::process::id()));
    fs::copy(new, &staged)?;
    fs::set_permissions(&staged, fs::Permissions::from_mode(0o755))?;
    fs::rename(&staged, exe).inspect_err(|_| {
        let _ = fs::remove_file(&staged);
    })
}

fn sudo_install(new: &Path, exe: &Path) -> Result<()> {
    let status = Command::new("sudo")
        .arg("install")
        .args(["-m", "755"])
        .arg(new)
        .arg(exe)
        .status()
        .map_err(|e| Error::Failed(format!("could not run sudo: {e}")))?;
    if status.success() {
        Ok(())
    } else {
        Err(Error::Failed(format!(
            "could not replace {}; nothing was changed",
            exe.display()
        )))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn compares_versions_numerically() {
        assert!(is_newer("0.10.0", "0.9.0"));
        assert!(is_newer("1.0.0", "0.9.9"));
        assert!(!is_newer("0.1.0", "0.1.0"));
        assert!(!is_newer("0.1.0", "0.2.0"));
        assert!(!is_newer("garbage", "0.1.0"));
        assert!(!is_newer("0.1", "0.0.1"));
    }

    #[test]
    fn swap_replaces_the_file_in_place() {
        let dir = env::temp_dir().join(format!("keymate-swap-{}", std::process::id()));
        fs::create_dir_all(&dir).unwrap();
        let (new, exe) = (dir.join("new"), dir.join("keymate"));
        fs::write(&new, "new").unwrap();
        fs::write(&exe, "old").unwrap();
        swap(&new, &exe).unwrap();
        assert_eq!(fs::read_to_string(&exe).unwrap(), "new");
        assert_eq!(
            fs::metadata(&exe).unwrap().permissions().mode() & 0o777,
            0o755
        );
        assert_eq!(fs::read_dir(&dir).unwrap().count(), 2);
        fs::remove_dir_all(dir).unwrap();
    }
}
