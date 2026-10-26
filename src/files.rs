//! Where Keymate's files are, and careful local file changes: atomic writes
//! and restrictive permissions.

use std::env;
use std::fs::{self, DirBuilder, OpenOptions};
use std::io::{self, Write};
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};

use crate::{Error, Result};

/// The home folder, from `HOME`.
pub(crate) fn home() -> Option<PathBuf> {
    env::var_os("HOME").map(PathBuf::from)
}

/// `~/.ssh`, where key files and Keymate's settings live.
pub(crate) fn ssh_dir() -> Result<PathBuf> {
    let home = home().ok_or_else(|| Error::Failed("HOME is not set".into()))?;
    Ok(home.join(".ssh"))
}

/// Delete `path`; a missing file is fine.
pub(crate) fn remove_file(path: &Path) -> Result<()> {
    match fs::remove_file(path) {
        Err(e) if e.kind() != io::ErrorKind::NotFound => Err(Error::Failed(format!(
            "Could not delete {}: {e}",
            path.display()
        ))),
        _ => Ok(()),
    }
}

/// Create `dir` (and missing parents) readable only by the user.
pub(crate) fn ensure_private_dir(dir: &Path) -> io::Result<()> {
    if dir.is_dir() {
        return Ok(());
    }
    DirBuilder::new().recursive(true).mode(0o700).create(dir)
}

/// Replace `path` with `contents` atomically. A symlinked file (for example
/// one managed by a dotfiles tool) is updated at its target, keeping the link.
pub(crate) fn write_atomic(path: &Path, contents: &str, mode: u32) -> io::Result<()> {
    let path = resolve(path)?;
    let dir = path
        .parent()
        .ok_or_else(|| io::Error::other("file has no parent directory"))?;
    let name = path
        .file_name()
        .ok_or_else(|| io::Error::other("path has no file name"))?;
    let temp = dir.join(format!(".{}.keymate-tmp", name.to_string_lossy()));

    match fs::remove_file(&temp) {
        Err(e) if e.kind() != io::ErrorKind::NotFound => return Err(e),
        _ => {}
    }
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(mode)
        .open(&temp)?;
    file.write_all(contents.as_bytes())?;
    file.sync_all()?;
    drop(file);
    fs::rename(&temp, &path)
}

/// `<file>.keymate-backup` next to the file (next to a symlink's target).
fn backup_path(path: &Path) -> io::Result<PathBuf> {
    let path = resolve(path)?;
    let mut name = path.file_name().unwrap_or_default().to_owned();
    name.push(".keymate-backup");
    Ok(path.with_file_name(name))
}

/// Backups of `path` that earlier Keymate versions made
/// (`<file>.keymate-backup` and `<file>.keymate-backup-<time>`), so removal
/// can clean them up.
pub(crate) fn backups(path: &Path) -> Vec<PathBuf> {
    let Ok(current) = backup_path(path) else {
        return Vec::new();
    };
    let Some(dir) = current.parent() else {
        return Vec::new();
    };
    let prefix = current
        .file_name()
        .unwrap_or_default()
        .to_string_lossy()
        .into_owned();
    let Ok(entries) = fs::read_dir(dir) else {
        return Vec::new();
    };
    let mut found: Vec<PathBuf> = entries
        .filter_map(|e| e.ok())
        .filter(|e| {
            let name = e.file_name().to_string_lossy().into_owned();
            name == prefix
                || name
                    .strip_prefix(&format!("{prefix}-"))
                    .is_some_and(|t| t.chars().all(|c| c.is_ascii_digit()))
        })
        .map(|e| e.path())
        .collect();
    found.sort();
    found
}

/// The permission bits of an existing file.
pub(crate) fn mode(path: &Path) -> Option<u32> {
    fs::metadata(path)
        .ok()
        .map(|m| m.permissions().mode() & 0o777)
}

fn resolve(path: &Path) -> io::Result<PathBuf> {
    match fs::symlink_metadata(path) {
        Ok(meta) if meta.file_type().is_symlink() => fs::canonicalize(path),
        _ => Ok(path.to_owned()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::symlink;

    fn scratch_dir(name: &str) -> PathBuf {
        let dir = env::temp_dir().join(format!("keymate-files-{name}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn writes_atomically_with_mode() {
        let dir = scratch_dir("write");
        let file = dir.join("config");
        fs::write(&file, "old").unwrap();
        write_atomic(&file, "new", 0o600).unwrap();
        assert_eq!(fs::read_to_string(&file).unwrap(), "new");
        assert_eq!(mode(&file), Some(0o600));
        assert!(!dir.join(".config.keymate-tmp").exists());
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn keeps_symlinks_and_finds_old_backups() {
        let dir = scratch_dir("link");
        let target = dir.join("dotfiles-config");
        let link = dir.join("config");
        fs::write(&target, "old").unwrap();
        symlink(&target, &link).unwrap();

        write_atomic(&link, "new", 0o600).unwrap();
        fs::write(dir.join("dotfiles-config.keymate-backup"), "old").unwrap();
        fs::write(dir.join("dotfiles-config.keymate-backup-123"), "older").unwrap();
        assert_eq!(backups(&link).len(), 2);

        assert!(
            fs::symlink_metadata(&link)
                .unwrap()
                .file_type()
                .is_symlink()
        );
        assert_eq!(fs::read_to_string(&target).unwrap(), "new");
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn private_dirs_are_user_only() {
        let dir = scratch_dir("private").join("a/b");
        ensure_private_dir(&dir).unwrap();
        assert_eq!(mode(&dir), Some(0o700));
        fs::remove_dir_all(dir.parent().unwrap().parent().unwrap()).unwrap();
    }
}
