//! Locating and validating the external tools Keymate relies on.

use std::env;
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

use crate::{Error, Result};

/// Where package managers and macOS install command-line tools, in the order
/// Keymate suggests them when the `PATH` lookup finds nothing suitable.
pub(crate) const KNOWN_DIRS: [&str; 3] = ["/opt/homebrew/bin", "/usr/local/bin", "/usr/bin"];

/// Find `name` the way a shell would, ignoring relative `PATH` entries.
pub(crate) fn find_on_path(name: &str) -> Option<PathBuf> {
    let path = env::var_os("PATH")?;
    find_in(env::split_paths(&path), name)
}

/// Find `name` in the well-known install directories.
pub(crate) fn find_in_known_dirs(name: &str) -> impl Iterator<Item = PathBuf> {
    KNOWN_DIRS
        .iter()
        .map(move |dir| Path::new(dir).join(name))
        .filter(|candidate| is_executable(candidate))
}

fn find_in(dirs: impl IntoIterator<Item = PathBuf>, name: &str) -> Option<PathBuf> {
    dirs.into_iter()
        .filter(|dir| dir.is_absolute())
        .map(|dir| dir.join(name))
        .find(|candidate| is_executable(candidate))
}

fn is_executable(path: &Path) -> bool {
    fs::metadata(path).is_ok_and(|meta| meta.is_file() && meta.permissions().mode() & 0o111 != 0)
}

/// Whether an OpenSSH binary (`ssh` or `ssh-keygen`) can use FIDO security keys.
///
/// OpenSSH talks to security keys through `libexec/ssh-sk-helper`. Builds
/// without libfido2, such as the one shipped with macOS, install a helper that
/// cannot reach a key, so look for libfido2 in the helper next to the binary.
pub(crate) fn openssh_supports_fido(binary: &Path) -> bool {
    let Ok(real) = fs::canonicalize(binary) else {
        return false;
    };
    let Some(prefix) = real.parent().and_then(Path::parent) else {
        return false;
    };
    fs::read(prefix.join("libexec/ssh-sk-helper"))
        .is_ok_and(|bytes| bytes.windows(8).any(|window| window == b"libfido2"))
}

/// `ssh` or `ssh-keygen` from an OpenSSH that can use security keys.
pub(crate) fn fido_openssh(name: &'static str) -> Result<PathBuf> {
    match find_on_path(name) {
        Some(path) if openssh_supports_fido(&path) => Ok(path),
        Some(path) => Err(Error::fixable(
            format!("{} can't use security keys", path.display()),
            "Run `keymate doctor` to see how to fix it",
        )),
        None => Err(Error::MissingTool {
            name,
            install: "brew install openssh",
        }),
    }
}

/// Strip control characters from text reported by devices or other tools.
pub(crate) fn sanitize(text: &str) -> String {
    text.chars().filter(|c| !c.is_control()).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scratch_dir(name: &str) -> PathBuf {
        let dir = env::temp_dir().join(format!("keymate-{name}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn write_file(path: &Path, contents: &[u8], mode: u32) {
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(path, contents).unwrap();
        fs::set_permissions(path, fs::Permissions::from_mode(mode)).unwrap();
    }

    #[test]
    fn path_lookup_skips_relative_and_non_executable_entries() {
        let dir = scratch_dir("path");
        write_file(&dir.join("a/tool"), b"", 0o644);
        write_file(&dir.join("b/tool"), b"", 0o755);
        let dirs = vec![PathBuf::from("relative"), dir.join("a"), dir.join("b")];
        assert_eq!(find_in(dirs, "tool"), Some(dir.join("b/tool")));
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn fido_support_depends_on_sk_helper_linking_libfido2() {
        let dir = scratch_dir("fido");
        write_file(&dir.join("fido/bin/ssh"), b"", 0o755);
        write_file(
            &dir.join("fido/libexec/ssh-sk-helper"),
            b"..libfido2.1.dylib..",
            0o755,
        );
        write_file(&dir.join("plain/bin/ssh"), b"", 0o755);
        write_file(&dir.join("plain/libexec/ssh-sk-helper"), b"..", 0o755);
        assert!(openssh_supports_fido(&dir.join("fido/bin/ssh")));
        assert!(!openssh_supports_fido(&dir.join("plain/bin/ssh")));
        assert!(!openssh_supports_fido(&dir.join("missing/bin/ssh")));
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn sanitize_removes_control_characters() {
        assert_eq!(sanitize("Yubi\u{1b}[31mKey\n"), "Yubi[31mKey");
    }
}
