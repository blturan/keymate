//! Keymate's `Include` line in `~/.ssh/config`.

use std::fs;
use std::path::Path;

use crate::Result;
use crate::error::Context;
use crate::files;

pub(crate) const INCLUDE: &str = "Include ~/.ssh/keymate/config";

/// The comment earlier versions put above [`INCLUDE`]; removal still takes
/// it out.
pub(crate) const INCLUDE_COMMENT: &str =
    "# Added by Keymate. Remove the next line to turn off Keymate's SSH settings.";

/// `config` with Keymate's `Include` prepended, or `None` if already present.
/// It goes first because OpenSSH uses the first value it finds for a setting.
pub(crate) fn with_include(config: &str) -> Option<String> {
    let present = config.lines().any(is_include_line);
    (!present).then(|| format!("{INCLUDE}\n\n{config}"))
}

/// Whether an SSH config line includes Keymate's config file.
pub(crate) fn is_include_line(line: &str) -> bool {
    let mut words = line.split_whitespace();
    words
        .next()
        .is_some_and(|w| w.eq_ignore_ascii_case("include"))
        && words.any(|w| w == "~/.ssh/keymate/config")
}

/// Take Keymate's lines out of `~/.ssh/config`. No new backup is made: the
/// edit only removes what setup added, and setup's backup is kept until then.
pub(crate) fn remove_include(ssh_dir: &Path) -> Result<bool> {
    let config = ssh_dir.join("config");
    let text = fs::read_to_string(&config).context("read ~/.ssh/config")?;
    let Some(updated) = without_include(&text) else {
        return Ok(false);
    };
    let mode = files::mode(&config).unwrap_or(0o600);
    files::write_atomic(&config, &updated, mode).context("update ~/.ssh/config")?;
    Ok(true)
}

/// `config` without Keymate's `Include` line and comment, or `None` if absent.
/// Text that setup prepended is removed exactly, restoring the original.
fn without_include(config: &str) -> Option<String> {
    // What setup prepends now, and with a comment in earlier versions.
    for prepended in [
        format!("{INCLUDE}\n\n"),
        format!("{INCLUDE_COMMENT}\n{INCLUDE}\n\n"),
    ] {
        if let Some(original) = config.strip_prefix(&prepended) {
            return Some(original.to_owned());
        }
    }
    if !config.lines().any(is_include_line) {
        return None;
    }
    let kept: Vec<&str> = config
        .lines()
        .filter(|l| !is_include_line(l) && l.trim() != INCLUDE_COMMENT)
        .collect();
    let mut text = kept.join("\n");
    if config.ends_with('\n') && !text.is_empty() {
        text.push('\n');
    }
    Some(text)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn include_is_prepended_once() {
        let updated = with_include("Host *\n    AddKeysToAgent yes\n").unwrap();
        assert!(updated.starts_with("Include ~/.ssh/keymate/config\n\nHost *\n"));
        assert_eq!(with_include(&updated), None);
        assert_eq!(with_include("include   ~/.ssh/keymate/config"), None);
        assert!(with_include("").is_some());
    }

    #[test]
    fn removing_include_restores_original_config() {
        let original = "Host *\n    AddKeysToAgent yes\n";
        let added = with_include(original).unwrap();
        assert_eq!(without_include(&added).as_deref(), Some(original));
        assert_eq!(without_include(original), None);
    }

    #[test]
    fn removes_include_written_by_earlier_versions() {
        let original = "Host *\n    User me\n";
        let earlier = format!("{INCLUDE_COMMENT}\n{INCLUDE}\n\n{original}");
        assert_eq!(without_include(&earlier).as_deref(), Some(original));
    }

    #[test]
    fn removes_include_that_was_moved_or_edited() {
        let edited = "Host *\n    User me\n\nInclude ~/.ssh/keymate/config\n";
        assert_eq!(
            without_include(edited).as_deref(),
            Some("Host *\n    User me\n\n")
        );
    }
}
