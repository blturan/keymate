//! Keymate's GitHub enrollments on this Mac: one key file per security key,
//! named `~/.ssh/id_<type>_sk_keymate_github_<name>`, with a small non-secret
//! `.info` file in `~/.ssh/keymate` describing the security key it belongs to.

use std::fs;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use super::api::key_identity;
use crate::devices::{self, Device, YUBICO};
use crate::error::Context;
use crate::files;
use crate::sshkey::{self, SkKey};
use crate::tools::sanitize;
use crate::{Error, Result};

const PREFIXES: [&str; 2] = ["id_ed25519_sk_keymate_github", "id_ecdsa_sk_keymate_github"];

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Enrollment {
    /// The private key file.
    pub key: PathBuf,
    /// Parsed key file; `None` if it is missing or unreadable.
    pub sk: Option<SkKey>,
    /// The public key as `type base64`, from the `.pub` file.
    pub public_key: Option<String>,
    /// Security key model recorded at setup, e.g. `YubiKey 5C NFC`.
    pub device: Option<String>,
    /// Setup date, `YYYY-MM-DD`.
    pub created: Option<String>,
}

impl Enrollment {
    pub fn file_name(&self) -> String {
        self.key
            .file_name()
            .unwrap_or_default()
            .to_string_lossy()
            .into_owned()
    }

    /// `~/.ssh/<file>`, as written in config files.
    pub fn display(&self) -> String {
        format!("~/.ssh/{}", self.file_name())
    }

    /// The name given at setup (the file suffix); `None` for files from
    /// versions without names.
    pub fn name(&self) -> Option<String> {
        PREFIXES.iter().find_map(|prefix| {
            let rest = self
                .file_name()
                .strip_prefix(prefix)?
                .strip_prefix('_')?
                .to_owned();
            Some(rest)
        })
    }

    /// The name, or the file for keys without one.
    pub fn short_name(&self) -> String {
        self.name().unwrap_or_else(|| self.display())
    }

    pub(crate) fn public_path(&self) -> PathBuf {
        public_path(&self.key)
    }

    pub(crate) fn info_path(&self) -> PathBuf {
        info_path(&self.key)
    }

    /// The key files and info file that exist.
    pub(crate) fn files(&self) -> Vec<PathBuf> {
        [self.key.clone(), self.public_path(), self.info_path()]
            .into_iter()
            .filter(|p| p.exists())
            .collect()
    }
}

pub(crate) fn public_path(key: &Path) -> PathBuf {
    let mut name = key.file_name().unwrap_or_default().to_owned();
    name.push(".pub");
    key.with_file_name(name)
}

fn info_path(key: &Path) -> PathBuf {
    let name = key.file_name().unwrap_or_default().to_string_lossy();
    key.with_file_name("keymate").join(format!("{name}.info"))
}

/// All Keymate enrollments in `ssh_dir`, sorted by file name.
pub(crate) fn list(ssh_dir: &Path) -> Vec<Enrollment> {
    let Ok(entries) = fs::read_dir(ssh_dir) else {
        return Vec::new();
    };
    let mut names: Vec<String> = entries
        .filter_map(|e| e.ok()?.file_name().into_string().ok())
        .map(|name| name.strip_suffix(".pub").unwrap_or(&name).to_owned())
        .filter(|name| is_key_name(name))
        .collect();
    names.sort();
    names.dedup();
    names
        .into_iter()
        .map(|name| load(&ssh_dir.join(name)))
        .collect()
}

fn is_key_name(name: &str) -> bool {
    PREFIXES.iter().any(|prefix| {
        name.strip_prefix(prefix).is_some_and(|rest| {
            rest.is_empty()
                || rest.strip_prefix('_').is_some_and(|s| {
                    !s.is_empty()
                        && s.chars()
                            .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-')
                })
        })
    })
}

pub(crate) fn load(key: &Path) -> Enrollment {
    let info = fs::read_to_string(info_path(key)).unwrap_or_default();
    let value = |name: &str| {
        info.lines()
            .find_map(|l| l.strip_prefix(name)?.strip_prefix('='))
            .map(sanitize)
    };
    Enrollment {
        key: key.to_owned(),
        sk: fs::read_to_string(key)
            .ok()
            .and_then(|text| sshkey::parse_private(&text)),
        public_key: fs::read_to_string(public_path(key))
            .ok()
            .and_then(|text| key_identity(&text)),
        device: value("device"),
        created: value("created"),
    }
}

/// How the connected security key relates to existing enrollments.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Detection {
    /// Keymate has no keys on this Mac.
    NoEnrollments,
    /// The connected key holds this enrollment's credential.
    ThisKey(Enrollment),
    /// Keymate keys exist, but none belongs to the connected key.
    OtherKeys,
    /// These enrollments could not be checked and may belong to the key.
    Unknown(Vec<Enrollment>),
}

/// Ask the connected key, without a touch, which enrollment is its own.
pub(crate) fn detect(enrollments: &[Enrollment], device: &Device) -> Detection {
    if enrollments.is_empty() {
        return Detection::NoEnrollments;
    }
    let mut unknown = Vec::new();
    for enrollment in enrollments {
        let owned = enrollment.sk.as_ref().and_then(|sk| {
            devices::owns_credential(device, &sk.application, &sk.key_handle_base64())
                .ok()
                .flatten()
        });
        match owned {
            Some(true) => return Detection::ThisKey(enrollment.clone()),
            Some(false) => {}
            None => unknown.push(enrollment.clone()),
        }
    }
    if unknown.is_empty() {
        Detection::OtherKeys
    } else {
        Detection::Unknown(unknown)
    }
}

/// The longest name: a resident credential stores it in its user id, which
/// OpenSSH caps at 31 characters, next to a random suffix (`name.a1b2c3`).
pub(crate) const MAX_NAME: usize = 24;

/// Check a name given with `--name`: lowercase letters, digits, and dashes.
pub(crate) fn validate_name(name: &str) -> std::result::Result<(), String> {
    let valid = !name.is_empty()
        && name.len() <= MAX_NAME
        && name
            .chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-');
    if valid {
        Ok(())
    } else {
        Err(format!(
            "Use 1-{MAX_NAME} lowercase letters, digits, or dashes, e.g. `yubikey` or `backup`."
        ))
    }
}

/// Whether a Keymate key file with this name exists, other than `except`
/// (the key being replaced, whose name may be reused).
pub(crate) fn name_taken(ssh_dir: &Path, name: &str, except: Option<&Path>) -> bool {
    PREFIXES.iter().any(|prefix| {
        let path = ssh_dir.join(format!("{prefix}_{name}"));
        except != Some(path.as_path()) && (path.exists() || public_path(&path).exists())
    })
}

/// Where a replacement with the replaced key's own name is created, so the
/// old key keeps working until the new one is tested. Not a key name, so
/// [`list`] ignores it.
pub(crate) fn staged_path(key: &Path) -> PathBuf {
    let mut name = key.file_name().unwrap_or_default().to_owned();
    name.push(".keymate-new");
    key.with_file_name(name)
}

/// Move a staged key's files (key, `.pub`, `.info`) to `key`, replacing
/// whatever is there.
pub(crate) fn unstage(staged: &Path, key: &Path) -> Result<()> {
    for (from, to) in [
        (staged.to_owned(), key.to_owned()),
        (public_path(staged), public_path(key)),
        (info_path(staged), info_path(key)),
    ] {
        fs::rename(&from, &to)
            .map_err(|e| Error::Failed(format!("Could not move {}: {e}", from.display())))?;
    }
    Ok(())
}

/// A free name suggestion based on the key's maker: `yubikey`, `yubikey-2`, ...
pub(crate) fn suggest_name(ssh_dir: &Path, device: &Device) -> String {
    let base = if device.vendor_id == YUBICO {
        "yubikey"
    } else {
        "securitykey"
    };
    std::iter::once(base.to_owned())
        .chain((2..).map(|n| format!("{base}-{n}")))
        .find(|name| !name_taken(ssh_dir, name, None))
        .expect("an unbounded sequence of names has a free one")
}

pub(crate) fn key_path(ssh_dir: &Path, ed25519: bool, name: &str) -> PathBuf {
    let prefix = PREFIXES[if ed25519 { 0 } else { 1 }];
    ssh_dir.join(format!("{prefix}_{name}"))
}

/// Record which security key an enrollment belongs to.
pub(crate) fn write_info(key: &Path, device: &str, account: &str) -> Result<()> {
    let path = info_path(key);
    let dir = path.parent().unwrap_or(Path::new("."));
    files::ensure_private_dir(dir).context("create ~/.ssh/keymate")?;
    let text = format!(
        "# Written by `keymate setup github`.\ndevice={}\ncreated={}\naccount={}\n",
        sanitize(device),
        today(),
        sanitize(account)
    );
    files::write_atomic(&path, &text, 0o600)
        .map_err(|e| Error::Failed(format!("Could not write {}: {e}", path.display())))
}

/// `~/.ssh/keymate/config`: every enrolled key may be used for github.com,
/// so whichever security key is plugged in works.
pub(crate) fn ssh_config(enrollments: &[Enrollment]) -> String {
    let mut text = String::from(
        "# Managed by Keymate (`keymate setup github`). Changes here may be replaced.\n\
         Host github.com\n",
    );
    for enrollment in enrollments {
        text += &format!("    IdentityFile {}\n", enrollment.display());
    }
    text += "    IdentitiesOnly yes\n    \
             UserKnownHostsFile ~/.ssh/known_hosts ~/.ssh/keymate/known_hosts\n";
    text
}

/// Write `~/.ssh/keymate/config` listing `enrolled`.
pub(crate) fn write_ssh_config(ssh_dir: &Path, enrolled: &[Enrollment]) -> Result<()> {
    let dir = ssh_dir.join("keymate");
    files::ensure_private_dir(&dir).context("create ~/.ssh/keymate")?;
    files::write_atomic(&dir.join("config"), &ssh_config(enrolled), 0o600)
        .context("write ~/.ssh/keymate/config")
}

/// Delete an enrollment's key files and info file.
pub(crate) fn delete_enrollment_files(enrollment: &Enrollment) -> Result<()> {
    for path in enrollment.files() {
        files::remove_file(&path)?;
    }
    Ok(())
}

/// Delete an enrollment's resident credential from `device` by its exact id,
/// unlocking the key with `pin`.
pub fn delete_resident(device: &Device, enrollment: &Enrollment, pin: &str) -> Result<String> {
    let Some(sk) = &enrollment.sk else {
        return Err(Error::Failed(
            "the key file is unreadable, so the credential id is unknown".into(),
        ));
    };
    devices::delete_credential(device, &sk.key_handle, pin)?;
    // Confirm it is gone, silently (no touch or PIN).
    let id = sk.key_handle_base64();
    if devices::owns_credential(device, &sk.application, &id)? == Some(true) {
        return Err(Error::fixable(
            format!("The credential is still on your {}", device.noun()),
            match device.vendor_id {
                devices::YUBICO => "Delete it with `ykman fido credentials delete`",
                _ => "Delete it with your security key's own tool",
            },
        ));
    }
    Ok(format!("Deleted the credential from {}", device.name))
}

/// Today's date in UTC as `YYYY-MM-DD`.
fn today() -> String {
    let days = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() / 86_400)
        .unwrap_or_default();
    civil_date(days as i64)
}

/// Convert days since 1970-01-01 to a calendar date (Howard Hinnant's algorithm).
fn civil_date(days: i64) -> String {
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = yoe + era * 400 + i64::from(month <= 2);
    format!("{year:04}-{month:02}-{day:02}")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sshkey::tests::key_file;
    use std::env;

    fn scratch_dir(name: &str) -> PathBuf {
        let dir = env::temp_dir().join(format!("keymate-enroll-{name}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(dir.join("keymate")).unwrap();
        dir
    }

    #[test]
    fn recognizes_keymate_key_names() {
        assert!(is_key_name("id_ed25519_sk_keymate_github"));
        assert!(is_key_name("id_ed25519_sk_keymate_github_19325896"));
        assert!(is_key_name("id_ecdsa_sk_keymate_github_2"));
        assert!(!is_key_name("id_ed25519_sk_keymate_github_"));
        assert!(!is_key_name("id_ed25519_sk_keymate_github.keymate-tmp"));
        assert!(!is_key_name("id_ed25519_sk"));
    }

    #[test]
    fn lists_enrollments_with_info() {
        let dir = scratch_dir("list");
        let key = dir.join("id_ed25519_sk_keymate_github_1");
        fs::write(&key, key_file("ssh:keymate-github", 0x01, b"h")).unwrap();
        fs::write(public_path(&key), "sk-ssh-ed25519@openssh.com AAAA c\n").unwrap();
        fs::write(dir.join("id_ed25519_sk"), "not ours").unwrap();
        write_info(&key, "YubiKey 5C NFC", "octocat").unwrap();

        let found = list(&dir);
        assert_eq!(found.len(), 1);
        let enrollment = &found[0];
        assert_eq!(
            enrollment.sk.as_ref().unwrap().application,
            "ssh:keymate-github"
        );
        assert_eq!(
            enrollment.public_key.as_deref(),
            Some("sk-ssh-ed25519@openssh.com AAAA")
        );
        assert_eq!(enrollment.device.as_deref(), Some("YubiKey 5C NFC"));
        assert_eq!(enrollment.files().len(), 3);
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn names_are_validated_and_suggested() {
        assert!(validate_name("yubikey").is_ok());
        assert!(validate_name("backup-2").is_ok());
        assert!(validate_name("").is_err());
        assert!(validate_name("My Key").is_err());
        assert!(validate_name("a_b").is_err());

        let dir = scratch_dir("names");
        let device = Device {
            path: "ioreg://1".into(),
            vendor_id: YUBICO,
            product_id: 0x0406,
            name: "YubiKey".into(),
            info: None,
        };
        assert_eq!(suggest_name(&dir, &device), "yubikey");
        let taken = key_path(&dir, true, "yubikey");
        fs::write(public_path(&taken), "x").unwrap();
        assert!(name_taken(&dir, "yubikey", None));
        assert!(!name_taken(&dir, "yubikey", Some(&taken)));
        assert!(!is_key_name(
            &staged_path(&taken).file_name().unwrap().to_string_lossy()
        ));
        assert_eq!(suggest_name(&dir, &device), "yubikey-2");
        assert!(key_path(&dir, false, "backup").ends_with("id_ecdsa_sk_keymate_github_backup"));
        assert_eq!(load(&taken).name().as_deref(), Some("yubikey"));
        assert_eq!(load(&dir.join("id_ed25519_sk_keymate_github")).name(), None);
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn ssh_config_lists_every_key() {
        let enrollment = |name: &str| Enrollment {
            key: PathBuf::from(format!("/h/.ssh/{name}")),
            sk: None,
            public_key: None,
            device: None,
            created: None,
        };
        let text = ssh_config(&[enrollment("a"), enrollment("b")]);
        assert!(
            text.contains(
                "Host github.com\n    IdentityFile ~/.ssh/a\n    IdentityFile ~/.ssh/b\n"
            )
        );
        assert!(text.contains("    IdentitiesOnly yes\n"));
    }

    #[test]
    fn converts_days_to_dates() {
        assert_eq!(civil_date(0), "1970-01-01");
        assert_eq!(civil_date(20_750), "2026-10-24");
        assert_eq!(civil_date(11_016), "2000-02-29");
    }
}
