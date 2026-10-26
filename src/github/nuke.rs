//! Undo `keymate setup github` for one or all enrolled security keys, step by
//! step after consent. Backups of `~/.ssh/config` are kept.

use std::fs;
use std::path::PathBuf;

use super::api::{self, Gh, GhKey, KeyKind, Session, describe_keys};
use super::enrollment::{self, Detection, Enrollment};
use super::setup::APPLICATION;
use super::signer;
use crate::devices::{self, Credential, Device, PinState};
use crate::files;
use crate::git::{self, GIT_INCLUDE, git_global, signing_key_name};
use crate::ssh_config::{self, is_include_line};
use crate::tools::find_on_path;
use crate::{Error, Result};

/// Shared files in `~/.ssh/keymate`, removed with the last key. (`state` was
/// written by earlier versions; Finder adds `.DS_Store` to folders it shows.)
/// Unknown files there are left alone.
const SHARED_FILES: [&str; 4] = ["config", "known_hosts", "state", ".DS_Store"];

/// Everything `keymate nuke github` found.
pub struct Nuke {
    /// Keymate keys on this Mac.
    pub enrollments: Vec<Enrollment>,
    /// The enrollment whose credential the connected security key holds.
    pub connected: Option<Enrollment>,
    /// Keymate keys on GitHub (by title) that no key file here belongs to,
    /// e.g. from another computer.
    pub github_only: Vec<GhKey>,
    /// Why GitHub could not be checked, if it could not.
    pub github_note: Option<String>,
    /// GitHub keys matching a Keymate key file here.
    registered: Vec<GhKey>,
    ssh_include: bool,
    git_include: bool,
    device: Option<Device>,
    github: Option<(Gh, Session)>,
    ssh_dir: PathBuf,
}

/// What removing a selection will do.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Plan {
    pub enrollments: Vec<Enrollment>,
    pub registrations: Vec<GhKey>,
    /// No Keymate keys remain, so Keymate's SSH configuration goes too.
    pub everything: bool,
    /// Git commit signing (which uses a removed key) is turned off.
    pub signing: bool,
    pub ssh_include: bool,
    /// `~/.ssh/keymate` goes too (unless it holds the person's own files).
    pub keymate_dir: bool,
    /// Keymate's backups of `~/.ssh/config`, deleted with the last key once
    /// the config is restored.
    pub backups: Vec<PathBuf>,
}

impl Plan {
    /// The clean-up after the last key, as the plan line and the line once
    /// done; `None` when there is nothing to clean up.
    pub fn clean_up(&self) -> Option<(String, String)> {
        let what = match (self.ssh_include, !self.backups.is_empty()) {
            (true, false) => Some("Keymate's settings from ~/.ssh/config"),
            (true, true) => Some("Keymate's settings and backups of ~/.ssh/config"),
            (false, true) => Some("Keymate's backups of ~/.ssh/config"),
            (false, false) => None,
        };
        let text = match (what, self.keymate_dir) {
            (Some(what), true) => format!("{what}, and ~/.ssh/keymate"),
            (Some(what), false) => what.to_owned(),
            (None, true) => "~/.ssh/keymate".to_owned(),
            (None, false) => return None,
        };
        Some((format!("Remove {text}"), format!("Removed {text}")))
    }
}

/// Find Keymate's keys, configuration, and GitHub registrations. Read-only;
/// checking which enrollment the connected key holds needs no touch or PIN.
pub fn prepare() -> Result<Nuke> {
    let ssh_dir = files::ssh_dir()?;
    let enrolled = enrollment::list(&ssh_dir);

    let device = devices::single_device().ok();
    let connected = device
        .as_ref()
        .and_then(|d| match enrollment::detect(&enrolled, d) {
            Detection::ThisKey(enrollment) => Some(enrollment),
            _ => None,
        });

    let mut github_note = None;
    let mut github = None;
    let mut registered = Vec::new();
    let mut github_only = Vec::new();
    match Gh::find() {
        Err(_) => github_note = Some("gh is not installed".to_owned()),
        Ok(gh) => match gh.session()? {
            None => github_note = Some("you are not signed in with `gh`".to_owned()),
            Some(session) => {
                for kind in [KeyKind::Authentication, KeyKind::Signing] {
                    // Without the scope to list them, Keymate could not have
                    // added keys of this kind either.
                    if session.missing_scope(kind).is_some() {
                        continue;
                    }
                    for key in gh.list_keys(kind)? {
                        if enrolled
                            .iter()
                            .any(|e| e.public_key.as_ref() == Some(&key.key))
                        {
                            registered.push(key);
                        } else if key.from_keymate() {
                            github_only.push(key);
                        }
                    }
                }
                github = Some((gh, session));
            }
        },
    }

    let ssh_include = fs::read_to_string(ssh_dir.join("config"))
        .is_ok_and(|text| text.lines().any(is_include_line));
    let git_include = match find_on_path("git") {
        Some(git) => git_global(&git, &["--get-all", "include.path"])?
            .is_some_and(|paths| paths.lines().any(|l| l.trim() == GIT_INCLUDE)),
        None => false,
    };

    Ok(Nuke {
        enrollments: enrolled,
        connected,
        github_only,
        github_note,
        registered,
        ssh_include,
        git_include,
        device,
        github,
        ssh_dir,
    })
}

impl Nuke {
    /// The GitHub account checked, if any.
    pub fn account(&self) -> Option<&str> {
        self.github.as_ref().map(|(_, s)| s.account.as_str())
    }

    /// The connected security key, if exactly one is connected.
    pub fn device(&self) -> Option<&Device> {
        self.device.as_ref()
    }

    /// Whether Keymate left anything on this Mac at all.
    pub fn found_anything(&self) -> bool {
        !self.enrollments.is_empty()
            || self.ssh_include
            || self.git_include
            || self.keymate_dir_left()
            || !files::backups(&self.ssh_dir.join("config")).is_empty()
    }

    /// Whether `~/.ssh/keymate` holds something of Keymate's to clean up, or
    /// is empty. A folder with only the person's own files doesn't count:
    /// nuke leaves those alone, so it could never remove it.
    fn keymate_dir_left(&self) -> bool {
        let Ok(entries) = fs::read_dir(self.ssh_dir.join("keymate")) else {
            return false;
        };
        let names: Vec<String> = entries
            .filter_map(|e| e.ok()?.file_name().into_string().ok())
            .collect();
        names.is_empty() || names.iter().any(|n| SHARED_FILES.contains(&n.as_str()))
    }

    /// Plan removing `selected` enrollments, and the GitHub-only Keymate keys
    /// when `github_only` is set.
    pub fn plan(&self, selected: &[Enrollment], github_only: bool) -> Plan {
        let keys: Vec<&String> = selected
            .iter()
            .filter_map(|e| e.public_key.as_ref())
            .collect();
        let mut registrations: Vec<GhKey> = self
            .registered
            .iter()
            .filter(|k| keys.contains(&&k.key))
            .cloned()
            .collect();
        if github_only {
            registrations.extend(self.github_only.iter().cloned());
        }
        let everything = self.enrollments.iter().all(|e| selected.contains(e));
        let signing_key = signing_key_name(&self.ssh_dir);
        let signing = if everything {
            self.git_include || signing_key.is_some()
        } else {
            signing_key.is_some_and(|name| selected.iter().any(|e| e.file_name() == name))
        };
        Plan {
            enrollments: selected.to_vec(),
            registrations,
            everything,
            signing,
            ssh_include: everything && self.ssh_include,
            keymate_dir: everything && self.keymate_dir_left(),
            backups: if everything {
                files::backups(&self.ssh_dir.join("config"))
            } else {
                Vec::new()
            },
        }
    }

    /// GitHub permissions the current sign-in lacks to delete the planned keys.
    pub fn missing_scopes(&self, plan: &Plan) -> Vec<&'static str> {
        let Some((_, session)) = &self.github else {
            return Vec::new();
        };
        let mut scopes: Vec<&'static str> = plan
            .registrations
            .iter()
            .filter_map(|k| session.missing_admin_scope(k.kind))
            .collect();
        scopes.sort_unstable();
        scopes.dedup();
        scopes
    }

    pub fn request_scope(&self, scope: &str) -> Result<()> {
        match &self.github {
            Some((gh, _)) => gh.request_scope(scope),
            None => Ok(()),
        }
    }

    // The steps of carrying out a plan, in order. Each returns what it did,
    // or `None` when there was nothing to do. GitHub goes first: if it
    // fails, the local setup still works for a retry.

    /// Delete the planned registrations from GitHub.
    pub fn remove_from_github(&self, plan: &Plan) -> Result<Option<String>> {
        let Some((gh, _)) = &self.github else {
            return Ok(None);
        };
        if plan.registrations.is_empty() {
            return Ok(None);
        }
        api::delete_registrations(gh, &plan.registrations)?;
        Ok(Some(format!(
            "Removed {} from GitHub",
            describe_keys(&plan.registrations)
        )))
    }

    /// Turn off commit signing when it used a removed key.
    pub fn turn_off_signing(&self, plan: &Plan) -> Result<Option<String>> {
        let turned_off = plan.signing && git::remove_signing(&self.ssh_dir)?;
        Ok(turned_off.then(|| "Turned off commit signing".to_owned()))
    }

    /// Delete the planned key files.
    pub fn delete_keys(&self, plan: &Plan) -> Result<Option<String>> {
        for enrollment in &plan.enrollments {
            enrollment::delete_enrollment_files(enrollment)?;
        }
        let names: Vec<String> = plan.enrollments.iter().map(Enrollment::display).collect();
        Ok((!names.is_empty()).then(|| format!("Deleted {}", names.join(" and "))))
    }

    /// Update Keymate's SSH config for the remaining keys, or, with the last
    /// key, take Keymate's lines out of `~/.ssh/config` and clean up.
    pub fn clean_up(&self, plan: &Plan) -> Result<Option<String>> {
        if !plan.everything {
            let remaining = enrollment::list(&self.ssh_dir);
            enrollment::write_ssh_config(&self.ssh_dir, &remaining)?;
            if !plan.signing && signing_key_name(&self.ssh_dir).is_some() {
                signer::update_allowed_signers(&self.ssh_dir)?;
            }
            return Ok(Some(match remaining.len() {
                1 => "Kept your other key for github.com".to_owned(),
                n => format!("Kept your {n} other keys for github.com"),
            }));
        }
        if plan.ssh_include {
            ssh_config::remove_include(&self.ssh_dir)?;
        }
        let dir = self.ssh_dir.join("keymate");
        let shared = SHARED_FILES.iter().map(|name| dir.join(name));
        for path in plan.backups.iter().cloned().chain(shared) {
            files::remove_file(&path)?;
        }
        // Only succeeds when empty, so unknown files are never deleted.
        let _ = fs::remove_dir(&dir);
        Ok(plan.clean_up().map(|(_, done)| done))
    }

    /// Whether the connected key may hold Keymate credentials: it stores
    /// credentials and has a PIN (they require one). Only the PIN can tell
    /// for sure, since OpenSSH hides them from silent requests.
    pub fn key_may_hold_credentials(&self) -> bool {
        self.device
            .as_ref()
            .and_then(|d| d.info.as_ref())
            .is_some_and(|i| i.resident_keys && i.pin == PinState::Set)
    }

    /// Delete Keymate's credentials from the connected key, unlocking it with
    /// `pin`, except those a key kept on this Mac still uses. This includes
    /// credentials whose key files are already gone. Returns what it deleted.
    pub fn delete_from_key(&self, plan: &Plan, pin: &str) -> Result<Vec<Credential>> {
        let Some(device) = &self.device else {
            return Err(Error::Failed("The security key is not connected.".into()));
        };
        let kept: Vec<&[u8]> = self
            .enrollments
            .iter()
            .filter(|e| !plan.enrollments.contains(e))
            .filter_map(|e| e.sk.as_ref())
            .map(|sk| sk.key_handle.as_slice())
            .collect();
        let mut deleted = Vec::new();
        for credential in devices::list_credentials(device, APPLICATION, pin)? {
            if kept.contains(&credential.id.as_slice()) {
                continue;
            }
            devices::delete_credential(device, &credential.id, pin)?;
            deleted.push(credential);
        }
        Ok(deleted)
    }
}

/// How to call a credential on a key: the name stored in its user id
/// (`primary.a1b2c3`), or the whole user id for credentials from versions
/// that stored the account instead.
pub fn credential_label(credential: &Credential) -> String {
    match credential.user.split_once('.') {
        Some((name, _)) if enrollment::validate_name(name).is_ok() => name.to_owned(),
        _ => credential.user.clone(),
    }
}
