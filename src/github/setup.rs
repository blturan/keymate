//! Guided GitHub SSH enrollment with a FIDO security key.
//!
//! Each step is a separate call so a frontend can explain it and ask for
//! consent first. Keymate recognizes a security key it already enrolled
//! (without a touch), so the frontend can offer to keep, replace, or add.
//! Steps are idempotent: keys already on GitHub are not added twice, and
//! config edits happen once. A replaced key is retired only after the new one
//! works.

use std::fs;
use std::path::{Path, PathBuf};
use std::time::Duration;

use super::api::{self, Gh, GhKey, KeyKind, Session, describe_keys};
use super::connection::Connection;
use super::enrollment::{self, Detection, Enrollment};
use super::signer;
use crate::devices::{self, Device, PinState};
use crate::error::Context;
use crate::files;
use crate::git::{self, find_git, git_global, signing_key_name};
use crate::process::{self, Stream};
use crate::ssh_config::with_include;
use crate::sshkey;
use crate::tools::{fido_openssh, sanitize};
use crate::{Error, Result};

/// Resident credentials get their own application string so they never
/// replace a resident `ssh:` credential that already exists on the key.
pub(crate) const APPLICATION: &str = "ssh:keymate-github";
/// Long enough to find the key, touch it, and type a PIN.
const TOUCH_TIMEOUT: Duration = Duration::from_secs(90);
const TIMEOUT: Duration = Duration::from_secs(15);

/// Where the credential lives.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Storage {
    /// The key handle is kept in the local key file; nothing is stored on the key.
    NonResident,
    /// Stored on the security key; restorable elsewhere with `ssh-keygen -K`.
    Resident,
}

/// A resident credential downloaded from the key, kept in memory until it is
/// saved under its name.
struct Found {
    /// The name stored in the credential's user id, if any.
    name: Option<String>,
    private: String,
    public: String,
    ed25519: bool,
}

/// What each SSH connection requires.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verification {
    Touch,
    /// Touch and the FIDO2 PIN (`verify-required`).
    PinAndTouch,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Options {
    pub storage: Storage,
    pub verification: Verification,
    /// Also register the key for commit signing on GitHub.
    pub signing: bool,
    /// Make git on this Mac sign commits and tags with the key. Off when
    /// another key signs: git signs with one key at a time.
    pub git_signs: bool,
}

/// What to do with the connected security key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Action {
    /// Reuse this enrollment: check its GitHub registration, test, configure.
    Keep(Enrollment),
    /// Create a new credential, then retire this enrollment once it works.
    Replace(Enrollment),
    /// Create a new credential next to any existing enrollments.
    Add,
    /// Download a resident Keymate credential from the key (`ssh-keygen -K`).
    Restore,
}

/// What is already in place for a kept key, from [`Setup::existing`].
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Existing {
    /// The key's registrations on GitHub.
    pub registered: Vec<GhKey>,
    /// `ssh github.com` already uses the key.
    pub ssh: bool,
    /// git already signs commits and tags with the key.
    pub signing: bool,
}

impl Existing {
    /// The key's GitHub registration of `kind`, if any.
    pub fn registration(&self, kind: KeyKind) -> Option<&GhKey> {
        self.registered.iter().find(|k| k.kind == kind)
    }
}

/// What happens while `ssh-keygen` creates the credential.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyEvent {
    /// The key is waiting for a touch.
    TouchNeeded,
    /// The key did not confirm: a wrong PIN, or no touch in time (security
    /// keys report both as denied). `ssh-keygen` asks for the PIN again.
    PinRejected,
    /// The key already holds a resident Keymate credential for this account
    /// (from an earlier setup); `ssh-keygen` asks on the terminal whether to
    /// overwrite it.
    AlreadyOnKey,
}

fn keygen_event(line: &str, asks_pin: bool) -> Option<KeyEvent> {
    if line.contains("touch your authenticator") {
        (!asks_pin || line.contains("again")).then_some(KeyEvent::TouchNeeded)
    } else if line.contains("PIN incorrect") {
        Some(KeyEvent::PinRejected)
    } else if line.contains("resident key scoped to") {
        Some(KeyEvent::AlreadyOnKey)
    } else {
        None
    }
}

/// What Keymate found before making any change, and the chosen action.
pub struct Setup {
    pub account: String,
    pub device: Device,
    /// How the connected key relates to Keymate keys on this Mac.
    pub detection: Detection,
    /// Keymate keys on GitHub that no key file on this Mac belongs to, e.g.
    /// from another computer.
    pub github_only: Vec<GhKey>,
    /// Public keys GitHub has as signing keys, when the connected key was
    /// recognized.
    signing_keys: Vec<String>,
    /// A credential found on the key for [`Action::Restore`], not saved yet.
    found: Option<Found>,
    /// Every Keymate credential on the key, until one is picked.
    candidates: Vec<Found>,
    action: Action,
    key: PathBuf,
    /// Where `key` moves once it works, when a replacement reuses the
    /// replaced key's file name and is created at a staged path meanwhile.
    final_key: Option<PathBuf>,
    /// The enrollment's name, used in the key file and GitHub titles.
    name: String,
    session: Session,
    gh: Gh,
    ssh: PathBuf,
    ssh_keygen: PathBuf,
    ssh_dir: PathBuf,
}

/// Inspect tools, the signed-in account, the connected key, and existing
/// enrollments. Read-only; needs no touch or PIN.
pub fn prepare() -> Result<Setup> {
    let ssh = fido_openssh("ssh")?;
    let ssh_keygen = fido_openssh("ssh-keygen")?;
    let gh = Gh::find()?;
    let session = gh.signed_in()?;
    let device = devices::single_device()?;

    let ssh_dir = files::ssh_dir()?;
    let existing = enrollment::list(&ssh_dir);
    let detection = enrollment::detect(&existing, &device);

    let github_only = if session.missing_scope(KeyKind::Authentication).is_none() {
        gh.list_keys(KeyKind::Authentication)?
            .into_iter()
            .filter(|k| k.from_keymate())
            .filter(|k| {
                !existing
                    .iter()
                    .any(|e| e.public_key.as_ref() == Some(&k.key))
            })
            .collect()
    } else {
        Vec::new()
    };
    // Only the recognized key's menu depends on its signing registration.
    let signing_keys = match &detection {
        Detection::ThisKey(_) if session.missing_scope(KeyKind::Signing).is_none() => gh
            .list_keys(KeyKind::Signing)?
            .into_iter()
            .map(|k| k.key)
            .collect(),
        _ => Vec::new(),
    };

    let name = enrollment::suggest_name(&ssh_dir, &device);
    let ed25519 = device.info.as_ref().is_some_and(|i| i.supports_ed25519());
    let key = enrollment::key_path(&ssh_dir, ed25519, &name);

    Ok(Setup {
        account: session.account.clone(),
        device,
        detection,
        github_only,
        signing_keys,
        found: None,
        candidates: Vec::new(),
        action: Action::Add,
        key,
        final_key: None,
        name,
        session,
        gh,
        ssh,
        ssh_keygen,
        ssh_dir,
    })
}

impl Setup {
    /// Choose what to do; the default is [`Action::Add`]. A replacement
    /// suggests the replaced key's name.
    pub fn select(&mut self, action: Action) {
        let name = match &action {
            Action::Keep(enrollment) => {
                self.key = enrollment.key.clone();
                enrollment.name()
            }
            Action::Replace(old) => old.name(),
            _ => None,
        };
        self.action = action;
        if let Some(name) = name {
            match self.reusing() {
                true => self.name = name,
                false => self.place(&name),
            }
        }
    }

    /// The suggested or chosen name for a new key.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Name a new key; it must be valid and not used by another Keymate key.
    pub fn set_name(&mut self, name: &str) -> std::result::Result<(), String> {
        self.name_check()(name)?;
        self.place(name);
        Ok(())
    }

    /// Point the new key at `name`'s file, staged when that is the file of
    /// the key being replaced.
    fn place(&mut self, name: &str) {
        // A credential found on the key keeps its own type.
        let ed25519 = match &self.found {
            Some(found) => found.ed25519,
            None => self
                .device
                .info
                .as_ref()
                .is_some_and(|i| i.supports_ed25519()),
        };
        let key = enrollment::key_path(&self.ssh_dir, ed25519, name);
        (self.key, self.final_key) = match self.replaced() {
            Some(old) if old.key == key => (enrollment::staged_path(&key), Some(key)),
            _ => (key, None),
        };
        self.name = name.to_owned();
    }

    fn replaced(&self) -> Option<&Enrollment> {
        match &self.action {
            Action::Replace(old) => Some(old),
            _ => None,
        }
    }

    /// A check for proposed names, usable while the person types. The key
    /// being replaced may pass its name on.
    pub fn name_check(&self) -> impl Fn(&str) -> std::result::Result<(), String> + 'static {
        let ssh_dir = self.ssh_dir.clone();
        let replaced = self.replaced().map(|old| old.key.clone());
        move |name| {
            enrollment::validate_name(name)?;
            if enrollment::name_taken(&ssh_dir, name, replaced.as_deref()) {
                return Err(format!("A Keymate key named `{name}` already exists."));
            }
            Ok(())
        }
    }

    /// Whether this action creates a key file that needs a name.
    pub fn needs_name(&self) -> bool {
        !self.reusing()
    }

    pub fn action(&self) -> &Action {
        &self.action
    }

    /// Whether an existing key file is used instead of creating a credential.
    pub fn reusing(&self) -> bool {
        matches!(self.action, Action::Keep(_))
    }

    /// Whether the connected key may hold a resident Keymate credential that
    /// could be restored: it stores credentials and has a PIN (resident
    /// credentials require one). Only the PIN can tell for sure, since
    /// OpenSSH hides resident credentials from silent requests; GitHub may
    /// have forgotten the key (e.g. after `keymate nuke`) while the key
    /// still holds it.
    pub fn can_restore(&self) -> bool {
        self.device
            .info
            .as_ref()
            .is_some_and(|i| i.resident_keys && i.pin == PinState::Set)
    }

    /// The `~/.ssh/...` form of the key path, as written in config files.
    pub fn key_display(&self) -> String {
        format!("~/.ssh/{}", self.key_name())
    }

    fn key_name(&self) -> String {
        self.final_key
            .as_ref()
            .unwrap_or(&self.key)
            .file_name()
            .unwrap_or_default()
            .to_string_lossy()
            .into_owned()
    }

    fn keymate_dir(&self) -> PathBuf {
        self.ssh_dir.join("keymate")
    }

    fn pin_state(&self) -> Option<PinState> {
        self.device.info.as_ref().map(|i| i.pin)
    }

    /// Fail early when the options need a PIN the key cannot have.
    pub fn check(&self, options: &Options) -> Result<()> {
        let unsupported = matches!(self.pin_state(), None | Some(PinState::Unsupported));
        if needs_pin(options) && self.creates_key() && unsupported {
            return Err(Error::fixable(
                "These choices need a PIN, which this key doesn't support",
                "Choose On this Mac and Touch",
            ));
        }
        Ok(())
    }

    fn creates_key(&self) -> bool {
        matches!(self.action, Action::Add | Action::Replace(_))
    }

    /// Whether a new key with these options first needs a PIN to be set.
    pub fn needs_new_pin(&self, options: &Options) -> bool {
        needs_pin(options) && self.creates_key() && self.pin_state() == Some(PinState::NotSet)
    }

    /// Set the key's first FIDO2 PIN to `pin`.
    pub fn set_pin(&mut self, pin: &str) -> Result<String> {
        devices::set_pin(&self.device, pin)?;
        let info = devices::refresh(&self.device)?;
        let set = info.pin == PinState::Set;
        self.device.info = Some(info);
        if set {
            Ok(format!("Set a PIN on {}", self.device.name))
        } else {
            Err(Error::Failed(
                "The key still reports no PIN. Nothing else was changed.".into(),
            ))
        }
    }

    /// GitHub permissions the current sign-in lacks for the chosen action.
    pub fn missing_scopes(&self, options: &Options) -> Vec<&'static str> {
        let mut scopes: Vec<&'static str> = kinds(options)
            .iter()
            .filter_map(|kind| self.session.missing_scope(*kind))
            .collect();
        if matches!(self.action, Action::Replace(_)) {
            scopes.extend(self.session.missing_admin_scope(KeyKind::Authentication));
            if self.session.missing_scope(KeyKind::Signing).is_none() {
                scopes.extend(self.session.missing_admin_scope(KeyKind::Signing));
            }
        }
        scopes.sort_unstable();
        scopes.dedup();
        scopes
    }

    /// Request a missing permission through GitHub's browser flow.
    pub fn request_scope(&self, scope: &str) -> Result<()> {
        self.gh.request_scope(scope)
    }

    /// Look on the key for resident Keymate credentials, unlocking it with
    /// `pin`, and return the name stored in each (`None` for credentials
    /// from versions that didn't store one). They're kept in memory until
    /// [`Setup::pick_found`] chooses one and [`Setup::restore`] saves it;
    /// nothing is written yet. Empty when the key holds none.
    pub fn look_on_key(&mut self, pin: &str) -> Result<Vec<Option<String>>> {
        self.candidates.clear();
        // List first: `ssh-keygen -K` fails with "invalid format" on a key
        // that holds no credentials at all, rather than finding none.
        if devices::list_credentials(&self.device, APPLICATION, pin)?.is_empty() {
            return Ok(Vec::new());
        }
        let temp = self
            .keymate_dir()
            .join(format!(".restore-{}", std::process::id()));
        files::ensure_private_dir(&temp).context("create a temporary folder")?;
        let result = self.download(&temp, pin);
        let _ = fs::remove_dir_all(&temp);
        self.candidates = result?;
        Ok(self.candidates.iter().map(|f| f.name.clone()).collect())
    }

    /// Restore the `index`th credential [`Setup::look_on_key`] found.
    pub fn pick_found(&mut self, index: usize) {
        if index < self.candidates.len() {
            self.found = Some(self.candidates.swap_remove(index));
            self.candidates.clear();
        }
    }

    /// The name stored in the credential to restore, when it has one.
    pub fn found_name(&self) -> Option<&str> {
        self.found.as_ref()?.name.as_deref()
    }

    /// GitHub titles of the credential [`Setup::look_on_key`] found, e.g.
    /// `keymate_auth_primary`, when GitHub still has it.
    pub fn found_titles(&self) -> Vec<&str> {
        let Some(found) = &self.found else {
            return Vec::new();
        };
        let key = api::key_identity(&found.public);
        self.github_only
            .iter()
            .filter(|k| Some(&k.key) == key.as_ref())
            .map(|k| k.title.as_str())
            .collect()
    }

    /// Save the credential [`Setup::look_on_key`] found as this key's file.
    pub fn restore(&mut self) -> Result<String> {
        let Some(found) = self.found.take() else {
            return Err(Error::Failed(
                "There is no credential from the key to restore".into(),
            ));
        };
        let key = self.key.clone();
        files::ensure_private_dir(&self.ssh_dir).context("create ~/.ssh")?;
        files::write_atomic(&key, &found.private, 0o600).context("save the restored key")?;
        files::write_atomic(&enrollment::public_path(&key), &found.public, 0o644)
            .context("save the restored public key")?;
        enrollment::write_info(&self.key, &self.device.name, &self.account)?;
        self.action = Action::Keep(enrollment::load(&self.key));
        Ok(format!(
            "Restored the credential from {} as {}",
            self.device.name,
            self.key_display()
        ))
    }

    /// Download the key's resident credentials into `temp` with
    /// `ssh-keygen -K`, giving it `pin` instead of letting it prompt, and
    /// keep Keymate's.
    fn download(&self, temp: &Path, pin: &str) -> Result<Vec<Found>> {
        let output = process::run_detached_in(
            &self.ssh_keygen,
            &["-q", "-K", "-N", ""],
            &format!("{pin}\n"),
            TOUCH_TIMEOUT,
            Some(temp),
        )
        .map_err(|e| Error::Failed(format!("could not run ssh-keygen: {e}")))?;
        if !output.status.success() {
            let detail = output
                .stderr
                .lines()
                .rev()
                .find(|line| !line.trim().is_empty())
                .map(|line| sanitize(line.trim()))
                .unwrap_or_default();
            return Err(Error::Failed(format!(
                "ssh-keygen could not download the credentials from the key ({detail}). Nothing was changed."
            )));
        }
        // `ssh-keygen -K` names files `id_<type>_sk_rk_<application>_<user>`.
        let mut paths: Vec<PathBuf> = fs::read_dir(temp)
            .context("read the downloaded credentials")?
            .filter_map(|entry| Some(entry.ok()?.path()))
            .filter(|path| path.extension().is_none_or(|ext| ext != "pub"))
            .collect();
        paths.sort();
        let mut found = Vec::new();
        for path in paths {
            let private = fs::read_to_string(&path).context("read the downloaded key")?;
            let Some(sk) = sshkey::parse_private(&private) else {
                continue;
            };
            if sk.application != APPLICATION {
                continue;
            }
            let file_name = path.file_name().unwrap_or_default().to_string_lossy();
            found.push(Found {
                name: credential_name(&file_name),
                public: fs::read_to_string(enrollment::public_path(&path))
                    .context("read the downloaded public key")?,
                ed25519: sk.key_type.starts_with("sk-ssh-ed25519"),
                private,
            });
        }
        Ok(found)
    }

    /// Whether creating the credential will ask for the PIN: resident and
    /// PIN-and-touch credentials always do, and so does a key with a PIN that
    /// cannot create credentials without it.
    pub fn create_asks_pin(&self, options: &Options) -> bool {
        let info = self.device.info.as_ref();
        needs_pin(options)
            || (info.is_some_and(|i| i.pin == PinState::Set)
                && !info.is_some_and(|i| i.create_without_pin))
    }

    /// Create the credential with `ssh-keygen`, which asks for the PIN on the
    /// terminal itself. Its output is followed to report [`KeyEvent`]s, so
    /// the frontend can ask for the touch at the right moment. Returns
    /// `false` when an existing key file is reused.
    pub fn create_key(
        &self,
        options: &Options,
        mut on_event: impl FnMut(KeyEvent),
    ) -> Result<bool> {
        if !self.creates_key() {
            return Ok(false);
        }
        files::ensure_private_dir(&self.ssh_dir).context("create ~/.ssh")?;
        // A staged key left by an earlier attempt would make ssh-keygen ask
        // to overwrite it.
        if self.final_key.is_some() {
            for path in [self.key.clone(), enrollment::public_path(&self.key)] {
                if path.exists() {
                    files::remove_file(&path)?;
                }
            }
        }
        let args = keygen_args(
            &self.key,
            &self.device.path,
            &credential_user(&self.name),
            options,
            &host_name(),
        );
        let failed = |detail: &str| {
            Error::Failed(format!(
                "ssh-keygen did not create the key ({detail}); nothing was registered with GitHub"
            ))
        };
        // ssh-keygen announces each attempt with "You may need to touch your
        // authenticator ...". When a PIN is needed, the first attempt only
        // learns that and the PIN prompt follows; the touch belongs to the
        // next attempt ("... again ...").
        let asks_pin = self.create_asks_pin(options);
        let mut last_error = String::from("it was cancelled");
        let status = process::run_streaming(&self.ssh_keygen, &args, |stream, line| {
            match (stream, keygen_event(line, asks_pin)) {
                (_, Some(event)) => on_event(event),
                (Stream::Stderr, None) if !line.trim().is_empty() => {
                    last_error = sanitize(line.trim());
                }
                _ => {}
            }
        })
        .map_err(|e| failed(&e.to_string()))?;
        if !status.success() {
            return Err(failed(&last_error));
        }
        if !enrollment::public_path(&self.key).exists() {
            return Err(failed("no public key file appeared"));
        }
        enrollment::write_info(&self.key, &self.device.name, &self.account)?;
        Ok(true)
    }

    fn public_key(&self) -> Result<String> {
        enrollment::load(&self.key)
            .public_key
            .ok_or_else(|| Error::Failed("the public key file is missing or invalid".into()))
    }

    /// Add the public key to GitHub unless it is already there.
    pub fn register(&self, options: &Options) -> Result<Vec<String>> {
        let key = self.public_key()?;
        let (mut added, mut found) = (Vec::new(), Vec::new());
        for kind in kinds(options) {
            let title = api::title(&self.name, kind);
            match self.gh.list_keys(kind)?.into_iter().find(|k| k.key == key) {
                Some(existing) => found.push(existing),
                None => {
                    self.gh
                        .add_key(&enrollment::public_path(&self.key), &title, kind)?;
                    added.push(title);
                }
            }
        }
        let mut changes = Vec::new();
        if !added.is_empty() {
            changes.push(format!("Added to GitHub as {}", added.join(" and ")));
        }
        if !found.is_empty() {
            changes.push(format!("Already on GitHub as {}", describe_keys(&found)));
        }
        Ok(changes)
    }

    /// Connect to github.com with only this key and GitHub's published host
    /// keys, ignoring the SSH agent and the user's SSH config. Over the same
    /// connection (one touch), ask a private repository of each organization
    /// for its refs, read-only, to find organizations whose SAML single
    /// sign-on still has to authorize the key.
    /// Get ready for [`Setup::test`]: GitHub's host keys and which
    /// organizations to check. Needs no touch.
    pub fn prepare_test(&self) -> Result<TestTarget> {
        let known_hosts = self.keymate_dir().join("known_hosts");
        files::ensure_private_dir(&self.keymate_dir()).context("create ~/.ssh/keymate")?;
        let lines: String = self
            .gh
            .host_keys()?
            .iter()
            // Port 443 (`ssh.github.com`) serves the same keys; listing that
            // name too spares people who use it a trust prompt.
            .map(|key| format!("github.com {key}\n[ssh.github.com]:443 {key}\n"))
            .collect();
        files::write_atomic(&known_hosts, &lines, 0o644)
            .context("write ~/.ssh/keymate/known_hosts")?;
        let organizations = self.gh.orgs().unwrap_or_default();
        let repos = match organizations.is_empty() {
            true => Vec::new(),
            false => self.gh.org_repos().unwrap_or_default(),
        };
        Ok(TestTarget {
            known_hosts,
            organizations,
            repos,
        })
    }

    /// Run the test prepared by [`Setup::prepare_test`]. `touched` is called
    /// once the key was touched and the remaining checks run. A key that
    /// isn't touched in time is [`Error::NotConfirmed`], so the caller can
    /// offer to try again with the same `target`.
    pub fn test(&self, target: &TestTarget, touched: impl FnOnce()) -> Result<AccessReport> {
        let TestTarget {
            known_hosts,
            organizations,
            repos,
        } = target;
        let asks_pin = enrollment::load(&self.key)
            .sk
            .is_some_and(|sk| sk.verify_required());
        let connection = Connection::open(
            &self.ssh,
            ssh_options(&self.key, known_hosts),
            &self.keymate_dir(),
            TOUCH_TIMEOUT,
            asks_pin,
        )?;
        touched();
        let output = connection.run(None)?;
        match greeting(&output.stderr) {
            Some(account) if account.eq_ignore_ascii_case(&self.account) => {}
            Some(account) => {
                return Err(Error::Failed(format!(
                    "GitHub accepted the key, but for account {account}, not {}",
                    self.account
                )));
            }
            None => {
                return Err(Error::Failed(format!(
                    "GitHub did not greet {}: {}",
                    self.account,
                    sanitize(output.stderr.lines().last().unwrap_or("no response"))
                )));
            }
        }

        let organizations = organizations
            .iter()
            .map(|org| {
                let access = match repos.iter().find(|(o, _)| o == org) {
                    Some((_, repo)) => probe(&connection, repo),
                    None => OrgAccess::Unknown,
                };
                (org.clone(), access)
            })
            .collect();
        Ok(AccessReport {
            account: self.account.clone(),
            organizations,
        })
    }

    /// Write `~/.ssh/keymate/config` for every enrolled key and include it
    /// from `~/.ssh/config`.
    pub fn configure_ssh(&self) -> Result<Vec<String>> {
        let all = enrollment::list(&self.ssh_dir);
        enrollment::write_ssh_config(&self.ssh_dir, &all)?;
        let changes = vec![if all.len() == 1 {
            "Configured github.com to use this key".to_owned()
        } else {
            format!(
                "Configured github.com to use any of your {} keys",
                all.len()
            )
        }];

        let config = self.ssh_dir.join("config");
        let existing = match fs::read_to_string(&config) {
            Ok(text) => Some(text),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => None,
            Err(e) => return Err(e).context("read ~/.ssh/config"),
        };
        // No backup copy: the edit is three prepended lines, written
        // atomically, which `keymate nuke` takes out exactly.
        if let Some(updated) = with_include(existing.as_deref().unwrap_or("")) {
            let mode = files::mode(&config).unwrap_or(0o600);
            files::write_atomic(&config, &updated, mode).context("update ~/.ssh/config")?;
        }
        Ok(changes)
    }

    /// What is already in place for a kept key: GitHub registrations, the
    /// SSH config, and git signing. Read-only; empty for new keys.
    pub fn existing(&self) -> Existing {
        if !self.reusing() {
            return Existing::default();
        }
        let registered = match enrollment::load(&self.key).public_key {
            Some(key) => [KeyKind::Authentication, KeyKind::Signing]
                .into_iter()
                .filter(|kind| self.session.missing_scope(*kind).is_none())
                .flat_map(|kind| self.gh.list_keys(kind).unwrap_or_default())
                .filter(|k| k.key == key)
                .collect(),
            None => Vec::new(),
        };
        Existing {
            registered,
            ssh: self.ssh_config_effective().unwrap_or(false),
            signing: signing_key_name(&self.ssh_dir) == Some(self.key_name())
                && self.signing_effective().unwrap_or(false),
        }
    }

    /// Whether `ssh github.com` now resolves to the key. Read-only.
    pub fn ssh_config_effective(&self) -> Result<bool> {
        let output = process::run(&self.ssh, &["-G", "github.com"], TIMEOUT)
            .map_err(|e| Error::Failed(format!("could not check the SSH config: {e}")))?;
        Ok(uses_key(&output.stdout, &self.key_name()))
    }

    /// Write `~/.ssh/keymate/gitconfig` and include it from the global git
    /// config, so commits and tags are signed with the key.
    pub fn configure_signing(&self) -> Result<Vec<String>> {
        signer::sign_with(
            &self.ssh_dir,
            &self.ssh_keygen,
            &enrollment::load(&self.key),
        )?;
        Ok(vec![
            "Configured git to sign commits and tags with this key".to_owned(),
        ])
    }

    /// Whether `enrollment` signs commits: git here signs with it, or GitHub
    /// has it as a signing key (another key may sign on this Mac).
    pub fn signs_with(&self, enrollment: &Enrollment) -> bool {
        signing_key_name(&self.ssh_dir) == Some(enrollment.file_name())
            || enrollment
                .public_key
                .as_ref()
                .is_some_and(|key| self.signing_keys.contains(key))
    }

    /// When git signs with a Keymate key, list every Keymate key (this one
    /// too) in `allowed_signers`, so git verifies their commits.
    pub fn refresh_allowed_signers(&self) -> Result<()> {
        if signing_key_name(&self.ssh_dir).is_some() {
            signer::update_allowed_signers(&self.ssh_dir)?;
        }
        Ok(())
    }

    /// Another Keymate key that git signs with now, if any. git signs with
    /// one key at a time. The key being replaced doesn't count: it goes.
    pub fn other_signer(&self) -> Option<Enrollment> {
        signer::current_signer(&self.ssh_dir, &enrollment::list(&self.ssh_dir))
            .filter(|e| e.key != self.key && Some(e) != self.replaced())
    }

    /// Whether git's effective global settings sign with the key.
    pub fn signing_effective(&self) -> Result<bool> {
        let git = find_git()?;
        // `--global` alone ignores include.path, which is where Keymate's
        // settings live.
        let format = git_global(&git, &["--includes", "--get", "gpg.format"])?;
        let key = git_global(&git, &["--includes", "--get", "user.signingkey"])?;
        Ok(format.as_deref() == Some("ssh")
            && key.is_some_and(|k| k.ends_with(&format!("{}.pub", self.key_name()))))
    }

    /// The GitHub title of the authentication key, as shown on GitHub.
    pub fn auth_title(&self) -> String {
        api::title(&self.name, KeyKind::Authentication)
    }

    /// The GitHub title of the signing key.
    pub fn sign_title(&self) -> String {
        api::title(&self.name, KeyKind::Signing)
    }

    /// After the new key was tested: move a staged replacement over the
    /// replaced key's files, so SSH and git are configured with its own
    /// name. Does nothing for other keys.
    pub fn put_in_place(&mut self) -> Result<()> {
        let Some(key) = self.final_key.take() else {
            return Ok(());
        };
        enrollment::unstage(&self.key, &key)?;
        self.key = key;
        Ok(())
    }

    /// After a replacement works: remove the old key from GitHub, delete its
    /// files, and drop it from the SSH config. A replacement with the same
    /// file name already took the old files' place.
    pub fn retire_replaced(&self, options: &Options) -> Result<Vec<String>> {
        let Action::Replace(old) = &self.action else {
            return Ok(Vec::new());
        };
        let same_file = old.key == self.key;
        if let Some(key) = &old.public_key {
            for kind in [KeyKind::Authentication, KeyKind::Signing] {
                if self.session.missing_scope(kind).is_some() {
                    continue;
                }
                let registered: Vec<GhKey> = self
                    .gh
                    .list_keys(kind)?
                    .into_iter()
                    .filter(|k| &k.key == key)
                    .collect();
                api::delete_registrations(&self.gh, &registered)?;
            }
        }
        // With the same file name, git signing with "the old key" now means
        // the new one, which only keeps signing when that was chosen.
        let signed_with_old = signing_key_name(&self.ssh_dir) == Some(old.file_name())
            && !(same_file && options.git_signs);
        if !same_file {
            enrollment::delete_enrollment_files(old)?;
        }
        enrollment::write_ssh_config(&self.ssh_dir, &enrollment::list(&self.ssh_dir))?;
        let mut changes = vec![match same_file {
            true => format!("Removed the old {} from GitHub", old.short_name()),
            false => format!("Removed {} from GitHub and this Mac", old.display()),
        }];
        if signed_with_old && git::remove_signing(&self.ssh_dir)? {
            changes.push("Turned off commit signing with the old key".to_owned());
        } else if signing_key_name(&self.ssh_dir).is_some() {
            signer::update_allowed_signers(&self.ssh_dir)?;
        }
        Ok(changes)
    }
}

/// How an organization's repositories answer the key.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OrgAccess {
    Works,
    /// The organization enforces SAML single sign-on and the key is not
    /// authorized for it yet.
    SsoPending,
    /// No repository could be checked, e.g. because single sign-on also
    /// blocks the GitHub CLI.
    Unknown,
}

/// What [`Setup::test`] connects with and checks.
pub struct TestTarget {
    known_hosts: PathBuf,
    organizations: Vec<String>,
    repos: Vec<(String, String)>,
}

/// The result of [`Setup::test`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AccessReport {
    pub account: String,
    /// Each organization the account belongs to, and whether the key works.
    pub organizations: Vec<(String, OrgAccess)>,
}

/// Ask `repo` for its refs; GitHub names SAML SSO when it refuses the key.
fn probe(connection: &Connection, repo: &str) -> OrgAccess {
    let safe = repo
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || "-_./".contains(c));
    if !safe {
        return OrgAccess::Unknown;
    }
    match connection.run(Some(&format!("git-upload-pack '{repo}.git'"))) {
        Ok(output) if output.stderr.contains("SAML SSO") => OrgAccess::SsoPending,
        Ok(output) if !output.stdout.is_empty() => OrgAccess::Works,
        _ => OrgAccess::Unknown,
    }
}

fn needs_pin(options: &Options) -> bool {
    options.storage == Storage::Resident || options.verification == Verification::PinAndTouch
}

fn kinds(options: &Options) -> Vec<KeyKind> {
    let mut kinds = vec![KeyKind::Authentication];
    if options.signing {
        kinds.push(KeyKind::Signing);
    }
    kinds
}

fn host_name() -> String {
    process::run(Path::new("/bin/hostname"), &["-s"], TIMEOUT)
        .ok()
        .map(|o| sanitize(o.stdout.trim()))
        .filter(|h| !h.is_empty())
        .unwrap_or_else(|| "this Mac".to_owned())
}

/// The user id for a resident credential: the key's name plus a random
/// suffix (`primary.a1b2c3`). Restore reads the name back; the suffix keeps a
/// new credential from colliding with (and asking to overwrite) an older one
/// on the same key. OpenSSH allows 31 characters, which
/// [`enrollment::MAX_NAME`] leaves room for.
fn credential_user(name: &str) -> String {
    let mut bytes = [0u8; 3];
    if let Ok(mut random) = fs::File::open("/dev/urandom") {
        let _ = std::io::Read::read_exact(&mut random, &mut bytes);
    }
    let suffix: String = bytes.iter().map(|b| format!("{b:02x}")).collect();
    format!("{name}.{suffix}")
}

/// The name in a credential downloaded by `ssh-keygen -K`, whose file is
/// `id_<type>_sk_rk_keymate-github_<user>`. `None` for credentials from
/// versions that stored the account instead (`<account>-<random>`).
fn credential_name(file_name: &str) -> Option<String> {
    let app = APPLICATION.trim_start_matches("ssh:");
    let user = file_name.split_once(&format!("_rk_{app}_"))?.1;
    let (name, _suffix) = user.split_once('.')?;
    enrollment::validate_name(name).ok()?;
    Some(name.to_owned())
}

fn keygen_args(key: &Path, device: &str, user: &str, options: &Options, host: &str) -> Vec<String> {
    let ed25519 = key
        .file_name()
        .is_some_and(|n| n.to_string_lossy().starts_with("id_ed25519"));
    let key_type = if ed25519 { "ed25519-sk" } else { "ecdsa-sk" };
    let mut args = vec![
        "-t".to_owned(),
        key_type.to_owned(),
        "-f".to_owned(),
        key.to_string_lossy().into_owned(),
        "-C".to_owned(),
        format!("keymate-github@{host}"),
        "-N".to_owned(),
        String::new(),
        "-O".to_owned(),
        format!("device={device}"),
    ];
    if options.storage == Storage::Resident {
        args.extend([
            "-O".to_owned(),
            "resident".to_owned(),
            "-O".to_owned(),
            format!("application={APPLICATION}"),
            "-O".to_owned(),
            format!("user={user}"),
        ]);
    }
    if options.verification == Verification::PinAndTouch {
        args.extend(["-O".to_owned(), "verify-required".to_owned()]);
    }
    args
}

/// Options that make ssh use only `key`, no agent, no user config, and only
/// GitHub's published host keys.
fn ssh_options(key: &Path, known_hosts: &Path) -> Vec<String> {
    [
        "-F",
        "/dev/null",
        "-o",
        "IdentitiesOnly=yes",
        "-o",
        "IdentityAgent=none",
        "-o",
        "StrictHostKeyChecking=yes",
        "-o",
    ]
    .iter()
    .map(|s| (*s).to_owned())
    .chain([
        format!("UserKnownHostsFile={}", known_hosts.display()),
        "-i".to_owned(),
        key.display().to_string(),
    ])
    .collect()
}

/// GitHub answers a successful `ssh -T` with
/// `Hi NAME! You've successfully authenticated, but GitHub does not provide shell access.`
fn greeting(stderr: &str) -> Option<String> {
    let rest = stderr.split("Hi ").nth(1)?;
    let (name, rest) = rest.split_once('!')?;
    rest.contains("successfully authenticated")
        .then(|| sanitize(name))
}

/// Whether `ssh -G` output uses only `key_name` for authentication.
fn uses_key(resolved: &str, key_name: &str) -> bool {
    let mut identity = false;
    let mut only = false;
    for line in resolved.lines() {
        match line.split_once(' ') {
            Some(("identityfile", path)) if path.ends_with(&format!("/{key_name}")) => {
                identity = true;
            }
            Some(("identitiesonly", "yes")) => only = true,
            _ => {}
        }
    }
    identity && only
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_github_greeting() {
        let stderr = "Hi octocat! You've successfully authenticated, but GitHub does not provide shell access.\n";
        assert_eq!(greeting(stderr).as_deref(), Some("octocat"));
        assert_eq!(
            greeting("git@github.com: Permission denied (publickey)."),
            None
        );
    }

    #[test]
    fn checks_resolved_ssh_config() {
        let resolved = "user git\nidentityfile ~/.ssh/id_rsa\n\
                        identityfile /Users/me/.ssh/id_ed25519_sk_keymate_github\nidentitiesonly yes\n";
        assert!(uses_key(resolved, "id_ed25519_sk_keymate_github"));
        assert!(!uses_key(
            "identityfile /Users/me/.ssh/id_ed25519_sk_keymate_github\n",
            "id_ed25519_sk_keymate_github"
        ));
        assert!(!uses_key(
            "identityfile /Users/me/.ssh/x_id_ed25519_sk_keymate_github_old\nidentitiesonly yes",
            "id_ed25519_sk_keymate_github"
        ));
    }

    #[test]
    fn follows_ssh_keygen_output() {
        let first = "You may need to touch your authenticator to authorize key generation.";
        let again = "You may need to touch your authenticator again to authorize key generation.";
        assert_eq!(keygen_event(first, false), Some(KeyEvent::TouchNeeded));
        assert_eq!(keygen_event(first, true), None);
        assert_eq!(keygen_event(again, true), Some(KeyEvent::TouchNeeded));
        assert_eq!(
            keygen_event("PIN incorrect", true),
            Some(KeyEvent::PinRejected)
        );
        assert_eq!(
            keygen_event(
                "A resident key scoped to 'ssh:keymate-github' with user id 'octocat' already exists.",
                true
            ),
            Some(KeyEvent::AlreadyOnKey)
        );
        assert_eq!(keygen_event("Your public key has been saved", true), None);
    }

    #[test]
    fn credential_users_carry_the_name() {
        let (a, b) = (credential_user("primary"), credential_user("primary"));
        assert!(a.starts_with("primary.") && a.len() == "primary.".len() + 6);
        assert_ne!(a, b);
        // The longest name still fits OpenSSH's 31 characters.
        assert!(credential_user(&"a".repeat(enrollment::MAX_NAME)).len() <= 31);
        let file = format!("id_ed25519_sk_rk_keymate-github_{a}");
        assert_eq!(credential_name(&file).as_deref(), Some("primary"));
        assert_eq!(
            credential_name("id_ed25519_sk_rk_keymate-github_octocat-1a2b3c"),
            None
        );
    }

    #[test]
    fn keygen_options_follow_choices() {
        let key = Path::new("/h/.ssh/id_ed25519_sk_keymate_github");
        let simple = Options {
            storage: Storage::NonResident,
            verification: Verification::Touch,
            signing: false,
            git_signs: false,
        };
        let args = keygen_args(key, "ioreg://1", "octocat-1a2b3c", &simple, "mac").join(" ");
        assert!(args.starts_with("-t ed25519-sk -f /h/.ssh/id_ed25519_sk_keymate_github "));
        assert!(args.contains("-O device=ioreg://1"));
        assert!(!args.contains("resident") && !args.contains("verify-required"));

        let strict = Options {
            storage: Storage::Resident,
            verification: Verification::PinAndTouch,
            signing: false,
            git_signs: false,
        };
        let ecdsa = Path::new("/h/.ssh/id_ecdsa_sk_keymate_github");
        let args = keygen_args(ecdsa, "ioreg://1", "octocat-1a2b3c", &strict, "mac").join(" ");
        assert!(args.starts_with("-t ecdsa-sk "));
        assert!(
            args.contains("-O resident -O application=ssh:keymate-github -O user=octocat-1a2b3c")
        );
        assert!(args.ends_with("-O verify-required"));
    }

    #[test]
    fn test_connection_ignores_agent_and_user_config() {
        let args = ssh_options(
            Path::new("/h/.ssh/k"),
            Path::new("/h/.ssh/keymate/known_hosts"),
        );
        let joined = args.join(" ");
        assert!(joined.contains("-F /dev/null"));
        assert!(joined.contains("IdentityAgent=none"));
        assert!(joined.contains("StrictHostKeyChecking=yes"));
        assert!(joined.ends_with("-i /h/.ssh/k"));
    }
}
