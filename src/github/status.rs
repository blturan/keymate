//! Read-only status of the keys Keymate set up. No authentication attempts,
//! PIN prompts, credential downloads, scope requests, or configuration
//! writes.

use std::path::PathBuf;
use std::time::Duration;

use super::api::{Gh, GhKey, KeyKind, describe_keys};
use super::enrollment::{self, Detection, Enrollment};
use crate::check::{Check, Mark};
use crate::devices;
use crate::files;
use crate::git::{find_git, git_global};
use crate::process;
use crate::tools::{find_on_path, sanitize};
use crate::{Error, Result};

/// One key Keymate set up: its checks (GitHub, SSH) and facts (file, storage).
#[derive(Debug, Clone)]
pub struct KeyReport {
    pub enrollment: Enrollment,
    pub checks: Vec<Check>,
}

/// What `keymate status` shows.
#[derive(Debug, Clone, Default)]
pub struct Report {
    /// The GitHub account, when signed in.
    pub account: Option<String>,
    /// What kept a check from running, such as not being signed in.
    pub notes: Vec<Check>,
    pub keys: Vec<KeyReport>,
    /// Keymate keys on GitHub without a key on this Mac.
    pub github_only: Vec<Check>,
    /// The plugged-in security key and commit signing.
    pub this_mac: Vec<Check>,
}

impl Report {
    pub fn checks(&self) -> impl Iterator<Item = &Check> {
        self.notes
            .iter()
            .chain(self.keys.iter().flat_map(|key| &key.checks))
            .chain(&self.github_only)
            .chain(&self.this_mac)
    }

    /// Checks that need fixing. Warnings and facts don't.
    pub fn problems(&self) -> usize {
        self.checks().filter(|c| c.mark == Mark::Fail).count()
    }

    pub fn warnings(&self) -> usize {
        self.checks().filter(|c| c.mark == Mark::Warn).count()
    }

    pub fn ready(&self) -> bool {
        self.problems() == 0
    }
}

/// A note on what could not be checked.
fn note(detail: impl Into<String>) -> Check {
    Check::new("", Mark::Warn, detail)
}

/// To fix most problems with a key, run setup again and keep the key.
const KEEP: &str = "Run `keymate setup github` and choose Keep to fix it";

pub fn run() -> Result<Report> {
    let enrolled = enrollment::list(&files::ssh_dir()?);
    let mut report = Report::default();

    let github = github(&mut report);
    let ssh = match ssh_identities() {
        Ok(identities) => Some(identities),
        Err(error) => {
            report.notes.push(note(format!(
                "Couldn't check your SSH settings: {}",
                sanitize(&error.to_string())
            )));
            None
        }
    };
    let (signing, signer) = signing_check(&enrolled).unwrap_or_else(|error| {
        (
            Check::new(
                "Commit signing",
                Mark::Warn,
                format!("couldn't check: {}", sanitize(&error.to_string())),
            ),
            None,
        )
    });

    for enrollment in &enrolled {
        let mut checks = Vec::new();
        if let Some(problem) = file_problem(enrollment) {
            checks.push(
                Check::new("Key file", Mark::Fail, problem)
                    .hint("Set the key up again with `keymate setup github`"),
            );
        }
        if let (Some(public), Some(github)) = (&enrollment.public_key, &github) {
            let signs = signer.as_ref() == Some(&enrollment.key);
            checks.extend(registration(public, github, signs));
        }
        if let Some(identities) = &ssh {
            checks.push(ssh_check(enrollment, identities));
        }
        checks.push(Check::new("File", Mark::Info, enrollment.display()));
        if let Some(sk) = &enrollment.sk {
            let storage = if sk.resident() {
                "on the key"
            } else {
                "on this Mac"
            };
            let needs = if sk.verify_required() {
                "PIN + touch"
            } else {
                "touch"
            };
            checks.push(Check::new(
                "Stored",
                Mark::Info,
                format!("{storage} · {needs}"),
            ));
        }
        report.keys.push(KeyReport {
            enrollment: enrollment.clone(),
            checks,
        });
    }

    if let Some(github) = &github {
        let elsewhere: Vec<GhKey> = github
            .listed()
            .filter(|key| {
                key.from_keymate()
                    && !enrolled
                        .iter()
                        .any(|e| e.public_key.as_ref() == Some(&key.key))
            })
            .cloned()
            .collect();
        if !elsewhere.is_empty() {
            report.github_only.push(
                Check::new(
                    "",
                    Mark::Warn,
                    format!(
                        "{} {} no key on this Mac",
                        describe_keys(&elsewhere),
                        if elsewhere.len() == 1 { "has" } else { "have" }
                    ),
                )
                .hint(
                    "Another computer may use it. To use it here, plug in its security key \
                 and run `keymate setup github`",
                ),
            );
        }
    }

    report.this_mac.extend(plugged_in(&enrolled));
    report.this_mac.push(signing);
    Ok(report)
}

/// The keys listed on GitHub, per kind; `None` when that kind couldn't be
/// listed.
struct GitHub {
    authentication: Option<Vec<GhKey>>,
    signing: Option<Vec<GhKey>>,
}

impl GitHub {
    fn listed(&self) -> impl Iterator<Item = &GhKey> {
        self.authentication.iter().chain(&self.signing).flatten()
    }
}

/// List the account's keys. What can't be checked becomes a note.
fn github(report: &mut Report) -> Option<GitHub> {
    let gh = match Gh::find() {
        Ok(gh) => gh,
        Err(error) => {
            report.notes.push(match error.fix() {
                Some(fix) => note(format!("Couldn't check GitHub: {error}")).hint(fix),
                None => note(format!("Couldn't check GitHub: {error}")),
            });
            return None;
        }
    };
    let session = match gh.session() {
        Ok(Some(session)) => session,
        Ok(None) => {
            report.notes.push(
                note("Couldn't check GitHub: you're not signed in")
                    .hint("Sign in with `gh auth login --web`"),
            );
            return None;
        }
        Err(error) => {
            report
                .notes
                .push(note(format!("Couldn't check GitHub: {error}")));
            return None;
        }
    };
    report.account = Some(session.account.clone());
    let mut list = |kind: KeyKind| {
        if let Some(scope) = session.missing_scope(kind) {
            report.notes.push(
                note(format!("Couldn't check your {kind} keys on GitHub")).hint(format!(
                    "Allow it with `gh auth refresh -h github.com -s {scope}`"
                )),
            );
            return None;
        }
        match gh.list_keys(kind) {
            Ok(keys) => Some(keys),
            Err(error) => {
                report.notes.push(note(format!(
                    "Couldn't list your {kind} keys on GitHub: {error}"
                )));
                None
            }
        }
    };
    Some(GitHub {
        authentication: list(KeyKind::Authentication),
        signing: list(KeyKind::Signing),
    })
}

/// What's wrong with an enrollment's files, if anything.
fn file_problem(enrollment: &Enrollment) -> Option<&'static str> {
    match (enrollment.sk.is_some(), enrollment.public_key.is_some()) {
        (true, true) => None,
        (false, true) => Some("the key handle file is missing or invalid"),
        (true, false) => Some("the public key file is missing or invalid"),
        (false, false) => Some("the key handle and public key files are missing or invalid"),
    }
}

/// Where the key is registered on GitHub, matched by public key, not title.
/// Signing only matters for the key that signs commits.
fn registration(public: &str, github: &GitHub, signs: bool) -> Option<Check> {
    let find = |keys: &Option<Vec<GhKey>>| {
        keys.as_ref().map(|keys| {
            keys.iter()
                .find(|k| k.key == public)
                .map(|k| k.title.clone())
        })
    };
    // `None`: couldn't be listed (a note says why).
    let authentication = find(&github.authentication)?;
    let signing = find(&github.signing);
    Some(match (authentication, signing) {
        (None, _) => Check::new("GitHub", Mark::Fail, "not registered").hint(KEEP),
        (Some(auth), Some(Some(sign))) if auth == sign => Check::new("GitHub", Mark::Pass, auth),
        (Some(auth), Some(Some(sign))) => {
            Check::new("GitHub", Mark::Pass, format!("{auth} and {sign}"))
        }
        (Some(auth), Some(None)) if signs => Check::new(
            "GitHub",
            Mark::Warn,
            format!("{auth}, not registered for signing"),
        )
        .hint(
            "Commits signed with it won't show as Verified. Run `keymate setup github` \
             and choose Keep to fix it",
        ),
        (Some(auth), _) => Check::new("GitHub", Mark::Pass, auth),
    })
}

/// The identity files `ssh github.com` resolves to.
fn ssh_identities() -> Result<Vec<String>> {
    let ssh = find_on_path("ssh").ok_or(Error::MissingTool {
        name: "ssh",
        install: "brew install openssh",
    })?;
    match process::run(&ssh, &["-G", "github.com"], Duration::from_secs(15)) {
        Ok(output) if output.status.success() => Ok(output
            .stdout
            .lines()
            .filter_map(|line| line.strip_prefix("identityfile "))
            .map(str::to_owned)
            .collect()),
        Ok(output) => Err(Error::Failed(sanitize(output.stderr.trim()))),
        Err(error) => Err(Error::Failed(error.to_string())),
    }
}

fn ssh_check(enrollment: &Enrollment, identities: &[String]) -> Check {
    let used = identities
        .iter()
        .any(|path| *path == enrollment.display() || *path == enrollment.key.to_string_lossy());
    match used {
        true => Check::new("SSH", Mark::Pass, "used for github.com"),
        false => Check::new("SSH", Mark::Warn, "not used for github.com").hint(KEEP),
    }
}

/// The plugged-in security key, and which key Keymate set up on it. Nothing
/// when none is plugged in: keys stay set up while unplugged.
fn plugged_in(enrolled: &[Enrollment]) -> Option<Check> {
    let devices = match devices::list() {
        Ok(devices) => devices,
        Err(error) => {
            return Some(Check::new(
                "Security key",
                Mark::Warn,
                format!("couldn't check: {}", sanitize(&error.to_string())),
            ));
        }
    };
    let usable: Vec<_> = devices
        .iter()
        .filter(|d| d.info.as_ref().is_some_and(|i| i.supports_fido2()))
        .collect();
    Some(match usable.as_slice() {
        [] => return None,
        [device] => match enrollment::detect(enrolled, device) {
            Detection::ThisKey(e) => Check::new(
                "Security key",
                Mark::Info,
                format!(
                    "{}, set up as {}",
                    device.name,
                    e.name().unwrap_or_else(|| e.file_name())
                ),
            ),
            Detection::Unknown(_) => Check::new(
                "Security key",
                Mark::Warn,
                format!("{}, couldn't tell which key it is", device.name),
            ),
            _ => Check::new(
                "Security key",
                Mark::Info,
                format!("{}, not set up yet", device.name),
            ),
        },
        several => Check::new(
            "Security key",
            Mark::Info,
            format!("{} plugged in", several.len()),
        ),
    })
}

/// Git's global commit signing, and the enrollment it signs with, if any.
fn signing_check(enrolled: &[Enrollment]) -> Result<(Check, Option<PathBuf>)> {
    let git = find_git()?;
    let get = |name| git_global(&git, &["--includes", "--get", name]);
    let on = |name| -> Result<bool> {
        Ok(
            git_global(&git, &["--includes", "--type=bool", "--get", name])?.as_deref()
                == Some("true"),
        )
    };
    if !on("commit.gpgsign")? && !on("tag.gpgsign")? {
        return Ok((Check::new("Commit signing", Mark::Info, "off"), None));
    }
    let Some(key) = get("user.signingkey")? else {
        return Ok((
            Check::new(
                "Commit signing",
                Mark::Warn,
                "on, but no signing key is set",
            )
            .hint("Choose one with `keymate signer github`"),
            None,
        ));
    };
    let format = get("gpg.format")?.unwrap_or_else(|| "openpgp".into());
    if format != "ssh" {
        return Ok((
            Check::new("Commit signing", Mark::Info, format!("with a {format} key")),
            None,
        ));
    }
    let signer = enrolled.iter().find(|e| {
        [
            format!("{}.pub", e.display()),
            format!("{}.pub", e.key.display()),
            e.display(),
            e.key.to_string_lossy().into_owned(),
        ]
        .contains(&key)
    });
    let with = signer.map_or(key.clone(), |e| e.name().unwrap_or_else(|| e.file_name()));
    Ok((
        Check::new("Commit signing", Mark::Info, format!("with {with}")),
        signer.map(|e| e.key.clone()),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(kind: KeyKind, public: &str, title: &str) -> GhKey {
        GhKey {
            id: 1,
            kind,
            key: public.into(),
            title: title.into(),
        }
    }

    fn github(authentication: Vec<GhKey>, signing: Vec<GhKey>) -> GitHub {
        GitHub {
            authentication: Some(authentication),
            signing: Some(signing),
        }
    }

    #[test]
    fn registration_matches_public_key_not_title() {
        let listed = github(
            vec![key(KeyKind::Authentication, "sk AAAA", "old name")],
            vec![],
        );
        let check = registration("sk AAAA", &listed, false).unwrap();
        assert_eq!(check.mark, Mark::Pass);
        assert_eq!(check.detail, "old name");
    }

    #[test]
    fn both_registrations_share_one_line() {
        let listed = github(
            vec![key(KeyKind::Authentication, "sk AAAA", "keymate_auth_a")],
            vec![key(KeyKind::Signing, "sk AAAA", "keymate_sign_a")],
        );
        let check = registration("sk AAAA", &listed, true).unwrap();
        assert_eq!(check.detail, "keymate_auth_a and keymate_sign_a");
    }

    #[test]
    fn missing_registration_fails_and_signing_only_matters_for_the_signer() {
        assert_eq!(
            registration("sk AAAA", &github(vec![], vec![]), false)
                .unwrap()
                .mark,
            Mark::Fail
        );
        let auth_only = github(vec![key(KeyKind::Authentication, "sk AAAA", "a")], vec![]);
        assert_eq!(
            registration("sk AAAA", &auth_only, false).unwrap().mark,
            Mark::Pass
        );
        assert_eq!(
            registration("sk AAAA", &auth_only, true).unwrap().mark,
            Mark::Warn
        );
    }

    #[test]
    fn unlisted_registrations_are_not_called_missing() {
        let unknown = GitHub {
            authentication: None,
            signing: None,
        };
        assert!(registration("sk AAAA", &unknown, false).is_none());
    }

    #[test]
    fn broken_key_files_are_named() {
        let enrollment = Enrollment {
            key: PathBuf::from("/home/test/.ssh/id_ed25519_sk_keymate_github_test"),
            sk: None,
            public_key: Some("sk AAAA".into()),
            device: None,
            created: None,
        };
        assert_eq!(
            file_problem(&enrollment),
            Some("the key handle file is missing or invalid")
        );
    }

    #[test]
    fn ssh_identity_must_match_exactly() {
        let enrollment = Enrollment {
            key: PathBuf::from("/home/test/.ssh/id_ed25519_sk_keymate_github_test"),
            sk: None,
            public_key: None,
            device: None,
            created: None,
        };
        let used = |path: &str| ssh_check(&enrollment, &[path.to_owned()]).mark;
        assert_eq!(used(&enrollment.display()), Mark::Pass);
        assert_eq!(used(&format!("{}-other", enrollment.display())), Mark::Warn);
        assert_eq!(used("~/.ssh/id_other"), Mark::Warn);
    }

    #[test]
    fn failures_count_as_problems_and_warnings_do_not() {
        let mut report = Report {
            this_mac: vec![Check::new("x", Mark::Fail, "")],
            ..Report::default()
        };
        assert!(!report.ready());
        report.this_mac[0].mark = Mark::Warn;
        assert!(report.ready());
        assert_eq!(report.warnings(), 1);
    }
}
