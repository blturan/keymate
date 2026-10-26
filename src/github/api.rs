//! GitHub access through the GitHub CLI (`gh`).

use std::ffi::OsStr;
use std::fmt;
use std::path::{Path, PathBuf};
use std::time::Duration;

use crate::process;
use crate::tools::{find_on_path, sanitize};
use crate::{Error, Result};

const TIMEOUT: Duration = Duration::from_secs(30);
const HOST: &str = "github.com";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyKind {
    Authentication,
    Signing,
}

impl KeyKind {
    fn api_path(self) -> &'static str {
        match self {
            KeyKind::Authentication => "/user/keys",
            KeyKind::Signing => "/user/ssh_signing_keys",
        }
    }

    /// The scope GitHub requires to delete keys of this kind.
    fn admin_scope(self) -> &'static str {
        self.scopes()[0]
    }

    /// Token scopes that allow listing and adding keys of this kind.
    fn scopes(self) -> [&'static str; 2] {
        match self {
            KeyKind::Authentication => ["admin:public_key", "write:public_key"],
            KeyKind::Signing => ["admin:ssh_signing_key", "write:ssh_signing_key"],
        }
    }
}

impl fmt::Display for KeyKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            KeyKind::Authentication => "authentication",
            KeyKind::Signing => "signing",
        })
    }
}

/// A key registered on GitHub.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GhKey {
    pub id: u64,
    pub kind: KeyKind,
    /// `type base64`, without a comment.
    pub key: String,
    pub title: String,
}

impl GhKey {
    /// Keymate titles its keys `keymate_auth_<name>` and `keymate_sign_<name>`
    /// (earlier versions: `Keymate: <security key> on <computer>`).
    pub fn from_keymate(&self) -> bool {
        self.title.starts_with("keymate_") || self.title.starts_with("Keymate:")
    }
}

/// The GitHub title for a Keymate key named `name`.
pub(crate) fn title(name: &str, kind: KeyKind) -> String {
    let suffix = match kind {
        KeyKind::Authentication => "auth",
        KeyKind::Signing => "sign",
    };
    format!("keymate_{suffix}_{name}")
}

pub(crate) struct Gh {
    path: PathBuf,
}

pub(crate) struct Session {
    pub account: String,
    /// `None` when `gh` does not report scopes, e.g. for `GH_TOKEN` tokens.
    pub scopes: Option<Vec<String>>,
}

impl Session {
    /// The scope to request when the token cannot manage `kind` keys.
    pub fn missing_scope(&self, kind: KeyKind) -> Option<&'static str> {
        let scopes = self.scopes.as_ref()?;
        let [admin, write] = kind.scopes();
        let has = |s: &str| scopes.iter().any(|have| have == s);
        (!has(admin) && !has(write)).then_some(admin)
    }
}

impl Session {
    /// The scope to request when the token cannot delete `kind` keys.
    pub fn missing_admin_scope(&self, kind: KeyKind) -> Option<&'static str> {
        let scopes = self.scopes.as_ref()?;
        let admin = kind.admin_scope();
        (!scopes.iter().any(|s| s == admin)).then_some(admin)
    }
}

impl Gh {
    pub fn find() -> Result<Gh> {
        let path = find_on_path("gh").ok_or(Error::MissingTool {
            name: "gh",
            install: "brew install gh",
        })?;
        Ok(Gh { path })
    }

    /// The signed-in github.com account; an error when signed out.
    pub fn signed_in(&self) -> Result<Session> {
        self.session()?.ok_or_else(|| {
            Error::fixable(
                "You're not signed in to GitHub",
                "Sign in with `gh auth login --web`, then try again",
            )
        })
    }

    /// The signed-in github.com account, or `None` when signed out.
    pub fn session(&self) -> Result<Option<Session>> {
        let output = process::run(&self.path, &["auth", "status", "--hostname", HOST], TIMEOUT)
            .map_err(|e| failed(e.to_string()))?;
        if !output.status.success() {
            return Ok(None);
        }
        let text = format!("{}\n{}", output.stdout, output.stderr);
        let Some(account) = parse_account(&text) else {
            return Err(failed("could not read the signed-in account".into()));
        };
        Ok(Some(Session {
            account,
            scopes: parse_scopes(&text),
        }))
    }

    /// Organizations the account belongs to.
    pub fn orgs(&self) -> Result<Vec<String>> {
        let text = self.api(&["--paginate", "/user/orgs", "--jq", ".[].login"])?;
        Ok(text
            .lines()
            .map(sanitize)
            .filter(|l| !l.is_empty())
            .collect())
    }

    /// One private or internal repository per organization, as
    /// `(organization, owner/repo)`, to probe access with.
    pub fn org_repos(&self) -> Result<Vec<(String, String)>> {
        let text = self.api(&[
            "--paginate",
            "/user/repos?affiliation=organization_member&per_page=100",
            "--jq",
            r#".[] | select(.private) | "\(.owner.login) \(.full_name)""#,
        ])?;
        let mut repos: Vec<(String, String)> = Vec::new();
        for line in text.lines() {
            let Some((org, repo)) = line.split_once(' ') else {
                continue;
            };
            if !repos.iter().any(|(o, _)| o == org) {
                repos.push((sanitize(org), sanitize(repo)));
            }
        }
        Ok(repos)
    }

    /// Ask for extra token scopes through GitHub's browser flow.
    pub fn request_scope(&self, scope: &str) -> Result<()> {
        let status = process::run_interactive(
            &self.path,
            &["auth", "refresh", "--hostname", HOST, "--scopes", scope],
        )
        .map_err(|e| failed(e.to_string()))?;
        if status.success() {
            Ok(())
        } else {
            Err(failed(format!("could not add the {scope} permission")))
        }
    }

    /// Keys of `kind` on the account.
    pub fn list_keys(&self, kind: KeyKind) -> Result<Vec<GhKey>> {
        let text = self.api(&[
            "--paginate",
            kind.api_path(),
            "--jq",
            r#".[] | "\(.id)\t\(.key)\t\(.title)""#,
        ])?;
        Ok(parse_key_list(&text, kind))
    }

    pub fn delete_key(&self, kind: KeyKind, id: u64) -> Result<()> {
        let path = format!("{}/{id}", kind.api_path());
        self.api(&["--method", "DELETE", &path]).map(|_| ())
    }

    pub fn add_key(&self, public_key: &Path, title: &str, kind: KeyKind) -> Result<()> {
        let kind = kind.to_string();
        let args = [
            OsStr::new("ssh-key"),
            OsStr::new("add"),
            public_key.as_os_str(),
            OsStr::new("--title"),
            OsStr::new(title),
            OsStr::new("--type"),
            OsStr::new(&kind),
        ];
        let output = process::run(&self.path, &args, TIMEOUT).map_err(|e| failed(e.to_string()))?;
        if output.status.success() {
            Ok(())
        } else {
            Err(failed(sanitize(output.stderr.trim())))
        }
    }

    /// GitHub's SSH host keys from the API, which is fetched over verified TLS.
    pub fn host_keys(&self) -> Result<Vec<String>> {
        let text = self.api(&["meta", "--jq", ".ssh_keys[]"])?;
        let keys: Vec<String> = text.lines().filter_map(key_identity).collect();
        if keys.is_empty() {
            return Err(failed("GitHub did not return its SSH host keys".into()));
        }
        Ok(keys)
    }

    fn api(&self, args: &[&str]) -> Result<String> {
        let mut full = vec!["api", "--hostname", HOST];
        full.extend_from_slice(args);
        self.run(&full, TIMEOUT)
    }

    /// Run `gh` with `args`; its output on success.
    pub fn run(&self, args: &[&str], timeout: Duration) -> Result<String> {
        let output = process::run(&self.path, args, timeout).map_err(|e| failed(e.to_string()))?;
        if output.status.success() {
            Ok(output.stdout)
        } else {
            Err(failed(sanitize(output.stderr.trim())))
        }
    }
}

/// Name GitHub keys for people: `keymate_auth_x and keymate_sign_x`. A title
/// used for several kinds (earlier versions) lists them: `title
/// (authentication and signing)`.
pub fn describe_keys(keys: &[GhKey]) -> String {
    let mut titles: Vec<&str> = Vec::new();
    for key in keys {
        if !titles.contains(&key.title.as_str()) {
            titles.push(&key.title);
        }
    }
    let names: Vec<String> = titles
        .into_iter()
        .map(|title| {
            let uses: Vec<String> = keys
                .iter()
                .filter(|k| k.title == title)
                .map(|k| k.kind.to_string())
                .collect();
            match uses.len() {
                1 => title.to_owned(),
                _ => format!("{title} ({})", uses.join(" and ")),
            }
        })
        .collect();
    match names.split_last() {
        None => String::new(),
        Some((last, [])) => last.clone(),
        Some((last, rest)) => format!("{} and {last}", rest.join(", ")),
    }
}

pub(crate) fn delete_registrations(gh: &Gh, keys: &[GhKey]) -> Result<()> {
    for key in keys {
        gh.delete_key(key.kind, key.id)?;
    }
    Ok(())
}

fn failed(detail: String) -> Error {
    Error::ToolFailed { name: "gh", detail }
}

/// Parse `id<TAB>key<TAB>title` lines.
fn parse_key_list(text: &str, kind: KeyKind) -> Vec<GhKey> {
    text.lines()
        .filter_map(|line| {
            let mut fields = line.splitn(3, '\t');
            let id = fields.next()?.parse().ok()?;
            let key = key_identity(fields.next()?)?;
            let title = sanitize(fields.next().unwrap_or_default());
            Some(GhKey {
                id,
                kind,
                key,
                title,
            })
        })
        .collect()
}

/// Reduce an OpenSSH public key line to `type base64`, dropping the comment.
pub(crate) fn key_identity(line: &str) -> Option<String> {
    let mut fields = line.split_whitespace();
    let (kind, data) = (fields.next()?, fields.next()?);
    Some(sanitize(&format!("{kind} {data}")))
}

/// Extract the account from `Logged in to github.com account NAME (keyring)`
/// or the older `Logged in to github.com as NAME (...)`.
pub(crate) fn parse_account(text: &str) -> Option<String> {
    let rest = text.split("Logged in to github.com ").nth(1)?;
    let rest = rest
        .strip_prefix("account ")
        .or_else(|| rest.strip_prefix("as "))?;
    rest.split_whitespace().next().map(sanitize)
}

/// Extract scopes from `Token scopes: 'gist', 'read:org', 'repo'`.
fn parse_scopes(text: &str) -> Option<Vec<String>> {
    let line = text.lines().find_map(|l| l.split_once("Token scopes:"))?.1;
    Some(
        line.split(',')
            .map(|s| s.trim().trim_matches('\'').to_owned())
            .filter(|s| !s.is_empty())
            .collect(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    const STATUS: &str = "github.com
  ✓ Logged in to github.com account octocat (keyring)
  - Active account: true
  - Token scopes: 'admin:public_key', 'gist', 'read:org', 'repo'
";

    #[test]
    fn parses_account_from_current_and_older_output() {
        assert_eq!(parse_account(STATUS).as_deref(), Some("octocat"));
        assert_eq!(
            parse_account("✓ Logged in to github.com as octocat (oauth_token)").as_deref(),
            Some("octocat")
        );
        assert_eq!(
            parse_account("You are not logged into any GitHub hosts"),
            None
        );
    }

    #[test]
    fn finds_missing_scopes() {
        let session = Session {
            account: "octocat".into(),
            scopes: parse_scopes(STATUS),
        };
        assert_eq!(session.missing_scope(KeyKind::Authentication), None);
        assert_eq!(
            session.missing_scope(KeyKind::Signing),
            Some("admin:ssh_signing_key")
        );
        let unknown = Session {
            account: "octocat".into(),
            scopes: None,
        };
        assert_eq!(unknown.missing_scope(KeyKind::Signing), None);
    }

    #[test]
    fn parses_key_list() {
        let keys = parse_key_list(
            "7\tsk-ssh-ed25519@openssh.com AAAA\tkeymate_auth_yubikey\n\
             8\tssh-ed25519 BBBB\tlaptop\nbad line\n",
            KeyKind::Authentication,
        );
        assert_eq!(keys.len(), 2);
        assert_eq!(keys[0].id, 7);
        assert_eq!(keys[0].key, "sk-ssh-ed25519@openssh.com AAAA");
        assert!(keys[0].from_keymate());
        assert!(!keys[1].from_keymate());
        assert_eq!(title("backup", KeyKind::Signing), "keymate_sign_backup");
    }

    #[test]
    fn describes_keys_once_per_title() {
        let key = |title: &str, kind| GhKey {
            id: 1,
            kind,
            key: "k".into(),
            title: title.into(),
        };
        let keys = [
            key("keymate_a_auth", KeyKind::Authentication),
            key("Keymate: old", KeyKind::Authentication),
            key("Keymate: old", KeyKind::Signing),
        ];
        assert_eq!(
            describe_keys(&keys),
            "keymate_a_auth and Keymate: old (authentication and signing)"
        );
        assert_eq!(describe_keys(&keys[..1]), "keymate_a_auth");
    }

    #[test]
    fn key_identity_drops_comments() {
        assert_eq!(
            key_identity("sk-ssh-ed25519@openssh.com AAAAGnNr keymate@host").as_deref(),
            Some("sk-ssh-ed25519@openssh.com AAAAGnNr")
        );
        assert_eq!(key_identity("garbage"), None);
    }
}
