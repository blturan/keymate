//! Read-only checks of local tooling and connected keys. Nothing here asks
//! for a PIN, requires a touch, or changes any file.

use std::path::Path;
use std::time::Duration;

use crate::Service;
use crate::check::{Check, Mark};
use crate::devices::{self, PinState};
use crate::github::api::parse_account;
use crate::process;
use crate::tools::{find_in_known_dirs, find_on_path, openssh_supports_fido, sanitize};

const TIMEOUT: Duration = Duration::from_secs(15);

/// Checks under a heading, e.g. "Tools".
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Section {
    pub title: &'static str,
    pub checks: Vec<Check>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Report {
    pub sections: Vec<Section>,
}

impl Report {
    pub fn checks(&self) -> impl Iterator<Item = &Check> {
        self.sections.iter().flat_map(|s| &s.checks)
    }

    /// Checks that block setup. Warnings don't.
    pub fn problems(&self) -> usize {
        self.count(Mark::Fail)
    }

    pub fn warnings(&self) -> usize {
        self.count(Mark::Warn)
    }

    fn count(&self, mark: Mark) -> usize {
        self.checks().filter(|c| c.mark == mark).count()
    }

    pub fn ready(&self) -> bool {
        self.problems() == 0
    }
}

/// Shared tools and the security key, plus the tool and sign-in of
/// `service` when given.
pub fn run(service: Option<Service>) -> Report {
    let mut sections = vec![shared_tools()];
    if find_on_path("fido2-token").is_some() {
        sections.push(Section {
            title: "Security key",
            checks: security_keys(),
        });
    }
    sections.extend(service.map(self::service));
    Report { sections }
}

/// The checks for one service: its tools, and that you're signed in.
pub fn service(service: Service) -> Section {
    let mut section = service_tools(service);
    match service {
        Service::GitHub => {
            if let Some(gh) = find_on_path("gh") {
                section.checks.push(github_sign_in(&gh));
            }
        }
    }
    section
}

/// Check installed software only, without signing in or a security key: the
/// shared tools and those of `service`, or of every service when none is
/// given. One line per package to install.
pub fn dependencies(service: Option<Service>) -> Report {
    let services = match service {
        Some(service) => vec![service],
        None => Service::ALL.to_vec(),
    };
    let mut sections = vec![shared_tools()];
    sections.extend(services.into_iter().map(service_tools));
    Report { sections }
}

/// A service's own tools.
fn service_tools(service: Service) -> Section {
    match service {
        Service::GitHub => github_tools(),
    }
}

/// What every service needs: OpenSSH, libfido2 and Git.
fn shared_tools() -> Section {
    Section {
        title: "Tools",
        checks: vec![
            openssh(),
            tools(
                "libfido2",
                &["fido2-token", "fido2-assert"],
                "brew install libfido2",
            ),
            tools("Git", &["git"], "brew install git"),
        ],
    }
}

fn github_tools() -> Section {
    Section {
        title: "GitHub",
        checks: vec![tools("GitHub CLI", &["gh"], "brew install gh")],
    }
}

/// All of `names` must be on PATH; reports where the first one is.
fn tools(label: &'static str, names: &[&str], install: &str) -> Check {
    let mut found = Vec::new();
    for name in names {
        match find_on_path(name) {
            Some(path) => found.push(path),
            None => {
                return Check::new(label, Mark::Fail, format!("{name} not found")).hint(install);
            }
        }
    }
    let path = &found[0];
    let shown = if names.len() == 1 {
        path
    } else {
        path.parent().unwrap_or(path)
    };
    Check::new(label, Mark::Pass, shown.display().to_string())
}

/// `ssh` and `ssh-keygen` must both come from an OpenSSH that can use
/// security keys; the macOS one can't.
fn openssh() -> Check {
    for name in ["ssh", "ssh-keygen"] {
        let Some(path) = find_on_path(name) else {
            return Check::new("OpenSSH", Mark::Fail, format!("{name} not found"))
                .hint("Install OpenSSH with security-key support: brew install openssh");
        };
        if openssh_supports_fido(&path) {
            continue;
        }
        let check = Check::new(
            "OpenSSH",
            Mark::Fail,
            format!("{} cannot use security keys", path.display()),
        );
        return match find_in_known_dirs(name).find(|p| openssh_supports_fido(p)) {
            Some(better) => check.hint(format!(
                "Put {} before {} in your PATH",
                better.parent().unwrap_or(&better).display(),
                path.parent().unwrap_or(&path).display()
            )),
            None => check.hint(
                "Install OpenSSH with security-key support (brew install openssh) \
                 and put /opt/homebrew/bin before /usr/bin in your PATH",
            ),
        };
    }
    let ssh = find_on_path("ssh").unwrap_or_default();
    let version = ssh_version(&ssh)
        .map(|v| format!("{}, ", v.trim_start_matches("OpenSSH_")))
        .unwrap_or_default();
    Check::new(
        "OpenSSH",
        Mark::Pass,
        format!("{version}{}", ssh.parent().unwrap_or(&ssh).display()),
    )
}

/// `ssh -V` prints e.g. `OpenSSH_10.6p1, OpenSSL 4.0.3 ...` to stderr.
fn ssh_version(ssh: &Path) -> Option<String> {
    if ssh.file_name()? != "ssh" {
        return None;
    }
    let output = process::run(ssh, &["-V"], TIMEOUT).ok()?;
    let text = if output.stderr.is_empty() {
        output.stdout
    } else {
        output.stderr
    };
    let version = text.split(',').next()?.trim();
    (!version.is_empty()).then(|| sanitize(version))
}

fn github_sign_in(gh: &Path) -> Check {
    match process::run(gh, &["auth", "status", "--hostname", "github.com"], TIMEOUT) {
        Ok(output) if output.status.success() => {
            let account = parse_account(&output.stdout).or_else(|| parse_account(&output.stderr));
            let detail = match account {
                Some(account) => account,
                None => "signed in".to_owned(),
            };
            Check::new("Account", Mark::Pass, detail)
        }
        Ok(_) => Check::new("Account", Mark::Warn, "not signed in").hint("gh auth login --web"),
        Err(error) => Check::new("Account", Mark::Warn, format!("could not check: {error}")),
    }
}

fn security_keys() -> Vec<Check> {
    let Some(tool) = find_on_path("fido2-token") else {
        return vec![
            Check::new("fido2-token", Mark::Fail, "not found, cannot look for keys")
                .hint("brew install libfido2"),
        ];
    };
    let devices = match devices::list_with(&tool) {
        Ok(devices) => devices,
        Err(error) => return vec![Check::new("", Mark::Fail, error.to_string())],
    };
    if devices.is_empty() {
        return vec![
            Check::new("", Mark::Fail, "No security key connected")
                .hint("Plug one in, then run `keymate doctor` again"),
        ];
    }

    let mut checks: Vec<Check> = devices.iter().map(security_key).collect();
    if devices.len() > 1 {
        checks.push(
            Check::new(
                "",
                Mark::Warn,
                format!("{} security keys connected", devices.len()),
            )
            .hint("Connect only the key you want to enroll during setup"),
        );
    }
    checks
}

fn security_key(device: &devices::Device) -> Check {
    let name = &device.name;
    let Some(info) = &device.info else {
        return Check::new(
            "",
            Mark::Warn,
            format!("{name} did not report its capabilities"),
        )
        .hint("Unplug the key, plug it back in, and try again");
    };
    if !info.supports_fido2() {
        return Check::new(
            "",
            Mark::Fail,
            format!("{name} supports only U2F; Keymate needs FIDO2"),
        );
    }

    match (info.pin, info.pin_retries) {
        (PinState::Set, Some(retries)) if retries <= 3 => Check::new(
            "",
            Mark::Warn,
            format!("{name}, only {retries} PIN attempts left"),
        )
        .hint("Do not guess the PIN; a locked FIDO application must be reset, erasing its credentials"),
        (PinState::Set, retries) => {
            let attempts = retries
                .map(|r| format!(" ({r} attempts left)"))
                .unwrap_or_default();
            Check::new(
                "",
                Mark::Pass,
                format!("{name}, PIN set{attempts}"),
            )
        }
        (PinState::NotSet, _) => Check::new(
            "",
            Mark::Warn,
            format!("{name}, no PIN set"),
        )
        .hint("`keymate setup github` can set one if your choices need it"),
        (PinState::Unsupported, _) => Check::new(
            "",
            Mark::Warn,
            format!("{name}, no PIN support"),
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::devices::{Device, DeviceInfo};

    fn device(info: Option<DeviceInfo>) -> Device {
        Device {
            path: "ioreg://1".into(),
            vendor_id: 0x1050,
            product_id: 0x0406,
            name: "YubiKey".into(),
            info,
        }
    }

    fn fido2(pin: PinState, pin_retries: Option<u32>) -> DeviceInfo {
        DeviceInfo {
            versions: vec!["FIDO_2_0".into()],
            algorithms: vec!["es256".into(), "eddsa".into()],
            pin,
            pin_retries,
            min_pin_length: Some(4),
            resident_keys: true,
            create_without_pin: false,
        }
    }

    #[test]
    fn key_with_pin_passes() {
        let check = security_key(&device(Some(fido2(PinState::Set, Some(8)))));
        assert_eq!(check.mark, Mark::Pass);
        assert_eq!(check.detail, "YubiKey, PIN set (8 attempts left)");
    }

    #[test]
    fn key_problems_warn_or_fail() {
        let low = security_key(&device(Some(fido2(PinState::Set, Some(2)))));
        assert_eq!(low.mark, Mark::Warn);
        let unset = security_key(&device(Some(fido2(PinState::NotSet, None))));
        assert_eq!(unset.mark, Mark::Warn);
        let u2f_only = DeviceInfo {
            versions: vec!["U2F_V2".into()],
            ..DeviceInfo::default()
        };
        assert_eq!(security_key(&device(Some(u2f_only))).mark, Mark::Fail);
        assert_eq!(security_key(&device(None)).mark, Mark::Warn);
    }

    #[test]
    fn report_is_ready_unless_something_fails() {
        let report = |checks| Report {
            sections: vec![Section {
                title: "Tools",
                checks,
            }],
        };
        let warn = Check::new("x", Mark::Warn, "");
        let fail = Check::new("y", Mark::Fail, "");
        assert!(report(vec![warn.clone()]).ready());
        let failing = report(vec![warn, fail]);
        assert!(!failing.ready());
        assert_eq!(failing.problems(), 1);
    }
}
