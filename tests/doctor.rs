#![cfg(unix)]

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicUsize, Ordering};

static NEXT: AtomicUsize = AtomicUsize::new(0);

struct Fixture(PathBuf);

impl Fixture {
    fn new() -> Self {
        let root = std::env::temp_dir().join(format!(
            "keymate-doctor-test-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&root).unwrap();
        fs::create_dir(root.join("bin")).unwrap();
        fs::create_dir(root.join("libexec")).unwrap();
        fs::write(
            root.join("libexec/ssh-sk-helper"),
            "fixture linked to libfido2",
        )
        .unwrap();
        for name in [
            "ssh",
            "ssh-keygen",
            "gh",
            "git",
            "fido2-token",
            "fido2-assert",
        ] {
            let path = root.join("bin").join(name);
            fs::write(&path, format!("#!/bin/sh\nprintf '%s %s\\n' '{name}' \"$*\" >> \"$HOME/calls\"\n[ '{name}' = ssh ] && [ \"$*\" = '-V' ] && {{ echo 'OpenSSH_fixture, test' >&2; exit 0; }}\nexit 99\n")).unwrap();
            fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).unwrap();
        }
        Self(root)
    }

    fn run(&self) -> (bool, String) {
        let output = Command::new(env!("CARGO_BIN_EXE_keymate"))
            .args(["doctor", "--deps-only"])
            .env("PATH", self.0.join("bin"))
            .env("HOME", &self.0)
            .env("NO_COLOR", "1")
            .stdin(Stdio::null())
            .output()
            .unwrap();
        (
            output.status.success(),
            String::from_utf8(output.stdout).unwrap(),
        )
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        fs::remove_dir_all(&self.0).unwrap();
    }
}

#[test]
fn dependency_check_needs_no_account_or_device_and_is_read_only() {
    let fixture = Fixture::new();
    let (success, text) = fixture.run();
    assert!(success, "{text}");
    for label in ["OpenSSH", "libfido2", "GitHub CLI", "Git"] {
        assert!(text.contains(label), "{label}: {text}");
    }
    assert_eq!(
        text.lines().filter(|l| l.starts_with("  ✓")).count(),
        4,
        "{text}"
    );
    assert!(text.contains("All required tools are installed"));
    assert_eq!(
        fs::read_to_string(fixture.0.join("calls")).unwrap(),
        "ssh -V\n"
    );
    assert!(!fixture.0.join(".ssh").exists());
}

#[test]
fn each_missing_dependency_causes_failure() {
    for name in [
        "ssh",
        "ssh-keygen",
        "gh",
        "git",
        "fido2-token",
        "fido2-assert",
    ] {
        let fixture = Fixture::new();
        fs::remove_file(fixture.0.join("bin").join(name)).unwrap();
        let (success, text) = fixture.run();
        assert!(!success, "missing {name}: {text}");
        assert!(text.contains("not found"));
    }
}

#[test]
fn openssh_without_fido_support_causes_failure() {
    let fixture = Fixture::new();
    fs::remove_file(fixture.0.join("libexec/ssh-sk-helper")).unwrap();
    let (success, text) = fixture.run();
    assert!(!success);
    assert!(text.contains("cannot use security keys"));
}
