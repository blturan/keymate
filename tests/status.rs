#![cfg(unix)]

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicUsize, Ordering};

static NEXT: AtomicUsize = AtomicUsize::new(0);

struct Fixture(PathBuf);

impl Fixture {
    fn new(gh: &str) -> Self {
        let root = std::env::temp_dir().join(format!(
            "keymate-status-test-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&root).unwrap();
        let fixture = Self(root);
        for (name, body) in [
            ("gh", gh),
            ("ssh", "[ \"$*\" = '-G github.com' ] || exit 99\nexit 0"),
            (
                "git",
                "case \"$*\" in 'config --global --includes --type=bool --get '*gpgsign) exit 1 ;; *) exit 99 ;; esac",
            ),
            ("fido2-token", "[ \"$*\" = '-L' ] || exit 99\nexit 0"),
        ] {
            let path = fixture.0.join(name);
            fs::write(
                &path,
                format!(
                    "#!/bin/sh\nprintf '%s %s\\n' '{name}' \"$*\" >> \"$HOME/calls\"\n{body}\n"
                ),
            )
            .unwrap();
            fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).unwrap();
        }
        fixture
    }

    fn run(&self) -> (std::process::Output, String) {
        let output = Command::new(env!("CARGO_BIN_EXE_keymate"))
            .args(["status", "github"])
            .env("HOME", &self.0)
            .env("PATH", &self.0)
            .env("NO_COLOR", "1")
            .stdin(Stdio::null())
            .output()
            .unwrap();
        let text = String::from_utf8(output.stdout.clone()).unwrap();
        (output, text)
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        fs::remove_dir_all(&self.0).unwrap();
    }
}

#[test]
fn status_is_noninteractive_and_only_runs_read_only_commands() {
    let fixture = Fixture::new(
        "case \"$*\" in
        'auth status --hostname github.com') printf '%s\\n' 'Logged in to github.com account tester' \"Token scopes: 'admin:public_key', 'admin:ssh_signing_key'\" ;;
        'api --hostname github.com --paginate /user/keys --jq '*) printf '1\\tsk-type AAAA\\tkeymate_auth_test\\n' ;;
        'api --hostname github.com --paginate /user/ssh_signing_keys --jq '*) exit 0 ;;
        *) exit 99 ;;
        esac",
    );
    let (output, text) = fixture.run();
    assert!(output.status.success(), "{text}");
    assert!(
        text.starts_with("No keys on this Mac · tester on GitHub\n"),
        "{text}"
    );
    assert!(
        text.contains("On GitHub only:\n  ! keymate_auth_test has no key on this Mac"),
        "{text}"
    );
    assert!(text.ends_with("\n! 1 warning\n"), "{text}");
    assert!(!fixture.0.join(".ssh").exists());
    let calls = fs::read_to_string(fixture.0.join("calls")).unwrap();
    assert!(!calls.contains("auth refresh"));
    assert!(!calls.contains("ssh-keygen"));
    assert!(!calls.contains("git@github.com"));
}

#[test]
fn github_failure_preserves_local_status_and_reports_unknown() {
    let fixture = Fixture::new("exit 1");
    let (output, text) = fixture.run();
    assert!(output.status.success());
    assert!(
        text.starts_with("No keys on this Mac\n! Couldn't check GitHub: you're not signed in\n"),
        "{text}"
    );
    assert!(
        text.contains("→ Sign in with gh auth login --web"),
        "{text}"
    );
    assert!(text.contains("Commit signing  off"), "{text}");
}

#[test]
fn missing_scopes_are_unknown_and_never_request_permissions() {
    let fixture = Fixture::new(
        "case \"$*\" in
        'auth status --hostname github.com') printf '%s\\n' 'Logged in to github.com account tester' \"Token scopes: 'repo'\" ;;
        *) exit 99 ;;
        esac",
    );
    let (output, text) = fixture.run();
    assert!(output.status.success());
    assert!(
        text.contains("! Couldn't check your authentication keys on GitHub"),
        "{text}"
    );
    assert!(
        text.contains("→ Allow it with gh auth refresh -h github.com -s admin:public_key"),
        "{text}"
    );
    let calls = fs::read_to_string(fixture.0.join("calls")).unwrap();
    assert!(!calls.contains("gh api"));
    assert!(!calls.contains("auth refresh"));
}

#[test]
fn broken_local_key_exits_unsuccessfully_without_changing_files() {
    let fixture = Fixture::new("exit 1");
    fs::create_dir(fixture.0.join(".ssh")).unwrap();
    let key = fixture.0.join(".ssh/id_ed25519_sk_keymate_github_test");
    fs::write(&key, "broken handle\n").unwrap();
    let (output, text) = fixture.run();
    assert!(!output.status.success());
    assert!(text.contains("test:\n  ✗ Key file"), "{text}");
    assert!(text.contains("missing or invalid"), "{text}");
    assert!(text.contains("✗ 1 problem to fix"), "{text}");
    assert_eq!(fs::read_to_string(&key).unwrap(), "broken handle\n");
    assert!(!fixture.0.join(".ssh/keymate").exists());
}
