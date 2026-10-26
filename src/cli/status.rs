//! `keymate status github`: the keys Keymate set up, read-only.

use std::process::ExitCode;

use console::style;
use keymate::Result;
use keymate::github::status::{self, Report};

use super::render::{first_line, heading, label_width, render_checks, summary};
use super::ui;

pub fn github() -> Result<ExitCode> {
    let report = ui::spin("Checking your keys on GitHub...", status::run, |_| {
        String::new()
    })?;
    print!("{}", render_status(&report));
    Ok(if report.ready() {
        ExitCode::SUCCESS
    } else {
        ExitCode::FAILURE
    })
}

fn render_status(report: &Report) -> String {
    let keys = match report.keys.len() {
        0 => "No keys on this Mac".to_owned(),
        1 => "1 key on this Mac".to_owned(),
        n => format!("{n} keys on this Mac"),
    };
    let mut parts = vec![keys];
    parts.extend(
        report
            .account
            .iter()
            .map(|account| format!("{account} on GitHub")),
    );
    let mut out = first_line(&parts) + &render_checks(&report.notes, "", 0);

    let width = label_width(
        report
            .keys
            .iter()
            .flat_map(|key| &key.checks)
            .chain(&report.this_mac),
    );
    let mut sections: Vec<String> = report
        .keys
        .iter()
        .map(|key| {
            let name = key
                .enrollment
                .name()
                .unwrap_or_else(|| key.enrollment.file_name());
            heading(&name) + &render_checks(&key.checks, "  ", width)
        })
        .collect();
    if !report.github_only.is_empty() {
        sections.push(heading("On GitHub only") + &render_checks(&report.github_only, "  ", 0));
    }
    if !report.this_mac.is_empty() {
        sections.push(heading("This Mac") + &render_checks(&report.this_mac, "  ", width));
    }
    if !sections.is_empty() {
        out += "\n";
        out += &sections.join("\n");
    }

    let next = match report.keys.is_empty() {
        true => format!("Next: {}", style("keymate setup github").cyan()),
        false => String::new(),
    };
    match summary(report.problems(), report.warnings(), &next) {
        line if line.is_empty() => out,
        line => out + "\n" + &line,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use keymate::check::{Check, Mark};
    use keymate::github::enrollment::Enrollment;
    use keymate::github::status::KeyReport;

    #[test]
    fn status_without_keys_suggests_setup() {
        let text = render_status(&Report {
            account: Some("blturan".into()),
            ..Default::default()
        });
        assert!(
            text.starts_with("No keys on this Mac · blturan on GitHub\n"),
            "{text}"
        );
        assert!(text.ends_with("\n→ Next: keymate setup github\n"), "{text}");
    }

    #[test]
    fn status_shows_each_key_under_its_own_heading() {
        let row = |label, mark, detail: &str| Check::new(label, mark, detail);
        let key = |name: &str| KeyReport {
            enrollment: Enrollment {
                key: format!("/home/test/.ssh/id_ed25519_sk_keymate_github_{name}").into(),
                sk: None,
                public_key: None,
                device: None,
                created: None,
            },
            checks: vec![
                row("GitHub", Mark::Pass, &format!("keymate_auth_{name}")),
                row("SSH", Mark::Pass, "used for github.com"),
                row(
                    "File",
                    Mark::Info,
                    &format!("~/.ssh/id_ed25519_sk_keymate_github_{name}"),
                ),
            ],
        };
        let text = render_status(&Report {
            account: Some("blturan".into()),
            keys: vec![key("primary"), key("test")],
            this_mac: vec![
                row("Security key", Mark::Info, "YubiKey, set up as test"),
                row("Commit signing", Mark::Info, "with primary"),
            ],
            ..Default::default()
        });
        assert!(
            text.starts_with("2 keys on this Mac · blturan on GitHub\n\nprimary:\n"),
            "{text}"
        );
        let (primary, test, mac) = (
            text.find("primary:").unwrap(),
            text.find("test:").unwrap(),
            text.find("This Mac:").unwrap(),
        );
        assert!(primary < test && test < mac);
        assert!(text[primary..test].contains("✓ GitHub          keymate_auth_primary"));
        assert!(text[test..mac].contains("keymate_auth_test"));
        assert!(text.contains("    File            ~/.ssh/id_ed25519_sk_keymate_github_primary"));
        // All good: no last line.
        assert!(text.ends_with("with primary\n"), "{text}");
    }
}
