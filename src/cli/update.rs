//! `keymate update` (or `upgrade`): Homebrew upgrades Keymate if it installed
//! it; otherwise Keymate replaces itself with the release's binary.

use std::process::ExitCode;
use std::time::Instant;

use keymate::update::{self, CURRENT, Install};
use keymate::{Error, Result};

use super::ui;

pub fn run(version: Option<String>) -> ExitCode {
    let started = Instant::now();
    ui::finish(started, update(version))
}

fn update(version: Option<String>) -> Result<()> {
    let exe = match update::install()? {
        Install::Homebrew(brew) => {
            if version.is_some() {
                return Err(Error::Failed(
                    "Homebrew installed Keymate, so it can only update to the latest version"
                        .into(),
                ));
            }
            ui::step("Homebrew installed Keymate, so Homebrew updates it");
            update::brew_upgrade(&brew)?;
            return Ok(());
        }
        Install::Binary(exe) => exe,
    };

    let target = match version {
        Some(version) => version.trim_start_matches('v').to_owned(),
        None => {
            let latest = ui::spin("Checking for a new version...", update::latest, |_| {
                String::new()
            })?;
            if !update::is_newer(&latest, CURRENT) {
                ui::context(&[&format!("keymate {CURRENT} is the latest version")]);
                return Ok(());
            }
            ui::context(&[
                &format!("keymate {CURRENT}"),
                &format!("{latest} is available"),
            ]);
            latest
        }
    };
    // No spinner: sudo may need to ask for a password if the binary lives
    // somewhere only root can write.
    ui::gap();
    ui::step(&format!("Downloading keymate {target}"));
    ui::success(&update::replace(&target, &exe)?);
    Ok(())
}
