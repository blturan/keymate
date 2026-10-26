//! The interactive `keymate signer github` flow: choose which Keymate key
//! signs commits and tags (git signs with one key at a time).

use std::process::ExitCode;
use std::time::Instant;

use keymate::github::enrollment::Enrollment;
use keymate::github::signer::{self, Signer};
use keymate::{Error, Result};

use super::ui;

/// What to sign with, from `--use NAME` or `--off`; asked when absent.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Choice {
    Key(String),
    Off,
}

pub fn github(choice: Option<Choice>) -> ExitCode {
    let started = Instant::now();
    ui::finish(started, run(choice))
}

fn run(choice: Option<Choice>) -> Result<()> {
    let signer = ui::spin("Looking at your keys...", signer::prepare, |_| {
        String::new()
    })?;
    if signer.enrollments.is_empty() {
        return Err(Error::fixable(
            "Keymate hasn't set up a key on this Mac",
            "Set one up with `keymate setup github`",
        ));
    }
    match &signer.current {
        Some(key) => ui::context(&[&format!("Signing with {}", key.short_name())]),
        None => ui::context(&["Signing is off"]),
    }

    let target = match choice {
        Some(Choice::Off) => None,
        Some(Choice::Key(name)) => Some(find(&signer, &name)?),
        None => {
            ui::gap();
            ask(&signer)?
        }
    };

    match &target {
        Some(key) if signer.current.as_ref() == Some(key) => {
            signer.refresh()?;
            ui::info(&format!("Already signing with {}", key.short_name()));
            return Ok(());
        }
        None if signer.current.is_none() => {
            ui::info("Signing is already off");
            return Ok(());
        }
        _ => {}
    }

    ui::gap();
    if let Some(scope) = target.as_ref().and(signer.missing_scope()) {
        ui::grant(scope, || signer.request_scope(scope))?;
    }
    match &target {
        Some(key) => ui::spin_changes("Switching commit signing...", || signer.switch_to(key))?,
        None => {
            ui::spin(
                "Turning off commit signing...",
                || signer.turn_off(),
                |done| done.clone().unwrap_or_default(),
            )?;
        }
    }
    Ok(())
}

/// The enrollment called `name` (the `--name` given at setup).
fn find(signer: &Signer, name: &str) -> Result<Enrollment> {
    signer
        .enrollments
        .iter()
        .find(|e| e.name().as_deref() == Some(name))
        .cloned()
        .ok_or_else(|| {
            let names: Vec<String> = signer
                .enrollments
                .iter()
                .filter_map(Enrollment::name)
                .collect();
            Error::fixable(
                format!("No key is named `{name}`"),
                format!("Choose one of: {}", names.join(", ")),
            )
        })
}

fn ask(signer: &Signer) -> Result<Option<Enrollment>> {
    // The key that signs now gets a check mark.
    let names: Vec<String> = signer
        .enrollments
        .iter()
        .map(|e| {
            let name = e.short_name();
            match signer.current.as_ref() == Some(e) {
                true => format!("{name} {}", ui::check()),
                false => name,
            }
        })
        .collect();
    let hints: Vec<String> = signer
        .enrollments
        .iter()
        .map(|e| e.device.clone().unwrap_or_default())
        .collect();
    let mut items: Vec<(Option<Enrollment>, &str, &str)> = signer
        .enrollments
        .iter()
        .zip(names.iter().zip(&hints))
        .map(|(e, (name, hint))| (Some(e.clone()), name.as_str(), hint.as_str()))
        .collect();
    items.push((None, "Off", "don't sign commits"));
    ui::select("Sign commits with", &items)
}
