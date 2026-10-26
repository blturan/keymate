//! The interactive `keymate nuke github` flow, laid out exactly like setup:
//! what Keymate found, the questions, the plan, then the changes.

use std::process::ExitCode;
use std::time::Instant;

use keymate::Result;
use keymate::devices::Credential;
use keymate::github::SSH_SETTINGS_URL;
use keymate::github::api::describe_keys;
use keymate::github::enrollment::Enrollment;
use keymate::github::nuke::{self, Nuke, Plan};

use super::ui::{self, PlanLine};

pub fn github() -> ExitCode {
    let started = Instant::now();
    ui::finish(started, run())
}

fn run() -> Result<()> {
    ui::require_terminal("nuke github")?;
    let nuke = ui::spin("Looking for what Keymate set up...", nuke::prepare, |_| {
        String::new()
    })?;
    let keys = match nuke.enrollments.len() {
        0 => "No keys on this Mac".to_owned(),
        1 => "1 key on this Mac".to_owned(),
        n => format!("{n} keys on this Mac"),
    };
    let account = nuke.account().map(|account| format!("{account} on GitHub"));
    let parts: Vec<&str> = std::iter::once(keys.as_str())
        .chain(account.as_deref())
        .collect();
    match nuke.enrollments.is_empty() {
        true => ui::warning(&parts.join(" · ")),
        false => ui::context(&parts),
    }
    if let Some(note) = &nuke.github_note {
        ui::warning(&format!("Couldn't check GitHub: {note}"));
        ui::hint(&format!("Review your keys at {SSH_SETTINGS_URL}"));
    }
    // The plugged-in key may still hold credentials whose key files are gone,
    // so it's worth a look even when nothing else is left.
    let nothing_else = !nuke.found_anything() && nuke.github_only.is_empty();
    if nothing_else {
        ui::warning("Nothing of Keymate's is left on this Mac or GitHub");
    }
    if nothing_else && !nuke.key_may_hold_credentials() {
        unplugged_hint(&nuke);
        return Ok(());
    }

    ui::gap();
    let (selected, github_only) = match nothing_else {
        true => (Vec::new(), false),
        false => (choose_keys(&nuke)?, choose_github_only(&nuke)?),
    };
    let plan = nuke.plan(&selected, github_only);
    let clean_key = choose_clean_key(&nuke, nothing_else)?;
    if nothing_else && !clean_key {
        return Ok(());
    }
    let scopes = nuke.missing_scopes(&plan);
    ui::approve(&lines(&nuke, &plan, clean_key, !scopes.is_empty()), None)?;

    ui::gap();
    for scope in scopes {
        ui::grant(scope, || nuke.request_scope(scope))?;
    }
    let done = |result: &Option<String>| result.clone().unwrap_or_default();
    ui::spin(
        "Removing from GitHub...",
        || nuke.remove_from_github(&plan),
        done,
    )?;
    let signing_off = ui::spin(
        "Turning off commit signing...",
        || nuke.turn_off_signing(&plan),
        done,
    )?;
    if signing_off.is_some() && !plan.everything {
        ui::hint("Sign with another key using `keymate signer github`");
    }
    ui::spin("Deleting key files...", || nuke.delete_keys(&plan), done)?;
    ui::spin("Cleaning up SSH settings...", || nuke.clean_up(&plan), done)?;
    let mut deleted = Vec::new();
    if let Some(device) = nuke.device().filter(|_| clean_key) {
        let noun = device.noun();
        let prompt = format!("Enter your {noun}'s PIN to delete Keymate's credentials");
        deleted = ui::with_pin(&prompt, |pin| nuke.delete_from_key(&plan, pin))?;
        match deleted.is_empty() {
            true => ui::success(&format!("Your {noun} holds no Keymate credentials")),
            false => {
                let names: Vec<String> = deleted.iter().map(nuke::credential_label).collect();
                ui::success(&format!("Deleted {} from your {noun}", names.join(" and ")));
            }
        }
    }
    resident_elsewhere(&nuke, &plan, &deleted);
    Ok(())
}

/// Without a security key plugged in, Keymate can't see or delete the
/// credentials stored on one, so say how to.
fn unplugged_hint(nuke: &Nuke) {
    if nuke.device().is_none() {
        ui::hint(
            "To delete Keymate's credentials from your security key, plug it in and run `keymate nuke` again",
        );
    }
}

/// Which enrollments to remove.
fn choose_keys(nuke: &Nuke) -> Result<Vec<Enrollment>> {
    let all = &nuke.enrollments;
    if all.len() <= 1 {
        return Ok(all.clone());
    }
    let everything = format!("{} keys", all.len());
    if let Some(connected) = &nuke.connected {
        let name = connected.short_name();
        return ui::select(
            "Remove which keys?",
            &[
                (vec![connected.clone()], "This key", name.as_str()),
                (all.clone(), "All", everything.as_str()),
            ],
        );
    }
    let names: Vec<String> = all.iter().map(Enrollment::short_name).collect();
    let hints: Vec<String> = all
        .iter()
        .map(|e| e.device.clone().unwrap_or_default())
        .collect();
    let mut items: Vec<(Vec<Enrollment>, &str, &str)> = all
        .iter()
        .zip(names.iter().zip(&hints))
        .map(|(e, (name, hint))| (vec![e.clone()], name.as_str(), hint.as_str()))
        .collect();
    items.push((all.clone(), "All", everything.as_str()));
    ui::select("Remove which keys?", &items)
}

/// Keymate keys on GitHub without a key file here may be used by another
/// computer, so they are only removed when the person says so.
fn choose_github_only(nuke: &Nuke) -> Result<bool> {
    if nuke.github_only.is_empty() {
        return Ok(false);
    }
    let prompt = format!("GitHub also has {}", describe_keys(&nuke.github_only));
    ui::select(
        &prompt,
        &[
            (false, "Keep them", "another computer may use them"),
            (true, "Remove them", ""),
        ],
    )
}

/// Credentials stored on a security key outlive its key files. When the
/// plugged-in key may hold Keymate's, ask up front whether to delete them
/// too; only the PIN shows what's there.
fn choose_clean_key(nuke: &Nuke, nothing_else: bool) -> Result<bool> {
    let Some(device) = nuke.device().filter(|_| nuke.key_may_hold_credentials()) else {
        return Ok(false);
    };
    let noun = device.noun();
    let prompt = match nothing_else {
        true => format!("Look on your {noun} for Keymate credentials and delete them?"),
        false => format!("Also delete Keymate's credentials from your {noun}?"),
    };
    ui::confirm(&prompt, None)
}

fn lines(nuke: &Nuke, plan: &Plan, clean_key: bool, grant: bool) -> Vec<PlanLine> {
    let mut lines = Vec::new();
    if grant {
        lines.push(PlanLine::Add(ui::GRANT.to_owned()));
    }
    if !plan.registrations.is_empty() {
        lines.push(PlanLine::Remove(format!(
            "Remove {} from GitHub",
            describe_keys(&plan.registrations)
        )));
    }
    if plan.signing {
        lines.push(PlanLine::Remove("Turn off commit signing".to_owned()));
    }
    for enrollment in &plan.enrollments {
        lines.push(PlanLine::Remove(format!("Delete {}", enrollment.display())));
    }
    if let Some(device) = nuke.device().filter(|_| clean_key) {
        lines.push(PlanLine::Remove(format!(
            "Delete Keymate's credentials from your {}",
            device.noun()
        )));
    }
    if plan.everything {
        if let Some((todo, _)) = plan.clean_up() {
            lines.push(PlanLine::Remove(todo));
        }
    } else {
        lines.push(PlanLine::InPlace("Your other keys keep working".to_owned()));
    }
    lines
}

/// Credentials stored on a key that isn't plugged in (or wasn't cleaned)
/// stay there; name them, and say how to delete them.
fn resident_elsewhere(nuke: &Nuke, plan: &Plan, deleted: &[Credential]) {
    let elsewhere: Vec<String> = plan
        .enrollments
        .iter()
        .filter(|e| e.sk.as_ref().is_some_and(|k| k.resident()))
        .filter(|e| {
            let handle = e.sk.as_ref().map(|k| k.key_handle.as_slice());
            !deleted.iter().any(|c| Some(c.id.as_slice()) == handle)
        })
        .map(Enrollment::short_name)
        .collect();
    if !elsewhere.is_empty() {
        let (names, verb) = match elsewhere.len() {
            1 => (elsewhere[0].clone(), "is"),
            _ => (elsewhere.join(" and "), "are"),
        };
        ui::warning(&format!("{names} {verb} still stored on its security key"));
    }
    // Without a key plugged in, Keymate can't see what's stored on one.
    if !elsewhere.is_empty() || nuke.device().is_none() {
        ui::hint(
            "To delete Keymate's credentials from your security key, plug it in and run `keymate nuke` again",
        );
    }
}
