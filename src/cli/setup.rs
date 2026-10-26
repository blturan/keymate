//! The interactive `keymate setup github` flow, laid out exactly like nuke:
//! what Keymate found, the questions, the plan, then the changes.

use std::process::ExitCode;
use std::time::Instant;

use keymate::github::SSH_SETTINGS_URL;
use keymate::github::api::{KeyKind, describe_keys};
use keymate::github::enrollment::{self, Detection, Enrollment};
use keymate::github::setup::{
    self, AccessReport, Action, Existing, KeyEvent, Options, OrgAccess, Setup, Storage,
    Verification,
};
use keymate::{Error, Result};

use super::ui::{self, PlanLine};

/// Choices given on the command line; anything missing is asked for.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct Preset {
    pub name: Option<String>,
    pub storage: Option<Storage>,
    pub verification: Option<Verification>,
    pub signing: Option<bool>,
}

pub fn github(preset: Preset) -> ExitCode {
    let started = Instant::now();
    ui::finish(started, run(preset))
}

fn run(preset: Preset) -> Result<()> {
    ui::require_terminal("setup github")?;
    let mut setup = ui::spin(
        "Checking your tools, GitHub and your security key...",
        setup::prepare,
        |_| String::new(),
    )?;
    ui::context(&[&setup.device.name, &format!("{} on GitHub", setup.account)]);

    ui::gap();
    let Some((action, signing)) = choose_action(&setup)? else {
        return Err(Error::Cancelled);
    };
    let preset = Preset {
        signing: preset.signing.or(signing),
        ..preset
    };
    setup.select(action);
    if *setup.action() == Action::Restore {
        look_on_key(&mut setup)?;
    }
    if setup.needs_name() {
        choose_name(&mut setup, preset.name.as_deref())?;
    } else if preset.name.is_some() {
        ui::warning("This key is kept as it is, so `--name` isn't used");
    }
    let existing = match setup.reusing() {
        true => ui::spin(
            "Checking what's already set up...",
            || Ok(setup.existing()),
            |_| String::new(),
        )?,
        false => Existing::default(),
    };
    let options = choose_options(&setup, &preset, &existing)?;
    setup.check(&options)?;
    let delete_old_credential = choose_old_credential(&setup)?;
    let scopes = setup.missing_scopes(&options);
    let mut lines = plan(&setup, &options, &existing, !scopes.is_empty());
    if delete_old_credential.is_some() {
        lines.push(PlanLine::Remove(format!(
            "Then delete the old credential from your {}",
            setup.device.noun()
        )));
    }
    ui::approve(&lines, Some(true))?;

    ui::gap();
    for scope in scopes {
        ui::grant(scope, || setup.request_scope(scope))?;
    }
    apply(&mut setup, &options)?;
    if let Some(old) = delete_old_credential {
        let prompt = format!(
            "Enter your {}'s PIN to delete the old credential",
            setup.device.noun()
        );
        ui::success(&ui::with_pin(&prompt, |pin| {
            enrollment::delete_resident(&setup.device, &old, pin)
        })?);
    }
    Ok(())
}

/// Keep, replace, add, or restore, based on what Keymate recognized, and
/// whether that already decided signing. `None` means cancel.
fn choose_action(setup: &Setup) -> Result<Option<(Action, Option<bool>)>> {
    let without_signing = |choice: Option<Action>| choice.map(|action| (action, None));
    match &setup.detection {
        Detection::ThisKey(enrollment) if setup.signs_with(enrollment) => {
            let choice = ui::select(
                &format!("This key is already set up as {}", enrollment.short_name()),
                &[
                    (
                        Some(Action::Keep(enrollment.clone())),
                        "Keep",
                        "check and test it",
                    ),
                    (
                        Some(Action::Replace(enrollment.clone())),
                        "Replace",
                        "with a new credential",
                    ),
                    (None, "Cancel", ""),
                ],
            )?;
            return Ok(without_signing(choice));
        }
        // Set up for SSH only: offer to add commit signing first.
        Detection::ThisKey(enrollment) => {
            let keep = Action::Keep(enrollment.clone());
            return ui::select(
                &format!(
                    "This key is set up as {}, for SSH only",
                    enrollment.short_name()
                ),
                &[
                    (Some((keep.clone(), Some(true))), "Also sign commits", ""),
                    (Some((keep, Some(false))), "Keep", "check and test it"),
                    (
                        Some((Action::Replace(enrollment.clone()), None)),
                        "Replace",
                        "with a new credential",
                    ),
                    (None, "Cancel", ""),
                ],
            );
        }
        Detection::Unknown(candidates) => {
            let names: Vec<String> = candidates.iter().map(Enrollment::short_name).collect();
            let hints: Vec<String> = candidates
                .iter()
                .map(|e| match (&e.device, &e.created) {
                    (Some(device), Some(date)) => format!("{device}, set up {date}"),
                    (Some(device), None) => device.clone(),
                    _ => String::new(),
                })
                .collect();
            let mut items: Vec<(Option<Action>, &str, &str)> = candidates
                .iter()
                .zip(names.iter().zip(&hints))
                .map(|(e, (name, hint))| {
                    (Some(Action::Keep(e.clone())), name.as_str(), hint.as_str())
                })
                .collect();
            items.push((Some(Action::Add), "Another key", "set it up too"));
            items.push((None, "Cancel", ""));
            return Ok(without_signing(ui::select("Which key is this?", &items)?));
        }
        Detection::OtherKeys | Detection::NoEnrollments => {}
    }

    if !setup.can_restore() {
        return Ok(Some((Action::Add, None)));
    }
    let restore = match setup.github_only.is_empty() {
        false => format!(
            "{} · from the key, needs PIN",
            describe_keys(&setup.github_only)
        ),
        true => format!(
            "if your {} already holds one · needs PIN",
            setup.device.noun()
        ),
    };
    let choice = ui::select(
        "Set up this key",
        &[
            (Some(Action::Add), "New credential", "recommended"),
            (Some(Action::Restore), "Restore", restore.as_str()),
            (None, "Cancel", ""),
        ],
    )?;
    Ok(without_signing(choice))
}

/// Restore starts by looking on the key, so the person hears right away
/// whether there is anything to restore. With nothing there, offer a new
/// credential instead.
fn look_on_key(setup: &mut Setup) -> Result<()> {
    let noun = setup.device.noun();
    let prompt = format!("Enter your {noun}'s PIN to look for a Keymate credential on it");
    let names = ui::with_pin(&prompt, |pin| setup.look_on_key(pin))?;
    let label = |name: &Option<String>| match name {
        Some(name) => name.clone(),
        None => "unnamed".to_owned(),
    };
    match names.len() {
        0 => {}
        1 => {
            setup.pick_found(0);
            ui::success(&match &names[0] {
                Some(name) => format!("Found {name} on your {noun}"),
                None => format!("Found a Keymate credential on your {noun}"),
            });
            return Ok(());
        }
        count => {
            ui::success(&format!("Found {count} Keymate credentials on your {noun}"));
            let labels: Vec<String> = names.iter().map(label).collect();
            let items: Vec<(usize, &str, &str)> = labels
                .iter()
                .enumerate()
                .map(|(index, label)| (index, label.as_str(), ""))
                .collect();
            let index = ui::select("Restore which one?", &items)?;
            setup.pick_found(index);
            return Ok(());
        }
    }
    ui::warning(&format!(
        "Your {noun} holds no Keymate credential, so there's nothing to restore"
    ));
    ui::gap();
    match ui::select(
        "Set up this key",
        &[
            (Some(Action::Add), "New credential", ""),
            (None, "Cancel", ""),
        ],
    )? {
        Some(action) => {
            setup.select(action);
            Ok(())
        }
        None => Err(Error::Cancelled),
    }
}

/// When a resident credential is replaced by a non-resident one, the old one
/// stays on the security key; ask up front whether to delete it afterwards.
fn choose_old_credential(setup: &Setup) -> Result<Option<Enrollment>> {
    let Action::Replace(old) = setup.action() else {
        return Ok(None);
    };
    if !old.sk.as_ref().is_some_and(|k| k.resident()) {
        return Ok(None);
    }
    let prompt = format!(
        "Also delete the old credential from your {}?",
        setup.device.noun()
    );
    Ok(ui::confirm(&prompt, None)?.then(|| old.clone()))
}

/// Use `--name`, the name a restored credential carries (or its GitHub
/// label), or ask with a suggestion.
fn choose_name(setup: &mut Setup, given: Option<&str>) -> Result<()> {
    const PROMPT: &str = "Name this key";
    if given.is_none() && *setup.action() == Action::Restore {
        let name = setup
            .found_name()
            .map(str::to_owned)
            .or_else(|| unique_restore_name(setup.found_titles()));
        if let Some(name) = name.filter(|name| setup.name_check()(name).is_ok()) {
            setup.set_name(&name).map_err(Error::Failed)?;
            ui::given(PROMPT, &name);
            return Ok(());
        }
    }
    let name = match given {
        Some(name) => name.to_owned(),
        None => ui::input(PROMPT, setup.name(), setup.name_check())?,
    };
    setup.set_name(&name).map_err(Error::Failed)
}

/// Authentication and signing titles may share a label. This is only a naming
/// hint; registration still matches the public key after restoration.
fn unique_restore_name<'a>(titles: impl IntoIterator<Item = &'a str>) -> Option<String> {
    let mut name: Option<&str> = None;
    for title in titles {
        let candidate = title
            .strip_prefix("keymate_auth_")
            .or_else(|| title.strip_prefix("keymate_sign_"))?;
        if candidate.is_empty() || name.is_some_and(|name| name != candidate) {
            return None;
        }
        name = Some(candidate);
    }
    name.map(str::to_owned)
}

fn choose_options(setup: &Setup, preset: &Preset, existing: &Existing) -> Result<Options> {
    // Storage and verification are fixed once a credential exists.
    let fixed = match setup.action() {
        Action::Keep(enrollment) => Some(options_of(enrollment)),
        Action::Restore => Some((Storage::Resident, Verification::Touch)),
        _ => None,
    };
    let (storage, verification) = match fixed {
        Some(fixed) => fixed,
        None => (ask_storage(preset)?, ask_verification(preset)?),
    };
    let signing = match preset.signing {
        Some(signing) => signing,
        // Already signing with this key: nothing to ask.
        None if existing.signing || existing.registration(KeyKind::Signing).is_some() => true,
        None => ui::select(
            "Sign commits too?",
            &[
                (true, "Yes", "Verified badge · touch per commit"),
                (false, "No", "access only"),
            ],
        )?,
    };
    // GitHub verifies commits from every signing key it knows, but git signs
    // with one key at a time: another key that signs now keeps doing so.
    let git_signs = signing && (existing.signing || setup.other_signer().is_none());
    Ok(Options {
        storage,
        verification,
        signing,
        git_signs,
    })
}

fn options_of(enrollment: &Enrollment) -> (Storage, Verification) {
    let sk = enrollment.sk.as_ref();
    let storage = if sk.is_some_and(|k| k.resident()) {
        Storage::Resident
    } else {
        Storage::NonResident
    };
    let verification = if sk.is_some_and(|k| k.verify_required()) {
        Verification::PinAndTouch
    } else {
        Verification::Touch
    };
    (storage, verification)
}

fn ask_storage(preset: &Preset) -> Result<Storage> {
    match preset.storage {
        Some(storage) => Ok(storage),
        None => ui::select(
            "Store the credential",
            &[
                (
                    Storage::Resident,
                    "On the key",
                    "resident · portable, uses a slot",
                ),
                (Storage::NonResident, "On this Mac", "recommended"),
            ],
        ),
    }
}

fn ask_verification(preset: &Preset) -> Result<Verification> {
    match preset.verification {
        Some(verification) => Ok(verification),
        None => ui::select(
            "Each push and pull needs",
            &[
                (Verification::Touch, "Touch", "recommended"),
                (Verification::PinAndTouch, "PIN + touch", "stricter"),
            ],
        ),
    }
}

/// The plan as a diff: `+` for changes, `=` for what is already in place,
/// `-` for removals.
fn plan(setup: &Setup, options: &Options, existing: &Existing, grant: bool) -> Vec<PlanLine> {
    let mut lines = Vec::new();
    if grant {
        lines.push(PlanLine::Add(ui::GRANT.to_owned()));
    }
    let noun = setup.device.noun();
    if setup.needs_new_pin(options) {
        lines.push(PlanLine::Add(format!("Set a PIN on your {noun}")));
    }
    match setup.action() {
        Action::Keep(enrollment) => {
            lines.push(PlanLine::InPlace(format!("Keep {}", enrollment.display())))
        }
        Action::Restore => lines.push(PlanLine::Add(format!(
            "Save the credential from your {noun} as {}",
            setup.key_display()
        ))),
        Action::Add | Action::Replace(_) => {
            lines.push(PlanLine::Add(format!("Create {}", setup.key_display())))
        }
    }
    let mut kinds = vec![(KeyKind::Authentication, setup.auth_title())];
    if options.signing {
        kinds.push((KeyKind::Signing, setup.sign_title()));
    }
    let (present, missing): (Vec<_>, Vec<_>) = kinds
        .into_iter()
        .partition(|(kind, _)| existing.registration(*kind).is_some());
    if !present.is_empty() {
        let titles: Vec<&str> = present
            .iter()
            .filter_map(|(kind, _)| existing.registration(*kind))
            .map(|k| k.title.as_str())
            .collect();
        lines.push(PlanLine::InPlace(format!(
            "Already on GitHub as {}",
            titles.join(" and ")
        )));
    }
    if *setup.action() == Action::Restore {
        lines.push(PlanLine::Add(
            restore_registration_plan(options.signing).to_owned(),
        ));
    } else if !missing.is_empty() {
        let titles: Vec<&str> = missing.iter().map(|(_, title)| title.as_str()).collect();
        lines.push(PlanLine::Add(format!(
            "Add it to GitHub as {}",
            titles.join(" and ")
        )));
    }
    lines.push(PlanLine::Add("Test SSH access to github.com".to_owned()));
    lines.push(match existing.ssh {
        true => PlanLine::InPlace("Already used for github.com".to_owned()),
        false => PlanLine::Add("Use it for github.com".to_owned()),
    });
    let other_signer = setup.other_signer();
    match (options.signing, existing.signing, &other_signer) {
        (true, true, _) => lines.push(PlanLine::InPlace(
            "Already signs commits and tags".to_owned(),
        )),
        (true, false, Some(other)) => lines.push(PlanLine::InPlace(format!(
            "git on this Mac keeps signing with {} (switch with `keymate signer github`)",
            other.short_name()
        ))),
        (true, false, None) => {
            lines.push(PlanLine::Add("Sign commits and tags with it".to_owned()))
        }
        (false, _, Some(other)) => lines.push(PlanLine::InPlace(format!(
            "Signing stays with {}",
            other.short_name()
        ))),
        (false, _, None) => {}
    }
    match setup.action() {
        Action::Replace(old) => lines.push(PlanLine::Remove(format!(
            "Then remove {} from GitHub and this Mac",
            old.short_name()
        ))),
        Action::Add if !matches!(setup.detection, Detection::NoEnrollments) => {
            lines.push(PlanLine::InPlace("Your other keys keep working".to_owned()))
        }
        _ => {}
    }
    lines
}

/// A restored public key is not known until after the PIN prompt, so its
/// GitHub registrations cannot be classified as present or missing yet.
fn restore_registration_plan(signing: bool) -> &'static str {
    if signing {
        "Add it to GitHub for SSH and signing, unless it's already there"
    } else {
        "Add it to GitHub, unless it's already there"
    }
}

fn apply(setup: &mut Setup, options: &Options) -> Result<()> {
    let noun = setup.device.noun();
    if setup.needs_new_pin(options) {
        let minimum = setup
            .device
            .info
            .as_ref()
            .and_then(|i| i.min_pin_length)
            .unwrap_or(4);
        ui::step(&format!(
            "Your {noun} needs a PIN of at least {minimum} characters"
        ));
        ui::hint("Keep it safe: after too many wrong tries the key locks and must be reset");
        let pin = ui::new_pin(noun, minimum as usize)?;
        ui::success(&setup.set_pin(&pin)?);
    }

    if *setup.action() == Action::Restore {
        ui::success(&setup.restore()?);
    }

    if matches!(setup.action(), Action::Add | Action::Replace(_)) {
        create_key(setup, options)?;
    }

    ui::spin_changes("Adding the key to GitHub...", || setup.register(options))?;

    let tested =
        |report: &AccessReport| format!("Tested SSH access to github.com as {}", report.account);
    let target = ui::spin(
        "Preparing the SSH test...",
        || setup.prepare_test(),
        |_| String::new(),
    )?;
    let report = loop {
        let result = if options.verification == Verification::PinAndTouch {
            ui::step(&format!("Enter your {noun}'s PIN, then touch it"));
            setup
                .test(&target, || {})
                .inspect(|report| ui::success(&tested(report)))
        } else {
            ui::touch(
                noun,
                |touched| {
                    setup.test(&target, || {
                        touched.proceed("Checking organization access...")
                    })
                },
                tested,
            )
        };
        match result {
            Err(Error::NotConfirmed) => {
                ui::warning(&match options.verification {
                    Verification::PinAndTouch => format!(
                        "Your {noun} didn't confirm: the PIN was wrong, or it wasn't touched in time"
                    ),
                    Verification::Touch => format!("Your {noun} wasn't touched in time"),
                });
                if !ui::confirm("Try again?", Some(true))? {
                    return Err(Error::Cancelled);
                }
            }
            result => break result?,
        }
    };
    report_organizations(setup, &report);
    setup.put_in_place()?;

    ui::spin_changes("Configuring SSH...", || setup.configure_ssh())?;
    if !setup.ssh_config_effective()? {
        ui::warning(
            "Another setting in your SSH config wins, so `ssh github.com` may not use this key",
        );
    }

    if options.git_signs {
        ui::spin_changes("Setting up commit signing...", || setup.configure_signing())?;
        if !setup.signing_effective()? {
            ui::warning("Other settings in ~/.gitconfig override Keymate's signing settings");
        }
    } else {
        // git verifies commits from every Keymate key, this one included.
        setup.refresh_allowed_signers()?;
    }

    if matches!(setup.action(), Action::Replace(_)) {
        ui::spin_changes("Removing the old key...", || setup.retire_replaced(options))?;
    }
    Ok(())
}

/// Create the key, asking for the touch exactly when `ssh-keygen` waits for
/// it. With a PIN, `ssh-keygen` asks for that first on the terminal.
fn create_key(setup: &Setup, options: &Options) -> Result<()> {
    let noun = setup.device.noun();
    if setup.create_asks_pin(options) {
        ui::step(&format!("Enter your {noun}'s PIN to create the key"));
    }
    let prompt = ui::TouchPrompt::new(noun);
    setup.create_key(options, |event| match event {
        KeyEvent::TouchNeeded => prompt.start(),
        KeyEvent::PinRejected => {
            prompt.stop();
            ui::warning("The PIN was wrong, or the key wasn't touched in time");
            ui::step(&format!(
                "Enter the PIN again, then touch your {noun} when it blinks"
            ));
        }
        KeyEvent::AlreadyOnKey => {
            prompt.stop();
            ui::warning(&format!(
                "Your {noun} already holds a Keymate credential for {} from an earlier setup",
                setup.account
            ));
            ui::step("Type y and press Enter to replace it, or n to stop");
        }
    })?;
    prompt.stop();
    ui::success(&format!("Created {}", setup.key_display()));
    Ok(())
}

/// Organizations whose SAML single sign-on refused the key need it
/// authorized in the browser; GitHub has no API for that.
fn report_organizations(setup: &Setup, report: &AccessReport) {
    let with = |access| -> Vec<&str> {
        report
            .organizations
            .iter()
            .filter(|(_, a)| *a == access)
            .map(|(org, _)| org.as_str())
            .collect()
    };
    let (works, pending, unknown) = (
        with(OrgAccess::Works),
        with(OrgAccess::SsoPending),
        with(OrgAccess::Unknown),
    );
    if !works.is_empty() {
        let count = works.len();
        ui::success(&format!(
            "Checked access to {count} organization{}",
            if count == 1 { "" } else { "s" }
        ));
    }
    let authorize = format!(
        "On {SSH_SETTINGS_URL}, click Configure SSO next to {} and authorize it",
        setup.auth_title()
    );
    if !pending.is_empty() {
        ui::warning(&format!(
            "Single sign-on hasn't authorized this key yet for {}",
            pending.join(", ")
        ));
        ui::hint(&authorize);
    } else if !unknown.is_empty() {
        ui::warning("Organizations with SAML single sign-on may need to authorize this key");
        ui::hint(&authorize);
    }
}

#[cfg(test)]
mod tests {
    use super::{restore_registration_plan, unique_restore_name};

    #[test]
    fn restore_reuses_a_unique_github_label() {
        assert_eq!(
            unique_restore_name(["keymate_auth_test"]),
            Some("test".to_owned())
        );
        assert_eq!(
            unique_restore_name(["keymate_auth_test", "keymate_sign_test"]),
            Some("test".to_owned())
        );
    }

    #[test]
    fn restore_asks_when_github_labels_are_ambiguous_or_unknown() {
        assert_eq!(unique_restore_name([]), None);
        assert_eq!(
            unique_restore_name(["keymate_auth_primary", "keymate_auth_backup"]),
            None
        );
        assert_eq!(unique_restore_name(["Keymate: old key on Mac"]), None);
        assert_eq!(unique_restore_name(["keymate_auth_"]), None);
    }

    #[test]
    fn restore_plan_adds_only_what_is_missing() {
        let line = restore_registration_plan(false);
        assert!(line.contains("unless it's already there"));
        assert!(!line.contains("signing"));
    }

    #[test]
    fn restore_plan_includes_signing_when_requested() {
        let line = restore_registration_plan(true);
        assert!(line.contains("SSH and signing"));
        assert!(line.contains("unless it's already there"));
    }
}
