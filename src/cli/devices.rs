//! `keymate devices`: the plugged-in security keys and what they support.

use std::process::ExitCode;

use console::style;
use keymate::Result;
use keymate::check::{Check, Mark};
use keymate::devices::{self, Device, PinState};

use super::render::{heading, render_checks};
use super::ui;

pub fn run() -> Result<ExitCode> {
    let devices = ui::spin("Looking for security keys...", devices::list, |_| {
        String::new()
    })?;
    print!("{}", render_devices(&devices));
    Ok(if devices.is_empty() {
        ExitCode::FAILURE
    } else {
        ExitCode::SUCCESS
    })
}

fn render_devices(devices: &[Device]) -> String {
    if devices.is_empty() {
        return heading("Security keys")
            + &render_checks(
                &[Check::new("", Mark::Fail, "No security key connected")
                    .hint("Plug one in, then run `keymate devices` again")],
                "  ",
                0,
            );
    }
    let width = "Resident keys".len() + 2;
    // Each key's name under the heading, then its capabilities with a mark,
    // like the checks in `doctor`; plain facts (USB id, path) line up under
    // them without one.
    let capability = |yes: bool, label: &str, detail: &str| {
        let mark = if yes {
            style("✓").green()
        } else {
            style("!").yellow()
        };
        format!("    {mark} {label:<width$}{detail}")
            .trim_end()
            .to_owned()
            + "\n"
    };
    let fact = |label: &str, value: &str| format!("      {label:<width$}{}\n", style(value).dim());
    let mut keys = Vec::new();
    for device in devices {
        let mut text = format!("  {}\n", device.name);
        match &device.info {
            None => {
                text += &format!(
                    "    {} the key did not report its capabilities\n",
                    style("!").yellow()
                )
            }
            Some(info) => {
                let (pin_ok, pin) = match (info.pin, info.pin_retries) {
                    (PinState::Set, Some(r)) => (true, format!("set, {r} attempts left")),
                    (PinState::Set, None) => (true, "set".to_owned()),
                    (PinState::NotSet, _) => (false, "not set".to_owned()),
                    (PinState::Unsupported, _) => (false, "not supported".to_owned()),
                };
                text += &if info.supports_fido2() {
                    capability(true, "FIDO2", &info.versions.join(", "))
                } else {
                    format!(
                        "    {} {:<width$}not supported\n",
                        style("✗").red(),
                        "FIDO2"
                    )
                };
                text += &capability(pin_ok, "PIN", &pin);
                text += &capability(info.supports_ed25519(), "ed25519-sk", "");
                text += &capability(info.resident_keys, "Resident keys", "");
            }
        }
        text += &fact(
            "USB ID",
            &format!("{:04x}:{:04x}", device.vendor_id, device.product_id),
        );
        text += &fact("Path", &device.path);
        keys.push(text);
    }
    heading("Security keys") + &keys.join("\n")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn renders_devices_and_empty_list() {
        let empty = render_devices(&[]);
        assert!(empty.starts_with("Security keys:\n"), "{empty}");
        assert!(empty.contains("✗ No security key connected"));
        let device = Device {
            path: "ioreg://1".into(),
            vendor_id: 0x1050,
            product_id: 0x0406,
            name: "Yubico YubiKey FIDO+CCID".into(),
            info: None,
        };
        let text = render_devices(&[device]);
        assert!(
            text.starts_with("Security keys:\n  Yubico YubiKey FIDO+CCID\n"),
            "{text}"
        );
        assert!(text.contains("did not report its capabilities"));
        assert!(text.contains("1050:0406"));
    }
}
