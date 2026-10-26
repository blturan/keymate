//! Read-only discovery of connected FIDO security keys through libfido2's
//! `fido2-token`. Listing and `getInfo` need no PIN and no touch.

use std::path::Path;

use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use std::time::Duration;

use crate::process;
use crate::tools::{find_on_path, sanitize};
use crate::{Error, Result};

const TIMEOUT: Duration = Duration::from_secs(10);

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Device {
    /// libfido2 device path, e.g. `ioreg://4295204009` on macOS.
    pub path: String,
    pub vendor_id: u16,
    pub product_id: u16,
    pub name: String,
    /// `None` when the key did not answer an info request.
    pub info: Option<DeviceInfo>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct DeviceInfo {
    /// Protocol versions such as `U2F_V2` and `FIDO_2_0`.
    pub versions: Vec<String>,
    /// COSE algorithm names such as `es256` and `eddsa`.
    pub algorithms: Vec<String>,
    pub pin: PinState,
    pub pin_retries: Option<u32>,
    /// Shortest PIN the key accepts, when it reports one.
    pub min_pin_length: Option<u32>,
    pub resident_keys: bool,
    /// Whether the key creates non-resident credentials without its PIN even
    /// when a PIN is set (CTAP 2.1 `makeCredUvNotRqd`).
    pub create_without_pin: bool,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum PinState {
    Set,
    NotSet,
    #[default]
    Unsupported,
}

impl Device {
    /// What to call the key in messages: "YubiKey" or "security key".
    pub fn noun(&self) -> &'static str {
        if self.vendor_id == YUBICO {
            "YubiKey"
        } else {
            "security key"
        }
    }
}

impl DeviceInfo {
    pub fn supports_fido2(&self) -> bool {
        self.versions.iter().any(|v| v.starts_with("FIDO_2"))
    }

    /// Whether the key can hold `ed25519-sk` SSH keys; otherwise `ecdsa-sk`.
    pub fn supports_ed25519(&self) -> bool {
        self.algorithms.iter().any(|a| a == "eddsa")
    }
}

/// List connected FIDO keys and their capabilities.
pub fn list() -> Result<Vec<Device>> {
    let tool = find_on_path("fido2-token").ok_or(Error::MissingTool {
        name: "fido2-token",
        install: "brew install libfido2",
    })?;
    list_with(&tool)
}

/// The one connected FIDO2 key; setup and removal refuse to guess.
pub(crate) fn single_device() -> Result<Device> {
    let mut usable: Vec<Device> = list()?
        .into_iter()
        .filter(|d| d.info.as_ref().is_some_and(|i| i.supports_fido2()))
        .collect();
    match usable.len() {
        0 => Err(Error::fixable(
            "No security key connected",
            "Plug one in, then try again",
        )),
        1 => Ok(usable.remove(0)),
        n => Err(Error::fixable(
            format!("{n} security keys are connected"),
            "Unplug all but the one you mean, then try again",
        )),
    }
}

/// Yubico's USB vendor id.
pub(crate) const YUBICO: u16 = 0x1050;

/// Run `fido2-token` with `pin` given on its input instead of the terminal,
/// so its prompt (which names macOS's device path) never shows. Keymate asks
/// for the PIN itself and keeps it only for this call.
fn run_with_pin(args: &[&str], input: &str) -> Result<process::Output> {
    let tool = find_on_path("fido2-token").ok_or(Error::MissingTool {
        name: "fido2-token",
        install: "brew install libfido2",
    })?;
    process::run_detached(&tool, args, input, PIN_TIMEOUT).map_err(|e| Error::ToolFailed {
        name: "fido2-token",
        detail: e.to_string(),
    })
}

/// Long enough for the key to check a PIN, which can take a few seconds.
const PIN_TIMEOUT: Duration = Duration::from_secs(30);

/// The libfido2 error in `fido2-token`'s output, e.g. `FIDO_ERR_PIN_INVALID`.
fn fido_error(stderr: &str) -> Option<&str> {
    let start = stderr.find("FIDO_ERR_")?;
    let rest = &stderr[start..];
    let end = rest
        .find(|c: char| !(c.is_ascii_alphanumeric() || c == '_'))
        .unwrap_or(rest.len());
    Some(&rest[..end])
}

/// Turn a failed PIN operation into an error the person can act on.
fn pin_error(output: &process::Output, failed: &str) -> Error {
    match fido_error(&output.stderr) {
        Some("FIDO_ERR_PIN_INVALID") => Error::WrongPin,
        Some("FIDO_ERR_PIN_AUTH_BLOCKED") => Error::fixable(
            "Too many wrong PINs in a row",
            "Unplug the key, plug it back in, and try again",
        ),
        Some("FIDO_ERR_PIN_BLOCKED") => Error::fixable(
            "The key's PIN is blocked after too many wrong tries",
            "The key's FIDO2 part must be reset, which deletes its credentials",
        ),
        Some("FIDO_ERR_PIN_POLICY_VIOLATION") => {
            Error::Failed("The key doesn't accept that PIN; try a longer one".into())
        }
        Some(code) => Error::Failed(format!("{failed} ({code})")),
        None => Error::Failed(failed.to_owned()),
    }
}

/// Set the first FIDO2 PIN on `device` (`fido2-token` wants it twice).
pub fn set_pin(device: &Device, pin: &str) -> Result<()> {
    let output = run_with_pin(&["-S", &device.path], &format!("{pin}\n{pin}\n"))?;
    match output.status.success() {
        true => Ok(()),
        false => Err(pin_error(
            &output,
            "The PIN was not set; nothing else was changed",
        )),
    }
}

/// A resident credential stored on a security key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Credential {
    /// The credential id; key files call it the key handle.
    pub id: Vec<u8>,
    /// The user id given at creation, e.g. `primary.a1b2c3`.
    pub user: String,
}

/// The resident credentials for `rp_id` (e.g. `ssh:keymate-github`) on
/// `device`, listed with `pin`.
pub(crate) fn list_credentials(device: &Device, rp_id: &str, pin: &str) -> Result<Vec<Credential>> {
    let output = run_with_pin(&["-L", "-k", rp_id, &device.path], &format!("{pin}\n"))?;
    if output.status.success() {
        return Ok(output.stdout.lines().filter_map(parse_credential).collect());
    }
    match fido_error(&output.stderr) {
        Some("FIDO_ERR_NO_CREDENTIALS") => Ok(Vec::new()),
        _ => Err(pin_error(
            &output,
            "Couldn't list the credentials on the security key",
        )),
    }
}

/// A line of `fido2-token -L -k`:
/// `00: <id> <display name> <user id> <type> <protection> <payment>`, with
/// the ids in base64.
fn parse_credential(line: &str) -> Option<Credential> {
    let fields: Vec<&str> = line.split_whitespace().collect();
    if fields.len() < 6 {
        return None;
    }
    let id = STANDARD.decode(fields[1]).ok()?;
    let user = STANDARD.decode(fields[fields.len() - 4]).ok()?;
    // OpenSSH pads the user id with zeros to 32 bytes.
    let user = String::from_utf8_lossy(&user)
        .trim_end_matches('\0')
        .to_owned();
    Some(Credential { id, user })
}

/// Delete the resident credential `credential_id` from `device`, unlocking
/// it with `pin`. A wrong PIN is [`Error::WrongPin`], so the caller can ask
/// again.
pub(crate) fn delete_credential(device: &Device, credential_id: &[u8], pin: &str) -> Result<()> {
    let id = STANDARD.encode(credential_id);
    let output = run_with_pin(&["-D", "-i", &id, &device.path], &format!("{pin}\n"))?;
    match output.status.success() {
        true => Ok(()),
        false => Err(pin_error(
            &output,
            "The credential was not deleted from the security key",
        )),
    }
}

/// Whether `device` holds the credential `credential_id` for `application`.
///
/// Asks for an assertion with user presence turned off, so the key neither
/// blinks nor needs a touch or PIN. `None` means the key could not answer,
/// e.g. because it does not support silent requests.
pub(crate) fn owns_credential(
    device: &Device,
    application: &str,
    credential_id: &str,
) -> Result<Option<bool>> {
    let tool = find_on_path("fido2-assert").ok_or(Error::MissingTool {
        name: "fido2-assert",
        install: "brew install libfido2",
    })?;
    // The client data hash only feeds a signature that is thrown away.
    let input = format!(
        "{}\n{application}\n{credential_id}\n",
        STANDARD.encode([0u8; 32])
    );
    let output = process::run_with_input(
        &tool,
        &["-G", "-t", "up=false", &device.path],
        Some(&input),
        TIMEOUT,
    )
    .map_err(|e| Error::ToolFailed {
        name: "fido2-assert",
        detail: e.to_string(),
    })?;
    Ok(if output.status.success() {
        Some(true)
    } else if output.stderr.contains("FIDO_ERR_NO_CREDENTIALS") {
        Some(false)
    } else {
        None
    })
}

/// Read the current capabilities of `device` again, e.g. after setting a PIN.
pub fn refresh(device: &Device) -> Result<DeviceInfo> {
    let tool = find_on_path("fido2-token").ok_or(Error::MissingTool {
        name: "fido2-token",
        install: "brew install libfido2",
    })?;
    run(&tool, &["-I", &device.path]).map(|text| parse_info(&text))
}

pub(crate) fn list_with(tool: &Path) -> Result<Vec<Device>> {
    let output = run(tool, &["-L"])?;
    let mut devices = parse_list(&output);
    for device in &mut devices {
        device.info = run(tool, &["-I", &device.path])
            .ok()
            .map(|text| parse_info(&text));
    }
    Ok(devices)
}

fn run(tool: &Path, args: &[&str]) -> Result<String> {
    let failed = |detail: String| Error::ToolFailed {
        name: "fido2-token",
        detail,
    };
    let output = process::run(tool, args, TIMEOUT).map_err(|e| failed(e.to_string()))?;
    if output.status.success() {
        Ok(output.stdout)
    } else {
        Err(failed(sanitize(output.stderr.trim())))
    }
}

/// Parse `fido2-token -L` lines such as
/// `ioreg://4295204009: vendor=0x1050, product=0x0406 (Yubico YubiKey FIDO+CCID)`.
fn parse_list(text: &str) -> Vec<Device> {
    text.lines()
        .filter_map(|line| {
            let (path, rest) = line.split_once(": vendor=")?;
            let (vendor, rest) = rest.split_once(", product=")?;
            let (product, name) = rest.split_once(' ').unwrap_or((rest, ""));
            Some(Device {
                path: sanitize(path),
                vendor_id: parse_hex(vendor)?,
                product_id: parse_hex(product)?,
                name: sanitize(name.trim().trim_start_matches('(').trim_end_matches(')')),
                info: None,
            })
        })
        .collect()
}

fn parse_hex(text: &str) -> Option<u16> {
    u16::from_str_radix(text.trim().trim_start_matches("0x"), 16).ok()
}

/// Parse the `key: value` lines printed by `fido2-token -I`.
fn parse_info(text: &str) -> DeviceInfo {
    let mut info = DeviceInfo::default();
    for line in text.lines() {
        let Some((key, value)) = line.split_once(':') else {
            continue;
        };
        let items = || value.split(',').map(str::trim).filter(|s| !s.is_empty());
        match key.trim() {
            "version strings" => info.versions = items().map(sanitize).collect(),
            "algorithms" => {
                info.algorithms = items()
                    .map(|a| sanitize(a.split_whitespace().next().unwrap_or(a)))
                    .collect();
            }
            "options" => {
                for option in items() {
                    match option {
                        "clientPin" => info.pin = PinState::Set,
                        "noclientPin" => info.pin = PinState::NotSet,
                        "rk" => info.resident_keys = true,
                        "makeCredUvNotRqd" => info.create_without_pin = true,
                        _ => {}
                    }
                }
            }
            "pin retries" => info.pin_retries = value.trim().parse().ok(),
            "minpinlen" => info.min_pin_length = value.trim().parse().ok(),
            _ => {}
        }
    }
    info
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_listed_credentials() {
        // `primary.a1b2c3` padded with zeros to 32 bytes, as OpenSSH stores it.
        let mut user = b"primary.a1b2c3".to_vec();
        user.resize(32, 0);
        let line = format!(
            "00: AQID (null) {} eddsa uvopt+id nopay",
            STANDARD.encode(&user)
        );
        let credential = parse_credential(&line).unwrap();
        assert_eq!(credential.id, vec![1, 2, 3]);
        assert_eq!(credential.user, "primary.a1b2c3");
        assert_eq!(parse_credential("nonsense"), None);
    }

    #[test]
    fn reads_libfido2_errors() {
        let stderr =
            "Enter PIN for ioreg://1: fido2-token: fido_credman_del_dev_rk: FIDO_ERR_PIN_INVALID\n";
        assert_eq!(fido_error(stderr), Some("FIDO_ERR_PIN_INVALID"));
        assert_eq!(fido_error("fido2-token: no device"), None);
    }

    const YUBIKEY_INFO: &str = "\
proto: 0x02
version strings: U2F_V2, FIDO_2_0, FIDO_2_1_PRE
extension strings: credProtect, hmac-secret
transport strings: usb
algorithms: es256 (public-key), eddsa (public-key)
options: rk, up, noplat, clientPin, credentialMgmtPreview
pin retries: 8
minpinlen: 4
uv retries: undefined
";

    #[test]
    fn parses_device_list() {
        let devices = parse_list(
            "ioreg://4295204009: vendor=0x1050, product=0x0406 (Yubico YubiKey FIDO+CCID)\n\
             garbage line\n",
        );
        assert_eq!(
            devices,
            vec![Device {
                path: "ioreg://4295204009".into(),
                vendor_id: 0x1050,
                product_id: 0x0406,
                name: "Yubico YubiKey FIDO+CCID".into(),
                info: None,
            }]
        );
    }

    #[test]
    fn parses_device_info() {
        let info = parse_info(YUBIKEY_INFO);
        assert_eq!(info.versions, ["U2F_V2", "FIDO_2_0", "FIDO_2_1_PRE"]);
        assert_eq!(info.algorithms, ["es256", "eddsa"]);
        assert_eq!(info.pin, PinState::Set);
        assert_eq!(info.pin_retries, Some(8));
        assert_eq!(info.min_pin_length, Some(4));
        assert!(info.resident_keys);
        assert!(!info.create_without_pin);
        assert!(parse_info("options: rk, makeCredUvNotRqd").create_without_pin);
        assert!(info.supports_fido2());
        assert!(info.supports_ed25519());
    }

    #[test]
    fn distinguishes_unset_and_unsupported_pins() {
        assert_eq!(parse_info("options: rk, noclientPin").pin, PinState::NotSet);
        assert_eq!(
            parse_info("version strings: U2F_V2").pin,
            PinState::Unsupported
        );
        assert!(!parse_info("version strings: U2F_V2").supports_fido2());
    }
}
