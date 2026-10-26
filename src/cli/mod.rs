//! The terminal frontend: arguments, prompts and output for each command.

mod devices;
mod doctor;
mod nuke;
mod render;
mod setup;
mod signer;
mod status;
mod ui;
mod update;

use std::io::{self, IsTerminal};
use std::process::ExitCode;

use clap::{Parser, Subcommand, ValueEnum};
use keymate::github::setup::{Storage, Verification};
use keymate::{Error, Result, Service};

/// Set up and manage your hardware security keys
#[derive(Debug, Parser)]
#[command(name = "keymate", version)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand, PartialEq, Eq)]
enum Command {
    /// Check your tools, accounts and security key
    Doctor {
        /// Also check this service's tool and your sign-in
        service: Option<ServiceArg>,
        /// Only check the tools; no sign-in or security key needed
        #[arg(long)]
        deps_only: bool,
    },
    /// Show plugged-in security keys
    Devices,
    /// Set up a security key
    Setup {
        /// The service, e.g. github (asked if omitted)
        service: Option<ServiceArg>,
        /// A name for the key, e.g. yubikey or backup (asked if omitted)
        #[arg(long)]
        name: Option<String>,
        /// Where to store the credential (asked if omitted)
        #[arg(long, value_enum)]
        storage: Option<StorageArg>,
        /// What each push and pull needs (asked if omitted)
        #[arg(long, value_enum)]
        verification: Option<VerificationArg>,
        /// Sign commits and tags with the key (asked if omitted)
        #[arg(long, value_name = "yes|no", hide_possible_values = true, value_parser = clap::builder::BoolishValueParser::new())]
        signing: Option<bool>,
    },
    /// Show the keys you've set up
    Status {
        /// The service, e.g. github (asked if omitted)
        service: Option<ServiceArg>,
    },
    /// Choose the key that signs commits
    Signer {
        /// The service, e.g. github (asked if omitted)
        service: Option<ServiceArg>,
        /// The key to sign with, by name (asked if omitted)
        #[arg(long = "use", value_name = "NAME", conflicts_with = "off")]
        key: Option<String>,
        /// Turn commit signing off
        #[arg(long)]
        off: bool,
    },
    /// Undo a setup
    Nuke {
        /// The service, e.g. github (asked if omitted)
        service: Option<ServiceArg>,
    },
    /// Update Keymate
    #[command(alias = "upgrade")]
    Update {
        /// Install this version instead of the latest, e.g. 0.2.0
        #[arg(long)]
        version: Option<String>,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
enum ServiceArg {
    Github,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
enum StorageArg {
    /// On this Mac (recommended)
    NonResident,
    /// On the security key: portable, uses a slot
    Resident,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
enum VerificationArg {
    /// A touch (recommended)
    Touch,
    /// Your PIN and a touch
    Pin,
}

impl From<ServiceArg> for Service {
    fn from(arg: ServiceArg) -> Self {
        match arg {
            ServiceArg::Github => Service::GitHub,
        }
    }
}

/// Parse the arguments, run the command, then mention a new release.
pub fn run() -> ExitCode {
    let cli = Cli::parse();
    ui::handle_ctrl_c();
    let updating = matches!(cli.command, Command::Update { .. });
    let code = match dispatch(cli.command) {
        Ok(code) => code,
        Err(Error::Cancelled) => {
            ui::cancelled();
            ExitCode::FAILURE
        }
        Err(error) => {
            ui::print_error(&error);
            ExitCode::FAILURE
        }
    };
    // Like Thops: mention a new release after the command's own output.
    // Only for people at a terminal, and never while updating.
    if !updating
        && io::stderr().is_terminal()
        && let Some(latest) = keymate::update::newer_release()
    {
        ui::notice(&format!(
            "keymate {latest} is available: run `keymate update`"
        ));
    }
    code
}

fn dispatch(command: Command) -> Result<ExitCode> {
    match command {
        Command::Devices => devices::run(),
        Command::Doctor { service, deps_only } => {
            doctor::run(service.map(Service::from), deps_only)
        }
        Command::Setup {
            service,
            name,
            storage,
            verification,
            signing,
        } => {
            let preset = setup::Preset {
                name,
                storage: storage.map(|s| match s {
                    StorageArg::NonResident => Storage::NonResident,
                    StorageArg::Resident => Storage::Resident,
                }),
                verification: verification.map(|v| match v {
                    VerificationArg::Touch => Verification::Touch,
                    VerificationArg::Pin => Verification::PinAndTouch,
                }),
                signing,
            };
            match pick_service(service, "setup")? {
                Service::GitHub => Ok(setup::github(preset)),
            }
        }
        Command::Nuke { service } => match pick_service(service, "nuke")? {
            Service::GitHub => Ok(nuke::github()),
        },
        Command::Signer { service, key, off } => match pick_service(service, "signer")? {
            Service::GitHub => Ok(signer::github(match (key, off) {
                (Some(name), _) => Some(signer::Choice::Key(name)),
                (None, true) => Some(signer::Choice::Off),
                (None, false) => None,
            })),
        },
        Command::Status { service } => match pick_service(service, "status")? {
            Service::GitHub => status::github(),
        },
        Command::Update { version } => Ok(update::run(version)),
    }
}

/// The service a command is for: from the command line, or asked. Without a
/// terminal to ask on, the person has to name it.
fn pick_service(service: Option<ServiceArg>, command: &str) -> Result<Service> {
    if let Some(service) = service {
        return Ok(service.into());
    }
    if !interactive() {
        return Err(Error::fixable(
            "No service given",
            format!("Name one, e.g. `keymate {command} github`"),
        ));
    }
    choose_service("Choose a service")?.ok_or(Error::Cancelled)
}

fn interactive() -> bool {
    io::stdin().is_terminal() && io::stderr().is_terminal()
}

/// Ask for a service, listing every one Keymate supports. `None` when the
/// person cancels.
fn choose_service(prompt: &str) -> Result<Option<Service>> {
    let services: Vec<(Service, String)> = ServiceArg::value_variants()
        .iter()
        .map(|&arg| {
            let service = Service::from(arg);
            (service, service.to_string())
        })
        .collect();
    let mut items: Vec<(Option<Service>, &str, &str)> = services
        .iter()
        .map(|(service, name)| (Some(*service), name.as_str(), ""))
        .collect();
    items.push((None, "Cancel", ""));
    match ui::select(prompt, &items) {
        Err(Error::Cancelled) => Ok(None),
        choice => choice,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::{CommandFactory, error::ErrorKind};

    fn parse(args: &[&str]) -> std::result::Result<Command, clap::Error> {
        Cli::try_parse_from(std::iter::once("keymate").chain(args.iter().copied()))
            .map(|cli| cli.command)
    }

    #[test]
    fn cli_definition_is_valid() {
        Cli::command().debug_assert();
    }

    #[test]
    fn parses_planned_commands() {
        assert_eq!(parse(&["devices"]).unwrap(), Command::Devices);
        assert_eq!(
            parse(&["doctor"]).unwrap(),
            Command::Doctor {
                service: None,
                deps_only: false
            }
        );
        assert_eq!(
            parse(&["doctor", "github", "--deps-only"]).unwrap(),
            Command::Doctor {
                service: Some(ServiceArg::Github),
                deps_only: true
            }
        );
        assert_eq!(
            parse(&["doctor", "--deps-only"]).unwrap(),
            Command::Doctor {
                service: None,
                deps_only: true
            }
        );
        assert_eq!(
            parse(&["upgrade"]).unwrap(),
            Command::Update { version: None }
        );
        assert_eq!(
            parse(&["update", "--version", "0.2.0"]).unwrap(),
            Command::Update {
                version: Some("0.2.0".into())
            }
        );
        assert_eq!(
            parse(&["setup", "github"]).unwrap(),
            Command::Setup {
                service: Some(ServiceArg::Github),
                name: None,
                storage: None,
                verification: None,
                signing: None,
            }
        );
        assert_eq!(
            parse(&[
                "setup",
                "github",
                "--storage",
                "resident",
                "--verification",
                "pin",
                "--signing",
                "yes",
                "--name",
                "backup"
            ])
            .unwrap(),
            Command::Setup {
                service: Some(ServiceArg::Github),
                name: Some("backup".into()),
                storage: Some(StorageArg::Resident),
                verification: Some(VerificationArg::Pin),
                signing: Some(true),
            }
        );
        assert_eq!(
            parse(&["signer", "github", "--use", "backup"]).unwrap(),
            Command::Signer {
                service: Some(ServiceArg::Github),
                key: Some("backup".into()),
                off: false,
            }
        );
        assert!(parse(&["signer", "github", "--use", "a", "--off"]).is_err());
        assert_eq!(
            parse(&["nuke", "github"]).unwrap(),
            Command::Nuke {
                service: Some(ServiceArg::Github)
            }
        );
        assert_eq!(
            parse(&["status", "github"]).unwrap(),
            Command::Status {
                service: Some(ServiceArg::Github)
            }
        );
    }

    #[test]
    fn the_service_is_optional_and_asked_for() {
        for command in ["setup", "status", "signer", "nuke"] {
            let parsed = format!("{:?}", parse(&[command]).unwrap());
            assert!(parsed.contains("service: None"), "{parsed}");
        }
    }

    #[test]
    fn help_and_version_are_handled_by_clap() {
        assert_eq!(
            parse(&["--help"]).unwrap_err().kind(),
            ErrorKind::DisplayHelp
        );
        assert_eq!(
            parse(&["-V"]).unwrap_err().kind(),
            ErrorKind::DisplayVersion
        );
    }

    #[test]
    fn rejects_unknown_input() {
        assert!(parse(&["setup", "gitlab"]).is_err());
        assert!(parse(&["setup", "github", "extra"]).is_err());
        assert!(parse(&["doctor", "extra"]).is_err());
    }
}
