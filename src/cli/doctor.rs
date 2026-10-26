//! `keymate doctor`: check the tools, the security key and, for a service,
//! its tool and the sign-in.

use std::io::{self, Write};
use std::process::ExitCode;

use console::style;
use keymate::Result;
use keymate::Service;
use keymate::doctor::{self, Report};

use super::render::{heading, label_width, render_checks, summary};
use super::{choose_service, interactive, ui};

pub fn run(service: Option<Service>, deps_only: bool) -> Result<ExitCode> {
    if deps_only {
        let report = ui::spin(
            "Checking required software...",
            || Ok(doctor::dependencies(service)),
            |_| String::new(),
        )?;
        print!("{}", render_dependencies(&report));
        return Ok(exit_code(&report));
    }
    let mut report = ui::spin(
        "Checking your tools and security key...",
        || Ok(doctor::run(service)),
        |_| String::new(),
    )?;
    // Without a service, show the shared checks and ask which
    // service to check too; scripts just get the shared checks.
    if service.is_some() || !interactive() {
        print!("{}", render_report(&report, service));
        return Ok(exit_code(&report));
    }
    print!("{}", render_sections(&report));
    let _ = io::stdout().flush();
    eprintln!();
    let chosen = choose_service("Check a service")?;
    if let Some(service) = chosen {
        let section = ui::spin(
            &format!("Checking {service}..."),
            || Ok(doctor::service(service)),
            |_| String::new(),
        )?;
        let added = Report {
            sections: vec![section],
        };
        print!("\n{}", render_sections(&added));
        report.sections.extend(added.sections);
    }
    print!("{}", last_line(&report, chosen));
    Ok(exit_code(&report))
}

fn exit_code(report: &Report) -> ExitCode {
    if report.ready() {
        ExitCode::SUCCESS
    } else {
        ExitCode::FAILURE
    }
}

fn render_report(report: &Report, service: Option<Service>) -> String {
    render_sections(report) + &last_line(report, service)
}

/// The summary under the checks, with a blank line before it; empty when
/// all is well and there's no next step to suggest.
fn last_line(report: &Report, service: Option<Service>) -> String {
    let ready = match service {
        Some(Service::GitHub) => format!("Next: {}", style("keymate setup github").cyan()),
        None => String::new(),
    };
    match summary(report.problems(), report.warnings(), &ready) {
        line if line.is_empty() => line,
        line => format!("\n{line}"),
    }
}

fn render_dependencies(report: &Report) -> String {
    render_sections(report)
        + "\n"
        + &summary(
            report.problems(),
            report.warnings(),
            "All required tools are installed",
        )
}

/// Each section under its heading, separated by blank lines. The column fits
/// `doctor`'s widest label, so sections printed one after another line up.
fn render_sections(report: &Report) -> String {
    let width = label_width(report.checks()).max("GitHub CLI".len());
    report
        .sections
        .iter()
        .map(|section| heading(section.title) + &render_checks(&section.checks, "  ", width))
        .collect::<Vec<_>>()
        .join("\n")
}
