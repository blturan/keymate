//! Report rendering shared by `doctor`, `devices` and `status`: headings,
//! check rows and the summary line. Reports go to stdout.

use console::style;
use keymate::check::{Check, Mark};

/// A section heading: `Tools:`.
pub fn heading(title: &str) -> String {
    format!("{}\n", style(format!("{title}:")).bold())
}

/// The first line of a report, like the first line of a flow:
/// `2 keys on this Mac · blturan on GitHub`.
pub fn first_line(parts: &[String]) -> String {
    parts.join(&style(" · ").dim().to_string()) + "\n"
}

/// The widest label, so rows line up; 0 when no row has a label.
pub fn label_width<'a>(checks: impl IntoIterator<Item = &'a Check>) -> usize {
    checks.into_iter().map(|c| c.label.len()).max().unwrap_or(0)
}

/// Show `backticked` text, such as commands, in cyan without the backticks.
fn commands(text: &str) -> String {
    text.split('`')
        .enumerate()
        .map(|(index, part)| match index % 2 {
            1 => style(part).cyan().to_string(),
            _ => part.to_owned(),
        })
        .collect()
}

pub fn render_checks(checks: &[Check], indent: &str, width: usize) -> String {
    let column = if width == 0 { 0 } else { width + 2 };
    let mut out = String::new();
    for check in checks {
        // A row without a label (e.g. the security key) skips the column.
        let column = if check.label.is_empty() { 0 } else { column };
        let (mark, detail) = match check.mark {
            Mark::Pass => (style("✓").green(), commands(&check.detail)),
            Mark::Warn => (style("!").yellow(), commands(&check.detail)),
            Mark::Fail => (style("✗").red(), commands(&check.detail)),
            Mark::Info => (style(" "), style(&check.detail).dim().to_string()),
        };
        out += &format!("{indent}{mark} {:<column$}{detail}\n", check.label);
        if let Some(hint) = &check.hint {
            out += &format!(
                "{indent}  {:column$}{} {}\n",
                "",
                style("→").dim(),
                commands(hint)
            );
        }
    }
    out
}

/// The last line, marked like the worst check: problems, else warnings,
/// else `all_good` as a quiet hint, without another check mark.
pub fn summary(problems: usize, warnings: usize, all_good: &str) -> String {
    let count = |n: usize, noun: &str| format!("{n} {noun}{}", if n == 1 { "" } else { "s" });
    let line = if problems > 0 {
        let mut text = format!("{} to fix", count(problems, "problem"));
        if warnings > 0 {
            text += &format!(", {}", count(warnings, "warning"));
        }
        format!("{} {text}", style("✗").red())
    } else if warnings > 0 {
        format!("{} {}", style("!").yellow(), count(warnings, "warning"))
    } else if all_good.is_empty() {
        return String::new();
    } else {
        format!("{} {all_good}", style("→").dim())
    };
    line + "\n"
}
