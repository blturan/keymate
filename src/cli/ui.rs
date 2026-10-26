//! Terminal presentation for the interactive commands. Every flow has the
//! same calm layout: one line on what Keymate found, the questions, the plan
//! with `Continue?` under it, a `✓` line per change, and `Done`. Blank lines
//! only separate those blocks. Colour is kept for marks (`✓ ! + -`), the
//! active prompt, and commands. Everything goes to stderr, and colours switch
//! off when stderr is not a terminal.
//!
//! Spinners are only used while Keymate waits by itself. When an external
//! tool may ask for a PIN or show a code, the step is announced without a
//! spinner so the animation never draws over the tool's prompt.

use std::cell::RefCell;
use std::fmt::Display;
use std::io::{self, IsTerminal};
use std::process::ExitCode;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread;
use std::time::{Duration, Instant};

use console::{Key, Style, StyledObject, Term, style};
use dialoguer::theme::ColorfulTheme;
use dialoguer::{Confirm, Input};
use indicatif::{ProgressBar, ProgressStyle};
use keymate::{Error, Result};

const SPINNER: &[&str] = &["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏", " "];

/// The plan line for a GitHub permission the GitHub CLI still needs.
pub const GRANT: &str = "Give the GitHub CLI permission to manage your keys (in your browser)";

fn paint<D>(value: D) -> StyledObject<D> {
    style(value).for_stderr()
}

/// Whether anything was printed yet, and whether the last line was blank, so
/// blocks are separated by exactly one blank line.
static PRINTED: AtomicBool = AtomicBool::new(false);
static AT_GAP: AtomicBool = AtomicBool::new(false);

fn say(text: impl Display) {
    eprintln!("{text}");
    PRINTED.store(true, Ordering::Relaxed);
    AT_GAP.store(false, Ordering::Relaxed);
}

/// Show or hide the cursor, e.g. while a line animates; only on a terminal,
/// so piped output stays free of escape codes.
fn cursor(show: bool) {
    let term = Term::stderr();
    if term.is_term() {
        let _ = if show {
            term.show_cursor()
        } else {
            term.hide_cursor()
        };
    }
}

/// Start a new block: one blank line, never two, and none at the top.
pub fn gap() {
    if PRINTED.load(Ordering::Relaxed) && !AT_GAP.swap(true, Ordering::Relaxed) {
        eprintln!();
    }
}

pub fn require_terminal(command: &str) -> Result<()> {
    if io::stdin().is_terminal() {
        Ok(())
    } else {
        Err(Error::Failed(format!(
            "`keymate {command}` needs an interactive terminal"
        )))
    }
}

/// Ctrl+C stops Keymate; restore the cursor a prompt or spinner hid.
pub fn handle_ctrl_c() {
    let _ = ctrlc::set_handler(|| {
        cursor(true);
        // Ends the interrupted line first.
        show_cancelled("\n\n");
        std::process::exit(130);
    });
}

/// Print "Cancelled" once, even when Ctrl+C reaches both a prompt and the
/// signal handler.
fn show_cancelled(before: &str) {
    static SHOWN: AtomicBool = AtomicBool::new(false);
    if !SHOWN.swap(true, Ordering::SeqCst) {
        say(format!("{before}{}", paint("Cancelled").yellow()));
    }
}

/// End a flow started at `started`: `Done in 12.3s`, or the error.
pub fn finish(started: Instant, result: Result<()>) -> ExitCode {
    gap();
    match result {
        Ok(()) => {
            say(format!(
                "{} {}",
                paint("Done").green(),
                paint(format!("in {}", elapsed(started.elapsed()))).dim()
            ));
            ExitCode::SUCCESS
        }
        Err(Error::Cancelled) => {
            show_cancelled("");
            ExitCode::FAILURE
        }
        Err(error) => {
            print_error(&error);
            ExitCode::FAILURE
        }
    }
}

/// Report that the person cancelled.
pub fn cancelled() {
    show_cancelled("");
}

/// An error, like a problem in `doctor`: `✗ What went wrong` and, when the
/// person can fix it, `→ How` under it.
pub fn print_error(error: &Error) {
    say(format!(
        "{} {}",
        paint("✗").red(),
        highlight(&sentence(&error.to_string()))
    ));
    if let Some(fix) = error.fix() {
        hint(&sentence(&fix));
    }
}

/// Messages read like every other line: a capital first letter and no
/// closing full stop.
fn sentence(text: &str) -> String {
    let text = text.trim().trim_end_matches('.');
    let mut chars = text.chars();
    match chars.next() {
        Some(first) => first.to_uppercase().chain(chars).collect(),
        None => String::new(),
    }
}

fn theme() -> ColorfulTheme {
    ColorfulTheme {
        prompt_prefix: paint("?".to_owned()).cyan(),
        prompt_suffix: paint("›".to_owned()).dim(),
        prompt_style: Style::new().for_stderr(),
        success_prefix: paint("?".to_owned()).dim(),
        success_suffix: paint("·".to_owned()).dim(),
        error_prefix: paint("✗".to_owned()).red(),
        hint_style: Style::new().for_stderr().dim(),
        defaults_style: Style::new().for_stderr().dim(),
        values_style: Style::new().for_stderr(),
        ..ColorfulTheme::default()
    }
}

/// An answered question, as it stays on screen: `? Name this key · work`.
/// Also for choices Keymate made itself, so every choice reads the same.
pub fn given(prompt: &str, answer: &str) {
    say(format!(
        "{} {prompt} {} {answer}",
        paint("?").dim(),
        paint("·").dim()
    ));
}

/// The first line of a flow: what Keymate found, e.g.
/// `YubiKey 5C NFC · blturan on GitHub`.
pub fn context(parts: &[&str]) {
    say(parts.join(&paint(" · ").dim().to_string()));
}

/// Choose one of `items` (value, label, hint) with the arrow keys; the first
/// is preselected and Esc cancels. Only labels are listed; the hint of the
/// active one shows dim under the list, like Inquirer and Charm's huh.
pub fn select<T: Clone>(prompt: &str, items: &[(T, &str, &str)]) -> Result<T> {
    let term = Term::stderr();
    let chosen =
        choose(&term, prompt, items).map_err(|error| prompt_error(dialoguer::Error::IO(error)));
    let _ = term.show_cursor();
    let chosen = chosen?.ok_or(Error::Cancelled)?;
    given(prompt, items[chosen].1);
    Ok(items[chosen].0.clone())
}

fn choose<T>(term: &Term, prompt: &str, items: &[(T, &str, &str)]) -> io::Result<Option<usize>> {
    let header = format!("{} {prompt} {}", paint("?").cyan(), paint("›").dim());
    let mut active = 0;
    let mut height = 0;
    term.hide_cursor()?;
    loop {
        term.clear_last_lines(height)?;
        term.write_line(&header)?;
        for (index, (_, label, _)) in items.iter().enumerate() {
            term.write_line(&match index == active {
                true => format!("{} {}", paint("❯").cyan(), paint(label).cyan()),
                false => format!("  {label}"),
            })?;
        }
        let width = usize::from(term.size().1).saturating_sub(2);
        let hint = console::truncate_str(items[active].2, width, "…");
        term.write_line(&format!("  {}", paint(hint).dim()))?;
        height = items.len() + 2;
        match term.read_key()? {
            Key::ArrowUp | Key::Char('k') | Key::BackTab => {
                active = (active + items.len() - 1) % items.len();
            }
            Key::ArrowDown | Key::Char('j') | Key::Tab => active = (active + 1) % items.len(),
            Key::Home => active = 0,
            Key::End => active = items.len() - 1,
            Key::Enter | Key::Char(' ') => {
                term.clear_last_lines(height)?;
                return Ok(Some(active));
            }
            Key::Escape | Key::Char('q') => {
                term.clear_last_lines(height)?;
                return Ok(None);
            }
            _ => {}
        }
    }
}

/// Ask for the security key's PIN and try it with `attempt`; a wrong PIN
/// asks again. The PIN shows as dots and is gone from the screen afterwards.
pub fn with_pin<T>(prompt: &str, mut attempt: impl FnMut(&str) -> Result<T>) -> Result<T> {
    loop {
        let pin = read_pin(prompt)?;
        match attempt(&pin) {
            Err(Error::WrongPin) => warning("That PIN was wrong, try again"),
            result => return result,
        }
    }
}

/// Ask for a new PIN twice, at least `minimum` characters long.
pub fn new_pin(noun: &str, minimum: usize) -> Result<String> {
    loop {
        let pin = read_pin(&format!("Choose a PIN for your {noun}"))?;
        // CTAP allows PINs of up to 63 bytes.
        if pin.chars().count() < minimum || pin.len() > 63 {
            warning(&format!("Use {minimum} to 63 characters"));
            continue;
        }
        if read_pin("Type it again")? == pin {
            return Ok(pin);
        }
        warning("The PINs didn't match, try again");
    }
}

/// Read a PIN key by key, without echoing it. Enter on an empty line does
/// nothing; Esc and Ctrl+C cancel.
fn read_pin(prompt: &str) -> Result<String> {
    let term = Term::stderr();
    let header = format!("{} {prompt} {} ", paint("?").cyan(), paint("›").dim());
    let mut pin = String::new();
    let result = loop {
        let _ = term.clear_line();
        let _ = term.write_str(&format!("{header}{}", "•".repeat(pin.chars().count())));
        match term.read_key() {
            Ok(Key::Enter) if !pin.is_empty() => break Ok(()),
            Ok(Key::Backspace) => {
                pin.pop();
            }
            Ok(Key::Char(c)) if !c.is_control() => pin.push(c),
            Ok(Key::Escape) => break Err(Error::Cancelled),
            Ok(_) => {}
            Err(error) => break Err(prompt_error(dialoguer::Error::IO(error))),
        }
    };
    let _ = term.clear_line();
    result.map(|()| pin)
}

/// A yes/no question. With a `default`, Enter takes it; without one, Enter
/// does nothing and only `y` or `n` answers, for choices that remove things.
pub fn confirm(prompt: &str, default: Option<bool>) -> Result<bool> {
    let theme = theme();
    let mut question = Confirm::with_theme(&theme)
        .with_prompt(prompt)
        .report(false);
    if let Some(default) = default {
        question = question.default(default);
    }
    let answer = question
        .interact_opt()
        .map_err(prompt_error)?
        .ok_or(Error::Cancelled)?;
    given(prompt, if answer { "Yes" } else { "No" });
    Ok(answer)
}

/// Ask for text with a default, checked by `validate` on Enter.
pub fn input(
    prompt: &str,
    default: &str,
    validate: impl Fn(&str) -> std::result::Result<(), String>,
) -> Result<String> {
    let answer: String = Input::with_theme(&theme())
        .with_prompt(prompt)
        .default(default.to_owned())
        .report(false)
        .validate_with(|text: &String| validate(text))
        .interact_text()
        .map_err(prompt_error)?;
    given(prompt, &answer);
    Ok(answer)
}

/// A line of the plan shown before any change.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PlanLine {
    /// `+`: something Keymate will add or change.
    Add(String),
    /// `-`: something Keymate will remove.
    Remove(String),
    /// `=`: already in place; nothing to do.
    InPlace(String),
}

/// The plan, like a diff (`+` adds, `-` removes, `=` is already in place),
/// with `Continue?` right under it. Saying no cancels. See [`confirm`] for
/// `default`.
pub fn approve(lines: &[PlanLine], default: Option<bool>) -> Result<()> {
    gap();
    say(paint("Plan:").bold());
    for line in lines {
        say(match line {
            PlanLine::Remove(text) => format!("  {} {}", paint('-').red(), highlight(text)),
            PlanLine::InPlace(text) => paint(format!("  = {text}")).dim().to_string(),
            PlanLine::Add(text) => format!("  {} {}", paint('+').green(), highlight(text)),
        });
    }
    match confirm("Continue?", default)? {
        true => Ok(()),
        false => Err(Error::Cancelled),
    }
}

/// Ask the GitHub CLI for a permission, through GitHub's browser flow.
pub fn grant(scope: &str, request: impl FnOnce() -> Result<()>) -> Result<()> {
    step(&format!(
        "Give the GitHub CLI the `{scope}` permission in your browser"
    ));
    request()?;
    success(&format!("Granted `{scope}`"));
    Ok(())
}

/// Run `work` behind a spinner, then report `done(&result)` unless empty.
pub fn spin<T>(
    working: &str,
    work: impl FnOnce() -> Result<T>,
    done: impl FnOnce(&T) -> String,
) -> Result<T> {
    let bar = ProgressBar::new_spinner().with_style(spinner_style());
    bar.set_message(working.to_owned());
    bar.enable_steady_tick(Duration::from_millis(80));
    // The cursor would sit at the end of the animated line.
    cursor(false);
    let result = work();
    bar.finish_and_clear();
    cursor(true);
    if let Ok(value) = &result {
        success(&done(value));
    }
    result
}

/// Wait for `work`, which needs a touch on the security key, behind a
/// [`TouchPrompt`], then report `done(&result)`.
pub fn touch<T>(
    key: &'static str,
    work: impl FnOnce(&TouchPrompt) -> Result<T>,
    done: impl FnOnce(&T) -> String,
) -> Result<T> {
    let prompt = TouchPrompt::new(key);
    prompt.start();
    let result = work(&prompt);
    prompt.stop();
    if let Ok(value) = &result {
        success(&done(value));
    }
    result
}

/// A pulsing "Touch your YubiKey" counting down the key's ~30 second
/// window. It can start and stop repeatedly, e.g. around PIN prompts.
pub struct TouchPrompt {
    /// What to call the key: "YubiKey" or "security key".
    key: &'static str,
    active: RefCell<Option<Active>>,
}

struct Active {
    bar: ProgressBar,
    waiting: Arc<AtomicBool>,
    finished: Arc<AtomicBool>,
    ticker: thread::JoinHandle<()>,
}

impl TouchPrompt {
    pub fn new(key: &'static str) -> Self {
        TouchPrompt {
            key,
            active: RefCell::new(None),
        }
    }

    /// Show the prompt (no-op if it is showing).
    pub fn start(&self) {
        let mut active = self.active.borrow_mut();
        if active.is_some() {
            return;
        }
        cursor(false);
        let bar = ProgressBar::new_spinner().with_style(touch_style());
        bar.set_message(touch_message(self.key, Duration::ZERO));
        bar.enable_steady_tick(Duration::from_millis(120));
        let waiting = Arc::new(AtomicBool::new(true));
        let finished = Arc::new(AtomicBool::new(false));
        let ticker = {
            let (bar, waiting, finished) = (bar.clone(), waiting.clone(), finished.clone());
            let (key, started) = (self.key, Instant::now());
            thread::spawn(move || {
                while !finished.load(Ordering::Relaxed) {
                    if waiting.load(Ordering::Relaxed) {
                        bar.set_message(touch_message(key, started.elapsed()));
                    }
                    thread::sleep(Duration::from_millis(200));
                }
            })
        };
        *active = Some(Active {
            bar,
            waiting,
            finished,
            ticker,
        });
    }

    /// The key was touched; show `message` with a normal spinner instead.
    pub fn proceed(&self, message: &str) {
        if let Some(active) = self.active.borrow().as_ref() {
            active.waiting.store(false, Ordering::Relaxed);
            active.bar.set_style(spinner_style());
            active.bar.set_message(message.to_owned());
        }
    }

    /// Hide the prompt (no-op if it is hidden).
    pub fn stop(&self) {
        if let Some(active) = self.active.borrow_mut().take() {
            active.finished.store(true, Ordering::Relaxed);
            let _ = active.ticker.join();
            active.bar.finish_and_clear();
            cursor(true);
        }
    }
}

impl Drop for TouchPrompt {
    fn drop(&mut self) {
        self.stop();
    }
}

fn touch_style() -> ProgressStyle {
    ProgressStyle::with_template("{spinner:.yellow} {msg}")
        .expect("valid template")
        .tick_strings(&["◉", "◉", "◎", "○", "○", "◎", " "])
}

fn spinner_style() -> ProgressStyle {
    ProgressStyle::with_template("{spinner:.cyan} {msg}")
        .expect("valid template")
        .tick_strings(SPINNER)
}

/// Security keys stop waiting for a touch after about 30 seconds.
const TOUCH_WINDOW: Duration = Duration::from_secs(30);

fn touch_message(key: &str, waited: Duration) -> String {
    let left = TOUCH_WINDOW.saturating_sub(waited).as_secs();
    format!("Touch your {key} {}", paint(format!("· {left}s")).dim())
}

/// Run `work` behind a spinner and report each change it made.
pub fn spin_changes(working: &str, work: impl FnOnce() -> Result<Vec<String>>) -> Result<()> {
    for change in spin(working, work, |_| String::new())? {
        success(&change);
    }
    Ok(())
}

/// A line on its own at the end, like doctor's `→ Next: …`. Always after a
/// blank line: reports print to stdout, which `gap` doesn't see.
pub fn notice(message: &str) {
    if !AT_GAP.load(Ordering::Relaxed) {
        eprintln!();
    }
    say(format!("{} {}", paint("→").dim(), highlight(message)));
}

/// A finished change: `✓ Created ~/.ssh/…`.
pub fn success(message: &str) {
    if !message.is_empty() {
        say(format!("{} {}", paint("✓").green(), highlight(message)));
    }
}

/// Ask the person to act, e.g. enter a PIN; the tool's prompt follows.
pub fn step(message: &str) {
    say(format!("{} {}", paint("›").cyan(), highlight(message)));
}

/// Neutral information.
pub fn info(message: &str) {
    say(highlight(message));
}

pub fn warning(message: &str) {
    say(format!("{} {}", paint("!").yellow(), highlight(message)));
}

/// What to do about the line above, indented under its text.
pub fn hint(message: &str) {
    say(format!("  {} {}", paint("→").dim(), highlight(message)));
}

/// A green check mark, e.g. to mark the current choice.
pub fn check() -> String {
    paint("✓").green().to_string()
}

/// Show `backticked` text, such as commands, in cyan without the backticks.
pub fn highlight(text: &str) -> String {
    text.split('`')
        .enumerate()
        .map(|(index, part)| match index % 2 {
            1 => paint(part).cyan().to_string(),
            _ => part.to_owned(),
        })
        .collect()
}

/// `850ms`, `2.3s`, or `1m 05s`, like uv.
fn elapsed(duration: Duration) -> String {
    let millis = duration.as_millis();
    match millis {
        0..1000 => format!("{millis}ms"),
        1000..60_000 => format!("{:.1}s", duration.as_secs_f64()),
        _ => format!("{}m {:02}s", millis / 60_000, (millis / 1000) % 60),
    }
}

fn prompt_error(error: dialoguer::Error) -> Error {
    let dialoguer::Error::IO(error) = error;
    if error.kind() == io::ErrorKind::Interrupted {
        Error::Cancelled
    } else {
        Error::Failed(format!("could not read your answer: {error}"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn formats_durations_like_uv() {
        assert_eq!(elapsed(Duration::from_millis(850)), "850ms");
        assert_eq!(elapsed(Duration::from_millis(2340)), "2.3s");
        assert_eq!(elapsed(Duration::from_secs(65)), "1m 05s");
    }

    #[test]
    fn touch_prompt_counts_down_from_30() {
        assert_eq!(
            touch_message("YubiKey", Duration::from_secs(2)),
            "Touch your YubiKey · 28s"
        );
        assert_eq!(
            touch_message("security key", Duration::from_secs(40)),
            "Touch your security key · 0s"
        );
    }

    #[test]
    fn highlights_without_changing_plain_text() {
        // Colours are off when stderr is not a terminal, as in tests.
        assert_eq!(
            highlight("Wrote ~/.ssh/keymate/config via `ssh -G`"),
            "Wrote ~/.ssh/keymate/config via ssh -G"
        );
    }

    #[test]
    fn errors_read_like_sentences() {
        assert_eq!(
            sentence("could not run git: denied."),
            "Could not run git: denied"
        );
        assert_eq!(sentence("`gh` failed"), "`gh` failed");
        assert_eq!(sentence(""), "");
    }
}
