//! Running external tools with structured arguments and a timeout.

use std::ffi::OsStr;
use std::io::{self, BufRead, BufReader, Read, Write};
use std::os::unix::process::CommandExt;
use std::path::Path;
use std::process::{Command, ExitStatus, Stdio};
use std::sync::mpsc;
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

pub(crate) struct Output {
    pub status: ExitStatus,
    pub stdout: String,
    pub stderr: String,
}

/// Run `program` without a shell or stdin, killing it after `timeout`.
///
/// Tools that need a PIN read it from `/dev/tty`, so they can still prompt.
pub(crate) fn run<S: AsRef<OsStr>>(
    program: &Path,
    args: &[S],
    timeout: Duration,
) -> io::Result<Output> {
    run_with_input(program, args, None, timeout)
}

/// Like [`run`], writing `input` to the program's stdin when given.
pub(crate) fn run_with_input<S: AsRef<OsStr>>(
    program: &Path,
    args: &[S],
    input: Option<&str>,
    timeout: Duration,
) -> io::Result<Output> {
    let mut command = Command::new(program);
    command.args(args);
    run_command(command, input, timeout)
}

/// Like [`run_with_input`], but without a controlling terminal, so a tool
/// that asks for a PIN on `/dev/tty` reads `input` instead. Keymate then asks
/// for the PIN itself, in its own words, and the tool's prompt stays hidden.
pub(crate) fn run_detached<S: AsRef<OsStr>>(
    program: &Path,
    args: &[S],
    input: &str,
    timeout: Duration,
) -> io::Result<Output> {
    run_detached_in(program, args, input, timeout, None)
}

/// Like [`run_detached`], in the working directory `dir` when given.
pub(crate) fn run_detached_in<S: AsRef<OsStr>>(
    program: &Path,
    args: &[S],
    input: &str,
    timeout: Duration,
    dir: Option<&Path>,
) -> io::Result<Output> {
    let mut command = Command::new(program);
    command.args(args);
    if let Some(dir) = dir {
        command.current_dir(dir);
    }
    detach(&mut command);
    run_command(command, Some(input), timeout)
}

/// Start `command` in its own session, without a controlling terminal, so it
/// can't prompt on `/dev/tty`.
pub(crate) fn detach(command: &mut Command) {
    unsafe extern "C" {
        fn setsid() -> i32;
    }
    // SAFETY: setsid is async-signal-safe and touches no memory of ours.
    unsafe {
        command.pre_exec(|| match setsid() {
            -1 => Err(io::Error::last_os_error()),
            _ => Ok(()),
        });
    }
}

fn run_command(mut command: Command, input: Option<&str>, timeout: Duration) -> io::Result<Output> {
    let mut child = command
        .stdin(if input.is_some() {
            Stdio::piped()
        } else {
            Stdio::null()
        })
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;
    if let (Some(input), Some(mut stdin)) = (input, child.stdin.take()) {
        let input = input.to_owned();
        thread::spawn(move || {
            let _ = stdin.write_all(input.as_bytes());
        });
    }
    let stdout = read_in_background(child.stdout.take());
    let stderr = read_in_background(child.stderr.take());

    let deadline = Instant::now() + timeout;
    let status = loop {
        if let Some(status) = child.try_wait()? {
            break status;
        }
        if Instant::now() >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                format!("did not finish within {} seconds", timeout.as_secs()),
            ));
        }
        thread::sleep(Duration::from_millis(20));
    };

    Ok(Output {
        status,
        stdout: stdout.join().unwrap_or_default(),
        stderr: stderr.join().unwrap_or_default(),
    })
}

/// Run `program` attached to the terminal so it can show its own prompts,
/// such as touch requests, PIN entry, or a browser sign-in code.
pub(crate) fn run_interactive<S: AsRef<OsStr>>(
    program: &Path,
    args: &[S],
) -> io::Result<ExitStatus> {
    Command::new(program).args(args).status()
}

/// Which output stream a line came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Stream {
    Stdout,
    Stderr,
}

/// Run `program` with the terminal as stdin (so it can prompt there) while
/// reading its output line by line as it appears.
pub(crate) fn run_streaming<S: AsRef<OsStr>>(
    program: &Path,
    args: &[S],
    mut on_line: impl FnMut(Stream, &str),
) -> io::Result<ExitStatus> {
    let mut child = Command::new(program)
        .args(args)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;
    let (sender, receiver) = mpsc::channel();
    let readers = [
        (
            Stream::Stdout,
            child
                .stdout
                .take()
                .map(|p| Box::new(p) as Box<dyn Read + Send>),
        ),
        (
            Stream::Stderr,
            child
                .stderr
                .take()
                .map(|p| Box::new(p) as Box<dyn Read + Send>),
        ),
    ]
    .map(|(stream, pipe)| {
        let sender = sender.clone();
        thread::spawn(move || {
            if let Some(pipe) = pipe {
                for line in BufReader::new(pipe).lines().map_while(io::Result::ok) {
                    let _ = sender.send((stream, line));
                }
            }
        })
    });
    drop(sender);
    for (stream, line) in receiver {
        on_line(stream, &line);
    }
    for reader in readers {
        let _ = reader.join();
    }
    child.wait()
}

fn read_in_background<R: Read + Send + 'static>(pipe: Option<R>) -> JoinHandle<String> {
    thread::spawn(move || {
        let mut bytes = Vec::new();
        if let Some(mut pipe) = pipe {
            let _ = pipe.read_to_end(&mut bytes);
        }
        String::from_utf8_lossy(&bytes).into_owned()
    })
}
