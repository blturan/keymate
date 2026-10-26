//! One authenticated SSH connection to GitHub, reused for several requests
//! through OpenSSH connection sharing (`ControlMaster`), so the person touches
//! the security key once for the access test and every organization check.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

use crate::process::{self, Output};
use crate::tools::sanitize;
use crate::{Error, Result};

const HOST: &str = "git@github.com";
const REQUEST_TIMEOUT: Duration = Duration::from_secs(20);

pub(crate) struct Connection {
    ssh: PathBuf,
    options: Vec<String>,
    socket: PathBuf,
    log: PathBuf,
    master: Child,
}

impl Connection {
    /// Connect with `options` (which pin the key and host keys), waiting up to
    /// `timeout` for the touch. With `asks_pin`, OpenSSH asks for the PIN on
    /// the terminal; otherwise it runs without one, so it can't stall on a
    /// prompt nobody sees. Temporary files go in `dir`.
    ///
    /// When the key isn't touched in time, OpenSSH takes it for a missing PIN:
    /// it asks for one, then has the key blink a second time. Its log shows
    /// the first refusal, so this stops there with [`Error::NotConfirmed`].
    pub fn open(
        ssh: &Path,
        options: Vec<String>,
        dir: &Path,
        timeout: Duration,
        asks_pin: bool,
    ) -> Result<Self> {
        let id = std::process::id();
        let socket = dir.join(format!("mux-{id}"));
        let log = dir.join(format!("ssh-{id}.log"));
        let _ = fs::remove_file(&socket);
        let _ = fs::remove_file(&log);

        let mut args = options.clone();
        args.extend(
            [
                "-o",
                "LogLevel=DEBUG1",
                "-M",
                "-S",
                &path(&socket),
                "-N",
                "-E",
                &path(&log),
                HOST,
            ]
            .map(String::from),
        );
        let mut command = Command::new(ssh);
        command
            .args(&args)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        if !asks_pin {
            process::detach(&mut command);
        }
        let master = command
            .spawn()
            .map_err(|e| Error::Failed(format!("could not run ssh: {e}")))?;
        let mut connection = Connection {
            ssh: ssh.to_owned(),
            options,
            socket,
            log,
            master,
        };

        // The control socket appears once authentication succeeded.
        let deadline = Instant::now() + timeout;
        loop {
            if connection.key_refused() {
                return Err(Error::NotConfirmed);
            }
            if connection.master.try_wait().ok().flatten().is_some() {
                return Err(Error::Failed(format!(
                    "GitHub did not accept the key: {}",
                    connection.last_log_line()
                )));
            }
            if connection.alive() {
                return Ok(connection);
            }
            if Instant::now() >= deadline {
                return Err(Error::NotConfirmed);
            }
            thread::sleep(Duration::from_millis(200));
        }
    }

    /// Whether the security key refused to sign: no touch in time, or a
    /// wrong PIN.
    fn key_refused(&self) -> bool {
        fs::read_to_string(&self.log).is_ok_and(|text| text.contains("helper returned error"))
    }

    fn alive(&self) -> bool {
        let args = [
            "-F",
            "/dev/null",
            "-S",
            &path(&self.socket),
            "-O",
            "check",
            HOST,
        ];
        process::run(&self.ssh, &args, REQUEST_TIMEOUT).is_ok_and(|o| o.status.success())
    }

    /// Run `command` (or request a session without one) over the connection.
    pub fn run(&self, command: Option<&str>) -> Result<Output> {
        let mut args = self.options.clone();
        args.extend(
            [
                "-S",
                &path(&self.socket),
                "-o",
                "ControlMaster=no",
                "-T",
                HOST,
            ]
            .map(String::from),
        );
        args.extend(command.map(String::from));
        process::run(&self.ssh, &args, REQUEST_TIMEOUT)
            .map_err(|e| Error::Failed(format!("the SSH request did not finish: {e}")))
    }

    fn last_log_line(&self) -> String {
        let text = fs::read_to_string(&self.log).unwrap_or_default();
        sanitize(text.lines().last().unwrap_or("no response").trim())
    }
}

impl Drop for Connection {
    fn drop(&mut self) {
        let _ = process::run(
            &self.ssh,
            &[
                "-F",
                "/dev/null",
                "-S",
                &path(&self.socket),
                "-O",
                "exit",
                HOST,
            ],
            REQUEST_TIMEOUT,
        );
        let _ = self.master.kill();
        let _ = self.master.wait();
        let _ = fs::remove_file(&self.socket);
        let _ = fs::remove_file(&self.log);
    }
}

fn path(path: &Path) -> String {
    path.display().to_string()
}
