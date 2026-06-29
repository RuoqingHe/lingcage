// SPDX-FileCopyrightText: 2026 LingCage <opensource@lingcage.com>
//
// SPDX-License-Identifier: Apache-2.0

//! Running a command in sandbox, its process and exit status.

use std::collections::BTreeMap;
use std::fs::File;
use std::io::Read;
use std::sync::{Arc, mpsc};
use std::time::{Duration, Instant};

use crate::error::{Error, Result};
use crate::lcp;
pub use crate::lcp::PtySize;
use crate::sandbox::demux::Demux;

/// Command to be run in a sandbox.
#[derive(Debug, Clone, Default)]
pub struct Command {
    /// Program to run, looked up in `PATH` if it is a relative path.
    pub program: String,
    /// Arguments to the program, not including program name.
    pub args: Vec<String>,
    /// Environment variables for the command, replacing those of the agent.
    pub env: BTreeMap<String, String>,
    /// Working directory, defaults to the agent's if not set.
    pub cwd: Option<String>,
    /// User to run the command as, defaults to root if not set.
    pub user: Option<String>,
    /// PTY size to run the command under, no PTY if not set.
    pub pty: Option<PtySize>,
    /// Maximum time the command is allowed to run.
    pub timeout: Option<Duration>,
}

impl Command {
    /// Create a command which runs `program` without arguments.
    pub fn new(program: impl Into<String>) -> Self {
        Command {
            program: program.into(),
            ..Default::default()
        }
    }

    /// Add one argument to the command.
    pub fn arg(mut self, arg: impl Into<String>) -> Self {
        self.args.push(arg.into());
        self
    }

    /// Add multiple arguments to the command.
    pub fn args<I, S>(mut self, args: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.args.extend(args.into_iter().map(Into::into));
        self
    }

    /// Set one environment variable for the command.
    pub fn env(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.env.insert(key.into(), value.into());
        self
    }

    /// Set working directory of the command.
    pub fn cwd(mut self, cwd: impl Into<String>) -> Self {
        self.cwd = Some(cwd.into());
        self
    }

    /// Run the command under a PTY with given `size`.
    pub fn pty(mut self, size: PtySize) -> Self {
        self.pty = Some(size);
        self
    }

    /// Set timeout for the command.
    pub fn timeout(mut self, timeout: Duration) -> Self {
        self.timeout = Some(timeout);
        self
    }
}

/// Receiver of frames reported for a started command, exit or error.
pub(crate) type ExitWatch = mpsc::Receiver<lcp::Frame>;

/// Running command with its streams and exit status once it ends. Each
/// stream is a separate connection. Dropping `stdin` closes it and the
/// command would read EOF. Dropping `Process` closes all three streams
/// but leaves the command running until the sandbox stops, use `signal`
/// then `wait` to end it properly.
pub struct Process {
    /// Stdin of the command.
    pub stdin: Option<File>,
    /// Stdout of the command.
    pub stdout: Option<File>,
    /// Stderr of the command.
    pub stderr: Option<File>,
    /// Pid of the command process in the guest.
    pub(crate) pid: u32,
    /// Receives the exit frame and errors reported with the command's id.
    pub(crate) exit: ExitWatch,
    /// Demux used to send resize and signal frames.
    pub(crate) demux: Arc<Demux>,
    /// Id of the exec exchange, frames with this id are routed to `exit`.
    pub(crate) id: u32,
}

impl Process {
    /// Returns the pid of the command in the guest.
    pub fn pid(&self) -> u32 {
        self.pid
    }

    /// Resize the PTY of the command. The frame is sent to the agent without
    /// waiting for a reply, if the agent refuses it, the error is reported on
    /// the exit watch and returned by `wait` as `Error::Agent`.
    pub fn resize(&self, size: PtySize) -> Result<()> {
        let frame = lcp::Frame::with_payload(self.id, lcp::kind::EXEC_RESIZE, 0, &size)
            .map_err(Error::Protocol)?;
        self.demux.tell(frame)
    }

    /// Send `signal` to the process group of the command, delivered in the
    /// same way as `resize`.
    pub fn signal(&self, signal: i32) -> Result<()> {
        let frame =
            lcp::Frame::with_payload(self.id, lcp::kind::EXEC_SIGNAL, 0, &lcp::Signal { signal })
                .map_err(Error::Protocol)?;
        self.demux.tell(frame)
    }

    /// Close stdin, wait for the command to end and return its exit status.
    /// Output streams are kept open until then, a command which fills them up
    /// would block, so read them first or use `wait_with_output` instead.
    ///
    /// There is no deadline for this wait since the command's own timeout
    /// bounds it. If the agent stops responding, this thread is held until
    /// the sandbox is ended from another thread. Use `wait_timeout` to wait
    /// with a deadline.
    pub fn wait(mut self) -> Result<ExitStatus> {
        let status = self.wait_until(None)?;
        Ok(status.expect("wait without deadline ends with a status"))
    }

    /// Close stdin and wait at most `within` for the command to end. `None`
    /// is returned if the command is still running, caller may wait again.
    /// Note that the status is received only once, a wait after that would
    /// report the connection as ended.
    pub fn wait_timeout(&mut self, within: Duration) -> Result<Option<ExitStatus>> {
        self.wait_until(Some(Instant::now() + within))
    }

    /// Common wait used by both, reads frames until exit or `deadline`.
    fn wait_until(&mut self, deadline: Option<Instant>) -> Result<Option<ExitStatus>> {
        drop(self.stdin.take());
        let status = loop {
            let frame = match deadline {
                None => self
                    .exit
                    .recv()
                    .map_err(|_| Error::Protocol(lcp::Error::Truncated))?,
                Some(at) => match self
                    .exit
                    .recv_timeout(at.saturating_duration_since(Instant::now()))
                {
                    Ok(frame) => frame,
                    Err(mpsc::RecvTimeoutError::Timeout) => return Ok(None),
                    Err(mpsc::RecvTimeoutError::Disconnected) => {
                        return Err(Error::Protocol(lcp::Error::Truncated));
                    }
                },
            };
            match frame.kind {
                lcp::kind::EXEC_EXIT => {
                    break frame.payload::<lcp::ExecExit>().map_err(Error::Protocol)?;
                }
                lcp::kind::ERROR => {
                    let report: lcp::ErrorPayload = frame.payload().map_err(Error::Protocol)?;
                    return Err(Error::Agent {
                        what: format!("{}: {}", report.code, report.message),
                    });
                }
                other => log::warn!("unexpected frame of kind {other} on exit watch, dropped"),
            }
        };
        exit_status(&status).map(Some)
    }

    /// Close stdin, read stdout and stderr to EOF, then wait for the command
    /// to end.
    pub fn wait_with_output(mut self) -> Result<Output> {
        drop(self.stdin.take());
        let mut stdout = self.stdout.take();
        let mut stderr = self.stderr.take();
        let (out, err) = std::thread::scope(|scope| {
            let err = scope.spawn(move || read_all(stderr.as_mut()));
            let out = read_all(stdout.as_mut());
            (out, err.join().expect("stderr reader panicked"))
        });
        let status = self.wait()?;
        Ok(Output {
            status,
            stdout: out.map_err(Error::Io)?,
            stderr: err.map_err(Error::Io)?,
        })
    }
}

impl Drop for Process {
    fn drop(&mut self) {
        self.demux.complete(self.id);
    }
}

/// Read `stream` to EOF, returns empty bytes if the stream is absent.
fn read_all(stream: Option<&mut File>) -> std::io::Result<Vec<u8>> {
    let mut bytes = Vec::new();
    if let Some(stream) = stream {
        stream.read_to_end(&mut bytes)?;
    }
    Ok(bytes)
}

/// Map an exit report to `ExitStatus`, a kill by the command's own timeout
/// is `TimedOut`, then the code, then the signal. Timeout is flagged in
/// the report since host clock can not tell such a kill from another.
fn exit_status(report: &lcp::ExecExit) -> Result<ExitStatus> {
    match (report.code, report.signal) {
        _ if report.timed_out => Ok(ExitStatus::TimedOut),
        (Some(code), None) => Ok(ExitStatus::Exited(code)),
        (None, Some(signal)) => Ok(ExitStatus::Signalled(signal)),
        _ => Err(Error::Agent {
            what: "exit report with both code and signal, or neither".to_string(),
        }),
    }
}

/// Exit status of a command.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExitStatus {
    /// Command exited with given code.
    Exited(i32),
    /// Command was killed by given signal.
    Signalled(i32),
    /// Timeout of the command expired.
    TimedOut,
}

impl ExitStatus {
    /// Returns `true` if the command exited with code 0.
    pub fn success(&self) -> bool {
        *self == ExitStatus::Exited(0)
    }

    /// Returns the exit code, `None` for a killed or timed out command.
    pub fn code(&self) -> Option<i32> {
        match self {
            ExitStatus::Exited(code) => Some(*code),
            _ => None,
        }
    }
}

/// Exit status of a command together with its full output.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Output {
    /// Exit status of the command.
    pub status: ExitStatus,
    /// Bytes written to stdout by the command.
    pub stdout: Vec<u8>,
    /// Bytes written to stderr by the command.
    pub stderr: Vec<u8>,
}

#[cfg(test)]
mod tests {
    use crate::sandbox::exec::*;

    #[test]
    fn test_command_builder() {
        let command = Command::new("sh")
            .arg("-c")
            .args(["echo", "hi"])
            .env("PATH", "/bin")
            .cwd("/tmp")
            .pty(PtySize { rows: 24, cols: 80 })
            .timeout(Duration::from_secs(5));
        assert_eq!(command.program, "sh");
        assert_eq!(command.args, vec!["-c", "echo", "hi"]);
        assert_eq!(command.env.get("PATH").map(String::as_str), Some("/bin"));
        assert_eq!(command.cwd.as_deref(), Some("/tmp"));
        assert_eq!(command.pty, Some(PtySize { rows: 24, cols: 80 }));
        assert_eq!(command.timeout, Some(Duration::from_secs(5)));
    }

    /// Helper to build an exit report of a command not killed by timeout.
    fn ended(code: Option<i32>, signal: Option<i32>) -> lcp::ExecExit {
        lcp::ExecExit {
            code,
            signal,
            timed_out: false,
        }
    }

    #[test]
    fn test_exit_code_to_exited() {
        let report = ended(Some(3), None);
        let status = exit_status(&report).expect("map a code");
        assert_eq!(status, ExitStatus::Exited(3));
        assert_eq!(status.code(), Some(3));
        assert!(!status.success());
        assert!(ExitStatus::Exited(0).success());
    }

    #[test]
    fn test_signal_to_signalled() {
        let status = exit_status(&ended(None, Some(15))).expect("map a signal");
        assert_eq!(status, ExitStatus::Signalled(15));
        assert_eq!(status.code(), None);
    }

    #[test]
    fn test_timeout_kill_to_timed_out() {
        let report = lcp::ExecExit {
            code: None,
            signal: Some(libc::SIGKILL),
            timed_out: true,
        };
        assert_eq!(
            exit_status(&report).expect("map the kill"),
            ExitStatus::TimedOut
        );
    }

    #[test]
    fn test_plain_kill_to_signalled() {
        // SIGKILL without timed_out flag maps to Signalled.
        let report = ended(None, Some(libc::SIGKILL));
        assert_eq!(
            exit_status(&report).expect("map the kill"),
            ExitStatus::Signalled(libc::SIGKILL)
        );
    }

    #[test]
    fn test_invalid_report_agent_error() {
        // Both code and signal set, or neither, should be an agent error.
        assert!(matches!(
            exit_status(&ended(Some(0), Some(9))),
            Err(Error::Agent { .. })
        ));
        assert!(matches!(
            exit_status(&ended(None, None)),
            Err(Error::Agent { .. })
        ));
    }
}
