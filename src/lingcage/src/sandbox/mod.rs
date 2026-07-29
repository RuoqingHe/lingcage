// SPDX-FileCopyrightText: 2026 LingCage <opensource@lingcage.com>
//
// SPDX-License-Identifier: Apache-2.0

//! Sandbox in this process, a guest cloned from template and driven
//! through its control connection, with console attached. [`Starting`]
//! and [`Sandbox`] are separate types, only the latter runs commands.
//! Teardown consumes the sandbox, `shutdown` and `kill` take `self` and
//! dropping a sandbox tears it down as `kill` does.

pub mod console;
pub mod demux;
pub mod exec;
pub mod spec;

use std::fs::File;
use std::io::Read as _;
use std::os::fd::OwnedFd;
use std::os::unix::net::UnixListener;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, Weak, mpsc};
use std::time::{Duration, Instant};

use lingcore::hv::backend::kvm::hypervisor::KvmHv;
use lingcore::hv::vcpu::VmExit;
use lingcore::machine::{Channel, Config, Machine, State};
use lingcore::seccomp::Refusal;

use crate::error::{Error, Result};
use crate::hv::Hv;
use crate::lcp;
use crate::random::draw;
use crate::sandbox::console::{Console, Sink};
use crate::sandbox::demux::{Demux, accept_within};
use crate::sandbox::exec::{Command, ExitWatch, Process};
use crate::sandbox::spec::{Limits, SandboxSpec};
use crate::template::Template;

/// Host port the agent connects to for control connection.
const CONTROL_PORT: u32 = 1;

/// Host port the agent connects to for log connection.
const LOG_PORT: u32 = 2;

/// Lowest host port assigned to a stream, ports below are fixed.
const FIRST_STREAM_PORT: u32 = 1024;

/// Number of tries to draw a free stream port before `exec` fails.
const PORT_DRAWS: u32 = 8;

/// Maximum time `exec` waits for the start report and stream connections.
const EXEC_WITHIN: Duration = Duration::from_secs(10);

/// Maximum time `ping` waits for the reply.
const PING_WITHIN: Duration = Duration::from_secs(5);

/// Number of console bytes attached to readiness failure.
const CONSOLE_TAIL: usize = 4 << 10;

/// Id of a sandbox, twelve hex chars randomly drawn at spawn.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct SandboxId(String);

impl SandboxId {
    /// Returns the id as string slice.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Display for SandboxId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

/// Identity of the guest, applied at handshake.
#[derive(Debug, Clone)]
pub struct Identity {
    /// Vsock context id of the guest.
    pub cid: u64,
    /// Hostname to be set in the guest.
    pub hostname: String,
    /// Value written to `/etc/machine-id` inside the guest.
    pub machine_id: String,
}

/// Exit of a sandbox, as returned by `shutdown` and `kill`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Exit {
    /// Guest powered off as requested.
    PoweredOff,
    /// Guest reset instead of powering off, reset ends the machine as well.
    Rebooted,
    /// Guest was stopped without power-off, `after` the request was sent.
    Killed {
        /// Time allowed for power-off before the forced stop.
        after: Duration,
    },
    /// A vCPU exited `run` for another reason, kept in `what`.
    Failed {
        /// Exit reason as reported by the backend.
        what: String,
    },
}

/// Started sandbox, its agent has not connected yet.
pub struct Starting {
    inner: Inner,
}

impl Starting {
    /// Wait at most `within` for the agent to connect and identify itself,
    /// otherwise the guest is torn down and the tail of its console is
    /// attached to the error.
    pub fn ready(mut self, within: Duration) -> Result<Sandbox> {
        let deadline = Instant::now() + within;
        match self.inner.demux.identify_first(deadline) {
            Ok((hostname, ready)) => {
                log::info!(
                    "sandbox {} ready as {hostname}, agent {} up in {} ms, guest uptime {:.2} s, \
                     {:.1} ms after start",
                    self.inner.id,
                    ready.agent,
                    ready.init_ms,
                    ready.uptime,
                    self.inner.started.elapsed().as_secs_f64() * 1e3
                );
                crate::event::emit(
                    "sandbox",
                    "ready",
                    serde_json::json!({
                        "id": self.inner.id.as_str(),
                        "hostname": hostname,
                        "agent": ready.agent,
                        "init_ms": ready.init_ms,
                        "uptime": ready.uptime,
                        "after_ms": self.inner.started.elapsed().as_millis() as u64,
                    }),
                );
                self.inner.identity.hostname = hostname;
                Ok(Sandbox {
                    inner: Arc::new(self.inner),
                })
            }
            Err(_) if self.inner.faulted() => {
                if let Err(err) = self.inner.teardown("lost image") {
                    log::warn!("teardown of guest with lost image failed: {err}");
                }
                Err(Error::Image)
            }
            Err(source) => {
                let console_tail = self.inner.console.tail(CONSOLE_TAIL);
                if let Err(err) = self.inner.teardown("not ready") {
                    log::warn!("teardown of not ready guest failed: {err}");
                }
                Err(Error::NotReady {
                    console_tail,
                    source: Box::new(source),
                })
            }
        }
    }

    /// Console of the guest, useful for diagnosing readiness failure.
    pub fn console(&self) -> Console {
        self.inner.console.clone()
    }

    /// Give up on the guest and tear it down.
    pub fn abandon(self) -> Result<()> {
        self.inner.teardown("abandoned")
    }
}

/// Ready sandbox, a guest in this process with agent on the control
/// connection. It is `Send + Sync` and guest operations take `&self`, so
/// multiple threads can issue operations concurrently without extra locking.
pub struct Sandbox {
    inner: Arc<Inner>,
}

impl Sandbox {
    /// Clone the template, restore and start it under a run directory of
    /// the store. This returns before the guest is usable, call
    /// `Starting::ready` to wait for the agent.
    pub fn start(hv: &Hv, template: &Template, spec: &SandboxSpec) -> Result<Starting> {
        let shape = &template.meta().shape;
        let of_template = Limits {
            memory: shape.memory,
            vcpus: shape.vcpus,
        };
        if spec.limits != of_template {
            return Err(Error::Shape {
                asked: spec.limits.to_string(),
                shape: of_template.to_string(),
            });
        }
        let id = sandbox_id()?;
        let run_dir = template.run_root().join(id.as_str());
        std::fs::create_dir_all(&run_dir).map_err(Error::Io)?;
        std::fs::set_permissions(
            &run_dir,
            std::os::unix::fs::PermissionsExt::from_mode(0o700),
        )
        .map_err(Error::Io)?;
        match assemble(hv, template, spec, id, run_dir.clone()) {
            Ok(starting) => {
                crate::event::emit(
                    "sandbox",
                    "starting",
                    serde_json::json!({
                        "id": starting.inner.id.as_str(),
                        "template": template.id().to_string(),
                        "hostname": starting.inner.identity.hostname,
                    }),
                );
                Ok(starting)
            }
            Err(err) => {
                if let Err(left) = std::fs::remove_dir_all(&run_dir) {
                    log::warn!("run directory of failed start not removed: {left}");
                }
                Err(err)
            }
        }
    }

    /// Returns `Error::Image` if a page of the RAM image is lost under the
    /// guest, which happens with a truncated image. The guest reads zeros
    /// for its memory in that case, caller should end the sandbox on this.
    fn sound(&self) -> Result<()> {
        if self.inner.faulted() {
            return Err(Error::Image);
        }
        Ok(())
    }

    /// Returns `Error::Image` in place of `err` if the RAM image is lost,
    /// since a command not started on a guest reading zeros for its memory
    /// has only one reason worth reporting.
    fn blame(&self, err: Error) -> Error {
        match self.sound() {
            Err(image) => image,
            Ok(()) => err,
        }
    }

    pub fn id(&self) -> &SandboxId {
        &self.inner.id
    }

    /// Returns the identity applied at handshake.
    pub fn identity(&self) -> &Identity {
        &self.inner.identity
    }

    /// Console of the guest, for reading recent output and writing input.
    pub fn console(&self) -> Console {
        self.inner.console.clone()
    }

    /// Run a command. Its three streams are separate connections, each of
    /// them is opened by the guest with the nonce given in the request.
    pub fn exec(&self, command: Command) -> Result<Process> {
        self.sound()?;
        let prefix = &self.inner.vsock_prefix;
        let stdin = bind_stream(prefix)?;
        let stdout = bind_stream(prefix)?;
        let stderr = bind_stream(prefix)?;
        let timeout = command.timeout;
        let exec = lcp::Exec {
            program: command.program,
            args: command.args,
            env: command.env,
            cwd: command.cwd,
            user: command.user,
            pty: command.pty,
            timeout_ms: timeout.map(|within| u64::try_from(within.as_millis()).unwrap_or(u64::MAX)),
            stdin: Some(stdin.stream),
            stdout: stdout.stream,
            stderr: stderr.stream,
        };
        let frame = lcp::Frame::with_payload(0, lcp::kind::EXEC, lcp::flags::SESSION_START, &exec)
            .map_err(Error::Protocol)?;
        let started = Instant::now();
        let deadline = started + EXEC_WITHIN;
        let demux = &self.inner.demux;
        let (id, watch) = demux.request(frame)?;
        let pid = match read_started(&watch, deadline) {
            Ok(pid) => pid,
            Err(err) => {
                // Missing start report does not mean the command is not
                // running, kill it anyway to cover both cases.
                kill_command(demux, id);
                return Err(self.blame(err));
            }
        };
        let accepted = accept_stream(&stdin, deadline).and_then(|stdin| {
            Ok((
                stdin,
                accept_stream(&stdout, deadline)?,
                accept_stream(&stderr, deadline)?,
            ))
        });
        match accepted {
            Ok((stdin, stdout, stderr)) => Ok(Process {
                stdin: Some(stdin),
                stdout: Some(stdout),
                stderr: Some(stderr),
                pid,
                exit: watch,
                demux: Arc::clone(demux),
                id,
            }),
            Err(err) => {
                // Command is already running in the guest but the host side
                // of its streams is not connected, kill it.
                kill_command(demux, id);
                Err(err)
            }
        }
    }

    /// Round-trip a nonce through the agent and return the time it took. A
    /// wedged guest which holds the connection open without replying costs
    /// `PING_WITHIN`, detecting such guest is the purpose of this call.
    pub fn ping(&self) -> Result<Duration> {
        self.sound()?;
        let mut nonce = [0u8; 8];
        draw(&mut nonce)?;
        let nonce = u64::from_be_bytes(nonce);
        let frame = lcp::Frame::with_payload(
            0,
            lcp::kind::PING,
            lcp::flags::SESSION_START,
            &lcp::Ping { nonce },
        )
        .map_err(Error::Protocol)?;
        let start = Instant::now();
        let answer = self
            .inner
            .demux
            .ask(frame, PING_WITHIN)
            .map_err(|err| self.blame(err))?;
        if answer.kind != lcp::kind::PONG {
            return Err(Error::Agent {
                what: format!("unexpected reply of kind {} to ping", answer.kind),
            });
        }
        let pong: lcp::Pong = answer.payload().map_err(Error::Protocol)?;
        if pong.nonce != nonce {
            return Err(Error::Agent {
                what: "pong returned with different nonce".to_string(),
            });
        }
        Ok(start.elapsed())
    }

    /// Request the guest to power off, stop it forcibly if it has not done
    /// so `within` the given time, then tear down. This consumes the
    /// sandbox, sockets are unlinked and run directory is removed.
    pub fn shutdown(self, within: Duration) -> Result<Exit> {
        if *self.inner.torn.lock().unwrap() {
            return Ok(Exit::Killed {
                after: Duration::ZERO,
            });
        }
        // If shutdown request is not sent, the guest would not power off
        // and the wait below just times out, then the guest gets stopped.
        if let Err(err) = self
            .inner
            .demux
            .tell_with_new_id(lcp::kind::SHUTDOWN, lcp::flags::SHUTDOWN)
        {
            log::warn!("failed to send shutdown request: {err}");
        }
        let exit = self.inner.await_exit(within)?;
        self.inner.teardown(&how(&exit))?;
        Ok(exit)
    }

    /// Stop the guest without power-off and tear down, consumes the sandbox.
    pub fn kill(self) -> Result<Exit> {
        self.inner.teardown("killed")?;
        Ok(Exit::Killed {
            after: Duration::ZERO,
        })
    }

    /// Returns a handle to stop the sandbox from another thread.
    pub fn stopper(&self) -> Stopper {
        Stopper {
            inner: Arc::downgrade(&self.inner),
        }
    }
}

/// Handle to stop a sandbox from another thread, which has the same effect
/// as `kill` but leaves the sandbox itself to its owner.
#[derive(Clone)]
pub struct Stopper {
    inner: Weak<Inner>,
}

impl Stopper {
    /// Stop the guest and tear down as `Sandbox::kill` does. No-op if the
    /// sandbox is already dropped.
    pub fn kill(&self) -> Result<()> {
        match self.inner.upgrade() {
            Some(inner) => inner.teardown("killed"),
            None => Ok(()),
        }
    }
}

/// State shared by `Starting` and `Sandbox`, torn down only once.
struct Inner {
    id: SandboxId,
    identity: Identity,
    /// The guest machine. Teardown drops it together with its RAM and the
    /// device ends of the streams.
    machine: Mutex<Option<Machine<KvmHv>>>,
    demux: Arc<Demux>,
    console: Console,
    run_dir: PathBuf,
    /// Socket prefix of the channel, socket of a port is `<prefix>_<port>`.
    vsock_prefix: PathBuf,
    /// Dup of the template's RAM image. Shared flock on it prevents the
    /// store from removing the template while the sandbox is using it,
    /// until teardown.
    image: Mutex<Option<File>>,
    /// Moment the start began, readiness is logged against it.
    started: Instant,
    /// Set by teardown, the lock is held for the entire teardown so that a
    /// second caller would wait for the first one to finish.
    torn: Mutex<bool>,
}

impl Inner {
    /// Returns whether a page of the RAM image mapped by the guest is lost.
    fn faulted(&self) -> bool {
        self.machine
            .lock()
            .unwrap()
            .as_ref()
            .is_some_and(|machine| machine.faulted())
    }

    /// Wait at most `within` for a vCPU to leave `run`, stop the guest if
    /// none did, and return the corresponding `Exit`.
    fn await_exit(&self, within: Duration) -> Result<Exit> {
        let mut guard = self.machine.lock().unwrap();
        let Some(machine) = guard.as_mut() else {
            return Ok(Exit::Killed {
                after: Duration::ZERO,
            });
        };
        match machine.wait_timeout(within).map_err(Error::Lingcore)? {
            Some(VmExit::Shutdown) => Ok(Exit::PoweredOff),
            Some(VmExit::Reboot) => Ok(Exit::Rebooted),
            Some(other) => Ok(Exit::Failed {
                what: format!("{other:?}"),
            }),
            None => {
                machine.stop().map_err(Error::Lingcore)?;
                machine.wait().map_err(Error::Lingcore)?;
                Ok(Exit::Killed { after: within })
            }
        }
    }

    /// Stop the guest and join its threads, stop the demux and remove the
    /// run directory, only once. `how` goes into the log line, "powered
    /// off" or "killed". `torn` flag is not set if teardown fails, so
    /// that the following drop would try again.
    fn teardown(&self, how: &str) -> Result<()> {
        let mut torn = self.torn.lock().unwrap();
        if *torn {
            return Ok(());
        }
        log::info!("sandbox {} torn down, {how}", self.id);
        crate::event::emit(
            "sandbox",
            "stopped",
            serde_json::json!({ "id": self.id.as_str(), "how": how }),
        );
        let stopped = match self.machine.lock().unwrap().take() {
            Some(mut machine) if matches!(machine.state(), State::Running | State::Paused) => {
                machine.stop().and_then(|()| machine.wait().map(drop))
            }
            _ => Ok(()),
        }
        .map_err(Error::Lingcore);
        self.demux.stop();
        let removed = match std::fs::remove_dir_all(&self.run_dir) {
            Err(gone) if gone.kind() == std::io::ErrorKind::NotFound => Ok(()),
            other => other.map_err(Error::Io),
        };
        drop(self.image.lock().unwrap().take());
        let done = stopped.and(removed);
        *torn = done.is_ok();
        done
    }
}

impl Drop for Inner {
    fn drop(&mut self) {
        if let Err(err) = self.teardown("dropped") {
            log::warn!("teardown of sandbox {} failed: {err}", self.id);
        }
    }
}

/// Returns the reason text of `exit` for a log line.
fn how(exit: &Exit) -> String {
    match exit {
        Exit::PoweredOff => "powered off".to_string(),
        Exit::Rebooted => "rebooted".to_string(),
        Exit::Killed { after } => format!("killed after {} s", after.as_secs()),
        Exit::Failed { what } => format!("failed: {what}"),
    }
}

/// Assemble the guest and its channel under `run_dir`. Caller is
/// responsible for removing the directory on error. No thread is spawned
/// for the machine until `start`, which is the last fallible step.
fn assemble(
    hv: &Hv,
    template: &Template,
    spec: &SandboxSpec,
    id: SandboxId,
    run_dir: PathBuf,
) -> Result<Starting> {
    let started = Instant::now();
    let vsock_prefix = run_dir.join("vs");
    let cid = crate::hv::next_cid();
    let shape = &template.meta().shape;
    let config = Config {
        memory: shape.memory,
        vcpus: shape.vcpus,
        kernel: template.kernel_path(),
        initrd: None,
        cmdline: String::new(),
        disks: Vec::new(),
        shares: Vec::new(),
        ports: Vec::new(),
        channel: Some(Channel {
            cid,
            at: vsock_prefix.clone(),
            ..Default::default()
        }),
        network: None,
        confine: Some(Refusal::Trap),
    };
    let sink = Sink::default();
    let image = template.ram().try_clone().map_err(Error::Io)?;
    let mut machine = Machine::cloned(hv.core(), &config, sink.clone(), template.ram())
        .map_err(Error::Lingcore)?;
    // State document is read through a buffer, since JSON reader reads one
    // byte at a time, which would be one syscall each on a bare file.
    machine
        .restore(template.state()?)
        .map_err(Error::Lingcore)?;
    // Bind both listeners before the guest runs, so that connections from
    // the agent are queued in the backlog.
    let control_at = at(&vsock_prefix, CONTROL_PORT);
    let control = UnixListener::bind(&control_at).map_err(Error::Io)?;
    let logs = UnixListener::bind(at(&vsock_prefix, LOG_PORT)).map_err(Error::Io)?;
    let identity = Identity {
        cid,
        hostname: hostname_of(spec, &id),
        machine_id: machine_id()?,
    };
    let demux = Arc::new(Demux::new(
        control,
        control_at,
        identity.clone(),
        Some(logs),
    ));
    machine.start().map_err(Error::Lingcore)?;
    let console = Console::new(&sink, machine.console());
    Ok(Starting {
        inner: Inner {
            id,
            identity,
            machine: Mutex::new(Some(machine)),
            demux,
            console,
            run_dir,
            vsock_prefix,
            image: Mutex::new(Some(image)),
            started,
            torn: Mutex::new(false),
        },
    })
}

/// Kill the command of `id` and remove its request from demux, used by
/// paths which give up on a command possibly still running in the guest.
fn kill_command(demux: &Demux, id: u32) {
    let kill = lcp::Frame::with_payload(
        id,
        lcp::kind::EXEC_SIGNAL,
        0,
        &lcp::Signal {
            signal: libc::SIGKILL,
        },
    )
    .map_err(Error::Protocol)
    .and_then(|frame| demux.tell(frame));
    if let Err(err) = kill {
        log::warn!("failed to send kill for abandoned command: {err}");
    }
    demux.complete(id);
}

/// Read start report of a command from `watch` before `deadline`. Returns
/// pid of the command, or the failure reported by agent.
fn read_started(watch: &ExitWatch, deadline: Instant) -> Result<u32> {
    let frame = watch
        .recv_timeout(deadline.saturating_duration_since(Instant::now()))
        .map_err(|err| match err {
            mpsc::RecvTimeoutError::Timeout => Error::Timeout("command start report"),
            mpsc::RecvTimeoutError::Disconnected => Error::Protocol(lcp::Error::Truncated),
        })?;
    match frame.kind {
        lcp::kind::EXEC_STARTED => {
            let started: lcp::ExecStarted = frame.payload().map_err(Error::Protocol)?;
            Ok(started.pid)
        }
        lcp::kind::EXEC_FAILED => {
            let failed: lcp::ExecFailed = frame.payload().map_err(Error::Protocol)?;
            Err(Error::ExecFailed {
                reason: failed.reason,
                errno: failed.errno,
            })
        }
        lcp::kind::ERROR => {
            let report: lcp::ErrorPayload = frame.payload().map_err(Error::Protocol)?;
            Err(Error::Agent {
                what: format!("{}: {}", report.code, report.message),
            })
        }
        other => Err(Error::Agent {
            what: format!("unexpected reply of kind {other} to command"),
        }),
    }
}

/// Stream port bound to a single command, its socket file is unlinked
/// on drop.
struct Bound {
    stream: lcp::Stream,
    listener: UnixListener,
    path: PathBuf,
}

impl Drop for Bound {
    fn drop(&mut self) {
        if let Err(err) = std::fs::remove_file(&self.path) {
            log::warn!("failed to remove {}: {err}", self.path.display());
        }
    }
}

/// Bind a listener on a randomly picked stream port, and generate the
/// nonce for the guest to open the connection with.
fn bind_stream(prefix: &Path) -> Result<Bound> {
    for _ in 0..PORT_DRAWS {
        let mut bytes = [0u8; 12];
        draw(&mut bytes)?;
        let (port, nonce) = bytes.split_at(4);
        let port = FIRST_STREAM_PORT
            + u32::from_be_bytes(port.try_into().expect("four bytes"))
                % (u32::MAX - FIRST_STREAM_PORT);
        let path = at(prefix, port);
        match UnixListener::bind(&path) {
            Ok(listener) => {
                return Ok(Bound {
                    stream: lcp::Stream {
                        port,
                        nonce: u64::from_be_bytes(nonce.try_into().expect("eight bytes")),
                    },
                    listener,
                    path,
                });
            }
            Err(err) if err.kind() == std::io::ErrorKind::AddrInUse => {}
            Err(err) => return Err(Error::Io(err)),
        }
    }
    Err(Error::Io(std::io::Error::from(
        std::io::ErrorKind::AddrInUse,
    )))
}

/// Accept the guest's connection on `bound` before `deadline`. Only the
/// connection which sends the correct nonce is returned as the stream,
/// others are closed.
fn accept_stream(bound: &Bound, deadline: Instant) -> Result<File> {
    loop {
        let conn = accept_within(&bound.listener, deadline, "incoming stream connection")?;
        let left = deadline.saturating_duration_since(Instant::now());
        if left.is_zero() {
            return Err(Error::Timeout("a stream's nonce"));
        }
        conn.set_read_timeout(Some(left)).map_err(Error::Io)?;
        let mut nonce = [0u8; lcp::NONCE];
        match (&conn).read_exact(&mut nonce) {
            Ok(()) if u64::from_be_bytes(nonce) == bound.stream.nonce => {
                conn.set_read_timeout(None).map_err(Error::Io)?;
                return Ok(File::from(OwnedFd::from(conn)));
            }
            Ok(()) => log::warn!(
                "connection on port {} sent unexpected nonce, closed",
                bound.stream.port
            ),
            Err(err) => log::warn!(
                "connection on port {} closed before sending nonce: {err}",
                bound.stream.port
            ),
        }
    }
}

/// Returns lowercase hex string of `bytes`.
fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

/// Generate a new sandbox id, twelve hex chars from `/dev/urandom`.
fn sandbox_id() -> Result<SandboxId> {
    let mut bytes = [0u8; 6];
    draw(&mut bytes)?;
    Ok(SandboxId(hex(&bytes)))
}

/// Generate a new machine id, 32 hex chars from `/dev/urandom`.
fn machine_id() -> Result<String> {
    let mut bytes = [0u8; 16];
    draw(&mut bytes)?;
    Ok(hex(&bytes))
}

/// Hostname from `hostname` label of the spec, `lc-<id>` if not set.
fn hostname_of(spec: &SandboxSpec, id: &SandboxId) -> String {
    match spec.labels.get("hostname") {
        Some(hostname) => hostname.clone(),
        None => format!("lc-{}", id.as_str()),
    }
}

/// Socket path of `port` under `prefix`, which is `<prefix>_<port>`.
fn at(prefix: &Path, port: u32) -> PathBuf {
    let mut path = prefix.as_os_str().to_os_string();
    path.push(format!("_{port}"));
    PathBuf::from(path)
}

#[cfg(test)]
mod tests {
    use crate::sandbox::*;
    use crate::template::TemplateId;

    #[test]
    fn test_sandbox_send_sync() {
        fn check<T: Send + Sync>() {}
        check::<Sandbox>();
        check::<Starting>();
        check::<Console>();
    }

    #[test]
    fn test_stopper_noop_after_sandbox_gone() {
        let stopper = Stopper { inner: Weak::new() };
        stopper.kill().expect("kill on stopper of gone sandbox");
    }

    #[test]
    fn test_socket_path_port_suffix() {
        let prefix = PathBuf::from("/run/lc/vs");
        assert_eq!(at(&prefix, 1), PathBuf::from("/run/lc/vs_1"));
        assert_eq!(at(&prefix, 1024), PathBuf::from("/run/lc/vs_1024"));
    }

    #[test]
    fn test_hostname_from_label_or_id() {
        let mut spec = SandboxSpec {
            template: TemplateId::from("t"),
            limits: Limits::default(),
            labels: Default::default(),
        };
        let id = SandboxId("0123456789ab".to_string());
        assert_eq!(hostname_of(&spec, &id), "lc-0123456789ab");
        spec.labels
            .insert("hostname".to_string(), "worker".to_string());
        assert_eq!(hostname_of(&spec, &id), "worker");
    }

    #[test]
    fn test_stream_port_bind_unlink() {
        // Stream port is above fixed ports and unlinked on drop.
        let dir = std::env::temp_dir().join(format!("lingcage-bind-{}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("create test dir");
        let prefix = dir.join("vs");
        let bound = bind_stream(&prefix).expect("bind stream port");
        assert!(bound.stream.port >= FIRST_STREAM_PORT);
        let path = bound.path.clone();
        assert_eq!(path, at(&prefix, bound.stream.port));
        assert!(path.exists(), "socket not present on disk");
        drop(bound);
        assert!(!path.exists(), "socket not removed after drop");
        std::fs::remove_dir_all(&dir).expect("remove test dir");
    }

    #[test]
    fn test_reject_spec_shape_mismatch() {
        // Mismatched spec should be refused and leave no run directory
        // behind.
        let dir = std::env::temp_dir().join(format!("lingcage-shape-{}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("create test dir");
        let ram = File::create(dir.join("ram.img")).expect("ram image");
        let template = Template {
            dir: dir.clone(),
            meta: crate::template::tests::test_meta("t"),
            ram,
            run_root: dir.join("run"),
            state: std::sync::OnceLock::new(),
        };
        let hv = Hv::open().expect("open /dev/kvm");
        let mut spec = SandboxSpec::for_template(&template);
        spec.limits.vcpus += 1;
        assert!(matches!(
            Sandbox::start(&hv, &template, &spec),
            Err(Error::Shape { .. })
        ));
        assert!(
            !dir.join("run").exists(),
            "run directory left after refused start"
        );
        std::fs::remove_dir_all(&dir).expect("remove test dir");
    }
}
