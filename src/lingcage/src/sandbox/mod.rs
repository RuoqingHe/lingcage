// SPDX-FileCopyrightText: 2026 LingCage <opensource@lingcage.com>
//
// SPDX-License-Identifier: Apache-2.0

//! Sandbox in this process, a guest cloned from template and driven
//! through its control connection, with console attached. [`Starting`]
//! and [`Sandbox`] are separate types, only the latter drives a guest.
//! Teardown consumes the sandbox, `shutdown` and `kill` take `self` and
//! dropping a sandbox tears it down as `kill` does.

pub mod console;
pub mod demux;
pub mod exec;
pub mod spec;

use std::fs::File;
use std::io::Read as _;
use std::os::unix::net::UnixListener;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use lingcore::hv::backend::kvm::hypervisor::KvmHv;
use lingcore::hv::vcpu::VmExit;
use lingcore::machine::{Channel, Config, Machine, State};
use lingcore::seccomp::Refusal;

use crate::error::{Error, Result};
use crate::hv::Hv;
use crate::lcp;
use crate::sandbox::console::{Console, Sink};
use crate::sandbox::demux::Demux;
use crate::sandbox::spec::{Limits, SandboxSpec};
use crate::template::Template;

/// Host port the agent connects to for control connection.
const CONTROL_PORT: u32 = 1;

/// Host port the agent connects to for log connection.
const LOG_PORT: u32 = 2;

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
            Ok(hostname) => {
                self.inner.identity.hostname = hostname;
                Ok(Sandbox {
                    inner: Arc::new(self.inner),
                })
            }
            Err(source) => {
                let console_tail = self.inner.console.tail(CONSOLE_TAIL);
                if let Err(err) = self.inner.teardown() {
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
        self.inner.teardown()
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
            Ok(starting) => Ok(starting),
            Err(err) => {
                if let Err(left) = std::fs::remove_dir_all(&run_dir) {
                    log::warn!("run directory of failed start not removed: {left}");
                }
                Err(err)
            }
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

    /// Round-trip a nonce through the agent and return the time it took. A
    /// wedged guest which holds the connection open without replying costs
    /// `PING_WITHIN`, detecting such guest is the purpose of this call.
    pub fn ping(&self) -> Result<Duration> {
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
        let answer = self.inner.demux.ask(frame, PING_WITHIN)?;
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
        // If the request failed to be sent, the guest can not power off, the
        // wait below then runs out the deadline and the forced stop follows.
        if let Err(err) = self
            .inner
            .demux
            .tell_with_new_id(lcp::kind::SHUTDOWN, lcp::flags::SHUTDOWN)
        {
            log::warn!("failed to send shutdown request: {err}");
        }
        let exit = self.inner.await_exit(within)?;
        self.inner.teardown()?;
        Ok(exit)
    }

    /// Stop the guest without power-off and tear down, consumes the sandbox.
    pub fn kill(self) -> Result<Exit> {
        self.inner.teardown()?;
        Ok(Exit::Killed {
            after: Duration::ZERO,
        })
    }
}

/// State shared by `Starting` and `Sandbox`, torn down only once.
struct Inner {
    id: SandboxId,
    identity: Identity,
    machine: Mutex<Machine<KvmHv>>,
    demux: Arc<Demux>,
    console: Console,
    run_dir: PathBuf,
    /// Set by teardown, which holds the lock till it finishes, so that a
    /// second caller waits for the first one to complete.
    torn: Mutex<bool>,
}

impl Inner {
    /// Wait at most `within` for a vCPU to leave `run`, stop the guest if
    /// none did, and return the corresponding `Exit`.
    fn await_exit(&self, within: Duration) -> Result<Exit> {
        let mut machine = self.machine.lock().unwrap();
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
    /// run directory, only once. `torn` flag is not set if teardown fails,
    /// so that the following drop would try again.
    fn teardown(&self) -> Result<()> {
        let mut torn = self.torn.lock().unwrap();
        if *torn {
            return Ok(());
        }
        let stopped = {
            let mut machine = self.machine.lock().unwrap();
            if matches!(machine.state(), State::Running | State::Paused) {
                machine.stop().and_then(|()| machine.wait().map(drop))
            } else {
                Ok(())
            }
        }
        .map_err(Error::Lingcore);
        self.demux.stop();
        let removed = std::fs::remove_dir_all(&self.run_dir).map_err(Error::Io);
        let done = stopped.and(removed);
        *torn = done.is_ok();
        done
    }
}

impl Drop for Inner {
    fn drop(&mut self) {
        if let Err(err) = self.teardown() {
            log::warn!("teardown of sandbox {} failed: {err}", self.id);
        }
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
    let vsock_prefix = run_dir.join("vs");
    let cid = crate::hv::next_cid();
    let shape = &template.meta().shape;
    let config = Config {
        memory: shape.memory,
        vcpus: shape.vcpus,
        kernel: template.kernel_path(),
        initrd: None,
        cmdline: String::new(),
        disk: None,
        channel: Some(Channel {
            cid,
            at: vsock_prefix.clone(),
        }),
        network: None,
        confine: Some(Refusal::Trap),
    };
    let sink = Sink::default();
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
            machine: Mutex::new(machine),
            demux,
            console,
            run_dir,
            torn: Mutex::new(false),
        },
    })
}

/// Fill `bytes` with random data read from `/dev/urandom`.
pub(crate) fn draw(bytes: &mut [u8]) -> Result<()> {
    let mut source = File::open("/dev/urandom").map_err(Error::Io)?;
    source.read_exact(bytes).map_err(Error::Io)
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
