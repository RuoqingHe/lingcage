// SPDX-FileCopyrightText: 2026 LingCage <opensource@lingcage.com>
//
// SPDX-License-Identifier: Apache-2.0

//! Template store, which builds, registers, lists and removes
//! templates. A flock protocol makes sure a live image is not removed
//! while a sandbox is still using it.

use std::collections::VecDeque;
use std::io::{Read as _, Write};
use std::os::fd::AsRawFd;
use std::os::unix::fs::symlink;
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime};

use lingcore::hv::backend::kvm::hypervisor::KvmHv;
use lingcore::machine::{Channel, Config, Machine};
use lingcore::seccomp::Refusal;

use crate::error::{Error, Result};
use crate::hv::Hv;
use crate::template::{
    BuildStamp, Digest, GuestShape, Template, TemplateId, TemplateMeta, TemplatePlan,
    TemplateStore, layout_digest, sanitize,
};

/// Hostname used by the build boot, a sandbox gets its own at spawn.
const BUILD_HOSTNAME: &str = "lc-build";

/// Request id of the only exchange in the build handshake.
const FIRST_REQUEST: u32 = 1;

/// Bytes of console output kept for the error of a failed boot.
const CONSOLE_TAIL: usize = 4 << 10;

impl TemplateStore {
    /// Open the store at `root`, create the layout if it is missing.
    pub fn open(root: impl AsRef<Path>) -> Result<Self> {
        let store = TemplateStore {
            root: root.as_ref().to_path_buf(),
        };
        std::fs::create_dir_all(store.aliases_dir()).map_err(Error::Io)?;
        std::fs::create_dir_all(store.run_dir()).map_err(Error::Io)?;
        Ok(store)
    }

    /// Boot a guest per the plan, wait for the agent, then pause, capture,
    /// sanitize, stamp and register. This is the only supported way to make
    /// a template.
    pub fn build(&self, plan: &TemplatePlan) -> Result<Template> {
        // TODO: A template with a disk or a network link is scheduled to next stage.
        if plan.devices.disk {
            return Err(Error::Unsupported("template with disk"));
        }
        if plan.devices.network {
            return Err(Error::Unsupported("template with network link"));
        }
        if !plan.devices.channel {
            return Err(Error::Unsupported("template without channel"));
        }
        if let Some(name) = &plan.name {
            check_name(name)?;
        }
        let hv = Hv::open()?;
        let cid = fresh_cid();
        let tag = format!("build-{}-{cid}", std::process::id());
        let staging = self.templates_dir().join(format!(".{tag}"));
        std::fs::create_dir_all(&staging).map_err(Error::Io)?;
        let built = self.boot_and_capture(plan, &hv, cid, &tag, &staging);
        match built {
            Ok(template) => Ok(template),
            Err(err) => {
                // Failed build should leave no directory in the store.
                // A dir already gone is not an error.
                for dir in [staging, self.run_dir().join(&tag)] {
                    match std::fs::remove_dir_all(&dir) {
                        Ok(()) => {}
                        Err(left) if left.kind() == std::io::ErrorKind::NotFound => {}
                        Err(left) => {
                            log::warn!("failed to remove {}: {left}", dir.display());
                        }
                    }
                }
                Err(err)
            }
        }
    }

    /// Adopt a template directory built elsewhere. Stamp, shape and digest
    /// are verified here, so that a bad template fails at register time
    /// instead of at spawn time.
    pub fn register(&self, dir: impl AsRef<Path>) -> Result<Template> {
        let dir = dir.as_ref();
        let meta = read_meta(dir)?;
        let id = template_id(dir).map_err(|err| match err {
            Error::Io(io) => Error::TemplateBad {
                what: format!("failed to read template files: {io}"),
            },
            other => other,
        })?;
        if id != meta.id {
            return Err(Error::TemplateBad {
                what: format!(
                    "template.json names {}, the files digest to {id}; the template needs \
                     re-baking",
                    meta.id
                ),
            });
        }
        if meta.stamp.lingcore != lingcore::VERSION {
            return Err(Error::TemplateBad {
                what: format!(
                    "template baked by lingcore {} but this build is {}, please re-bake it",
                    meta.stamp.lingcore,
                    lingcore::VERSION
                ),
            });
        }
        let layout = layout_digest(std::env::consts::ARCH, meta.shape.devices);
        if meta.stamp.layout != layout {
            return Err(Error::TemplateBad {
                what: format!(
                    "template baked for layout {} but this build has {layout}, re-bake is needed",
                    meta.stamp.layout
                ),
            });
        }
        let into = self.templates_dir().join(id.as_str());
        std::fs::create_dir_all(&into).map_err(Error::Io)?;
        for name in ["ram.img", "state.json", "kernel.img", "template.json"] {
            place(&dir.join(name), &into.join(name))?;
        }
        self.open_template(into)
    }

    /// Returns the template registered as `id`.
    pub fn get(&self, id: &TemplateId) -> Result<Template> {
        self.open_template(self.resolve(id)?)
    }

    /// List all registered templates.
    pub fn list(&self) -> Result<Vec<TemplateMeta>> {
        let mut metas = Vec::new();
        let mut seen = std::collections::HashSet::new();
        let mut read = |dir: PathBuf| -> Result<()> {
            let meta = read_meta(&dir)?;
            if seen.insert(meta.id.as_str().to_string()) {
                metas.push(meta);
            }
            Ok(())
        };
        for entry in std::fs::read_dir(self.templates_dir()).map_err(Error::Io)? {
            let entry = entry.map_err(Error::Io)?;
            let name = entry.file_name();
            let name = name.to_string_lossy();
            // Skip aliases dir and staging dir left by a crashed build.
            if name == "aliases" || name.starts_with('.') {
                continue;
            }
            if entry.path().is_dir() {
                read(entry.path())?;
            }
        }
        for entry in std::fs::read_dir(self.aliases_dir()).map_err(Error::Io)? {
            let entry = entry.map_err(Error::Io)?;
            // Skip dangling alias.
            let Ok(target) = entry.path().canonicalize() else {
                continue;
            };
            if target.is_dir() {
                read(target)?;
            }
        }
        Ok(metas)
    }

    /// Remove a template. Refused with `Error::TemplateInUse` if any sandbox
    /// is still holding it.
    pub fn remove(&self, id: &TemplateId) -> Result<()> {
        let dir = self.resolve(id)?;
        let ram = std::fs::File::open(dir.join("ram.img")).map_err(Error::Io)?;
        // In-use check. `open_template` holds a shared flock on the image as
        // long as the Template lives, so exclusive lock can only be taken when
        // no Template has the image open.
        if !try_lock_exclusive(&ram)? {
            return Err(Error::TemplateInUse {
                id: id.as_str().to_string(),
            });
        }
        let name = dir.file_name().unwrap_or_default().to_os_string();
        for entry in std::fs::read_dir(self.aliases_dir()).map_err(Error::Io)? {
            let entry = entry.map_err(Error::Io)?;
            let Ok(target) = std::fs::read_link(entry.path()) else {
                continue;
            };
            if target.file_name() == Some(name.as_os_str()) {
                std::fs::remove_file(entry.path()).map_err(Error::Io)?;
            }
        }
        std::fs::remove_dir_all(&dir).map_err(Error::Io)?;
        Ok(())
    }

    /// Build pipeline: boot, handshake, capture and register the result,
    /// staged under `staging`.
    fn boot_and_capture(
        &self,
        plan: &TemplatePlan,
        hv: &Hv,
        cid: u64,
        tag: &str,
        staging: &Path,
    ) -> Result<Template> {
        let run = self.run_dir().join(tag);
        std::fs::create_dir_all(&run).map_err(Error::Io)?;
        let prefix = run.join("vs");
        // Agent connects to port 1, the device connects to host listener at
        // `<prefix>_1`, which is bound before guest starts.
        let listener = UnixListener::bind(named(&prefix, 1)).map_err(Error::Io)?;
        let console = Arc::new(Mutex::new(VecDeque::new()));
        let sink = Tail {
            ring: Arc::clone(&console),
        };
        let config = Config {
            memory: plan.memory,
            vcpus: plan.vcpus,
            kernel: plan.kernel.clone(),
            initrd: plan.initrd.clone(),
            cmdline: plan.cmdline.clone(),
            disk: None,
            channel: Some(Channel { cid, at: prefix }),
            network: None,
            confine: Some(Refusal::Trap),
        };
        let mut machine = Machine::new(hv.core(), &config, sink).map_err(Error::Lingcore)?;
        machine.start().map_err(Error::Lingcore)?;
        let captured = capture_ready(
            &mut machine,
            &listener,
            plan.ready_timeout,
            &console,
            staging,
        );
        // Stop the boot after a failed capture as well, make sure no
        // guest keeps running behind the error.
        let stopped = stop_and_wait(&mut machine);
        drop(listener);
        let removed = std::fs::remove_dir_all(&run).map_err(Error::Io);
        captured.and(stopped).and(removed)?;
        self.register_baked(plan, staging)
    }

    /// Digest, sanitize, stamp and move the staged template into the store,
    /// with the alias given by the plan.
    fn register_baked(&self, plan: &TemplatePlan, staging: &Path) -> Result<Template> {
        let kernel_at = staging.join("kernel.img");
        std::fs::copy(&plan.kernel, &kernel_at).map_err(Error::Io)?;
        let kernel = Digest::of_file(&kernel_at)?;
        let rootfs = plan.initrd.as_deref().map(Digest::of_file).transpose()?;
        if let Some(initrd) = &plan.initrd {
            sanitize::check(initrd)?;
        }
        let id = template_id(staging)?;
        let meta = TemplateMeta {
            id: id.clone(),
            shape: GuestShape {
                memory: plan.memory,
                vcpus: plan.vcpus,
                devices: plan.devices,
            },
            stamp: BuildStamp {
                lingcore: lingcore::VERSION.to_string(),
                layout: layout_digest(std::env::consts::ARCH, plan.devices),
                arch: std::env::consts::ARCH.to_string(),
            },
            kernel,
            rootfs,
            built_at: SystemTime::now(),
            // template.json itself is written after counting.
            bytes: dir_size(staging)?,
        };
        let mut file = std::fs::File::create(staging.join("template.json")).map_err(Error::Io)?;
        serde_json::to_writer_pretty(&mut file, &meta)
            .map_err(std::io::Error::from)
            .map_err(Error::Io)?;
        let into = self.templates_dir().join(id.as_str());
        if into.join("template.json").is_file() {
            // Same content is registered already, drop the staging copy.
            std::fs::remove_dir_all(staging).map_err(Error::Io)?;
        } else {
            // Replace partial directory left by a crashed build or register.
            match std::fs::remove_dir_all(&into) {
                Ok(()) => {}
                Err(err) if err.kind() == std::io::ErrorKind::NotFound => {}
                Err(err) => return Err(Error::Io(err)),
            }
            std::fs::rename(staging, &into).map_err(Error::Io)?;
        }
        if let Some(name) = &plan.name {
            link_alias(&self.aliases_dir().join(name), &id)?;
        }
        self.open_template(into)
    }

    /// Open the template in `dir`. Meta is read and RAM image is kept open
    /// with a shared flock as long as the Template lives.
    fn open_template(&self, dir: PathBuf) -> Result<Template> {
        let meta = read_meta(&dir)?;
        let ram = std::fs::File::open(dir.join("ram.img")).map_err(Error::Io)?;
        lock_shared(&ram)?;
        Ok(Template {
            dir,
            meta,
            ram,
            state: std::sync::OnceLock::new(),
            run_root: self.run_dir(),
        })
    }

    /// Returns the directory of template `id`, either directly or through
    /// an alias.
    fn resolve(&self, id: &TemplateId) -> Result<PathBuf> {
        let direct = self.templates_dir().join(id.as_str());
        if direct.is_dir() {
            return Ok(direct);
        }
        let missing = || Error::TemplateMissing {
            id: id.as_str().to_string(),
        };
        let target =
            std::fs::canonicalize(self.aliases_dir().join(id.as_str())).map_err(|_| missing())?;
        let templates = std::fs::canonicalize(self.templates_dir()).map_err(Error::Io)?;
        if target.is_dir() && target.parent() == Some(templates.as_path()) {
            return Ok(target);
        }
        Err(missing())
    }

    fn templates_dir(&self) -> PathBuf {
        self.root.join("templates")
    }

    fn aliases_dir(&self) -> PathBuf {
        self.templates_dir().join("aliases")
    }

    fn run_dir(&self) -> PathBuf {
        self.root.join("run")
    }
}

/// Boot to the handshake and capture. Control connection is accepted
/// within `within`, build identity is applied, then guest is paused and
/// its state and RAM are written under `staging`.
fn capture_ready(
    machine: &mut Machine<KvmHv>,
    listener: &UnixListener,
    within: Duration,
    console: &Arc<Mutex<VecDeque<u8>>>,
    staging: &Path,
) -> Result<()> {
    let deadline = Instant::now() + within;
    let stream = accept_within(listener, deadline)?;
    stream.set_write_timeout(Some(within)).map_err(Error::Io)?;
    handshake(&stream, deadline, &build_identity()?, console)?;
    machine.pause().map_err(Error::Lingcore)?;
    let snapshot = machine.capture().map_err(Error::Lingcore)?;
    let mut state = std::fs::File::create(staging.join("state.json")).map_err(Error::Io)?;
    snapshot.write_to(&mut state).map_err(Error::Lingcore)?;
    let mut ram = std::fs::File::create(staging.join("ram.img")).map_err(Error::Io)?;
    machine.write_memory(&mut ram).map_err(Error::Lingcore)?;
    Ok(())
}

/// Accept one control connection from `listener` before `deadline`.
fn accept_within(listener: &UnixListener, deadline: Instant) -> Result<UnixStream> {
    loop {
        let left = deadline.saturating_duration_since(Instant::now());
        if left.is_zero() {
            return Err(Error::Timeout("build boot"));
        }
        let millis = i32::try_from(left.as_millis().min(1000)).unwrap_or(1000);
        let mut polled = libc::pollfd {
            fd: listener.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        };
        // SAFETY: `polled` is valid for a single descriptor during the call.
        let ready = unsafe { libc::poll(&mut polled, 1, millis) };
        if ready < 0 {
            let err = std::io::Error::last_os_error();
            if err.kind() == std::io::ErrorKind::Interrupted {
                continue;
            }
            return Err(Error::Io(err));
        }
        if ready == 0 {
            continue;
        }
        let (stream, _) = listener.accept().map_err(Error::Io)?;
        return Ok(stream);
    }
}

/// Build handshake: READY comes first, IDENTIFY is answered, IDENTIFIED
/// with the build hostname closes it. Anything else is a protocol error
/// with console tail attached. `deadline` covers all the reads, so an
/// image dribbling its frames runs out of the boot readiness timeout
/// instead of extending it.
fn handshake(
    stream: &UnixStream,
    deadline: Instant,
    identity: &crate::lcp::Identify,
    console: &Arc<Mutex<VecDeque<u8>>>,
) -> Result<()> {
    let first = crate::deadline::frame(stream, deadline, "ready frame of build")?;
    if first.kind != crate::lcp::kind::READY
        || (first.flags & crate::lcp::flags::SESSION_START) == 0
    {
        return Err(Error::Agent {
            what: format!(
                "first frame is type {} instead of READY, console tail: {}",
                first.kind,
                tail_of(console)
            ),
        });
    }
    let ready: crate::lcp::Ready = first.payload().map_err(Error::Protocol)?;
    if ready.protocol > crate::lcp::PROTOCOL {
        return Err(Error::Agent {
            what: format!(
                "agent protocol is {} but this build is {}",
                ready.protocol,
                crate::lcp::PROTOCOL
            ),
        });
    }
    log::debug!("build agent up in {} ms: {}", ready.init_ms, ready.agent);
    let answer =
        crate::lcp::Frame::with_payload(FIRST_REQUEST, crate::lcp::kind::IDENTIFY, 0, identity)
            .map_err(Error::Protocol)?;
    answer.write_to(&mut &*stream).map_err(Error::Protocol)?;
    let reply = crate::deadline::frame(stream, deadline, "identified frame of build")?;
    if reply.kind != crate::lcp::kind::IDENTIFIED {
        return Err(Error::Agent {
            what: format!(
                "reply to IDENTIFY is type {} instead of IDENTIFIED, console tail: {}",
                reply.kind,
                tail_of(console)
            ),
        });
    }
    let identified: crate::lcp::Identified = reply.payload().map_err(Error::Protocol)?;
    if identified.hostname != identity.hostname {
        return Err(Error::Agent {
            what: format!(
                "hostname is {:?} instead of {:?} we sent, console tail: {}",
                identified.hostname,
                identity.hostname,
                tail_of(console)
            ),
        });
    }
    Ok(())
}

/// Identity given to the build boot: build hostname, plus fresh entropy,
/// machine id and generation from the host.
fn build_identity() -> Result<crate::lcp::Identify> {
    let mut entropy = [0u8; 32];
    let mut machine_id = [0u8; 16];
    let mut generation = [0u8; 8];
    let mut source = std::fs::File::open("/dev/urandom").map_err(Error::Io)?;
    source.read_exact(&mut entropy).map_err(Error::Io)?;
    source.read_exact(&mut machine_id).map_err(Error::Io)?;
    source.read_exact(&mut generation).map_err(Error::Io)?;
    Ok(crate::lcp::Identify {
        hostname: BUILD_HOSTNAME.to_string(),
        machine_id: hex_of(&machine_id),
        generation: u64::from_ne_bytes(generation),
        entropy,
        unix_nanos: u64::try_from(
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|span| span.as_nanos())
                .unwrap_or(0),
        )
        .unwrap_or(u64::MAX),
    })
}

/// Stop the build boot and join its threads.
fn stop_and_wait(machine: &mut Machine<KvmHv>) -> Result<()> {
    machine.stop().map_err(Error::Lingcore)?;
    machine.wait().map_err(Error::Lingcore)?;
    Ok(())
}

/// Content address of a template directory, which is the hex digest
/// over bytes of ram.img, state.json and kernel.img in this order.
fn template_id(dir: &Path) -> Result<TemplateId> {
    use sha2::Digest as _;

    let mut hasher = sha2::Sha256::new();
    for name in ["ram.img", "state.json", "kernel.img"] {
        let mut file = std::fs::File::open(dir.join(name)).map_err(Error::Io)?;
        std::io::copy(&mut file, &mut hasher).map_err(Error::Io)?;
    }
    Ok(TemplateId(Digest(hasher.finalize().into()).to_string()))
}

/// Read template.json under `dir`.
fn read_meta(dir: &Path) -> Result<TemplateMeta> {
    let text =
        std::fs::read_to_string(dir.join("template.json")).map_err(|err| Error::TemplateBad {
            what: format!("failed to read template.json in {}: {err}", dir.display()),
        })?;
    serde_json::from_str(&text).map_err(|err| Error::TemplateBad {
        what: format!(
            "template.json in {} is not a valid template document: {err}",
            dir.display()
        ),
    })
}

/// Link `source` into the store at `at`, fall back to copy across
/// filesystems. Files are content addressed, so an existing one is kept.
fn place(source: &Path, at: &Path) -> Result<()> {
    match std::fs::hard_link(source, at) {
        Ok(()) => Ok(()),
        Err(err) if err.kind() == std::io::ErrorKind::AlreadyExists => Ok(()),
        Err(err) if err.raw_os_error() == Some(libc::EXDEV) => {
            std::fs::copy(source, at).map_err(Error::Io)?;
            Ok(())
        }
        Err(err) => Err(Error::Io(err)),
    }
}

/// Point alias `at` to template `id`, replacing a stale one if any.
fn link_alias(at: &Path, id: &TemplateId) -> Result<()> {
    let target = format!("../{id}");
    match symlink(&target, at) {
        Ok(()) => Ok(()),
        Err(err) if err.kind() == std::io::ErrorKind::AlreadyExists => {
            std::fs::remove_file(at).map_err(Error::Io)?;
            symlink(&target, at).map_err(Error::Io)
        }
        Err(err) => Err(Error::Io(err)),
    }
}

/// Refuse an alias name which is not a single path component.
fn check_name(name: &str) -> Result<()> {
    if name.is_empty() || name == "." || name == ".." || name.contains('/') {
        return Err(Error::TemplateBad {
            what: format!("{name:?} is not a valid template name"),
        });
    }
    Ok(())
}

/// Take a shared flock on `file`, held as long as the file is open.
fn lock_shared(file: &std::fs::File) -> Result<()> {
    // SAFETY: the descriptor is valid as long as `file` lives.
    if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_SH) } != 0 {
        return Err(Error::Io(std::io::Error::last_os_error()));
    }
    Ok(())
}

/// Try to take an exclusive flock on `file`, returns `false` if someone
/// else is holding it.
fn try_lock_exclusive(file: &std::fs::File) -> Result<bool> {
    // SAFETY: the descriptor is valid as long as `file` lives.
    if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } == 0 {
        return Ok(true);
    }
    let err = std::io::Error::last_os_error();
    if err.raw_os_error() == Some(libc::EWOULDBLOCK) {
        return Ok(false);
    }
    Err(Error::Io(err))
}

/// Bytes occupied by regular files directly under `dir`.
fn dir_size(dir: &Path) -> Result<u64> {
    let mut bytes = 0;
    for entry in std::fs::read_dir(dir).map_err(Error::Io)? {
        let entry = entry.map_err(Error::Io)?;
        let meta = entry.metadata().map_err(Error::Io)?;
        if meta.is_file() {
            bytes += meta.len();
        }
    }
    Ok(bytes)
}

/// Returns the socket path for `port` under `prefix`.
fn named(prefix: &Path, port: u32) -> PathBuf {
    let mut path = prefix.as_os_str().to_os_string();
    path.push(format!("_{port}"));
    PathBuf::from(path)
}

/// Returns the next guest cid for a build boot.
fn fresh_cid() -> u64 {
    crate::hv::next_cid()
}

/// Returns `bytes` as lowercase hex.
fn hex_of(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// Console output captured so far, converted lossily to text.
fn tail_of(console: &Arc<Mutex<VecDeque<u8>>>) -> String {
    let ring = console.lock().unwrap();
    let bytes: Vec<u8> = ring.iter().copied().collect();
    String::from_utf8_lossy(&bytes).into_owned()
}

/// Console sink of the build boot, a ring of the last CONSOLE_TAIL
/// bytes shared with the error paths.
struct Tail {
    ring: Arc<Mutex<VecDeque<u8>>>,
}

impl Write for Tail {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        let mut ring = self.ring.lock().unwrap();
        ring.extend(bytes);
        let over = ring.len().saturating_sub(CONSOLE_TAIL);
        drop(ring.drain(..over));
        Ok(bytes.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use crate::error::Error;
    use crate::template::store::*;
    use crate::template::tests::test_meta;
    use crate::template::{DeviceSet, TemplateId, TemplateStore};

    fn temp_root(tag: &str) -> PathBuf {
        let root =
            std::env::temp_dir().join(format!("lingcage-store-{tag}-{}", std::process::id()));
        // Leftover of a previous interrupted run would make the writes fail.
        match std::fs::remove_dir_all(&root) {
            Ok(()) => {}
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => {}
            Err(err) => panic!("failed to remove stale temp root: {err}"),
        }
        std::fs::create_dir_all(&root).expect("create the temp root");
        root
    }

    /// Write a template directory under templates dir of the store.
    fn fabricate(store: &TemplateStore, id: &str) {
        let dir = store.templates_dir().join(id);
        std::fs::create_dir_all(&dir).expect("create the template dir");
        std::fs::write(dir.join("ram.img"), b"ram").expect("write ram.img");
        std::fs::write(dir.join("state.json"), b"{}").expect("write state.json");
        std::fs::write(dir.join("kernel.img"), b"kernel").expect("write kernel.img");
        let json = serde_json::to_string(&test_meta(id)).expect("serialize meta");
        std::fs::write(dir.join("template.json"), json).expect("write template.json");
    }

    #[test]
    fn test_template_id_stable() {
        let root = temp_root("id");
        let dir = root.join("t");
        std::fs::create_dir_all(&dir).expect("create the dir");
        std::fs::write(dir.join("ram.img"), b"abc").expect("write ram.img");
        std::fs::write(dir.join("state.json"), b"").expect("write state.json");
        std::fs::write(dir.join("kernel.img"), b"").expect("write kernel.img");
        // sha256("abc") as per FIPS 180-4.
        let want = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";
        assert_eq!(template_id(&dir).expect("digest the dir").as_str(), want);
        assert_eq!(
            template_id(&dir).expect("digest the dir again").as_str(),
            want
        );
        std::fs::remove_dir_all(&root).expect("remove the temp root");
    }

    #[test]
    fn test_alias_resolve() {
        let root = temp_root("alias");
        let store = TemplateStore::open(&root).expect("open the store");
        fabricate(&store, "aa11");
        symlink("../aa11", store.aliases_dir().join("py")).expect("link the alias");
        let template = store
            .get(&TemplateId("py".to_string()))
            .expect("resolve the alias");
        assert_eq!(template.id().as_str(), "aa11");
        drop(template);
        // Name with neither directory nor alias is missing.
        assert!(matches!(
            store.get(&TemplateId("nope".to_string())),
            Err(Error::TemplateMissing { .. })
        ));
        std::fs::remove_dir_all(&root).expect("remove the temp root");
    }

    #[test]
    fn test_list_dedup_aliases() {
        // List follows aliases and reports each template once.
        let root = temp_root("list");
        let store = TemplateStore::open(&root).expect("open the store");
        fabricate(&store, "aa11");
        fabricate(&store, "bb22");
        symlink("../aa11", store.aliases_dir().join("py")).expect("link the alias");
        let mut ids: Vec<String> = store
            .list()
            .expect("list the store")
            .iter()
            .map(|meta| meta.id.as_str().to_string())
            .collect();
        ids.sort();
        assert_eq!(ids, vec!["aa11".to_string(), "bb22".to_string()]);
        std::fs::remove_dir_all(&root).expect("remove the temp root");
    }

    #[test]
    fn test_remove_refused_while_in_use() {
        let root = temp_root("inuse");
        let store = TemplateStore::open(&root).expect("open the store");
        fabricate(&store, "aa11");
        let held = store
            .get(&TemplateId("aa11".to_string()))
            .expect("hold the template");
        assert!(matches!(
            store.remove(&TemplateId("aa11".to_string())),
            Err(Error::TemplateInUse { .. })
        ));
        drop(held);
        store
            .remove(&TemplateId("aa11".to_string()))
            .expect("remove once released");
        assert!(matches!(
            store.get(&TemplateId("aa11".to_string())),
            Err(Error::TemplateMissing { .. })
        ));
        std::fs::remove_dir_all(&root).expect("remove the temp root");
    }

    #[test]
    fn test_register_verified_template() {
        let root = temp_root("register");
        let store = TemplateStore::open(root.join("store")).expect("open the store");
        let baked = root.join("baked");
        std::fs::create_dir_all(&baked).expect("create the baked dir");
        std::fs::write(baked.join("ram.img"), b"ram").expect("write ram.img");
        std::fs::write(baked.join("state.json"), b"{}").expect("write state.json");
        std::fs::write(baked.join("kernel.img"), b"kernel").expect("write kernel.img");
        let id = template_id(&baked).expect("digest the baked dir");
        let json = serde_json::to_string(&test_meta(id.as_str())).expect("serialize meta");
        std::fs::write(baked.join("template.json"), &json).expect("write template.json");

        let template = store.register(&baked).expect("register the template");
        assert_eq!(template.id(), &id);
        drop(template);
        store.get(&id).expect("get the registered template");

        // Stamp from another lingcore version is refused.
        let stale = json.replace(
            &format!("\"lingcore\":\"{}\"", lingcore::VERSION),
            "\"lingcore\":\"0.0.0\"",
        );
        std::fs::write(baked.join("template.json"), stale).expect("write the stale meta");
        assert!(matches!(
            store.register(&baked),
            Err(Error::TemplateBad { .. })
        ));
        std::fs::remove_dir_all(&root).expect("remove the temp root");
    }

    #[test]
    fn test_build_handshake_timeout() {
        // A slowly dribbled handshake hits the boot deadline.
        use std::io::Write as _;

        let (ours, mut theirs) = UnixStream::pair().expect("socket pair");
        let mut wire = Vec::new();
        crate::lcp::Frame::with_payload(
            0,
            crate::lcp::kind::READY,
            crate::lcp::flags::SESSION_START,
            &crate::lcp::Ready {
                agent: "dribbling-agent".to_string(),
                protocol: crate::lcp::PROTOCOL,
                uptime: 1.0,
                init_ms: 0,
                boot_id: "boot".to_string(),
            },
        )
        .expect("code the ready frame")
        .write_to(&mut wire)
        .expect("write the ready frame");
        let dribbling = std::thread::spawn(move || {
            for byte in wire {
                if theirs.write_all(&[byte]).is_err() {
                    return;
                }
                std::thread::sleep(Duration::from_millis(20));
            }
        });
        let console = Arc::new(Mutex::new(VecDeque::new()));
        let deadline = Instant::now() + Duration::from_millis(100);
        let refused = handshake(
            &ours,
            deadline,
            &build_identity().expect("identity"),
            &console,
        );
        assert!(
            matches!(refused, Err(Error::Timeout(_))),
            "dribbled build handshake passed the deadline: {refused:?}"
        );
        assert!(
            Instant::now() < deadline + Duration::from_millis(500),
            "build handshake ran past its deadline"
        );
        dribbling.join().expect("dribbling agent panicked");
    }

    #[test]
    fn test_build_reject_unsupported_devices() {
        let root = temp_root("refuse");
        let store = TemplateStore::open(&root).expect("open the store");
        let plan = |disk, channel, network| crate::template::TemplatePlan {
            devices: DeviceSet {
                disk,
                channel,
                network,
            },
            ..Default::default()
        };
        assert!(matches!(
            store.build(&plan(true, true, false)),
            Err(Error::Unsupported(_))
        ));
        assert!(matches!(
            store.build(&plan(false, true, true)),
            Err(Error::Unsupported(_))
        ));
        assert!(matches!(
            store.build(&plan(false, false, false)),
            Err(Error::Unsupported(_))
        ));
        std::fs::remove_dir_all(&root).expect("remove the temp root");
    }

    #[test]
    fn test_build_reject_bad_name() {
        let root = temp_root("badname");
        let store = TemplateStore::open(&root).expect("open the store");
        let plan = crate::template::TemplatePlan {
            name: Some("a/b".to_string()),
            ..Default::default()
        };
        assert!(matches!(store.build(&plan), Err(Error::TemplateBad { .. })));
        std::fs::remove_dir_all(&root).expect("remove the temp root");
    }
}
