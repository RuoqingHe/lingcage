// SPDX-FileCopyrightText: 2026 LingCage <opensource@lingcage.com>
//
// SPDX-License-Identifier: Apache-2.0

//! Machine assembly. Guest RAM, the kernel loaded into it, a bus with
//! the serial console, and a vCPU entered at the kernel. Entry is in
//! long mode on x86_64, and in supervisor mode with the device tree on
//! riscv64.

use std::fs::{File, OpenOptions};
use std::io::{Seek, SeekFrom, Write};
use std::path::PathBuf;
use std::sync::{Arc, Condvar, Mutex};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use log::error;
use thiserror::Error;

use crate::devices::bus::Bus;
use crate::devices::serial::Serial;
use crate::devices::virtio::block::Block;
use crate::devices::virtio::entropy::Entropy;
use crate::devices::virtio::mmio::{self, Transport};
use crate::devices::virtio::net::carrier::Framed;
use crate::devices::virtio::net::device::Net;
use crate::devices::virtio::vsock::device::Vsock;
use crate::devices::virtio::vsock::host::Sockets;
use crate::devices::{Blob, Receive, Shared};
use crate::hv::Interest;
use crate::hv::hypervisor::Hypervisor;
use crate::hv::memory::{MemMapOption, VmMemory};
use crate::hv::os::linux::ioeventfd::{IoeventFd, IoeventFdRegistry};
use crate::hv::os::linux::waiting::Waiting;
use crate::hv::vcpu::{Stopper, Vcpu, VmExit};
use crate::hv::vm::Vm;
use crate::machine::snapshot::Snapshot;
use crate::machine::vmgenid::VmGenId;
use crate::mem::GuestRam;
use crate::seccomp::{Filter, Refusal, Thread};
use crate::vcpu::VmOps;

#[cfg(target_arch = "riscv64")]
mod riscv64;
pub mod snapshot;
pub mod vmgenid;
#[cfg(target_arch = "x86_64")]
mod x86_64;

#[cfg(target_arch = "riscv64")]
use crate::machine::riscv64::*;
#[cfg(target_arch = "x86_64")]
use crate::machine::x86_64::*;

/// Bytes of RAM given to a guest by `Config::default`.
pub const DEFAULT_MEMORY: u64 = 128 << 20;

/// Host file read by the entropy source.
const ENTROPY_SOURCE: &str = "/dev/urandom";

/// Bytes of guest RAM which `write_memory` scans and writes as one
/// piece. A zero piece becomes a hole in the image.
const IMAGE_CHUNK: usize = 64 << 10;

/// Base of the token a host descriptor is reported with. Its token is
/// the base plus index of the transport. Token of an ioeventfd is its
/// index in `rings`, far below the base.
const OUTSIDE: u64 = 1 << 32;

/// Maximum time `pause` waits for vCPU and device threads to park. The
/// stop lands as a signal plus a flag read on entry to `run`, so a vCPU
/// thread still inside after this long is reported as `NotHeld`.
const HOLD_WITHIN: Duration = Duration::from_secs(10);

/// Index of the vCPU the guest boots on. Kernel starts the rest with
/// INIT and SIPI.
const BOOT_VCPU: u16 = 0;

/// Errors thrown while assembling a guest.
#[derive(Debug, Error)]
pub enum Error {
    #[error("hypervisor call failed")]
    Hv(#[from] crate::hv::Error),
    /// Failed to allocate guest RAM.
    #[error("failed to allocate guest RAM")]
    Mem(#[from] crate::mem::Error),
    /// Failed to load or enter the kernel.
    #[error("failed to load kernel")]
    Boot(#[from] crate::boot::Error),
    /// Failed to place a device on the bus.
    #[error("failed to place devices")]
    Devices(#[from] crate::devices::Error),
    /// Failed to open or read the kernel image.
    #[error("failed to read kernel image")]
    Image(#[source] std::io::Error),
    /// Failed to open or read the entropy source file.
    #[error("failed to open entropy source")]
    Entropy(#[source] std::io::Error),
    /// Failed to open the disk file or read its length.
    #[error("failed to open disk file")]
    Disk(#[source] std::io::Error),
    /// Failed to write the RAM image.
    #[error("failed to write RAM image")]
    Ram(#[source] std::io::Error),
    /// Failed to connect the network socket.
    #[error("failed to connect network socket")]
    Network(#[source] std::io::Error),
    /// Failed to bind the channel socket.
    #[error("failed to bind channel socket")]
    Channel(#[source] std::io::Error),
    /// `Config::kernel` is empty.
    #[error("guest needs a kernel")]
    NoKernel,
    /// MP table for the vCPU count overflows the kilobyte scanned by kernel.
    #[cfg(target_arch = "x86_64")]
    #[error("MP table does not fit in its kilobyte")]
    NoRoomForMpTable,
    /// ACPI tables overrun the area below the VM generation ID.
    #[cfg(target_arch = "x86_64")]
    #[error("ACPI tables overrun the area below the VM generation ID")]
    NoRoomForTables,
    /// Device tree overruns its window, or text offset of the kernel leaves
    /// no room for the tree and the identifier below the kernel.
    #[cfg(target_arch = "riscv64")]
    #[error("device tree does not fit below kernel")]
    NoRoomForTree,
    /// Failed to assemble the device tree.
    #[cfg(target_arch = "riscv64")]
    #[error("failed to assemble device tree")]
    Tree,
    /// Failed to encode or decode the snapshot.
    #[error("failed to read or write snapshot")]
    Snapshot,
    /// Snapshot names a format version not supported by this build.
    #[error("snapshot format version {version} is not supported")]
    SnapshotFormat {
        /// Format version named by the snapshot.
        version: u32,
    },
    /// Shape of the snapshot (RAM size and vCPU count) does not match this
    /// guest, or its RAM image is too short.
    #[error("snapshot does not fit shape of the guest")]
    SnapshotShape,
    /// vCPU or device thread did not park within `HOLD_WITHIN`, or a vCPU
    /// thread still holds its vCPU.
    #[error("vCPU did not stop for pause")]
    NotHeld,
    /// Guest stopped while `pause` was waiting.
    #[error("guest stopped during pause")]
    StoppedWhileHeld,
    /// vCPU thread panicked.
    #[error("vCPU thread panicked")]
    VcpuThread,
    /// Device thread panicked or exited on error.
    #[error("device thread panicked or exited on error")]
    DeviceThread,
    /// Failed to assemble or install an allowlist on a thread.
    #[error("failed to confine guest threads")]
    Seccomp(#[from] crate::seccomp::Error),
    /// `Config::vcpus` is zero.
    #[error("guest needs at least one vCPU")]
    NoVcpus,
    /// State of the guest does not permit the requested move.
    #[error("invalid transition from {from:?} to {to:?}")]
    BadTransition {
        /// Current state.
        from: State,
        /// Requested state.
        to: State,
    },
}

/// Result alias for assembling a guest.
pub type Result<T, E = Error> = std::result::Result<T, E>;

/// Vsock channel through which a guest is reached. Context id comes
/// from the caller, one per guest it runs.
#[derive(Debug, Clone)]
pub struct Channel {
    /// Context id of the guest.
    pub cid: u64,
    /// Prefix of host socket paths. A port connects to `<prefix>_<port>`.
    pub at: PathBuf,
}

/// Network link of a guest, Ethernet frames over a host stream socket.
/// The stack behind the socket belongs to the caller.
#[derive(Debug, Clone)]
pub struct Network {
    /// Path of the host socket. A listener is on it before the machine is
    /// assembled.
    pub at: PathBuf,
    /// MAC address in configuration space. `None` offers no `F_MAC` and the
    /// driver assigns a random one.
    pub mac: Option<[u8; 6]>,
}

/// Guest configuration which a `Machine` is assembled from.
///
/// `kernel` has no default and an empty path is refused. Other fields
/// can be taken from `Default::default()`:
///
/// ```no_run
/// # use lingcore::machine::Config;
/// let config = Config {
///     kernel: "bzImage".into(),
///     memory: 256 << 20,
///     vcpus: 2,
///     cmdline: "console=ttyS0".to_string(),
///     ..Default::default()
/// };
/// ```
#[derive(Debug, Clone)]
pub struct Config {
    /// Guest RAM size in bytes.
    pub memory: u64,
    /// Number of vCPUs, at least one.
    pub vcpus: u16,
    /// Kernel image path, a bzImage on x86_64 or an Image on riscv64.
    pub kernel: PathBuf,
    /// Initramfs path, a cpio archive loaded above the kernel.
    pub initrd: Option<PathBuf>,
    /// Kernel command line.
    pub cmdline: String,
    /// File backing the disk of the guest, if any.
    pub disk: Option<PathBuf>,
    /// Vsock channel to the guest, if any.
    pub channel: Option<Channel>,
    /// Network link of the guest, if any.
    pub network: Option<Network>,
    /// Action on a syscall outside allowlist of a thread. `None` installs
    /// no allowlist.
    pub confine: Option<Refusal>,
}

impl Default for Config {
    fn default() -> Self {
        Config {
            memory: DEFAULT_MEMORY,
            vcpus: 1,
            kernel: PathBuf::new(),
            initrd: None,
            cmdline: String::new(),
            disk: None,
            channel: None,
            network: None,
            confine: None,
        }
    }
}

/// Returns the number of virtio devices, the entropy source, plus the
/// disk, the channel and the network link, each one if named in
/// `Config`.
fn virtio_count(config: &Config) -> u8 {
    1 + u8::from(config.disk.is_some())
        + u8::from(config.channel.is_some())
        + u8::from(config.network.is_some())
}

/// Returns MMIO address of virtio register block `slot`.
fn virtio_at(slot: u8) -> u64 {
    VIRTIO_AT + u64::from(slot) * mmio::SIZE
}

/// Virtio device as placed. Transport is on the bus and an ioeventfd
/// per queue is bound on its notify register. Device thread waits on
/// the ioeventfds with the transport unlocked.
struct Wired {
    transport: Shared<Transport>,
    /// One ioeventfd per queue, matched by the queue index written to
    /// `QUEUE_NOTIFY`.
    ioeventfds: Vec<Arc<dyn IoeventFd>>,
}

/// Place `device` on `bus` in virtio register block `slot`, on line
/// `VIRTIO_IRQ + slot`, with one ioeventfd per queue bound on its
/// `QUEUE_NOTIFY`.
fn place_virtio<V: Vm>(
    bus: &mut Bus,
    vm: &V,
    registry: &V::IoeventFdRegistry,
    ram: &GuestRam,
    slot: u8,
    device: Box<dyn crate::devices::virtio::Device>,
) -> Result<Wired>
where
    V::IrqSender: 'static,
    <V::IoeventFdRegistry as IoeventFdRegistry>::IoeventFd: 'static,
{
    let line = vm.create_irq_sender(VIRTIO_IRQ + slot)?;
    let queues = device.queue_count();
    let transport = Shared::new(Transport::new(device, ram.clone(), Box::new(line)));
    bus.place_mmio(virtio_at(slot), mmio::SIZE, Box::new(transport.clone()))?;

    // One ioeventfd per queue. Kick without ioeventfd exits as MMIO and
    // is served by the vCPU thread.
    let mut ioeventfds: Vec<Arc<dyn IoeventFd>> = Vec::with_capacity(usize::from(queues));
    for index in 0..queues {
        let ioeventfd = registry.create()?;
        registry.register(
            &ioeventfd,
            virtio_at(slot) + mmio::QUEUE_NOTIFY,
            4,
            Some(u64::from(index)),
        )?;
        ioeventfds.push(Arc::new(ioeventfd));
    }
    Ok(Wired {
        transport,
        ioeventfds,
    })
}

/// Lifecycle state of a `Machine`. Allowed moves are `Created` to
/// `Running`, `Running` to `Paused` and back, and either of those to
/// `Shutdown`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum State {
    /// Assembled, vCPU 0 at the kernel entry.
    Created,
    /// Each vCPU running on its own thread.
    Running,
    /// Each vCPU thread parked outside `run` and each device thread between
    /// kicks, so that registers, RAM and devices can be read.
    Paused,
    /// Threads joined and exit reason read.
    Shutdown,
}

impl State {
    /// Returns `BadTransition` unless `next` is a valid move from `self`.
    fn valid_transition(self, next: State) -> Result<()> {
        match (self, next) {
            (State::Created, State::Running) => Ok(()),
            (State::Running, State::Paused) => Ok(()),
            (State::Paused, State::Running) => Ok(()),
            (State::Running | State::Paused, State::Shutdown) => Ok(()),
            _ => Err(Error::BadTransition {
                from: self,
                to: next,
            }),
        }
    }
}

/// Order read by a vCPU thread after an `Interrupted` exit, and by a
/// device thread after each ioeventfd wait.
#[derive(Clone, Copy, Default, PartialEq, Eq)]
enum Order {
    /// Re-enter `run`.
    #[default]
    Run,
    /// Park until the order changes.
    Hold,
    /// Leave the loop, guest is stopping.
    Stop,
}

/// Current order and number of threads parked on it.
#[derive(Default)]
struct Standing {
    order: Order,
    parked: usize,
}

/// Order shared by vCPU and device threads, `pause`, `stop`, `wait`,
/// and each `StopHandle`. Each thread reads the order before its next
/// run or wait. `parked` counts the threads parked on a `Hold`.
#[derive(Default)]
struct Orders {
    standing: Mutex<Standing>,
    changed: Condvar,
}

impl Orders {
    /// Set the order and wake up the threads.
    fn tell(&self, order: Order) {
        self.standing.lock().unwrap().order = order;
        self.changed.notify_all();
    }

    fn standing(&self) -> Order {
        self.standing.lock().unwrap().order
    }

    /// Park the thread while the order is `Hold`, counted in `parked`.
    /// Returns at once on any other order.
    fn wait_out_a_hold(&self) {
        let mut standing = self.standing.lock().unwrap();
        if standing.order != Order::Hold {
            return;
        }
        standing.parked += 1;
        self.changed.notify_all();
        while standing.order == Order::Hold {
            standing = self.changed.wait(standing).unwrap();
        }
        standing.parked -= 1;
    }

    /// Block until `count` threads are parked, the order leaves `Hold`, or
    /// `within` elapses.
    fn wait_until_still(&self, count: usize, within: Duration) -> Still {
        let deadline = Instant::now() + within;
        let mut standing = self.standing.lock().unwrap();
        loop {
            if standing.parked >= count {
                return Still::Held;
            }
            if standing.order != Order::Hold {
                return Still::Stopped;
            }
            let Some(left) = deadline.checked_duration_since(Instant::now()) else {
                return Still::Waiting;
            };
            standing = self.changed.wait_timeout(standing, left).unwrap().0;
        }
    }

    /// Block until the order is `Stop`.
    fn wait_for_a_stop(&self) {
        let mut standing = self.standing.lock().unwrap();
        while standing.order != Order::Stop {
            standing = self.changed.wait(standing).unwrap();
        }
    }
}

/// Outcome of waiting for the threads to park.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Still {
    /// Each thread is parked.
    Held,
    /// Order left `Hold` before the threads parked.
    Stopped,
    /// A thread had not parked when the wait elapsed.
    Waiting,
}

/// Set `Order::Stop` on drop, so that a panicking thread sets it too.
struct SignalOnDrop(Arc<Orders>);

impl Drop for SignalOnDrop {
    fn drop(&mut self) {
        self.0.tell(Order::Stop);
    }
}

/// The `Bus`, shared by vCPU threads under one lock.
#[derive(Clone)]
struct Devices(Arc<Mutex<Bus>>);

impl VmOps for Devices {
    #[cfg(target_arch = "x86_64")]
    fn read_port(&mut self, port: u16, size: u8) -> crate::hv::Result<u32> {
        self.0.lock().unwrap().read_port(port, size)
    }

    #[cfg(target_arch = "x86_64")]
    fn write_port(&mut self, port: u16, size: u8, value: u32) -> crate::hv::Result<Option<VmExit>> {
        self.0.lock().unwrap().write_port(port, size, value)
    }

    fn read_mmio(&mut self, addr: u64, size: u8) -> crate::hv::Result<u64> {
        self.0.lock().unwrap().read_mmio(addr, size)
    }

    fn write_mmio(&mut self, addr: u64, size: u8, value: u64) -> crate::hv::Result<Option<VmExit>> {
        self.0.lock().unwrap().write_mmio(addr, size, value)
    }
}

/// Starting point of an assembled guest.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Entry {
    /// Kernel loaded into RAM, vCPU 0 at its entry.
    Boot,
    /// RAM cloned from a template. vCPUs are written by `restore`.
    Restored,
}

/// Assembled guest, RAM, bus and vCPUs, plus the threads driving them.
pub struct Machine<H: Hypervisor> {
    vm: H::Vm,
    /// Address space the host pages are mapped into. Dropping it unmaps
    /// them.
    #[expect(dead_code, reason = "kept for the mappings")]
    memory: <H::Vm as Vm>::Memory,
    ram: GuestRam,
    devices: Devices,
    /// Guest shape from `Config`, checked against a snapshot on restore.
    memory_size: u64,
    vcpu_count: u16,
    /// Share of the console UART for input, the bus owns the other one.
    console: Arc<dyn Receive>,
    /// vCPUs, each one shared with the thread driving it. Thread holds the
    /// lock for the duration of one `run` and releases it before parking,
    /// so vCPUs of a paused guest can be locked from outside.
    vcpus: Vec<Arc<Mutex<<H::Vm as Vm>::Vcpu>>>,
    /// Virtio devices, each with one ioeventfd per queue on its notify
    /// register.
    wired: Vec<Wired>,
    /// The device thread once started, waiting on ioeventfds of each device.
    /// `Err` means an allowlist which failed to install.
    device_threads: Vec<JoinHandle<Result<()>>>,
    /// Registry the ioeventfds were created from, kept while they are bound.
    #[expect(dead_code, reason = "kept for the bindings")]
    registry: <H::Vm as Vm>::IoeventFdRegistry,
    /// One thread per started vCPU. `stop_vcpu` signals a vCPU through its
    /// handle.
    threads: Vec<JoinHandle<Result<VmExit>>>,
    /// One `Stopper` per vCPU, in creation order, shared with each
    /// `StopHandle`.
    stoppers: Arc<Vec<Box<dyn Stopper>>>,
    orders: Arc<Orders>,
    /// VM generation ID, renewed by `restore`.
    genid: VmGenId,
    /// `Config::confine`, read when the threads start.
    confine: Option<Refusal>,
    state: State,
}

impl<H: Hypervisor> Machine<H> {
    /// Assemble a guest on `hv` from `config`, with serial console writing
    /// to `console`, and leave vCPU 0 at the kernel entry.
    pub fn new<W>(hv: &H, config: &Config, console: W) -> Result<Self>
    where
        W: Write + Send + 'static,
        // The sender is boxed into the `Serial`, a `dyn Device` owned by
        // the `Bus`.
        <H::Vm as Vm>::IrqSender: 'static,
        // The ioeventfd is moved onto the device thread as an
        // `Arc<dyn IoeventFd>`.
        <<H::Vm as Vm>::IoeventFdRegistry as IoeventFdRegistry>::IoeventFd: 'static,
    {
        let ram = GuestRam::new(&layout(config.memory))?;
        Machine::assemble(hv, config, console, ram, Entry::Boot)
    }

    /// Assemble a guest over the RAM image in `template`, mapped private
    /// and copy on write, so writes of the guest leave the template as it
    /// was. The image already holds the kernel and tables. Registers and
    /// device state arrive through `restore`.
    pub fn cloned<W>(hv: &H, config: &Config, console: W, template: &File) -> Result<Self>
    where
        W: Write + Send + 'static,
        <H::Vm as Vm>::IrqSender: 'static,
        <<H::Vm as Vm>::IoeventFdRegistry as IoeventFdRegistry>::IoeventFd: 'static,
    {
        let ram = GuestRam::cloned_from(&layout(config.memory), template)?;
        Machine::assemble(hv, config, console, ram, Entry::Restored)
    }

    /// Wire up a guest over `ram` at `entry`. On `Boot` the kernel is loaded
    /// first and the machine is described to it once the vCPUs exist. On
    /// `Restored` the RAM carries both and `restore` writes the vCPUs.
    fn assemble<W>(hv: &H, config: &Config, console: W, ram: GuestRam, entry: Entry) -> Result<Self>
    where
        W: Write + Send + 'static,
        <H::Vm as Vm>::IrqSender: 'static,
        <<H::Vm as Vm>::IoeventFdRegistry as IoeventFdRegistry>::IoeventFd: 'static,
    {
        if config.vcpus == 0 {
            return Err(Error::NoVcpus);
        }
        if config.kernel.as_os_str().is_empty() {
            return Err(Error::NoKernel);
        }
        let vm = hv.create_vm()?;
        let memory = vm.create_vm_memory()?;
        for region in ram.regions() {
            memory.mem_map(region.gpa, region.size, region.hva, MemMapOption::default())?;
        }
        let loaded = match entry {
            Entry::Boot => Some(load(config, &ram)?),
            Entry::Restored => None,
        };

        // The irqchip goes into the kernel together with vCPUs. Devices come
        // after it, since their lines bind to it.
        let mut vcpus = create_vcpus(hv, &vm, config)?;

        let mut bus = Bus::new();
        let line = vm.create_irq_sender(COM1_IRQ)?;
        let uart = Shared::new(Serial::new(console).on_line(Box::new(line)));
        place_fixed(&mut bus, uart.clone())?;

        // The identifier goes into RAM before the description, which names
        // its address. A cloned guest gets a fresh one from `restore`.
        let announce = vm.create_irq_sender(EVENTS_IRQ)?;
        let drawn = File::open(ENTROPY_SOURCE).map_err(Error::Entropy)?;
        let mut genid = VmGenId::new(GENID_AT, Box::new(announce), drawn);
        genid.lay(&ram)?;

        let registry = vm.create_ioeventfd_registry()?;
        let seed = File::open(ENTROPY_SOURCE).map_err(Error::Entropy)?;
        // Each device takes the slot at its index here. Tables name
        // `virtio_count(config)` slots in the same order.
        let mut devices: Vec<Box<dyn crate::devices::virtio::Device>> =
            vec![Box::new(Entropy::new(seed))];
        if let Some(path) = &config.disk {
            let file = OpenOptions::new()
                .read(true)
                .write(true)
                .open(path)
                .map_err(Error::Disk)?;
            devices.push(Box::new(Block::new(file).map_err(Error::Disk)?));
        }
        if let Some(channel) = &config.channel {
            let sockets = Sockets::listening(&channel.at).map_err(Error::Channel)?;
            devices.push(Box::new(Vsock::new(channel.cid, Box::new(sockets))));
        }
        if let Some(network) = &config.network {
            let carrier = Framed::connect(&network.at).map_err(Error::Network)?;
            devices.push(Box::new(Net::new(network.mac, Box::new(carrier))));
        }
        let mut wired = Vec::with_capacity(devices.len());
        for (slot, device) in devices.into_iter().enumerate() {
            wired.push(place_virtio(
                &mut bus, &vm, &registry, &ram, slot as u8, device,
            )?);
        }

        // The description names the devices on the bus with their lines, so
        // command line carries no `virtio_mmio.device=` fragments, and vCPU 0
        // is entered at the kernel.
        if let Some(loaded) = &loaded {
            enter(&ram, config, &mut vcpus, loaded, &genid)?;
        }
        let stoppers = Arc::new(vcpus.iter().map(|vcpu| vcpu.stopper()).collect::<Vec<_>>());
        let vcpus = vcpus
            .into_iter()
            .map(|vcpu| Arc::new(Mutex::new(vcpu)))
            .collect();

        Ok(Machine {
            vm,
            memory,
            ram,
            devices: Devices(Arc::new(Mutex::new(bus))),
            wired,
            device_threads: Vec::new(),
            registry,
            console: Arc::new(uart),
            memory_size: config.memory,
            vcpu_count: config.vcpus,
            vcpus,
            stoppers,
            threads: Vec::new(),
            orders: Arc::new(Orders::default()),
            genid,
            confine: config.confine,
            state: State::Created,
        })
    }

    /// Returns current state of the guest.
    pub fn state(&self) -> State {
        self.state
    }

    /// Returns state of each vCPU and each device. `BadTransition` unless
    /// the guest is `Paused`, `NotHeld` if a thread still holds a vCPU.
    pub fn read_state(&self) -> Result<(Vec<crate::hv::StateBlob>, Vec<Option<Blob>>)> {
        if self.state != State::Paused {
            return Err(Error::BadTransition {
                from: self.state,
                to: State::Paused,
            });
        }
        // Locked vCPU means its thread is still inside `run`, so the lock is
        // tried instead of waited on.
        let processors = self
            .vcpus
            .iter()
            .map(|vcpu| match vcpu.try_lock() {
                Ok(vcpu) => vcpu.get_state().map_err(Error::from),
                Err(_) => Err(Error::NotHeld),
            })
            .collect::<Result<Vec<_>>>()?;
        let devices = self.devices.0.lock().unwrap().capture()?;
        Ok((processors, devices))
    }

    /// Capture the guest state other than RAM, through `read_state`. An
    /// irqchip or clock not supported by the backend is left out, any other
    /// read failure is returned.
    pub fn capture(&self) -> Result<Snapshot> {
        let (processors, devices) = self.read_state()?;
        let reported = |part: crate::hv::Result<crate::hv::StateBlob>| match part {
            Ok(blob) => Ok(Some(blob)),
            Err(crate::hv::Error::Unsupported(_)) => Ok(None),
            Err(err) => Err(err),
        };
        Ok(Snapshot::new(
            self.memory_size,
            self.vcpu_count,
            reported(self.vm.get_irqchip_state())?,
            reported(self.vm.get_clock())?,
            processors,
            devices,
        ))
    }

    /// Write guest RAM to `out`, region by region in layout order and
    /// without header. `BadTransition` unless the guest is `Paused`. Zero
    /// chunks are skipped by seeking, the image reads the same as a dense
    /// one.
    pub fn write_memory(&self, out: &mut File) -> Result<()> {
        if self.state != State::Paused {
            return Err(Error::BadTransition {
                from: self.state,
                to: State::Paused,
            });
        }
        let start = out.stream_position().map_err(Error::Ram)?;
        let mut total = 0u64;
        let mut chunk = vec![0u8; IMAGE_CHUNK];
        for region in self.ram.regions() {
            let mut at = 0u64;
            while at < region.size {
                let count = chunk.len().min((region.size - at) as usize);
                let piece = &mut chunk[..count];
                self.ram.read(region.gpa + at, piece)?;
                if piece.iter().any(|byte| *byte != 0) {
                    out.write_all(piece).map_err(Error::Ram)?;
                } else {
                    out.seek(SeekFrom::Current(count as i64))
                        .map_err(Error::Ram)?;
                }
                at += count as u64;
                total += count as u64;
            }
        }
        // Length is the start plus RAM size, no matter there are trailing
        // zeroes or not.
        out.set_len(start + total).map_err(Error::Ram)?;
        Ok(())
    }

    /// Read guest RAM from `from` as laid out by `write_memory`. A short
    /// region is reported as `SnapshotShape`. A hole in a sparse image
    /// reads back as zeroes. `BadTransition` unless the guest is `Created`
    /// or `Paused`.
    pub fn read_memory(&mut self, from: &mut File) -> Result<()> {
        if self.state != State::Created && self.state != State::Paused {
            return Err(Error::BadTransition {
                from: self.state,
                to: State::Paused,
            });
        }
        for region in self.ram.regions() {
            let want = region.size as usize;
            if self.ram.fill_all_from(region.gpa, from, want)? != want {
                return Err(Error::SnapshotShape);
            }
        }
        Ok(())
    }

    /// Restore `snapshot` onto this guest. `BadTransition` unless the guest
    /// is `Created`, `SnapshotShape` unless the shape matches.
    pub fn restore(&mut self, snapshot: &Snapshot) -> Result<()> {
        if self.state != State::Created {
            return Err(Error::BadTransition {
                from: self.state,
                to: State::Created,
            });
        }
        snapshot.fits(self.memory_size, self.vcpu_count)?;

        if let Some(blob) = snapshot.irqchip() {
            self.vm.set_irqchip_state(blob)?;
        }
        for (vcpu, blob) in self.vcpus.iter().zip(snapshot.processors()) {
            vcpu.lock().unwrap().set_state(blob)?;
        }
        self.devices.0.lock().unwrap().restore(snapshot.devices())?;
        // Restored RAM carries identifier and random pool of the template.
        // A fresh one with notification makes the kernel reseed at once
        // (`add_vmfork_randomness` in `drivers/char/random.c`).
        self.genid.renew(&self.ram)?;
        // Clock goes in last. `set_clock_elapsed` advances it by host time
        // since capture, and refuses a blob without realtime reading, which
        // is then set as captured.
        if let Some(blob) = snapshot.clock()
            && self.vm.set_clock_elapsed(blob).is_err()
        {
            self.vm.set_clock(blob)?;
        }
        Ok(())
    }

    /// Returns a share of the console, for input from another thread while
    /// the guest is running.
    pub fn console(&self) -> Arc<dyn Receive> {
        Arc::clone(&self.console)
    }

    /// Start each vCPU on its own thread and all devices on one thread.
    ///
    /// Each thread holds a clone of `GuestRam`. Host pages are unmapped
    /// together with the last clone instead of the `Machine`.
    ///
    /// With `Config::confine` set, allowlists are assembled here and each
    /// thread installs its own before its first run, so a list which fails
    /// to assemble is reported by this call.
    pub fn start(&mut self) -> Result<()>
    where
        H: 'static,
    {
        self.state.valid_transition(State::Running)?;
        let confine = |thread| self.confine.map(|how| Filter::new(thread, how)).transpose();
        let driving = confine(Thread::Vcpu)?;
        let working = confine(Thread::Device)?;
        self.threads = self
            .vcpus
            .iter()
            .map(|vcpu| {
                let mut devices = self.devices.clone();
                // The thread keeps the pages mapped after the `Machine` drops.
                let ram = self.ram.clone();
                let orders = Arc::clone(&self.orders);
                let vcpu = Arc::clone(vcpu);
                let driving = driving.clone();
                std::thread::spawn(move || {
                    let _ram = ram;
                    let _signal = SignalOnDrop(Arc::clone(&orders));
                    // From here on the thread runs the guest and writes the
                    // console, so the vCPU allowlist goes on now.
                    if let Some(filter) = driving {
                        filter.confine()?;
                    }
                    loop {
                        // Lock is released before the thread parks on a hold.
                        let exit = {
                            let mut held = vcpu.lock().unwrap();
                            crate::vcpu::run(&mut *held, &mut devices)?
                        };
                        // `Interrupted` is a signal, either stray or from
                        // `ask_out`, so the order read next decides. Any
                        // other exit ends the thread.
                        if exit != VmExit::Interrupted {
                            break Ok(exit);
                        }
                        match orders.standing() {
                            Order::Run => {}
                            Order::Hold => orders.wait_out_a_hold(),
                            Order::Stop => break Ok(exit),
                        }
                    }
                })
            })
            .collect();

        // One thread per machine, waiting on the ioeventfds, host
        // descriptors and deadlines of each device. Fewer threads per
        // guest, at the price that a device blocked in host I/O holds up
        // the rest. Chains are served here instead of on vCPU threads. It
        // reads the same order as vCPU threads, so a paused guest is not
        // captured with a chain half served. On error the thread logs and
        // returns `DeviceThread`, and the drop sets the stop order, so
        // `wait` returns it.
        let rings: Vec<(Shared<Transport>, Arc<dyn IoeventFd>, u16)> = self
            .wired
            .iter()
            .flat_map(|wired| {
                wired
                    .ioeventfds
                    .iter()
                    .enumerate()
                    .map(|(ring, ioeventfd)| {
                        (wired.transport.clone(), Arc::clone(ioeventfd), ring as u16)
                    })
                    .collect::<Vec<_>>()
            })
            .collect();
        // Each transport once, with the rings it owns, for its host
        // descriptors and deadlines. `rings` lists a device once per queue.
        let mut outsides: Vec<(Shared<Transport>, std::ops::Range<usize>)> =
            Vec::with_capacity(self.wired.len());
        let mut first = 0;
        for wired in &self.wired {
            let end = first + wired.ioeventfds.len();
            outsides.push((wired.transport.clone(), first..end));
            first = end;
        }
        let orders = Arc::clone(&self.orders);
        let filter = working.clone();
        self.device_threads = vec![std::thread::spawn(move || {
            let _signal = SignalOnDrop(Arc::clone(&orders));
            if let Some(filter) = filter {
                filter.confine()?;
            }
            let mut waiting = Waiting::new();
            let mut signalled = Vec::with_capacity(rings.len());
            let mut serving = Vec::with_capacity(rings.len());
            loop {
                // The set is rebuilt in each round. Descriptors of a device
                // change with its connections, and interest of each changes
                // with credit of the guest.
                waiting.clear();
                for (token, (_, ioeventfd, _)) in rings.iter().enumerate() {
                    waiting.add(ioeventfd.as_raw_fd(), token as u64, Interest::Read);
                }
                for (index, (transport, _)) in outsides.iter().enumerate() {
                    for (fd, interest) in transport.with(|t| t.outside()) {
                        waiting.add(fd, OUTSIDE + index as u64, interest);
                    }
                }
                // The nearest deadline reported by a device bounds the wait.
                // With none, `Duration::MAX` waits without one. `ready` caps
                // the poll at i32::MAX ms.
                let mut after = Duration::MAX;
                let mut armed: Vec<usize> = Vec::new();
                for (index, (transport, _)) in outsides.iter().enumerate() {
                    let Some(deadline) = transport.with(|t| t.wake_after()) else {
                        continue;
                    };
                    if deadline < after {
                        after = deadline;
                        armed.clear();
                        armed.push(index);
                    } else if deadline == after {
                        armed.push(index);
                    }
                }
                // Signal during `notify` or a hold stays counted for the
                // next wait. Ioeventfd of the entropy source keeps the set
                // non-empty, so the wait really waits.
                if waiting.ready(after, &mut signalled).is_err() {
                    error!("device thread exits, ioeventfd wait failed");
                    return Err(Error::DeviceThread);
                }
                // The read clears the count, ioeventfd left unread stays
                // ready. Host descriptor has no count to clear.
                let taken = signalled
                    .iter()
                    .filter(|token| **token < OUTSIDE)
                    .try_for_each(|token| {
                        rings[*token as usize].1.wait(Duration::ZERO).map(|_| ())
                    });
                if taken.is_err() {
                    error!("device thread exits, ioeventfd read failed");
                    return Err(Error::DeviceThread);
                }
                // Only serve what signalled. An ioeventfd names its ring, a
                // host descriptor names rings of its transport. A wait which
                // ran out a deadline serves the transport the deadline is
                // due on. Tied deadlines are all served.
                serving.clear();
                signalled.sort_unstable();
                signalled.dedup();
                for token in &signalled {
                    if *token < OUTSIDE {
                        serving.push(*token as usize);
                    } else {
                        serving.extend(outsides[(*token - OUTSIDE) as usize].1.clone());
                    }
                }
                if signalled.is_empty() {
                    for index in &armed {
                        serving.extend(outsides[*index].1.clone());
                    }
                }
                let worked = serving.iter().try_for_each(|ring| {
                    let (transport, _, queue) = &rings[*ring];
                    transport.with(|t| t.notify(*queue))
                });
                if let Err(unanswered) = worked {
                    error!("device thread exits, notify failed: {unanswered}");
                    return Err(Error::DeviceThread);
                }
                match orders.standing() {
                    Order::Run => {}
                    Order::Hold => orders.wait_out_a_hold(),
                    Order::Stop => break,
                }
            }
            Ok(())
        })];

        self.state = State::Running;
        Ok(())
    }

    /// Set `Order::Hold` and bring each vCPU out of `run`, then block until
    /// each thread has parked, at most `HOLD_WITHIN`. Guest stopping in the
    /// meantime is reported as `StoppedWhileHeld`, thread still inside `run`
    /// as `NotHeld`.
    pub fn pause(&mut self) -> Result<()> {
        self.state.valid_transition(State::Paused)?;
        self.orders.tell(Order::Hold);
        self.ask_out()?;
        let working = self.threads.len() + self.device_threads.len();
        match self.orders.wait_until_still(working, HOLD_WITHIN) {
            Still::Held => {
                self.state = State::Paused;
                Ok(())
            }
            Still::Stopped => Err(Error::StoppedWhileHeld),
            Still::Waiting => Err(Error::NotHeld),
        }
    }

    /// Set `Order::Run`, parked threads re-enter `run`.
    pub fn resume(&mut self) -> Result<()> {
        self.state.valid_transition(State::Running)?;
        self.orders.tell(Order::Run);
        self.state = State::Running;
        Ok(())
    }

    /// Set `Order::Stop` and bring each vCPU out of `run`. The run returns
    /// `Interrupted`.
    pub fn stop(&self) -> Result<()> {
        if self.state != State::Running && self.state != State::Paused {
            return Err(Error::BadTransition {
                from: self.state,
                to: State::Shutdown,
            });
        }
        self.orders.tell(Order::Stop);
        self.ask_out()
    }

    /// Returns a handle which stops the guest from a thread not owning the
    /// machine. It has the same effect as `stop` except the per-thread
    /// signal, which is sent by `wait`.
    pub fn stop_handle(&self) -> StopHandle {
        StopHandle {
            orders: Arc::clone(&self.orders),
            stoppers: Arc::clone(&self.stoppers),
            ioeventfds: self
                .wired
                .iter()
                .flat_map(|wired| wired.ioeventfds.iter().map(Arc::clone))
                .collect(),
        }
    }

    /// Stop each vCPU through its `Stopper`, which the backend checks on
    /// entry to `run`, and through `stop_vcpu`, a signal landing inside
    /// `run`. One call covers both cases, so `wait` joins without retry.
    fn ask_out(&self) -> Result<()> {
        for stopper in self.stoppers.iter() {
            stopper.stop();
        }
        for (index, thread) in self.threads.iter().enumerate() {
            self.vm.stop_vcpu(index as u16, thread)?;
        }
        // Signal is what wakes up the wait of device thread for an order.
        for wired in &self.wired {
            for ioeventfd in &wired.ioeventfds {
                ioeventfd.signal()?;
            }
        }
        Ok(())
    }

    /// Join the vCPU threads, then the device threads, and return the exit
    /// of the first vCPU thread joined, in creation order.
    ///
    /// Blocks on the stop flag, which a thread sets when it finishes. The
    /// rest are then signalled out of `run`, otherwise a vCPU waiting for
    /// INIT stays inside.
    pub fn wait(&mut self) -> Result<VmExit> {
        self.state.valid_transition(State::Shutdown)?;
        self.orders.wait_for_a_stop();
        self.ask_out()?;
        let mut first = None;
        for thread in self.threads.drain(..) {
            let exit = thread.join().map_err(|_| Error::VcpuThread)?;
            first = first.or(Some(exit));
        }
        // Device thread which panicked or exited on error is reported in
        // place of the vCPU exit, once the machine is `Shutdown`.
        let mut devices = Ok(());
        for thread in self.device_threads.drain(..) {
            let ended = thread
                .join()
                .map_err(|_| Error::DeviceThread)
                .and_then(|ended| ended);
            if devices.is_ok() {
                devices = ended;
            }
        }
        self.state = State::Shutdown;
        devices?;
        first.unwrap_or(Ok(VmExit::Shutdown))
    }
}

/// Stop of a machine, detached from the thread owning it. It is `Clone`
/// and `Send`, so one can be held on each stopping thread.
#[derive(Clone)]
pub struct StopHandle {
    orders: Arc<Orders>,
    stoppers: Arc<Vec<Box<dyn Stopper>>>,
    ioeventfds: Vec<Arc<dyn IoeventFd>>,
}

impl StopHandle {
    /// Set the stop order, stop each vCPU through its `Stopper` and signal
    /// the ioeventfds, so that the wait of device thread ends. A vCPU in the
    /// middle of `run` keeps running until `wait` signals it.
    pub fn stop(&self) -> Result<()> {
        self.orders.tell(Order::Stop);
        for stopper in self.stoppers.iter() {
            stopper.stop();
        }
        // Signal is what wakes up the wait of device thread for an order.
        for ioeventfd in &self.ioeventfds {
            ioeventfd.signal()?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use crate::machine::*;

    #[test]
    fn test_hold_waits_for_all_threads() {
        // Pause does not return until each told thread has parked.
        use std::sync::mpsc;

        let orders = Arc::new(Orders::default());
        orders.tell(Order::Hold);

        // One thread parks on the hold.
        let parking = Arc::clone(&orders);
        let (parked, told) = mpsc::channel();
        std::thread::spawn(move || {
            parking.wait_out_a_hold();
            let _ = parked.send(());
        });
        let deadline = std::time::Instant::now() + Duration::from_secs(5);
        while orders.standing.lock().unwrap().parked < 1 {
            assert!(std::time::Instant::now() < deadline, "no thread parked");
            std::thread::sleep(Duration::from_millis(5));
        }

        // The wait is `Held` at its count and `Waiting` above it.
        assert_eq!(
            orders.wait_until_still(1, Duration::from_millis(50)),
            Still::Held
        );
        assert_eq!(
            orders.wait_until_still(2, Duration::from_millis(50)),
            Still::Waiting,
            "Held with a thread short of the count"
        );

        orders.tell(Order::Run);
        told.recv_timeout(Duration::from_secs(5))
            .expect("parked thread did not return in 5 s");
    }

    #[test]
    fn test_reject_zero_vcpus() {
        let config = Config {
            vcpus: 0,
            cmdline: String::new(),
            confine: None,
            kernel: PathBuf::from("/nonexistent/kernel"),
            memory: 16 << 20,
            ..Default::default()
        };
        #[cfg(all(feature = "kvm", target_os = "linux"))]
        {
            use crate::hv::backend::kvm::hypervisor::KvmHv;

            let hv = KvmHv::new().expect("open /dev/kvm");
            assert!(matches!(
                Machine::new(&hv, &config, Vec::new()),
                Err(Error::NoVcpus)
            ));
        }
        let _ = &config;
    }

    #[test]
    fn test_reject_unreadable_kernel() {
        #[cfg(all(feature = "kvm", target_os = "linux"))]
        {
            use crate::hv::backend::kvm::hypervisor::KvmHv;

            let hv = KvmHv::new().expect("open /dev/kvm");
            let config = Config {
                vcpus: 1,
                cmdline: String::new(),
                confine: None,
                kernel: PathBuf::from("/nonexistent/kernel"),
                memory: 16 << 20,
                ..Default::default()
            };
            assert!(matches!(
                Machine::new(&hv, &config, Vec::new()),
                Err(Error::Image(_))
            ));
        }
    }
}
