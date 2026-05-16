// SPDX-FileCopyrightText: 2026 LingCage <opensource@lingcage.com>
//
// SPDX-License-Identifier: Apache-2.0

//! Machine assembly. Guest RAM, the kernel loaded into it, a bus with
//! the serial console, and a vCPU entered at the kernel in long mode.

use std::fs::{File, OpenOptions};
use std::io::Write;
use std::path::PathBuf;
use std::sync::{Arc, Condvar, Mutex};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use log::error;
use thiserror::Error;

use crate::boot;
use crate::devices::bus::Bus;
use crate::devices::i8042::I8042;
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

mod acpi;
mod cpuid;
mod mptable;
pub mod snapshot;
pub mod vmgenid;

/// End of low RAM. Window from here to 4 GiB holds the I/O APIC and the
/// LAPIC.
const MMIO_HOLE: u64 = 0xc000_0000;

/// Start of RAM above the window.
const HIGH_RAM: u64 = 0x1_0000_0000;

/// Port base of the first serial console, `ttyS0`.
const COM1: u16 = 0x3f8;

/// Size of the 16550 register window in bytes.
const COM1_SIZE: u16 = 8;

/// Command port of the i8042 keyboard controller. Data port is not
/// placed on the bus.
const I8042_COMMAND: u16 = 0x64;

/// IRQ of the first serial console, `ttyS0`.
const COM1_IRQ: u8 = 4;

/// MMIO address of the first virtio register block, in the hole below
/// the APICs. Each device takes the next block.
const VIRTIO_AT: u64 = 0xd000_0000;

/// IRQ of the GED. No device on the bus takes line 9, which is the SCI
/// on a PC.
const EVENTS_IRQ: u8 = 9;

/// IRQ of the first virtio device, an ISA line free on PC. Each device
/// takes the next line.
const VIRTIO_IRQ: u8 = 5;

/// Host file read by the entropy source.
const ENTROPY_SOURCE: &str = "/dev/urandom";

/// Maximum time the device thread waits on the ioeventfds and host
/// descriptors before reading the order.
const DEVICE_TICK: Duration = Duration::from_millis(200);

/// Token a host descriptor is reported with, token of an ioeventfd is
/// its ring index.
const OUTSIDE: u64 = u64::MAX;

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
    /// Failed to connect the network socket.
    #[error("failed to connect network socket")]
    Network(#[source] std::io::Error),
    /// Failed to bind the channel socket.
    #[error("failed to bind channel socket")]
    Channel(#[source] std::io::Error),
    /// MP table for the vCPU count overflows the kilobyte scanned by kernel.
    #[error("MP table does not fit in its kilobyte")]
    NoRoomForMpTable,
    /// ACPI tables overrun the area below the VM generation ID.
    #[error("ACPI tables overrun the area below the VM generation ID")]
    NoRoomForTables,
    /// Failed to encode or decode the snapshot.
    #[error("failed to read or write snapshot")]
    Snapshot,
    /// Snapshot names a format version not supported by this build.
    #[error("snapshot format version {version} is not supported")]
    SnapshotFormat {
        /// Format version named by the snapshot.
        version: u32,
    },
    /// Shape of the snapshot (RAM size, vCPU count, device count) does not
    /// match this guest, or its RAM image is too short.
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
    /// Device thread panicked.
    #[error("device thread panicked")]
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
#[derive(Debug, Clone)]
pub struct Config {
    /// Guest RAM size in bytes.
    pub memory: u64,
    /// Number of vCPUs, at least one.
    pub vcpus: u16,
    /// Kernel image path, a bzImage on x86.
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

/// Returns the guest ranges occupied by `size` bytes of RAM, up to
/// `MMIO_HOLE`, and the rest starting from `HIGH_RAM`.
fn layout(size: u64) -> Vec<(u64, u64)> {
    if size <= MMIO_HOLE {
        vec![(0, size)]
    } else {
        vec![(0, MMIO_HOLE), (HIGH_RAM, size - MMIO_HOLE)]
    }
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

/// Order shared by vCPU and device threads and `pause`, `stop` and
/// `wait`. Each thread reads the order before its next run or wait,
/// `parked` counts the threads parked on a `Hold`.
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
    /// One `Stopper` per vCPU, in creation order, used by `ask_out`.
    stoppers: Vec<Box<dyn Stopper>>,
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

    /// Wire up a guest over `ram` at `entry`.
    ///
    /// On `Boot`, kernel is loaded before boot parameters are written,
    /// since they are built from its `setup_header`. CPUID is set before
    /// the vCPU runs, since a kernel reads its model and feature bits from
    /// it.
    ///
    /// The irqchip is created before the vCPU, since `KVM_CREATE_IRQCHIP`
    /// fails once a vCPU exists. With irqchip in the kernel, `hlt` blocks
    /// inside the run instead of exiting as `Halt`.
    fn assemble<W>(hv: &H, config: &Config, console: W, ram: GuestRam, entry: Entry) -> Result<Self>
    where
        W: Write + Send + 'static,
        <H::Vm as Vm>::IrqSender: 'static,
        <<H::Vm as Vm>::IoeventFdRegistry as IoeventFdRegistry>::IoeventFd: 'static,
    {
        if config.vcpus == 0 {
            return Err(Error::NoVcpus);
        }
        let vm = hv.create_vm()?;
        vm.enable_in_kernel_irqchip()?;
        let memory = vm.create_vm_memory()?;
        for region in ram.regions() {
            memory.mem_map(region.gpa, region.size, region.hva, MemMapOption::default())?;
        }

        // RAM of a cloned guest already holds the kernel, boot parameters
        // and tables.
        let kernel = match entry {
            Entry::Boot => {
                let mut image = File::open(&config.kernel).map_err(Error::Image)?;
                let kernel = boot::load_kernel(&ram, &mut image)?;
                let initrd = match &config.initrd {
                    Some(path) => {
                        let mut image = File::open(path).map_err(Error::Image)?;
                        Some(boot::load_initrd(&ram, &kernel, &mut image)?)
                    }
                    None => None,
                };
                boot::write_boot_params(&ram, &kernel, &config.cmdline, initrd)?;
                mptable::write(&ram, config.vcpus)?;
                Some(kernel)
            }
            Entry::Restored => None,
        };

        let mut bus = Bus::new();
        let line = vm.create_irq_sender(COM1_IRQ)?;
        let uart = Shared::new(Serial::new(console).on_line(Box::new(line)));
        bus.place_port(COM1, COM1_SIZE, Box::new(uart.clone()))?;
        bus.place_port(I8042_COMMAND, 1, Box::new(I8042))?;

        // The identifier goes into RAM before the tables, which name its
        // address. A cloned guest gets a fresh one from `restore`.
        let announce = vm.create_irq_sender(EVENTS_IRQ)?;
        let drawn = File::open(ENTROPY_SOURCE).map_err(Error::Entropy)?;
        let mut genid = VmGenId::new(acpi::GENID_AT, Box::new(announce), drawn);
        genid.lay(&ram)?;

        let registry = vm.create_ioeventfd_registry()?;
        let seed = File::open(ENTROPY_SOURCE).map_err(Error::Entropy)?;
        // Each device takes the slot at its index here, ACPI tables name
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

        // The tables name the console and virtio blocks on the bus, with
        // their lines, so command line carries no `virtio_mmio.device=`
        // fragments.
        acpi::lay(
            &ram,
            &acpi::Parts {
                vcpus: config.vcpus,
                genid: genid.at(),
                events: EVENTS_IRQ,
                console: acpi::Named {
                    at: u64::from(COM1),
                    room: u64::from(COM1_SIZE),
                    line: Some(COM1_IRQ),
                },
                virtio: (0..virtio_count(config))
                    .map(|slot| acpi::Named {
                        at: virtio_at(slot),
                        room: mmio::SIZE,
                        line: Some(VIRTIO_IRQ + slot),
                    })
                    .collect(),
            },
        )?;

        // Only vCPU 0 is entered in long mode. The rest wait in reset state
        // for the INIT sent by kernel once it has read the MADT.
        let host = hv.supported_cpuid()?;
        let mut vcpus = Vec::with_capacity(usize::from(config.vcpus));
        let mut stoppers = Vec::with_capacity(usize::from(config.vcpus));
        for index in 0..config.vcpus {
            let mut vcpu = vm.create_vcpu(index)?;
            vcpu.set_cpuid(&cpuid::for_vcpu(&host, index))?;
            // vCPU 0 of a cloned guest is written by `restore` instead of
            // entered at the kernel.
            if let (Some(kernel), BOOT_VCPU) = (&kernel, index) {
                boot::enter_long_mode(&ram, &mut vcpu, kernel)?;
            }
            stoppers.push(vcpu.stopper());
            vcpus.push(Arc::new(Mutex::new(vcpu)));
        }

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
    /// irqchip or clock the backend can not report is left out.
    pub fn capture(&self) -> Result<Snapshot> {
        let (processors, devices) = self.read_state()?;
        Ok(Snapshot::new(
            self.memory_size,
            self.vcpu_count,
            self.vm.get_irqchip_state().ok(),
            self.vm.get_clock().ok(),
            processors,
            devices,
        ))
    }

    /// Write guest RAM to `out`, region by region in layout order and
    /// without header. Machine state is not checked.
    pub fn write_memory(&self, out: &mut File) -> Result<()> {
        for region in self.ram.regions() {
            self.ram.drain_to(region.gpa, out, region.size as usize)?;
        }
        Ok(())
    }

    /// Read guest RAM from `from` as laid out by `write_memory`, a short
    /// region is reported as `SnapshotShape`. Machine state is not checked.
    pub fn read_memory(&mut self, from: &mut File) -> Result<()> {
        for region in self.ram.regions() {
            let want = region.size as usize;
            if self.ram.fill_from(region.gpa, from, want)? != want {
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
        let devices = self.devices.0.lock().unwrap().count();
        snapshot.fits(self.memory_size, self.vcpu_count, devices)?;

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

        // One thread per machine, waiting on ioeventfds of each device.
        // Fewer threads per guest, at the price that a device blocked in
        // host I/O holds up the rest. Chains are served here instead of on
        // vCPU threads. It reads the same order as vCPU threads, so a paused
        // guest is not captured with a chain half served. On error the
        // thread logs and exits, machine state is unchanged.
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
        // Each transport once, for its host descriptors. `rings` lists a
        // device once per queue.
        let outsides: Vec<Shared<Transport>> = self
            .wired
            .iter()
            .map(|wired| wired.transport.clone())
            .collect();
        let orders = Arc::clone(&self.orders);
        let filter = working.clone();
        self.device_threads = vec![std::thread::spawn(move || {
            if let Some(filter) = filter {
                filter.confine()?;
            }
            let mut waiting = Waiting::new();
            let mut signalled = Vec::with_capacity(rings.len());
            loop {
                // The set is rebuilt in each round. Descriptors of a device
                // change with its connections, and interest of each changes
                // with credit of the guest.
                waiting.clear();
                for (token, (_, ioeventfd, _)) in rings.iter().enumerate() {
                    waiting.add(ioeventfd.as_raw_fd(), token as u64, Interest::Read);
                }
                for transport in &outsides {
                    for (fd, interest) in transport.with(|t| t.outside()) {
                        waiting.add(fd, OUTSIDE, interest);
                    }
                }
                // Signal during `notify` or a hold stays counted for the next
                // wait.
                if waiting.ready(DEVICE_TICK, &mut signalled).is_err() {
                    error!("device thread exits, ioeventfd wait failed");
                    break;
                }
                // The read clears the count, ioeventfd left unread stays
                // ready. Host descriptor has no count to clear.
                let taken = signalled
                    .iter()
                    .filter(|token| **token != OUTSIDE)
                    .try_for_each(|token| {
                        rings[*token as usize].1.wait(Duration::ZERO).map(|_| ())
                    });
                if taken.is_err() {
                    error!("device thread exits, ioeventfd read failed");
                    break;
                }
                // Each queue is served no matter it signalled or not. Host
                // descriptor is reported with `OUTSIDE` instead of against a
                // queue, and `notify` over an empty queue raises no line.
                let worked = rings
                    .iter()
                    .try_for_each(|(transport, _, ring)| transport.with(|t| t.notify(*ring)));
                if let Err(unanswered) = worked {
                    error!("device thread exits, notify failed: {unanswered}");
                    break;
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

    /// Stop each vCPU through its `Stopper`, which the backend checks on
    /// entry to `run`, and through `stop_vcpu`, a signal landing inside
    /// `run`. One call covers both cases, so `wait` joins without retry.
    fn ask_out(&self) -> Result<()> {
        for stopper in &self.stoppers {
            stopper.stop();
        }
        for (index, thread) in self.threads.iter().enumerate() {
            self.vm.stop_vcpu(index as u16, thread)?;
        }
        // Signal wakes the device thread now instead of at the next tick.
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
        for thread in self.device_threads.drain(..) {
            thread.join().map_err(|_| Error::DeviceThread)??;
        }
        self.state = State::Shutdown;
        first.unwrap_or(Ok(VmExit::Shutdown))
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
    fn test_layout_skips_mmio_hole() {
        // RAM which fits below the window is one region.
        assert_eq!(layout(512 << 20), [(0, 512 << 20)]);
        assert_eq!(layout(MMIO_HOLE), [(0, MMIO_HOLE)]);

        // The rest goes above 4 GiB, no range covers the window.
        assert_eq!(
            layout(MMIO_HOLE + (1 << 30)),
            [(0, MMIO_HOLE), (HIGH_RAM, 1 << 30)]
        );
        for (base, size) in layout(8 << 30) {
            assert!(
                base + size <= MMIO_HOLE || base >= HIGH_RAM,
                "RAM at {base:#x} covers the device window"
            );
        }
    }

    #[cfg(all(feature = "kvm", target_os = "linux", target_arch = "x86_64"))]
    #[test]
    fn test_boot_and_console_output() {
        use std::io;
        use std::sync::{Arc, Mutex};

        use crate::boot::tests::bzimage;
        use crate::hv::backend::kvm::hypervisor::KvmHv;

        /// Sink for the test to read back after the run.
        #[derive(Clone)]
        struct Tap(Arc<Mutex<Vec<u8>>>);

        impl Write for Tap {
            fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
                self.0.lock().unwrap().extend_from_slice(buf);
                Ok(buf.len())
            }

            fn flush(&mut self) -> io::Result<()> {
                Ok(())
            }
        }

        // mov edx, 0x3f8 / mov al, 'o' / out dx, al / mov al, 'k' / out dx, al
        // in al, 0x61 / and al, 0xcf / out dx, al / ud2
        //
        // Port 0x61 belongs to the PIT. With PIT in the kernel, bits 4 and 5
        // toggle and the rest read zero, without it the port is unclaimed and
        // reads as all ones. `ud2` with an empty IDT triple faults, so the run
        // ends in `Shutdown`.
        let program = [
            0xba, 0xf8, 0x03, 0x00, 0x00, 0xb0, 0x6f, 0xee, 0xb0, 0x6b, 0xee, 0xe4, 0x61, 0x24,
            0xcf, 0xee, 0x0f, 0x0b,
        ];
        let mut payload = vec![0u8; 0x200];
        payload.extend_from_slice(&program);

        let image = std::env::temp_dir().join(format!("lingcore-machine-{}", std::process::id()));
        std::fs::write(&image, bzimage(&payload)).expect("write the kernel image");

        let console = Tap(Arc::new(Mutex::new(Vec::new())));
        let config = Config {
            memory: 16 << 20,
            vcpus: 1,
            kernel: image.clone(),
            initrd: None,
            cmdline: "console=ttyS0".to_string(),
            disk: None,
            // With `Trap`, a syscall missed by the allowlists ends the test
            // with `SIGSYS`.
            confine: Some(Refusal::Trap),
            channel: None,
            network: None,
        };
        let hv = KvmHv::new().expect("open /dev/kvm");
        let mut machine = Machine::new(&hv, &config, console.clone()).expect("assemble the guest");
        std::fs::remove_file(&image).expect("remove the kernel image");

        machine.start().expect("start");
        assert_eq!(machine.wait().expect("run"), VmExit::Shutdown);
        assert_eq!(
            console.0.lock().unwrap().as_slice(),
            b"ok\x00",
            "guest console got other bytes"
        );
    }

    #[cfg(all(feature = "kvm", target_os = "linux", target_arch = "x86_64"))]
    #[test]
    fn test_console_input_to_running_guest() {
        use std::io;
        use std::sync::{Arc, Mutex};

        use crate::boot::tests::bzimage;
        use crate::hv::backend::kvm::hypervisor::KvmHv;

        /// Console sink for the test to read back.
        #[derive(Clone)]
        struct Tap(Arc<Mutex<Vec<u8>>>);

        impl Write for Tap {
            fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
                self.0.lock().unwrap().extend_from_slice(buf);
                Ok(buf.len())
            }

            fn flush(&mut self) -> io::Result<()> {
                Ok(())
            }
        }

        // Guest polls `DATA` until it reads a non-zero byte and echoes it.
        // `DATA` reads zero while the queue is empty, so one read finds and
        // takes the byte. `ecx` bounds the poll, with no byte the guest
        // echoes the zero and stops, so a failure shows as wrong byte
        // instead of a hang.
        let program = [
            0xb9, 0x00, 0x00, 0x01, 0x00, // mov ecx, 0x10000
            0xba, 0xf8, 0x03, 0x00, 0x00, // mov edx, 0x3f8
            0xec, // poll: in al, dx
            0x84, 0xc0, //       test al, al
            0x75, 0x02, //       jnz send
            0xe2, 0xf9, //       loop poll
            0xee, // send: out dx, al
            0x0f, 0x0b, //       ud2
        ];
        let mut payload = vec![0u8; 0x200];
        payload.extend_from_slice(&program);

        let image = std::env::temp_dir().join(format!("lingcore-input-{}", std::process::id()));
        std::fs::write(&image, bzimage(&payload)).expect("write the kernel image");

        let console = Tap(Arc::new(Mutex::new(Vec::new())));
        let config = Config {
            memory: 16 << 20,
            vcpus: 1,
            kernel: image.clone(),
            initrd: None,
            cmdline: "console=ttyS0".to_string(),
            disk: None,
            confine: None,
            channel: None,
            network: None,
        };
        let hv = KvmHv::new().expect("open /dev/kvm");
        let mut machine = Machine::new(&hv, &config, console.clone()).expect("assemble the guest");
        std::fs::remove_file(&image).expect("remove the kernel image");

        // The share is taken before `start` and used after, with the guest
        // on its vCPU thread.
        let input = machine.console();
        machine.start().expect("start the guest");
        input.receive(b"Z").expect("receive a byte");

        assert_eq!(machine.wait().expect("run"), VmExit::Shutdown);
        assert_eq!(
            console.0.lock().unwrap().as_slice(),
            b"Z",
            "guest did not echo the byte"
        );
    }

    #[cfg(all(feature = "kvm", target_os = "linux", target_arch = "x86_64"))]
    #[test]
    fn test_i8042_reset_exits_reboot() {
        use crate::boot::tests::bzimage;
        use crate::hv::backend::kvm::hypervisor::KvmHv;

        // Guest writes the reset command, then executes `ud2`. A run which
        // dropped the reset ends on the fault instead, so exit reason tells
        // the two apart.
        let program = [
            0xb0, 0xfe, // mov al, 0xfe
            0xe6, 0x64, // out 0x64, al
            0x0f, 0x0b, // ud2
        ];
        let mut payload = vec![0u8; 0x200];
        payload.extend_from_slice(&program);

        let image = std::env::temp_dir().join(format!("lingcore-reset-{}", std::process::id()));
        std::fs::write(&image, bzimage(&payload)).expect("write the kernel image");

        let config = Config {
            memory: 16 << 20,
            vcpus: 1,
            kernel: image.clone(),
            initrd: None,
            cmdline: "console=ttyS0".to_string(),
            disk: None,
            confine: None,
            channel: None,
            network: None,
        };
        let hv = KvmHv::new().expect("open /dev/kvm");
        let mut machine = Machine::new(&hv, &config, Vec::new()).expect("assemble the guest");
        std::fs::remove_file(&image).expect("remove the kernel image");

        machine.start().expect("start the guest");
        assert_eq!(
            machine.wait().expect("run"),
            VmExit::Reboot,
            "guest ran past the reset"
        );
    }

    #[cfg(all(feature = "kvm", target_os = "linux", target_arch = "x86_64"))]
    #[test]
    fn test_pause_and_resume() {
        // Check output stops while paused, state is readable, and resume works.
        use std::io;
        use std::sync::{Arc, Mutex};
        use std::time::{Duration, Instant};

        use crate::boot::tests::bzimage;
        use crate::hv::backend::kvm::hypervisor::KvmHv;

        /// Sink which counts the bytes written.
        #[derive(Clone)]
        struct Counter(Arc<Mutex<usize>>);

        impl Counter {
            fn sent(&self) -> usize {
                *self.0.lock().unwrap()
            }
        }

        impl Write for Counter {
            fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
                *self.0.lock().unwrap() += buf.len();
                Ok(buf.len())
            }

            fn flush(&mut self) -> io::Result<()> {
                Ok(())
            }
        }

        // Write a byte to the UART in a loop.
        let program = [
            0xba, 0xf8, 0x03, 0x00, 0x00, // mov edx, 0x3f8
            0xb0, 0x78, // mov al, 'x'
            0xee, // out dx, al
            0xeb, 0xfb, // jmp back to the mov
        ];
        let mut payload = vec![0u8; 0x200];
        payload.extend_from_slice(&program);

        let image = std::env::temp_dir().join(format!("lingcore-hold-{}", std::process::id()));
        std::fs::write(&image, bzimage(&payload)).expect("write the kernel image");

        let console = Counter(Arc::new(Mutex::new(0)));
        let config = Config {
            memory: 16 << 20,
            vcpus: 1,
            kernel: image.clone(),
            initrd: None,
            cmdline: "console=ttyS0".to_string(),
            disk: None,
            confine: None,
            channel: None,
            network: None,
        };
        let hv = KvmHv::new().expect("open /dev/kvm");
        let mut machine = Machine::new(&hv, &config, console.clone()).expect("assemble the guest");
        std::fs::remove_file(&image).expect("remove the kernel image");

        machine.start().expect("start the guest");
        assert_eq!(machine.state(), State::Running);

        // Wait for output before pausing, so that a count which stops moving
        // means the pause, not a slow start.
        let deadline = Instant::now() + Duration::from_secs(10);
        while console.sent() == 0 {
            assert!(
                Instant::now() < deadline,
                "guest produced no output in 10 s"
            );
            std::thread::sleep(Duration::from_millis(5));
        }

        machine.pause().expect("pause the guest");
        assert_eq!(machine.state(), State::Paused);

        // `pause` returns once each thread is parked, not before.
        assert_eq!(
            machine.orders.standing.lock().unwrap().parked,
            machine.threads.len() + machine.device_threads.len(),
            "pause returned with thread not parked yet"
        );

        // Running guest writes thousands of bytes in 100 ms.
        let held = console.sent();
        std::thread::sleep(Duration::from_millis(100));
        assert_eq!(console.sent(), held, "paused guest kept writing");

        machine.resume().expect("resume the guest");
        assert_eq!(machine.state(), State::Running);
        let deadline = Instant::now() + Duration::from_secs(10);
        while console.sent() == held {
            assert!(Instant::now() < deadline, "resumed guest stayed still");
            std::thread::sleep(Duration::from_millis(5));
        }

        // Paused guest can be read, running one is refused.
        machine.pause().expect("pause the guest again");
        let (processors, devices) = machine.read_state().expect("read the paused guest");
        assert_eq!(processors.len(), usize::from(config.vcpus));
        assert!(
            !processors[0].data.is_empty(),
            "state blob of vCPU 0 is empty"
        );
        assert_eq!(
            devices.len(),
            3,
            "the console, the keyboard controller and the entropy source"
        );
        assert!(
            devices
                .iter()
                .any(|blob| { blob.as_ref().is_some_and(|blob| blob.kind == "serial") }),
            "no blob of kind serial among them"
        );
        machine.resume().expect("resume the guest again");
        assert!(
            machine.read_state().is_err(),
            "read_state passed on a running guest"
        );

        machine.stop().expect("stop the guest");
        assert_eq!(machine.wait().expect("wait"), VmExit::Interrupted);
    }

    #[cfg(all(feature = "kvm", target_os = "linux", target_arch = "x86_64"))]
    #[test]
    fn test_stop_spinning_guest() {
        use crate::boot::tests::bzimage;
        use crate::hv::backend::kvm::hypervisor::KvmHv;

        /// `jmp` to itself, guest spins without any exit.
        const SPIN: [u8; 2] = [0xeb, 0xfe];

        let mut payload = vec![0u8; 0x200];
        payload.extend_from_slice(&SPIN);
        let image = std::env::temp_dir().join(format!("lingcore-spin-{}", std::process::id()));
        std::fs::write(&image, bzimage(&payload)).expect("write the kernel image");

        let config = Config {
            memory: 16 << 20,
            vcpus: 1,
            kernel: image.clone(),
            initrd: None,
            cmdline: "console=ttyS0".to_string(),
            disk: None,
            confine: None,
            channel: None,
            network: None,
        };
        let hv = KvmHv::new().expect("open /dev/kvm");
        let mut machine = Machine::new(&hv, &config, Vec::new()).expect("assemble the guest");
        std::fs::remove_file(&image).expect("remove the kernel image");

        machine.start().expect("start the guest");
        // Guest spins inside `run`, so only a stop ends it. One `stop` is
        // enough, the `Stopper` covers a thread outside `run` and the signal
        // covers one inside.
        machine.stop().expect("stop the guest");
        assert_eq!(
            machine.wait().expect("wait"),
            VmExit::Interrupted,
            "run did not end on the kick"
        );
    }

    #[cfg(all(feature = "kvm", target_os = "linux", target_arch = "x86_64"))]
    #[test]
    fn test_reject_bad_transition() {
        use crate::boot::tests::bzimage;
        use crate::hv::backend::kvm::hypervisor::KvmHv;

        /// `ud2` triple faults with the empty IDT, run ends in `Shutdown`.
        const FAULT: [u8; 2] = [0x0f, 0x0b];

        let mut payload = vec![0u8; 0x200];
        payload.extend_from_slice(&FAULT);
        let image = std::env::temp_dir().join(format!("lingcore-state-{}", std::process::id()));
        std::fs::write(&image, bzimage(&payload)).expect("write the kernel image");

        let config = Config {
            memory: 16 << 20,
            vcpus: 1,
            kernel: image.clone(),
            initrd: None,
            cmdline: String::new(),
            disk: None,
            confine: None,
            channel: None,
            network: None,
        };
        let hv = KvmHv::new().expect("open /dev/kvm");
        let mut machine = Machine::new(&hv, &config, Vec::new()).expect("assemble the guest");
        std::fs::remove_file(&image).expect("remove the kernel image");

        // Before `start` there is no thread to stop or to wait on.
        assert_eq!(machine.state(), State::Created);
        assert!(matches!(machine.wait(), Err(Error::BadTransition { .. })));
        assert!(matches!(machine.stop(), Err(Error::BadTransition { .. })));

        machine.start().expect("start");
        assert_eq!(machine.state(), State::Running);
        // Second `start` would drop the handles of the first threads.
        assert!(matches!(machine.start(), Err(Error::BadTransition { .. })));

        assert_eq!(machine.wait().expect("wait"), VmExit::Shutdown);
        assert_eq!(machine.state(), State::Shutdown);
        assert!(matches!(machine.wait(), Err(Error::BadTransition { .. })));
        assert!(matches!(machine.stop(), Err(Error::BadTransition { .. })));
    }

    #[cfg(all(feature = "kvm", target_os = "linux", target_arch = "x86_64"))]
    #[test]
    fn test_all_vcpus_exit_on_first_stop() {
        use crate::boot::tests::bzimage;
        use crate::hv::backend::kvm::hypervisor::KvmHv;

        /// `ud2` triple faults with the empty IDT, run ends in `Shutdown`.
        const FAULT: [u8; 2] = [0x0f, 0x0b];
        const VCPUS: u16 = 4;

        let mut payload = vec![0u8; 0x200];
        payload.extend_from_slice(&FAULT);
        let image = std::env::temp_dir().join(format!("lingcore-smp-{}", std::process::id()));
        std::fs::write(&image, bzimage(&payload)).expect("write the kernel image");

        let config = Config {
            memory: 16 << 20,
            vcpus: VCPUS,
            kernel: image.clone(),
            initrd: None,
            cmdline: String::new(),
            disk: None,
            confine: None,
            channel: None,
            network: None,
        };
        let hv = KvmHv::new().expect("open /dev/kvm");
        let mut machine = Machine::new(&hv, &config, Vec::new()).expect("assemble the guest");
        std::fs::remove_file(&image).expect("remove the kernel image");

        machine.start().expect("start");
        assert_eq!(
            machine.threads.len(),
            usize::from(VCPUS),
            "vCPU left unstarted"
        );

        // Only vCPU 0 runs, the rest wait for an INIT which is not sent.
        // `wait` runs on its own thread so that a hang fails on the timeout
        // below.
        let reason = std::sync::Arc::new(std::sync::Mutex::new(None));
        let sink = std::sync::Arc::clone(&reason);
        let (sender, waited) = std::sync::mpsc::channel::<()>();
        std::thread::spawn(move || {
            let _sender = sender;
            let mut machine = machine;
            let exit = machine.wait();
            *sink.lock().unwrap() = Some((exit, machine.state()));
        });
        assert!(
            matches!(
                waited.recv_timeout(std::time::Duration::from_secs(20)),
                Err(std::sync::mpsc::RecvTimeoutError::Disconnected)
            ),
            "wait did not return in 20 s"
        );

        let (exit, state) = reason.lock().unwrap().take().expect("reason");
        assert_eq!(
            exit.expect("wait"),
            VmExit::Shutdown,
            "run did not end on the fault"
        );
        assert_eq!(state, State::Shutdown);
    }

    #[test]
    fn test_reject_zero_vcpus() {
        let config = Config {
            memory: 16 << 20,
            vcpus: 0,
            kernel: PathBuf::from("/nonexistent/kernel"),
            initrd: None,
            cmdline: String::new(),
            disk: None,
            confine: None,
            channel: None,
            network: None,
        };
        #[cfg(all(feature = "kvm", target_os = "linux", target_arch = "x86_64"))]
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
        #[cfg(all(feature = "kvm", target_os = "linux", target_arch = "x86_64"))]
        {
            use crate::hv::backend::kvm::hypervisor::KvmHv;

            let hv = KvmHv::new().expect("open /dev/kvm");
            let config = Config {
                memory: 16 << 20,
                vcpus: 1,
                kernel: PathBuf::from("/nonexistent/kernel"),
                initrd: None,
                cmdline: String::new(),
                disk: None,
                confine: None,
                channel: None,
                network: None,
            };
            assert!(matches!(
                Machine::new(&hv, &config, Vec::new()),
                Err(Error::Image(_))
            ));
        }
    }
}
