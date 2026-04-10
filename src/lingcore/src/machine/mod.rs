// SPDX-FileCopyrightText: 2026 LingCage <opensource@lingcage.com>
//
// SPDX-License-Identifier: Apache-2.0

//! Machine assembly. Guest RAM, the kernel loaded into it, a bus with
//! the serial console, and a vCPU entered at the kernel in long mode.

use std::fs::File;
use std::io::Write;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;

use thiserror::Error;

use crate::boot;
use crate::devices::bus::Bus;
use crate::devices::serial::Serial;
use crate::hv::hypervisor::Hypervisor;
use crate::hv::memory::{MemMapOption, VmMemory};
use crate::hv::vcpu::{Vcpu, VmExit};
use crate::hv::vm::Vm;
use crate::mem::GuestRam;
use crate::vcpu::VmOps;

mod cpuid;
mod mptable;

/// End of low RAM. Window from here to 4 GiB holds the I/O APIC and the
/// LAPIC.
const MMIO_HOLE: u64 = 0xc000_0000;

/// Start of RAM above the window.
const HIGH_RAM: u64 = 0x1_0000_0000;

/// Port base of the first serial console, `ttyS0`.
const COM1: u16 = 0x3f8;

/// Size of the 16550 register window in bytes.
const COM1_SIZE: u16 = 8;

/// IRQ of the first serial console, `ttyS0`.
const COM1_IRQ: u8 = 4;

/// Index of the vCPU the guest boots on.
const BOOT_VCPU: u16 = 0;

/// Number of vCPUs given to a guest.
const VCPUS: u16 = 1;

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
    /// MP table for the vCPU count overflows the kilobyte scanned by kernel.
    #[error("MP table does not fit in its kilobyte")]
    NoRoomForMpTable,
    /// vCPU thread panicked.
    #[error("vCPU thread panicked")]
    VcpuThread,
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

/// Guest configuration which a `Machine` is assembled from.
#[derive(Debug, Clone)]
pub struct Config {
    /// Guest RAM size in bytes.
    pub memory: u64,
    /// Kernel image path, a bzImage on x86.
    pub kernel: PathBuf,
    /// Initramfs path, a cpio archive loaded above the kernel.
    pub initrd: Option<PathBuf>,
    /// Kernel command line.
    pub cmdline: String,
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
/// `Running` and `Running` to `Shutdown`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum State {
    /// Assembled, vCPU 0 at the kernel entry.
    Created,
    /// Each vCPU running on its own thread.
    Running,
    /// Threads joined and exit reason read.
    Shutdown,
}

impl State {
    /// Returns `BadTransition` unless `next` is a valid move from `self`.
    fn valid_transition(self, next: State) -> Result<()> {
        match (self, next) {
            (State::Created, State::Running) => Ok(()),
            (State::Running, State::Shutdown) => Ok(()),
            _ => Err(Error::BadTransition {
                from: self,
                to: next,
            }),
        }
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
    fn write_port(&mut self, port: u16, size: u8, value: u32) -> crate::hv::Result<()> {
        self.0.lock().unwrap().write_port(port, size, value)
    }

    fn read_mmio(&mut self, addr: u64, size: u8) -> crate::hv::Result<u64> {
        self.0.lock().unwrap().read_mmio(addr, size)
    }

    fn write_mmio(&mut self, addr: u64, size: u8, value: u64) -> crate::hv::Result<()> {
        self.0.lock().unwrap().write_mmio(addr, size, value)
    }
}

/// Assembled guest, with its vCPU at the kernel entry.
pub struct Machine<H: Hypervisor> {
    vm: H::Vm,
    /// Address space the host pages are mapped into. Dropping it unmaps
    /// them.
    #[expect(dead_code, reason = "kept for the mappings")]
    memory: <H::Vm as Vm>::Memory,
    ram: GuestRam,
    devices: Devices,
    /// vCPUs not started yet, `start` moves them onto threads.
    vcpus: Vec<<H::Vm as Vm>::Vcpu>,
    /// One thread per started vCPU, `stop_vcpu` signals a vCPU through its
    /// handle.
    threads: Vec<JoinHandle<Result<VmExit>>>,
    state: State,
}

impl<H: Hypervisor> Machine<H> {
    /// Assemble a guest on `hv` from `config`, with serial console writing
    /// to `console`, and leave vCPU 0 at the kernel entry.
    ///
    /// Kernel is loaded before boot parameters are written, since they are
    /// built from its `setup_header`. CPUID is set before the vCPU runs,
    /// since a kernel reads its model and feature bits from it.
    ///
    /// The irqchip is created before the vCPU, since `KVM_CREATE_IRQCHIP`
    /// fails once a vCPU exists. With irqchip in the kernel, `hlt` blocks
    /// inside the run instead of exiting as `Halt`.
    pub fn new<W>(hv: &H, config: &Config, console: W) -> Result<Self>
    where
        W: Write + Send + 'static,
        // The sender is boxed into the `Serial`, a `dyn Device` owned by
        // the `Bus`.
        <H::Vm as Vm>::IrqSender: 'static,
    {
        let ram = GuestRam::new(&layout(config.memory))?;
        let vm = hv.create_vm()?;
        vm.enable_in_kernel_irqchip()?;
        let memory = vm.create_vm_memory()?;
        for region in ram.regions() {
            memory.mem_map(region.gpa, region.size, region.hva, MemMapOption::default())?;
        }

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
        mptable::write(&ram, VCPUS)?;

        let mut bus = Bus::new();
        let line = vm.create_irq_sender(COM1_IRQ)?;
        bus.place_port(
            COM1,
            COM1_SIZE,
            Box::new(Serial::new(console).on_line(Box::new(line))),
        )?;

        let mut vcpu = vm.create_vcpu(BOOT_VCPU)?;
        vcpu.set_cpuid(&cpuid::for_vcpu(&hv.supported_cpuid()?, BOOT_VCPU))?;
        boot::enter_long_mode(&ram, &mut vcpu, &kernel)?;

        Ok(Machine {
            vm,
            memory,
            ram,
            devices: Devices(Arc::new(Mutex::new(bus))),
            vcpus: vec![vcpu],
            threads: Vec::new(),
            state: State::Created,
        })
    }

    /// Returns current state of the guest.
    pub fn state(&self) -> State {
        self.state
    }

    /// Start each vCPU on its own thread.
    ///
    /// Each thread holds a clone of `GuestRam`. Host pages are unmapped
    /// together with the last clone instead of the `Machine`.
    pub fn start(&mut self) -> Result<()>
    where
        H: 'static,
    {
        self.state.valid_transition(State::Running)?;
        self.threads = self
            .vcpus
            .drain(..)
            .map(|mut vcpu| {
                let mut devices = self.devices.clone();
                // The thread keeps the pages mapped after the `Machine` drops.
                let ram = self.ram.clone();
                std::thread::spawn(move || {
                    let _ram = ram;
                    Ok(crate::vcpu::run(&mut vcpu, &mut devices)?)
                })
            })
            .collect();
        self.state = State::Running;
        Ok(())
    }

    /// Signal each vCPU thread out of `run`, the run returns `Interrupted`.
    ///
    /// Signal landing before the thread enters `run` is consumed by the
    /// handler, so caller repeats the call until threads finish.
    pub fn stop(&self) -> Result<()> {
        if self.state != State::Running {
            return Err(Error::BadTransition {
                from: self.state,
                to: State::Shutdown,
            });
        }
        for (index, thread) in self.threads.iter().enumerate() {
            self.vm.stop_vcpu(index as u16, thread)?;
        }
        Ok(())
    }

    /// Join the vCPU threads and return the first exit reason.
    pub fn wait(&mut self) -> Result<VmExit> {
        self.state.valid_transition(State::Shutdown)?;
        let mut first = None;
        for thread in self.threads.drain(..) {
            let exit = thread.join().map_err(|_| Error::VcpuThread)?;
            first = first.or(Some(exit));
        }
        self.state = State::Shutdown;
        first.unwrap_or(Ok(VmExit::Shutdown))
    }
}

#[cfg(test)]
mod tests {
    use crate::machine::*;

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
            kernel: image.clone(),
            initrd: None,
            cmdline: "console=ttyS0".to_string(),
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
    fn test_stop_spinning_guest() {
        use std::time::Duration;

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
            kernel: image.clone(),
            initrd: None,
            cmdline: "console=ttyS0".to_string(),
        };
        let hv = KvmHv::new().expect("open /dev/kvm");
        let mut machine = Machine::new(&hv, &config, Vec::new()).expect("assemble the guest");
        std::fs::remove_file(&image).expect("remove the kernel image");

        machine.start().expect("start the guest");
        // Kick before the thread enters `run` has no effect, so repeat until
        for _ in 0..64 {
            if machine.threads.iter().all(|thread| thread.is_finished()) {
                break;
            }
            machine.stop().expect("stop the guest");
            std::thread::sleep(Duration::from_millis(20));
        }
        // Fail here instead of blocking in `wait` below.
        assert!(
            machine.threads.iter().all(|thread| thread.is_finished()),
            "vCPU thread still running after 64 kicks"
        );
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
            kernel: image.clone(),
            initrd: None,
            cmdline: String::new(),
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

    #[test]
    fn test_reject_unreadable_kernel() {
        #[cfg(all(feature = "kvm", target_os = "linux", target_arch = "x86_64"))]
        {
            use crate::hv::backend::kvm::hypervisor::KvmHv;

            let hv = KvmHv::new().expect("open /dev/kvm");
            let config = Config {
                memory: 16 << 20,
                kernel: PathBuf::from("/nonexistent/kernel"),
                initrd: None,
                cmdline: String::new(),
            };
            assert!(matches!(
                Machine::new(&hv, &config, Vec::new()),
                Err(Error::Image(_))
            ));
        }
    }
}
