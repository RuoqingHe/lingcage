// SPDX-FileCopyrightText: 2026 LingCage <opensource@lingcage.com>
//
// SPDX-License-Identifier: Apache-2.0

//! Assembly of a riscv64 guest. The memory map, the Image, the AIA, and
//! the vCPUs, with vCPU 0 entered in supervisor mode with the device
//! tree. The `cfg` is on the declaration in `machine/mod.rs`.

/// Device tree in guest RAM.
mod fdt;

use std::fs::File;
use std::io::Write;

use crate::boot;
use crate::devices::Shared;
use crate::devices::bus::Bus;
use crate::devices::serial::Serial;
use crate::devices::virtio::mmio;
use crate::hv::arch::{Aia, ConfigReg};
use crate::hv::hypervisor::Hypervisor;
use crate::hv::vcpu::Vcpu;
use crate::hv::vm::Vm;
use crate::machine::vmgenid::{self, VmGenId};
use crate::machine::{BOOT_VCPU, Config, Error, Result, virtio_at, virtio_count};
use crate::mem::GuestRam;

/// Start of guest RAM. Kernel is loaded `text_offset` above it, which is
/// 2 MiB on rv64. RAM below the kernel holds the device tree and VM
/// generation ID, and is left out of the memory node of the tree.
const RAM_AT: u64 = 0x4000_0000;

/// Guest address of the device tree, `FDT_ROOM` bytes at start of RAM.
const FDT_AT: u64 = RAM_AT;

/// Bytes the device tree may take.
const FDT_ROOM: u64 = 0x1_0000;

/// Guest address of the VM generation ID, above the device tree.
pub(in crate::machine) const GENID_AT: u64 = FDT_AT + FDT_ROOM;

/// Guest address of APLIC register block.
const APLIC_AT: u64 = 0x0040_0000;

/// Guest address of IMSIC file of hart 0. The one of hart `n` is `n`
/// pages above.
const IMSIC_AT: u64 = 0x0400_0000;

/// MMIO address of the serial console, `ttyS0`.
const COM1_AT: u64 = 0x0800_0000;

/// Size of the 16550 register window in bytes.
const COM1_SIZE: u64 = 8;

/// MMIO address of the first virtio register block. Each device takes
/// the next block.
pub(in crate::machine) const VIRTIO_AT: u64 = 0x0a00_0000;

/// APLIC source of the serial console.
pub(in crate::machine) const COM1_IRQ: u8 = 1;

/// APLIC source of the VM generation ID.
pub(in crate::machine) const EVENTS_IRQ: u8 = 2;

/// APLIC source of the first virtio device. Each device takes the next
/// source.
pub(in crate::machine) const VIRTIO_IRQ: u8 = 3;

/// Virtio devices the sources of this machine reach. Sources run from
/// one, so the last is `AIA.sources` itself.
pub(in crate::machine) const VIRTIO_DEVICES: usize = AIA.sources as usize + 1 - VIRTIO_IRQ as usize;

/// Returns the source of virtio register block `slot`, or `None` once
/// the sources of the AIA are spent. Sources here run one after
/// another, and this machine puts no other device on them.
pub(in crate::machine) fn virtio_line(slot: u8) -> Option<u8> {
    (usize::from(slot) < VIRTIO_DEVICES).then_some(VIRTIO_IRQ + slot)
}

/// The AIA, 31 wired sources, enough for the console, the identifier
/// and virtio devices, and the fewest identities an IMSIC file holds.
const AIA: Aia = Aia {
    aplic: APLIC_AT,
    imsic: IMSIC_AT,
    sources: 31,
    ids: 63,
};

/// Kernel as left in RAM by `load`, together with the initramfs named
/// by the device tree.
pub(in crate::machine) struct Loaded {
    kernel: boot::Kernel,
    initrd: Option<boot::Initrd>,
}

/// Returns the guest range occupied by `size` bytes of RAM, starting
/// from `RAM_AT`.
pub(in crate::machine) fn layout(size: u64) -> Vec<(u64, u64)> {
    vec![(RAM_AT, size)]
}

/// Load the kernel and the initramfs named by `config` into `ram`.
pub(in crate::machine) fn load(config: &Config, ram: &GuestRam) -> Result<Loaded> {
    let mut image = File::open(&config.kernel).map_err(Error::Image)?;
    let kernel = boot::load_kernel(ram, RAM_AT, &mut image)?;
    let initrd = match &config.initrd {
        Some(path) => {
            let mut image = File::open(path).map_err(Error::Image)?;
            Some(boot::load_initrd(ram, &kernel, &mut image)?)
        }
        None => None,
    };
    Ok(Loaded { kernel, initrd })
}

/// Create the vCPUs counted by `config`, then the AIA, which names an
/// IMSIC file per vCPU. `hv` is unused. The boot vCPU describes the
/// harts to the device tree, each with its ISA.
pub(in crate::machine) fn create_vcpus<H: Hypervisor>(
    _hv: &H,
    vm: &H::Vm,
    config: &Config,
) -> Result<Vec<<H::Vm as Vm>::Vcpu>> {
    let mut vcpus = Vec::with_capacity(usize::from(config.vcpus));
    for index in 0..config.vcpus {
        vcpus.push(vm.create_vcpu(index)?);
    }
    vm.enable_in_kernel_irqchip(&AIA)?;
    Ok(vcpus)
}

/// Place the fixed devices on `bus`, `uart` at `COM1_AT`.
pub(in crate::machine) fn place_fixed<W>(bus: &mut Bus, uart: Shared<Serial<W>>) -> Result<()>
where
    W: Write + Send + 'static,
{
    bus.place_mmio(COM1_AT, COM1_SIZE, Box::new(uart))?;
    Ok(())
}

/// Enter vCPU 0 of `vcpus` at `kernel` and write the device tree from
/// its ISA and configuration. RAM below the kernel holds the tree and
/// `genid`, and is left out of the memory node.
pub(in crate::machine) fn enter<V: Vcpu>(
    ram: &GuestRam,
    config: &Config,
    vcpus: &mut [V],
    kernel: &Loaded,
    genid: &VmGenId,
) -> Result<()> {
    if kernel.kernel.entry < GENID_AT + vmgenid::ROOM {
        return Err(Error::NoRoomForTree);
    }
    let first = &mut vcpus[usize::from(BOOT_VCPU)];
    boot::enter_kernel(first, &kernel.kernel, BOOT_VCPU, FDT_AT)?;
    let isa = first.isa()?;
    fdt::lay(
        ram,
        FDT_AT,
        FDT_ROOM,
        &fdt::Parts {
            vcpus: config.vcpus,
            isa: &isa,
            satp_mode: first.get_config(ConfigReg::SatpMode)?,
            timebase: first.get_config(ConfigReg::Timebase)?,
            cbom_block_size: first.get_config(ConfigReg::CbomBlockSize)?,
            cboz_block_size: first.get_config(ConfigReg::CbozBlockSize)?,
            memory: (
                kernel.kernel.entry,
                RAM_AT + config.memory - kernel.kernel.entry,
            ),
            cmdline: &config.cmdline,
            initrd: kernel.initrd,
            aia: &AIA,
            genid: fdt::Named {
                at: genid.at(),
                room: vmgenid::ROOM,
                line: EVENTS_IRQ,
            },
            console: fdt::Named {
                at: COM1_AT,
                room: COM1_SIZE,
                line: COM1_IRQ,
            },
            virtio: (0..virtio_count(config))
                .map(|slot| fdt::Named {
                    at: virtio_at(slot),
                    room: mmio::SIZE,
                    line: virtio_line(slot).unwrap_or(VIRTIO_IRQ),
                })
                .collect(),
        },
    )
}

#[cfg(test)]
mod tests {
    use crate::machine::*;

    /// li t0, COM1_AT / two bytes stored at `DATA` / ecall for
    /// `sbi_system_reset` shutdown / j .
    const OK: [u8; 40] = [
        0xb7, 0x02, 0x00, 0x08, 0x13, 0x03, 0xf0, 0x06, 0x23, 0x80, 0x62, 0x00, 0x13, 0x03, 0xb0,
        0x06, 0x23, 0x80, 0x62, 0x00, 0xb7, 0x58, 0x52, 0x53, 0x9b, 0x88, 0x48, 0x35, 0x01, 0x48,
        0x01, 0x45, 0x81, 0x45, 0x73, 0x00, 0x00, 0x00, 0x01, 0xa0,
    ];

    /// The `sbi_system_reset` shutdown call alone, plus the spin after it.
    const SHUTDOWN: [u8; 20] = [
        0xb7, 0x58, 0x52, 0x53, 0x9b, 0x88, 0x48, 0x35, 0x01, 0x48, 0x01, 0x45, 0x81, 0x45, 0x73,
        0x00, 0x00, 0x00, 0x01, 0xa0,
    ];

    /// `sbi_system_reset` with a cold reboot, plus the spin after it.
    const RESET: [u8; 20] = [
        0xb7, 0x58, 0x52, 0x53, 0x9b, 0x88, 0x48, 0x35, 0x01, 0x48, 0x05, 0x45, 0x81, 0x45, 0x73,
        0x00, 0x00, 0x00, 0x01, 0xa0,
    ];

    /// `j .`, guest spins without any exit.
    const SPIN: [u8; 2] = [0x01, 0xa0];

    /// A byte stored at `DATA` in a loop.
    const CHATTER: [u8; 14] = [
        0xb7, 0x02, 0x00, 0x08, 0x13, 0x03, 0x80, 0x07, 0x23, 0x80, 0x62, 0x00, 0xf5, 0xbf,
    ];

    /// Poll `LSR` for a byte, at most 0x10000 times, store the byte read
    /// from `DATA` back to `DATA` and shut down. With no byte it echoes a
    /// zero, so a failure shows as wrong byte instead of a hang.
    const ECHO: [u8; 52] = [
        0xb7, 0x02, 0x00, 0x08, 0xc1, 0x63, 0x03, 0x83, 0x52, 0x00, 0x13, 0x73, 0x13, 0x00, 0x63,
        0x15, 0x03, 0x00, 0xfd, 0x13, 0xe3, 0x99, 0x03, 0xfe, 0x03, 0x83, 0x02, 0x00, 0x23, 0x80,
        0x62, 0x00, 0xb7, 0x58, 0x52, 0x53, 0x9b, 0x88, 0x48, 0x35, 0x01, 0x48, 0x01, 0x45, 0x81,
        0x45, 0x73, 0x00, 0x00, 0x00, 0x01, 0xa0,
    ];

    /// Write an Image holding `program` and return its path.
    fn image_of(tag: &str, program: &[u8]) -> PathBuf {
        use crate::boot::image::tests::image;

        let path = std::env::temp_dir().join(format!("lingcore-{tag}-{}", std::process::id()));
        std::fs::write(&path, image(program)).expect("write the kernel image");
        path
    }

    #[cfg(all(feature = "kvm", target_os = "linux"))]
    #[test]
    fn test_boot_and_console_output() {
        use std::io;
        use std::sync::{Arc, Mutex};

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

        let image = image_of("machine", &OK);
        let console = Tap(Arc::new(Mutex::new(Vec::new())));
        let config = Config {
            vcpus: 1,
            cmdline: "console=ttyS0".to_string(),
            // `Trap` ends the test with `SIGSYS` on a syscall missed by the
            // allowlists.
            confine: Some(Refusal::Trap),
            kernel: image.clone(),
            memory: 16 << 20,
            ..Default::default()
        };
        let hv = KvmHv::new().expect("open /dev/kvm");
        let mut machine = Machine::new(&hv, &config, console.clone()).expect("assemble the guest");
        std::fs::remove_file(&image).expect("remove the kernel image");

        machine.start().expect("start");
        assert_eq!(machine.wait().expect("run"), VmExit::Shutdown);
        assert_eq!(
            console.0.lock().unwrap().as_slice(),
            b"ok",
            "guest console got other bytes"
        );
    }

    #[cfg(all(feature = "kvm", target_os = "linux"))]
    #[test]
    fn test_console_input_to_running_guest() {
        use std::io;
        use std::sync::{Arc, Mutex};

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

        let image = image_of("input", &ECHO);
        let console = Tap(Arc::new(Mutex::new(Vec::new())));
        let config = Config {
            vcpus: 1,
            cmdline: "console=ttyS0".to_string(),
            confine: None,
            kernel: image.clone(),
            memory: 16 << 20,
            ..Default::default()
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

    #[cfg(all(feature = "kvm", target_os = "linux"))]
    #[test]
    fn test_sbi_reset_exits_reboot() {
        use crate::hv::backend::kvm::hypervisor::KvmHv;

        let image = image_of("reset", &RESET);
        let config = Config {
            vcpus: 1,
            cmdline: "console=ttyS0".to_string(),
            confine: None,
            kernel: image.clone(),
            memory: 16 << 20,
            ..Default::default()
        };
        let hv = KvmHv::new().expect("open /dev/kvm");
        let mut machine = Machine::new(&hv, &config, Vec::new()).expect("assemble the guest");
        std::fs::remove_file(&image).expect("remove the kernel image");

        machine.start().expect("start the guest");
        assert_eq!(
            machine.wait().expect("run"),
            VmExit::Reboot,
            "guest stopped for another reason"
        );
    }

    #[cfg(all(feature = "kvm", target_os = "linux"))]
    #[test]
    fn test_pause_and_resume() {
        // Output stops while paused, state is readable, and resume works.
        use std::io;
        use std::sync::{Arc, Mutex};
        use std::time::{Duration, Instant};

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

        let image = image_of("hold", &CHATTER);
        let console = Counter(Arc::new(Mutex::new(0)));
        let config = Config {
            vcpus: 1,
            cmdline: "console=ttyS0".to_string(),
            confine: None,
            kernel: image.clone(),
            memory: 16 << 20,
            ..Default::default()
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
        assert_eq!(devices.len(), 2, "console and the entropy source");
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

    #[cfg(all(feature = "kvm", target_os = "linux"))]
    #[test]
    fn test_stop_spinning_guest() {
        use crate::hv::backend::kvm::hypervisor::KvmHv;

        let image = image_of("spin", &SPIN);
        let config = Config {
            vcpus: 1,
            cmdline: "console=ttyS0".to_string(),
            confine: None,
            kernel: image.clone(),
            memory: 16 << 20,
            ..Default::default()
        };
        let hv = KvmHv::new().expect("open /dev/kvm");
        let mut machine = Machine::new(&hv, &config, Vec::new()).expect("assemble the guest");
        std::fs::remove_file(&image).expect("remove the kernel image");

        machine.start().expect("start the guest");
        // Guest spins inside `run`, so only a stop ends it.
        machine.stop().expect("stop the guest");
        assert_eq!(
            machine.wait().expect("wait"),
            VmExit::Interrupted,
            "run did not end on the kick"
        );
    }

    #[cfg(all(feature = "kvm", target_os = "linux"))]
    #[test]
    fn test_reject_bad_transition() {
        use crate::hv::backend::kvm::hypervisor::KvmHv;

        let image = image_of("state", &SHUTDOWN);
        let config = Config {
            vcpus: 1,
            cmdline: String::new(),
            confine: None,
            kernel: image.clone(),
            memory: 16 << 20,
            ..Default::default()
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
        assert!(matches!(machine.start(), Err(Error::BadTransition { .. })));

        assert_eq!(machine.wait().expect("wait"), VmExit::Shutdown);
        assert_eq!(machine.state(), State::Shutdown);
        assert!(matches!(machine.wait(), Err(Error::BadTransition { .. })));
        assert!(matches!(machine.stop(), Err(Error::BadTransition { .. })));
    }

    #[cfg(all(feature = "kvm", target_os = "linux"))]
    #[test]
    fn test_all_vcpus_exit_on_first_stop() {
        use crate::hv::backend::kvm::hypervisor::KvmHv;

        const VCPUS: u16 = 4;

        let image = image_of("smp", &SHUTDOWN);
        let config = Config {
            vcpus: VCPUS,
            cmdline: String::new(),
            confine: None,
            kernel: image.clone(),
            memory: 16 << 20,
            ..Default::default()
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

        // Only vCPU 0 runs. The rest are stopped and wait for a start which
        // the guest never sends. `wait` runs on its own thread so that a hang
        // fails on the timeout below.
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
            "run did not end on the shutdown"
        );
        assert_eq!(state, State::Shutdown);
    }
}
