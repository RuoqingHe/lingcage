// SPDX-FileCopyrightText: 2026 LingCage <opensource@lingcage.com>
//
// SPDX-License-Identifier: Apache-2.0

//! Assembly of an x86_64 guest. The memory map, the bzImage, MP and
//! ACPI tables, and the vCPUs, with vCPU 0 entered in long mode.

/// ACPI tables in guest RAM.
mod acpi;
/// CPUID leaves per vCPU.
mod cpuid;
/// MP table in guest RAM.
mod mptable;

use std::fs::File;
use std::io::Write;

use crate::boot;
use crate::devices::Shared;
use crate::devices::bus::Bus;
use crate::devices::i8042::I8042;
use crate::devices::serial::Serial;
use crate::devices::virtio::mmio;
use crate::hv::hypervisor::Hypervisor;
use crate::hv::vcpu::Vcpu;
use crate::hv::vm::Vm;
use crate::machine::vmgenid::VmGenId;
use crate::machine::{BOOT_VCPU, Config, Error, Result, virtio_at, virtio_count};
use crate::mem::GuestRam;

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
pub(in crate::machine) const COM1_IRQ: u8 = 4;

/// MMIO address of the first virtio register block, in the hole below
/// the APICs. Each device takes the next block.
pub(in crate::machine) const VIRTIO_AT: u64 = 0xd000_0000;

/// IRQ of the GED. No device on the bus takes line 9, which is the SCI
/// on a PC.
pub(in crate::machine) const EVENTS_IRQ: u8 = 9;

/// IRQ of the first virtio device, an ISA line free on PC. Each device
/// takes the next line.
pub(in crate::machine) const VIRTIO_IRQ: u8 = 5;

/// Guest address of the VM generation ID, below the RSDP.
pub(in crate::machine) const GENID_AT: u64 = acpi::GENID_AT;

/// Kernel as left in RAM by `load`. Boot parameters name the initramfs.
pub(in crate::machine) type Loaded = boot::Kernel;

/// Returns the guest ranges occupied by `size` bytes of RAM, up to
/// `MMIO_HOLE` and the rest starting from `HIGH_RAM`.
pub(in crate::machine) fn layout(size: u64) -> Vec<(u64, u64)> {
    if size <= MMIO_HOLE {
        vec![(0, size)]
    } else {
        vec![(0, MMIO_HOLE), (HIGH_RAM, size - MMIO_HOLE)]
    }
}

/// Load the kernel and the initramfs named by `config` into `ram`, then
/// write boot parameters and the MP table.
pub(in crate::machine) fn load(config: &Config, ram: &GuestRam) -> Result<Loaded> {
    let mut image = File::open(&config.kernel).map_err(Error::Image)?;
    let kernel = boot::load_kernel(ram, &mut image)?;
    let initrd = match &config.initrd {
        Some(path) => {
            let mut image = File::open(path).map_err(Error::Image)?;
            Some(boot::load_initrd(ram, &kernel, &mut image)?)
        }
        None => None,
    };
    boot::write_boot_params(ram, &kernel, &config.cmdline, initrd)?;
    mptable::write(ram, config.vcpus)?;
    Ok(kernel)
}

/// Create the irqchip, then the vCPUs counted by `config` with their
/// CPUID leaves from `hv`. `KVM_CREATE_IRQCHIP` fails once a vCPU
/// exists. The rest wait in reset state for the INIT sent by kernel.
pub(in crate::machine) fn create_vcpus<H: Hypervisor>(
    hv: &H,
    vm: &H::Vm,
    config: &Config,
) -> Result<Vec<<H::Vm as Vm>::Vcpu>> {
    vm.enable_in_kernel_irqchip()?;
    let host = hv.supported_cpuid()?;
    let mut vcpus = Vec::with_capacity(usize::from(config.vcpus));
    for index in 0..config.vcpus {
        let mut vcpu = vm.create_vcpu(index)?;
        vcpu.set_cpuid(&cpuid::for_vcpu(&host, index))?;
        vcpus.push(vcpu);
    }
    Ok(vcpus)
}

/// Place the fixed devices on `bus`, `uart` on COM1, and the i8042
/// command port which a kernel writes its reset request to.
pub(in crate::machine) fn place_fixed<W>(bus: &mut Bus, uart: Shared<Serial<W>>) -> Result<()>
where
    W: Write + Send + 'static,
{
    bus.place_port(COM1, COM1_SIZE, Box::new(uart))?;
    bus.place_port(I8042_COMMAND, 1, Box::new(I8042))?;
    Ok(())
}

/// Write the ACPI tables and enter vCPU 0 of `vcpus` at `kernel` in
/// long mode. The tables name devices on the bus with their lines, so
/// command line carries no `virtio_mmio.device=` fragments.
pub(in crate::machine) fn enter<V: Vcpu>(
    ram: &GuestRam,
    config: &Config,
    vcpus: &mut [V],
    kernel: &Loaded,
    genid: &VmGenId,
) -> Result<()> {
    acpi::lay(
        ram,
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
    boot::enter_long_mode(ram, &mut vcpus[usize::from(BOOT_VCPU)], kernel)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use crate::machine::x86_64::*;
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

    #[cfg(all(feature = "kvm", target_os = "linux"))]
    #[test]
    fn test_boot_and_console_output() {
        use std::io;
        use std::sync::{Arc, Mutex};

        use crate::boot::bzimage::tests::bzimage;
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
            vcpus: 1,
            cmdline: "console=ttyS0".to_string(),
            // With `Trap` a syscall missed by the allowlists ends the test with
            // `SIGSYS`.
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
            b"ok\x00",
            "guest console got other bytes"
        );
    }

    #[cfg(all(feature = "kvm", target_os = "linux"))]
    #[test]
    fn test_console_input_to_running_guest() {
        use std::io;
        use std::sync::{Arc, Mutex};

        use crate::boot::bzimage::tests::bzimage;
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
        // takes the byte. `ecx` bounds the poll. With no byte the guest
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
    fn test_i8042_reset_exits_reboot() {
        use crate::boot::bzimage::tests::bzimage;
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
            "guest ran past the reset"
        );
    }

    #[cfg(all(feature = "kvm", target_os = "linux"))]
    #[test]
    fn test_pause_and_resume() {
        // Output stops while paused, state is readable, and resume works.
        use std::io;
        use std::sync::{Arc, Mutex};
        use std::time::{Duration, Instant};

        use crate::boot::bzimage::tests::bzimage;
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

    #[cfg(all(feature = "kvm", target_os = "linux"))]
    #[test]
    fn test_stop_spinning_guest() {
        use crate::boot::bzimage::tests::bzimage;
        use crate::hv::backend::kvm::hypervisor::KvmHv;

        /// `jmp` to itself, guest spins without any exit.
        const SPIN: [u8; 2] = [0xeb, 0xfe];

        let mut payload = vec![0u8; 0x200];
        payload.extend_from_slice(&SPIN);
        let image = std::env::temp_dir().join(format!("lingcore-spin-{}", std::process::id()));
        std::fs::write(&image, bzimage(&payload)).expect("write the kernel image");

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

    #[cfg(all(feature = "kvm", target_os = "linux"))]
    #[test]
    fn test_reject_bad_transition() {
        use crate::boot::bzimage::tests::bzimage;
        use crate::hv::backend::kvm::hypervisor::KvmHv;

        /// `ud2` triple faults with the empty IDT, run ends in `Shutdown`.
        const FAULT: [u8; 2] = [0x0f, 0x0b];

        let mut payload = vec![0u8; 0x200];
        payload.extend_from_slice(&FAULT);
        let image = std::env::temp_dir().join(format!("lingcore-state-{}", std::process::id()));
        std::fs::write(&image, bzimage(&payload)).expect("write the kernel image");

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
        // Second `start` would drop the handles of the first threads.
        assert!(matches!(machine.start(), Err(Error::BadTransition { .. })));

        assert_eq!(machine.wait().expect("wait"), VmExit::Shutdown);
        assert_eq!(machine.state(), State::Shutdown);
        assert!(matches!(machine.wait(), Err(Error::BadTransition { .. })));
        assert!(matches!(machine.stop(), Err(Error::BadTransition { .. })));
    }

    #[cfg(all(feature = "kvm", target_os = "linux"))]
    #[test]
    fn test_all_vcpus_exit_on_first_stop() {
        use crate::boot::bzimage::tests::bzimage;
        use crate::hv::backend::kvm::hypervisor::KvmHv;

        /// `ud2` triple faults with the empty IDT, run ends in `Shutdown`.
        const FAULT: [u8; 2] = [0x0f, 0x0b];
        const VCPUS: u16 = 4;

        let mut payload = vec![0u8; 0x200];
        payload.extend_from_slice(&FAULT);
        let image = std::env::temp_dir().join(format!("lingcore-smp-{}", std::process::id()));
        std::fs::write(&image, bzimage(&payload)).expect("write the kernel image");

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
}
