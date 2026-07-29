// SPDX-FileCopyrightText: 2026 LingCage <opensource@lingcage.com>
//
// SPDX-License-Identifier: Apache-2.0

//! Assembly of an aarch64 guest. The memory map, the Image, the GIC,
//! and the vCPUs, with vCPU 0 entered at EL1 with the device tree. The
//! `cfg` is on the declaration in `machine/mod.rs`.

/// Device tree in guest RAM.
mod fdt;

use std::fs::File;
use std::io::Write;

use crate::boot;
use crate::devices::Shared;
use crate::devices::bus::Bus;
use crate::devices::serial::Serial;
use crate::devices::virtio::mmio;
use crate::hv::arch::{Gic, redist_room};
use crate::hv::hypervisor::Hypervisor;
use crate::hv::vcpu::Vcpu;
use crate::hv::vm::Vm;
use crate::machine::vmgenid::{self, VmGenId};
use crate::machine::{BOOT_VCPU, Config, Error, Result, virtio_at, virtio_count};
use crate::mem::GuestRam;

/// Start of guest RAM.
const RAM_AT: u64 = 0x4000_0000;

/// Base the kernel is loaded from, `text_offset` above it. An arm64
/// Image asks to sit at a 2 MiB aligned base and most of them carry a
/// `text_offset` of zero, so the base is raised instead: RAM below it
/// holds the device tree and VM generation ID, and is left out of the
/// memory node of the tree.
const KERNEL_AT: u64 = RAM_AT + 0x20_0000;

/// Guest address of the device tree, `FDT_ROOM` bytes at start of RAM.
const FDT_AT: u64 = RAM_AT;

/// Bytes the device tree may take.
const FDT_ROOM: u64 = 0x1_0000;

/// Guest address of the VM generation ID, above the device tree.
pub(in crate::machine) const GENID_AT: u64 = FDT_AT + FDT_ROOM;

/// Guest address of the GIC distributor.
const GICD_AT: u64 = 0x0800_0000;

/// Guest address of the redistributor frame of vCPU 0. The one of vCPU
/// `n` is `n` frames above.
const GICR_AT: u64 = 0x080a_0000;

/// MMIO address of the serial console, `ttyS0`.
const COM1_AT: u64 = 0x0900_0000;

/// Size of the 16550 register window in bytes.
const COM1_SIZE: u64 = 8;

/// MMIO address of the first virtio register block. Each device takes
/// the next block.
pub(in crate::machine) const VIRTIO_AT: u64 = 0x0a00_0000;

/// GIC source of the serial console.
pub(in crate::machine) const COM1_IRQ: u8 = 0;

/// GIC source of the VM generation ID.
pub(in crate::machine) const EVENTS_IRQ: u8 = 1;

/// GIC source of the first virtio device. Each device uses next
/// source.
pub(in crate::machine) const VIRTIO_IRQ: u8 = 2;

/// Virtio devices the sources of this machine reach, the SPIs of the
/// GIC behind the console and the identifier.
pub(in crate::machine) const VIRTIO_DEVICES: usize = GIC.sources as usize - VIRTIO_IRQ as usize;

/// Returns the source of virtio register block `slot`, or `None` once
/// the sources of the GIC are spent. Sources here run one after
/// another, and this machine puts no other device on them.
pub(in crate::machine) fn virtio_line(slot: u8) -> Option<u8> {
    (usize::from(slot) < VIRTIO_DEVICES).then_some(VIRTIO_IRQ + slot)
}

/// The GIC, 32 SPIs, enough for the console, the identifier and virtio
/// devices, and the fewest interrupt ids KVM allows.
const GIC: Gic = Gic {
    dist: GICD_AT,
    redist: GICR_AT,
    sources: 32,
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
    let kernel = boot::load_kernel(ram, KERNEL_AT, &mut image)?;
    let initrd = match &config.initrd {
        Some(path) => {
            let mut image = File::open(path).map_err(Error::Image)?;
            Some(boot::load_initrd(ram, &kernel, &mut image)?)
        }
        None => None,
    };
    Ok(Loaded { kernel, initrd })
}

/// Create the vCPUs counted by `config`, then the GIC, which needs a
/// redistributor frame per vCPU. `hv` is unused.
pub(in crate::machine) fn create_vcpus<H: Hypervisor>(
    _hv: &H,
    vm: &H::Vm,
    config: &Config,
) -> Result<Vec<<H::Vm as Vm>::Vcpu>> {
    let mut vcpus = Vec::with_capacity(usize::from(config.vcpus));
    for index in 0..config.vcpus {
        vcpus.push(vm.create_vcpu(index)?);
    }
    vm.enable_in_kernel_irqchip(&GIC)?;
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
/// the affinity of each vCPU. RAM below the kernel holds the tree and
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
    let mut affinities = Vec::with_capacity(vcpus.len());
    for vcpu in vcpus.iter() {
        affinities.push(vcpu.affinity()?);
    }
    let first = &mut vcpus[usize::from(BOOT_VCPU)];
    boot::enter_kernel(first, &kernel.kernel, FDT_AT)?;
    fdt::lay(
        ram,
        FDT_AT,
        FDT_ROOM,
        &fdt::Parts {
            affinities: &affinities,
            memory: (
                kernel.kernel.entry,
                RAM_AT + config.memory - kernel.kernel.entry,
            ),
            cmdline: &config.cmdline,
            initrd: kernel.initrd,
            gic: &GIC,
            redist: redist_room(config.vcpus),
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
    use crate::machine::aarch64::*;
    use crate::machine::*;

    /// Store `o` and `k` at the console data register, then ask PSCI for
    /// a power off and spin.
    const OK: [u8; 36] = [
        0x01, 0x20, 0xa1, 0xd2, 0xe2, 0x0d, 0x80, 0x52, 0x22, 0x00, 0x00, 0x39, 0x62, 0x0d, 0x80,
        0x52, 0x22, 0x00, 0x00, 0x39, 0x00, 0x01, 0x80, 0x52, 0x00, 0x80, 0xb0, 0x72, 0x02, 0x00,
        0x00, 0xd4, 0x00, 0x00, 0x00, 0x14,
    ];

    /// The PSCI `SYSTEM_OFF` call alone, plus the spin after it.
    const SHUTDOWN: [u8; 16] = [
        0x00, 0x01, 0x80, 0x52, 0x00, 0x80, 0xb0, 0x72, 0x02, 0x00, 0x00, 0xd4, 0x00, 0x00, 0x00,
        0x14,
    ];

    /// The PSCI `SYSTEM_RESET` call, plus the spin after it.
    const RESET: [u8; 16] = [
        0x20, 0x01, 0x80, 0x52, 0x00, 0x80, 0xb0, 0x72, 0x02, 0x00, 0x00, 0xd4, 0x00, 0x00, 0x00,
        0x14,
    ];

    /// `b .`, guest spins without any exit.
    const SPIN: [u8; 4] = [0x00, 0x00, 0x00, 0x14];

    /// Poll `LSR` for a byte, at most 0x10000 times, store the byte read
    /// from the data register back to it and power off. With no byte it
    /// echoes a zero, so a failure shows as wrong byte instead of a hang.
    const ECHO: [u8; 52] = [
        0x01, 0x20, 0xa1, 0xd2, 0x23, 0x00, 0xa0, 0x52, 0x22, 0x14, 0x40, 0x39, 0x5f, 0x00, 0x00,
        0x72, 0x61, 0x00, 0x00, 0x54, 0x63, 0x04, 0x00, 0x71, 0x81, 0xff, 0xff, 0x54, 0x22, 0x00,
        0x40, 0x39, 0x22, 0x00, 0x00, 0x39, 0x00, 0x01, 0x80, 0x52, 0x00, 0x80, 0xb0, 0x72, 0x02,
        0x00, 0x00, 0xd4, 0x00, 0x00, 0x00, 0x14,
    ];

    /// Write an Image holding `program` and return its path.
    fn image_of(tag: &str, program: &[u8]) -> PathBuf {
        use crate::boot::image::tests::image;

        let path = std::env::temp_dir().join(format!("lingcore-{tag}-{}", std::process::id()));
        std::fs::write(&path, image(program)).expect("write the kernel image");
        path
    }

    /// Console sink the test reads back after the run.
    #[cfg(all(feature = "kvm", target_os = "linux"))]
    #[derive(Clone)]
    struct Tap(std::sync::Arc<std::sync::Mutex<Vec<u8>>>);

    #[cfg(all(feature = "kvm", target_os = "linux"))]
    impl Write for Tap {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(buf);
            Ok(buf.len())
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    /// Returns a config booting `program` as its kernel, with the image
    /// left on disk for the caller to remove.
    fn booting(tag: &str, program: &[u8]) -> (Config, PathBuf) {
        let image = image_of(tag, program);
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
        (config, image)
    }

    #[cfg(all(feature = "kvm", target_os = "linux"))]
    #[test]
    fn test_boot_and_console_output() {
        use crate::hv::backend::kvm::hypervisor::KvmHv;

        let console = Tap(std::sync::Arc::new(std::sync::Mutex::new(Vec::new())));
        let (config, image) = booting("machine", &OK);
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
        // A byte written to the console reaches the guest, which reads it
        // from the data register and writes it back.
        use crate::hv::backend::kvm::hypervisor::KvmHv;

        let console = Tap(std::sync::Arc::new(std::sync::Mutex::new(Vec::new())));
        let (config, image) = booting("input", &ECHO);
        let hv = KvmHv::new().expect("open /dev/kvm");
        let mut machine = Machine::new(&hv, &config, console.clone()).expect("assemble the guest");
        std::fs::remove_file(&image).expect("remove the kernel image");

        let input = machine.console();
        machine.start().expect("start");
        while input.receive(b"z").expect("queue a byte") == 0 {
            std::thread::sleep(std::time::Duration::from_millis(1));
        }
        assert_eq!(machine.wait().expect("run"), VmExit::Shutdown);
        assert_eq!(
            console.0.lock().unwrap().as_slice(),
            b"z",
            "guest echoed other bytes"
        );
    }

    #[cfg(all(feature = "kvm", target_os = "linux"))]
    #[test]
    fn test_psci_reset_exits_reboot() {
        // PSCI `SYSTEM_RESET` ends the machine as a reboot, which is not
        // served.
        use crate::hv::backend::kvm::hypervisor::KvmHv;

        let (config, image) = booting("reboot", &RESET);
        let hv = KvmHv::new().expect("open /dev/kvm");
        let mut machine = Machine::new(&hv, &config, Vec::new()).expect("assemble the guest");
        std::fs::remove_file(&image).expect("remove the kernel image");

        machine.start().expect("start");
        assert_eq!(machine.wait().expect("run"), VmExit::Reboot);
    }

    #[cfg(all(feature = "kvm", target_os = "linux"))]
    #[test]
    fn test_stop_spinning_guest() {
        use crate::hv::backend::kvm::hypervisor::KvmHv;

        let (mut config, image) = booting("spin", &SPIN);
        config.confine = None;
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
    fn test_all_vcpus_exit_on_first_stop() {
        // Every vCPU comes out when one of them powers the guest off.
        use crate::hv::backend::kvm::hypervisor::KvmHv;

        let (mut config, image) = booting("smp", &SHUTDOWN);
        config.vcpus = 2;
        let hv = KvmHv::new().expect("open /dev/kvm");
        let mut machine = Machine::new(&hv, &config, Vec::new()).expect("assemble the guest");
        std::fs::remove_file(&image).expect("remove the kernel image");

        machine.start().expect("start the guest");
        assert_eq!(machine.wait().expect("wait"), VmExit::Shutdown);
    }
}
