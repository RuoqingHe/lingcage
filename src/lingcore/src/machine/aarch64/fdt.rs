// SPDX-FileCopyrightText: 2026 LingCage <opensource@lingcage.com>
//
// SPDX-License-Identifier: Apache-2.0

//! Device tree of a kernel booted without firmware. CPUs, memory, PSCI,
//! the generic timer, the GIC, console, virtio register blocks and the
//! VM generation ID with their lines.

use vm_fdt::{FdtWriter, FdtWriterResult};

use crate::boot::Initrd;
use crate::hv::arch::{DIST_SIZE, Gic};
use crate::machine::{Error, Result};
use crate::mem::GuestRam;

/// phandle of the GIC, which every line of the tree is routed to.
const GIC_PHANDLE: u32 = 1;

/// Interrupt kinds of a GIC line, from
/// `include/dt-bindings/interrupt-controller/arm-gic.h`.
const GIC_SPI: u32 = 0;
const GIC_PPI: u32 = 1;

/// Trigger types from `include/dt-bindings/interrupt-controller/irq.h`.
/// Every device line is edge triggered here: the sender behind it is an
/// irqfd, which KVM asserts and never deasserts, so a level triggered
/// source would pend again on each acknowledge and the guest would
/// disable it.
const IRQ_TYPE_EDGE_RISING: u32 = 1;

/// Trigger type of the generic timer, which the guest itself lowers.
const IRQ_TYPE_LEVEL_HIGH: u32 = 4;

/// PPI numbers of the generic timer, its interrupt id less the sixteen
/// SGIs, for the secure, non-secure, virtual and hypervisor timer, as
/// `Documentation/devicetree/bindings/timer/arm,arch_timer.yaml` names
/// them.
const TIMER_PPIS: [u32; 4] = [13, 14, 11, 10];

/// `clock-frequency` of the console, the 1.8432 MHz reference clock
/// its divisor is set for.
const UART_CLOCK: u32 = 1_843_200;

/// `#address-cells` and `#size-cells` of the root, 64-bit addresses and
/// sizes.
const CELLS: u32 = 2;

/// `#address-cells` of the `cpus` node. Affinity of a vCPU stays below
/// `Aff3`, so one cell holds it.
const CPU_CELLS: u32 = 1;

/// Device named in the tree, with its register window and GIC source.
pub(in crate::machine::aarch64) struct Named {
    pub at: u64,
    pub room: u64,
    pub line: u8,
}

/// Parts named by the tree.
pub(in crate::machine::aarch64) struct Parts<'a> {
    /// Affinity of each vCPU, in creation order.
    pub affinities: &'a [u64],
    /// RAM reported to the kernel, start and length.
    pub memory: (u64, u64),
    pub cmdline: &'a str,
    pub initrd: Option<Initrd>,
    pub gic: &'a Gic,
    /// Redistributor frames, one per vCPU.
    pub redist: u64,
    /// The VM generation ID, its line is edge triggered.
    pub genid: Named,
    pub console: Named,
    pub virtio: Vec<Named>,
}

/// Write the tree for `parts` to `ram` at `at`. Tree over `room` bytes
/// is reported as `NoRoomForTree`.
pub(in crate::machine::aarch64) fn lay(
    ram: &GuestRam,
    at: u64,
    room: u64,
    parts: &Parts,
) -> Result<()> {
    let tree = build(parts).map_err(|_| Error::Tree)?;
    if tree.len() as u64 > room {
        return Err(Error::NoRoomForTree);
    }
    ram.write(at, &tree).map_err(|_| Error::NoRoomForTree)?;
    Ok(())
}

/// Returns the tree for `parts` as a flattened blob.
fn build(parts: &Parts) -> FdtWriterResult<Vec<u8>> {
    let mut fdt = FdtWriter::new()?;
    let root = fdt.begin_node("")?;
    fdt.property_string("compatible", "linux,dummy-virt")?;
    fdt.property_u32("#address-cells", CELLS)?;
    fdt.property_u32("#size-cells", CELLS)?;
    // Every line of the tree is a GIC line, so root sets it once.
    fdt.property_u32("interrupt-parent", GIC_PHANDLE)?;
    cpus(&mut fdt, parts)?;

    let (start, length) = parts.memory;
    let memory = fdt.begin_node(&format!("memory@{start:x}"))?;
    fdt.property_string("device_type", "memory")?;
    fdt.property_array_u64("reg", &[start, length])?;
    fdt.end_node(memory)?;

    let chosen = fdt.begin_node("chosen")?;
    fdt.property_string("bootargs", parts.cmdline)?;
    if let Some(initrd) = parts.initrd {
        fdt.property_u64("linux,initrd-start", initrd.addr)?;
        fdt.property_u64("linux,initrd-end", initrd.addr + initrd.size)?;
    }
    fdt.end_node(chosen)?;

    // KVM handles PSCI through `HVC`, and the guest resets, powers off and
    // starts its other CPUs through it.
    let psci = fdt.begin_node("psci")?;
    fdt.property_string_list(
        "compatible",
        vec!["arm,psci-1.0".to_string(), "arm,psci-0.2".to_string()],
    )?;
    fdt.property_string("method", "hvc")?;
    fdt.end_node(psci)?;

    let timer = fdt.begin_node("timer")?;
    fdt.property_string("compatible", "arm,armv8-timer")?;
    let ppis: Vec<u32> = TIMER_PPIS
        .iter()
        .flat_map(|ppi| [GIC_PPI, *ppi, IRQ_TYPE_LEVEL_HIGH])
        .collect();
    fdt.property_array_u32("interrupts", &ppis)?;
    fdt.property_null("always-on")?;
    fdt.end_node(timer)?;

    gic(&mut fdt, parts)?;

    let console = fdt.begin_node(&format!("serial@{:x}", parts.console.at))?;
    fdt.property_string("compatible", "ns16550a")?;
    fdt.property_array_u64("reg", &[parts.console.at, parts.console.room])?;
    fdt.property_u32("clock-frequency", UART_CLOCK)?;
    line(&mut fdt, parts.console.line, IRQ_TYPE_EDGE_RISING)?;
    fdt.end_node(console)?;

    for block in &parts.virtio {
        let node = fdt.begin_node(&format!("virtio_mmio@{:x}", block.at))?;
        fdt.property_string("compatible", "virtio,mmio")?;
        fdt.property_array_u64("reg", &[block.at, block.room])?;
        line(&mut fdt, block.line, IRQ_TYPE_EDGE_RISING)?;
        fdt.end_node(node)?;
    }

    let genid = fdt.begin_node(&format!("rng@{:x}", parts.genid.at))?;
    fdt.property_string("compatible", "microsoft,vmgenid")?;
    fdt.property_array_u64("reg", &[parts.genid.at, parts.genid.room])?;
    line(&mut fdt, parts.genid.line, IRQ_TYPE_EDGE_RISING)?;
    fdt.end_node(genid)?;

    fdt.end_node(root)?;
    fdt.finish()
}

/// Write the line of a device, GIC source `source` with `trigger`. An
/// SPI is numbered from 0 in the tree and the GIC adds its private ids.
fn line(fdt: &mut FdtWriter, source: u8, trigger: u32) -> FdtWriterResult<()> {
    fdt.property_array_u32("interrupts", &[GIC_SPI, u32::from(source), trigger])
}

/// Write the `cpus` node, one CPU per vCPU named by its affinity, as
/// described in `Documentation/devicetree/bindings/arm/cpus.yaml`. The
/// guest starts a CPU other than the first through PSCI.
fn cpus(fdt: &mut FdtWriter, parts: &Parts) -> FdtWriterResult<()> {
    let cpus = fdt.begin_node("cpus")?;
    fdt.property_u32("#address-cells", CPU_CELLS)?;
    fdt.property_u32("#size-cells", 0)?;
    for affinity in parts.affinities {
        let cpu = fdt.begin_node(&format!("cpu@{affinity:x}"))?;
        fdt.property_string("device_type", "cpu")?;
        fdt.property_string("compatible", "arm,arm-v8")?;
        fdt.property_string("enable-method", "psci")?;
        fdt.property_u32("reg", *affinity as u32)?;
        fdt.end_node(cpu)?;
    }
    fdt.end_node(cpus)?;
    Ok(())
}

/// Write the GIC, a v3 distributor with the redistributor frames after
/// it, as described by the `arm,gic-v3` binding.
fn gic(fdt: &mut FdtWriter, parts: &Parts) -> FdtWriterResult<()> {
    let node = fdt.begin_node(&format!("intc@{:x}", parts.gic.dist))?;
    fdt.property_string("compatible", "arm,gic-v3")?;
    fdt.property_u32("#interrupt-cells", 3)?;
    fdt.property_null("interrupt-controller")?;
    fdt.property_array_u64(
        "reg",
        &[parts.gic.dist, DIST_SIZE, parts.gic.redist, parts.redist],
    )?;
    fdt.property_u32("#address-cells", CELLS)?;
    fdt.property_u32("#size-cells", CELLS)?;
    fdt.property_null("ranges")?;
    fdt.property_u32("phandle", GIC_PHANDLE)?;
    fdt.end_node(node)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use crate::hv::arch::redist_room;
    use crate::machine::aarch64::fdt::*;

    fn parts<'a>(affinities: &'a [u64], gic: &'a Gic) -> Parts<'a> {
        Parts {
            affinities,
            memory: (0x4020_0000, 0x1000_0000),
            cmdline: "console=ttyS0",
            initrd: None,
            gic,
            redist: redist_room(affinities.len() as u16),
            genid: Named {
                at: 0x4001_0000,
                room: 0x1000,
                line: 1,
            },
            console: Named {
                at: 0x0900_0000,
                room: 8,
                line: 0,
            },
            virtio: vec![Named {
                at: 0x0a00_0000,
                room: 0x200,
                line: 2,
            }],
        }
    }

    /// Returns whether `blob` holds `text` as a NUL terminated string.
    fn holds(blob: &[u8], text: &str) -> bool {
        let mut wanted = text.as_bytes().to_vec();
        wanted.push(0);
        blob.windows(wanted.len()).any(|part| part == wanted)
    }

    #[test]
    fn test_tree_names_platform() {
        let gic = Gic {
            dist: 0x0800_0000,
            redist: 0x080a_0000,
            sources: 32,
        };
        let blob = build(&parts(&[0, 1], &gic)).expect("build the tree");

        for name in [
            "arm,gic-v3",
            "arm,armv8-timer",
            "arm,psci-1.0",
            "hvc",
            "psci",
            "ns16550a",
            "virtio,mmio",
            "microsoft,vmgenid",
            "cpu@0",
            "cpu@1",
            "intc@8000000",
            "memory@40200000",
            "console=ttyS0",
        ] {
            assert!(holds(&blob, name), "tree does not name {name}");
        }
    }

    #[test]
    fn test_tree_over_its_room_refused() {
        let gic = Gic {
            dist: 0x0800_0000,
            redist: 0x080a_0000,
            sources: 32,
        };
        let ram = GuestRam::new(&[(0x4000_0000, 2 << 20)]).expect("host pages");
        assert!(matches!(
            lay(&ram, 0x4000_0000, 16, &parts(&[0], &gic)),
            Err(Error::NoRoomForTree)
        ));
    }
}
