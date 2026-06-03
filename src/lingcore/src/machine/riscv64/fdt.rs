// SPDX-FileCopyrightText: 2026 LingCage <opensource@lingcage.com>
//
// SPDX-License-Identifier: Apache-2.0

//! Device tree of a kernel booted without firmware. Harts with their
//! interrupt controllers, memory, the AIA, console, virtio register
//! blocks and the VM generation ID with their lines.

use vm_fdt::{FdtWriter, FdtWriterResult};

use crate::boot::Initrd;
use crate::hv::arch::{APLIC_SIZE, Aia, IMSIC_SIZE, hart_index_bits};
use crate::machine::{Error, Result};
use crate::mem::GuestRam;

/// phandle of the APLIC.
const APLIC_PHANDLE: u32 = 1;

/// phandle of the IMSICs.
const IMSIC_PHANDLE: u32 = 2;

/// phandle of interrupt controller of hart 0. The one of hart `n` is `n`
/// above it.
const INTC_PHANDLE: u32 = 3;

/// Supervisor external interrupt, the input of interrupt controller of
/// a hart raised by the IMSIC (`IRQ_S_EXT` in
/// `arch/riscv/include/asm/csr.h`).
const IRQ_S_EXT: u32 = 9;

/// Trigger types from `include/dt-bindings/interrupt-controller/irq.h`.
const IRQ_TYPE_EDGE_RISING: u32 = 1;
const IRQ_TYPE_LEVEL_HIGH: u32 = 4;

/// `clock-frequency` of the console, the 1.8432 MHz reference clock
/// its divisor is set for.
const UART_CLOCK: u32 = 1_843_200;

/// `#address-cells` and `#size-cells` of the root, 64-bit addresses and
/// sizes.
const CELLS: u32 = 2;

/// Device named in the tree, with its register window and APLIC source.
pub(in crate::machine::riscv64) struct Named {
    pub at: u64,
    pub room: u64,
    pub line: u8,
}

/// Parts named by the tree.
pub(in crate::machine::riscv64) struct Parts<'a> {
    pub vcpus: u16,
    /// `riscv,isa` of each hart.
    pub isa: &'a str,
    /// `satp.MODE` of each hart, for `mmu-type`.
    pub satp_mode: u64,
    /// Ticks of `time` per second.
    pub timebase: u64,
    /// Block sizes of Zicbom and Zicboz, zero if the extension is absent.
    pub cbom_block_size: u64,
    pub cboz_block_size: u64,
    /// RAM reported to the kernel, start and length.
    pub memory: (u64, u64),
    pub cmdline: &'a str,
    pub initrd: Option<Initrd>,
    pub aia: &'a Aia,
    /// The VM generation ID, its line is edge triggered.
    pub genid: Named,
    pub console: Named,
    pub virtio: Vec<Named>,
}

/// Write the tree for `parts` to `ram` at `at`. Tree over `room` bytes
/// is reported as `NoRoomForTree`.
pub(in crate::machine::riscv64) fn lay(
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

/// Returns `mmu-type` for `satp_mode`, `None` for a mode not named by
/// the kernel.
fn mmu_type(satp_mode: u64) -> Option<&'static str> {
    match satp_mode {
        8 => Some("riscv,sv39"),
        9 => Some("riscv,sv48"),
        10 => Some("riscv,sv57"),
        _ => None,
    }
}

/// Returns the tree for `parts` as a flattened blob.
fn build(parts: &Parts) -> FdtWriterResult<Vec<u8>> {
    let mut fdt = FdtWriter::new()?;
    let root = fdt.begin_node("")?;
    fdt.property_string("compatible", "linux,dummy-virt")?;
    fdt.property_u32("#address-cells", CELLS)?;
    fdt.property_u32("#size-cells", CELLS)?;
    harts(&mut fdt, parts)?;

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

    aia(&mut fdt, parts)?;

    let console = fdt.begin_node(&format!("serial@{:x}", parts.console.at))?;
    fdt.property_string("compatible", "ns16550a")?;
    fdt.property_array_u64("reg", &[parts.console.at, parts.console.room])?;
    fdt.property_u32("clock-frequency", UART_CLOCK)?;
    line(&mut fdt, parts.console.line, IRQ_TYPE_LEVEL_HIGH)?;
    fdt.end_node(console)?;

    for block in &parts.virtio {
        let node = fdt.begin_node(&format!("virtio_mmio@{:x}", block.at))?;
        fdt.property_string("compatible", "virtio,mmio")?;
        fdt.property_array_u64("reg", &[block.at, block.room])?;
        line(&mut fdt, block.line, IRQ_TYPE_LEVEL_HIGH)?;
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

/// Write the line of a device, APLIC source `source` with `trigger`.
fn line(fdt: &mut FdtWriter, source: u8, trigger: u32) -> FdtWriterResult<()> {
    fdt.property_u32("interrupt-parent", APLIC_PHANDLE)?;
    fdt.property_array_u32("interrupts", &[u32::from(source), trigger])
}

/// Write the `cpus` node, one hart per vCPU, each with its interrupt
/// controller, as described in
/// `Documentation/devicetree/bindings/riscv/cpus.yaml`.
fn harts(fdt: &mut FdtWriter, parts: &Parts) -> FdtWriterResult<()> {
    let cpus = fdt.begin_node("cpus")?;
    fdt.property_u32("#address-cells", 1)?;
    fdt.property_u32("#size-cells", 0)?;
    match u32::try_from(parts.timebase) {
        Ok(timebase) => fdt.property_u32("timebase-frequency", timebase)?,
        Err(_) => fdt.property_u64("timebase-frequency", parts.timebase)?,
    }
    for hart in 0..u32::from(parts.vcpus) {
        let cpu = fdt.begin_node(&format!("cpu@{hart:x}"))?;
        fdt.property_string("device_type", "cpu")?;
        fdt.property_string("compatible", "riscv")?;
        fdt.property_string("riscv,isa", parts.isa)?;
        if let Some(mmu) = mmu_type(parts.satp_mode) {
            fdt.property_string("mmu-type", mmu)?;
        }
        // Cache operation extension is only taken with its block size.
        if parts.cbom_block_size != 0 {
            fdt.property_u32("riscv,cbom-block-size", parts.cbom_block_size as u32)?;
        }
        if parts.cboz_block_size != 0 {
            fdt.property_u32("riscv,cboz-block-size", parts.cboz_block_size as u32)?;
        }
        fdt.property_u32("reg", hart)?;
        fdt.property_string("status", "okay")?;

        let intc = fdt.begin_node("interrupt-controller")?;
        fdt.property_string("compatible", "riscv,cpu-intc")?;
        fdt.property_u32("#interrupt-cells", 1)?;
        fdt.property_null("interrupt-controller")?;
        fdt.property_u32("phandle", INTC_PHANDLE + hart)?;
        fdt.end_node(intc)?;
        fdt.end_node(cpu)?;
    }
    fdt.end_node(cpus)
}

/// Write the IMSICs and the APLIC, with the APLIC delivering through the
/// IMSICs as MSIs, as described by `riscv,imsics` and `riscv,aplic`
/// bindings.
fn aia(fdt: &mut FdtWriter, parts: &Parts) -> FdtWriterResult<()> {
    let harts = u32::from(parts.vcpus);
    let imsics = fdt.begin_node(&format!("imsics@{:x}", parts.aia.imsic))?;
    fdt.property_string("compatible", "riscv,imsics")?;
    fdt.property_array_u64("reg", &[parts.aia.imsic, IMSIC_SIZE * u64::from(harts)])?;
    fdt.property_u32("#interrupt-cells", 0)?;
    fdt.property_null("interrupt-controller")?;
    fdt.property_null("msi-controller")?;
    fdt.property_u32("#msi-cells", 0)?;
    fdt.property_u32("riscv,num-ids", parts.aia.ids)?;
    fdt.property_u32("riscv,hart-index-bits", hart_index_bits(harts))?;
    let mut parents = Vec::with_capacity(parts.vcpus as usize * 2);
    for hart in 0..harts {
        parents.push(INTC_PHANDLE + hart);
        parents.push(IRQ_S_EXT);
    }
    fdt.property_array_u32("interrupts-extended", &parents)?;
    fdt.property_u32("phandle", IMSIC_PHANDLE)?;
    fdt.end_node(imsics)?;

    let aplic = fdt.begin_node(&format!("aplic@{:x}", parts.aia.aplic))?;
    fdt.property_string("compatible", "riscv,aplic")?;
    fdt.property_array_u64("reg", &[parts.aia.aplic, APLIC_SIZE])?;
    fdt.property_u32("#interrupt-cells", 2)?;
    fdt.property_null("interrupt-controller")?;
    fdt.property_u32("riscv,num-sources", parts.aia.sources)?;
    fdt.property_u32("msi-parent", IMSIC_PHANDLE)?;
    fdt.property_u32("phandle", APLIC_PHANDLE)?;
    fdt.end_node(aplic)
}

#[cfg(test)]
mod tests {
    use crate::machine::riscv64::fdt::*;

    fn parts<'a>(isa: &'a str, cmdline: &'a str, aia: &'a Aia) -> Parts<'a> {
        Parts {
            vcpus: 2,
            isa,
            satp_mode: 9,
            timebase: 10_000_000,
            cbom_block_size: 64,
            cboz_block_size: 0,
            memory: (0x4020_0000, 0x1fe0_0000),
            cmdline,
            initrd: Some(Initrd {
                addr: 0x5000_0000,
                size: 0x1000,
            }),
            aia,
            genid: Named {
                at: 0x4001_0000,
                room: 16,
                line: 2,
            },
            console: Named {
                at: 0x0800_0000,
                room: 8,
                line: 1,
            },
            virtio: vec![Named {
                at: 0x0a00_0000,
                room: 0x200,
                line: 3,
            }],
        }
    }

    /// Returns whether `blob` holds `text` as a NUL terminated string.
    fn names(blob: &[u8], text: &str) -> bool {
        let mut wanted = text.as_bytes().to_vec();
        wanted.push(0);
        blob.windows(wanted.len()).any(|window| window == wanted)
    }

    #[test]
    fn test_tree_names_all_parts() {
        let aia = Aia {
            aplic: 0x0040_0000,
            imsic: 0x0400_0000,
            sources: 31,
            ids: 63,
        };
        let tree = build(&parts("rv64imafdc_zicbom_ssaia", "console=ttyS0", &aia)).expect("build");
        for text in [
            "riscv,cpu-intc",
            "riscv,imsics",
            "riscv,aplic",
            "ns16550a",
            "virtio,mmio",
            "microsoft,vmgenid",
            "rv64imafdc_zicbom_ssaia",
            "riscv,sv48",
            "console=ttyS0",
            "riscv,cbom-block-size",
            "linux,initrd-start",
        ] {
            assert!(names(&tree, text), "{text} not in the tree");
        }
        // Zicboz has no block size, so its property is left out.
        assert!(!names(&tree, "riscv,cboz-block-size"));
    }

    #[test]
    fn test_reject_small_window() {
        let aia = Aia {
            aplic: 0x0040_0000,
            imsic: 0x0400_0000,
            sources: 31,
            ids: 63,
        };
        let ram = GuestRam::new(&[(0x4000_0000, 0x2_0000)]).expect("host pages");
        assert!(matches!(
            lay(&ram, 0x4000_0000, 16, &parts("rv64imac", "", &aia)),
            Err(Error::NoRoomForTree)
        ));
        lay(&ram, 0x4000_0000, 0x1_0000, &parts("rv64imac", "", &aia)).expect("lay");
    }
}
