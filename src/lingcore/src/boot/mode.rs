// SPDX-FileCopyrightText: 2026 LingCage <opensource@lingcage.com>
//
// SPDX-License-Identifier: Apache-2.0

//! Entering long mode on direct boot. GDT, an empty IDT and page tables
//! which identity-map the low 1 GiB are written to low memory, then
//! vCPU is set up to run 64-bit code at kernel entry.

use crate::boot::bzimage::{BOOT_PARAMS, Error, Kernel, Result};
use crate::hv::arch::{DtReg, DtRegVal, Reg, SReg, SegReg, SegRegVal};
use crate::hv::vcpu::Vcpu;
use crate::mem::GuestRam;

/// Guest address of the GDT, right after real-mode IVT and BDA.
const GDT: u64 = 0x500;

/// Guest address of the IDT, right after the GDT.
const IDT: u64 = 0x520;

/// Guest addresses of the three page table levels, one page each.
const PML4: u64 = 0x9000;
const PDPT: u64 = 0xa000;
const PD: u64 = 0xb000;

/// Initial stack pointer, top of the page below the page tables.
const STACK: u64 = 0x8ff0;

/// Offset of 64-bit entry point from the start of loaded kernel.
const ENTRY_64: u64 = 0x200;

/// RFLAGS with only the reserved bit set, interrupts are disabled.
const RFLAGS_RESET: u64 = 0x2;

/// Code segment access rights: present, DPL 0, execute/read, long mode.
const CODE_ATTR: u16 = 0xa09b;

/// Data segment access rights: present, DPL 0, read/write, 32-bit default.
const DATA_ATTR: u16 = 0xc093;

/// TSS access rights: present, busy 64-bit TSS.
const TSS_ATTR: u16 = 0x808b;

/// GDT limit, four descriptors including the null one, minus one byte.
const GDT_LIMIT: u16 = 4 * size_of::<u64>() as u16 - 1;

/// Granularity bit, limit is counted in 4 KiB pages when set.
const GRANULARITY: u16 = 1 << 15;

/// Segment limit which covers the whole 32-bit address space.
const FLAT_LIMIT: u32 = 0xffff_ffff;

/// Protected mode enable.
const CR0_PE: u64 = 1;

/// Paging enable.
const CR0_PG: u64 = 1 << 31;

/// Physical address extension, required by 4-level paging.
const CR4_PAE: u64 = 1 << 5;

/// Long mode enable.
const EFER_LME: u64 = 1 << 8;

/// Long mode active. KVM refuses `CR0.PG` together with `EFER.LME` unless
/// this bit is also set.
const EFER_LMA: u64 = 1 << 10;

/// Page table entry flags, present and writable.
const PRESENT_WRITE: u64 = 0x3;

/// Page directory entry flag for 2 MiB page.
const LARGE_PAGE: u64 = 0x80;

/// Size of the 2 MiB page mapped by one directory entry.
const LARGE_PAGE_SIZE: u64 = 1 << 21;

/// Entries in the page directory, 512 pages of 2 MiB map the low 1 GiB.
const DIRECTORY_ENTRIES: u64 = 512;

/// Encode `seg` as an eight-byte GDT descriptor. Limit is shifted to
/// pages if granularity bit is set.
fn descriptor(seg: &SegRegVal) -> u64 {
    let limit = if seg.attr & GRANULARITY == 0 {
        u64::from(seg.limit)
    } else {
        u64::from(seg.limit >> 12)
    };
    let attr = u64::from(seg.attr);
    ((seg.base & 0xff00_0000) << 32)
        | ((attr & 0xf000) << 40)
        | ((limit & 0xf_0000) << 32)
        | ((attr & 0xff) << 40)
        | ((seg.base & 0x00ff_ffff) << 16)
        | (limit & 0xffff)
}

/// Write the GDT and an empty one-entry IDT. Returns code, data and TSS
/// segments in selector order. Note that an exception before the kernel
/// installs its own IDT would triple fault.
fn write_tables(ram: &GuestRam) -> Result<[SegRegVal; 3]> {
    let seg = |slot: u16, attr: u16| SegRegVal {
        base: 0,
        limit: FLAT_LIMIT,
        selector: slot * size_of::<u64>() as u16,
        attr,
    };
    // Slot 0 is the null descriptor.
    let segs = [seg(1, CODE_ATTR), seg(2, DATA_ATTR), seg(3, TSS_ATTR)];

    let mut table = [0u8; (1 + 3) * size_of::<u64>()];
    for (slot, seg) in table.chunks_exact_mut(size_of::<u64>()).skip(1).zip(&segs) {
        slot.copy_from_slice(&descriptor(seg).to_le_bytes());
    }
    ram.write(GDT, &table).map_err(|_| Error::NoRoomForTables)?;
    ram.write(IDT, &0u64.to_le_bytes())
        .map_err(|_| Error::NoRoomForTables)?;

    Ok(segs)
}

/// Write page tables which identity-map the low 1 GiB with 2 MiB pages.
/// Returns the PML4 address.
fn write_page_tables(ram: &GuestRam) -> Result<u64> {
    ram.write(PML4, &(PDPT | PRESENT_WRITE).to_le_bytes())
        .map_err(|_| Error::NoRoomForTables)?;
    ram.write(PDPT, &(PD | PRESENT_WRITE).to_le_bytes())
        .map_err(|_| Error::NoRoomForTables)?;

    let mut directory = Vec::with_capacity(DIRECTORY_ENTRIES as usize * size_of::<u64>());
    for index in 0..DIRECTORY_ENTRIES {
        let page = index * LARGE_PAGE_SIZE;
        directory.extend_from_slice(&(page | LARGE_PAGE | PRESENT_WRITE).to_le_bytes());
    }
    ram.write(PD, &directory)
        .map_err(|_| Error::NoRoomForTables)?;
    Ok(PML4)
}

/// Set up `vcpu` to run in long mode at the 64-bit entry of `kernel`,
/// with `BOOT_PARAMS` in `rsi` as required by the boot protocol. Tables
/// are written to `ram` first.
pub fn enter_long_mode<V: Vcpu>(ram: &GuestRam, vcpu: &mut V, kernel: &Kernel) -> Result<()> {
    let [code, data, tss] = write_tables(ram)?;
    let top = write_page_tables(ram)?;

    // Mode bits are added on top of reset values of CR0, CR4 and EFER.
    let cr0 = vcpu.get_sreg(SReg::Cr0).map_err(Error::Vcpu)?;
    let cr4 = vcpu.get_sreg(SReg::Cr4).map_err(Error::Vcpu)?;
    let efer = vcpu.get_sreg(SReg::Efer).map_err(Error::Vcpu)?;
    vcpu.set_sregs(
        &[
            (SReg::Cr0, cr0 | CR0_PE | CR0_PG),
            (SReg::Cr3, top),
            (SReg::Cr4, cr4 | CR4_PAE),
            (SReg::Efer, efer | EFER_LME | EFER_LMA),
        ],
        &[
            (SegReg::Cs, code),
            (SegReg::Ds, data),
            (SegReg::Es, data),
            (SegReg::Fs, data),
            (SegReg::Gs, data),
            (SegReg::Ss, data),
            (SegReg::Tr, tss),
        ],
        &[
            (
                DtReg::Gdt,
                DtRegVal {
                    base: GDT,
                    limit: GDT_LIMIT,
                },
            ),
            (
                DtReg::Idt,
                DtRegVal {
                    base: IDT,
                    limit: size_of::<u64>() as u16 - 1,
                },
            ),
        ],
    )
    .map_err(Error::Vcpu)?;

    vcpu.set_regs(&[
        (Reg::Rip, kernel.entry + ENTRY_64),
        (Reg::Rsp, STACK),
        (Reg::Rbp, STACK),
        (Reg::Rsi, BOOT_PARAMS),
        (Reg::Rflags, RFLAGS_RESET),
    ])
    .map_err(Error::Vcpu)
}

#[cfg(test)]
mod tests {
    use crate::boot::mode::*;

    /// Address in the second 2 MiB page, after the one kernel is loaded in.
    #[cfg(all(feature = "kvm", target_os = "linux"))]
    const HIGH: u64 = LARGE_PAGE_SIZE;

    /// L bit of code segment access rights.
    #[cfg(all(feature = "kvm", target_os = "linux"))]
    const CODE_LONG: u16 = 1 << 13;

    /// mov eax, 0x10 / mov ds, ax / mov r8, rsi / mov byte [r8], 0x42
    /// mov r9, 0x200000 / mov byte [r9], 0x37 / hlt
    ///
    /// Loading `ds` reads the GDT in guest memory, `r8` and `r9` only exist
    /// in long mode, and the two stores verify `rsi` and the second directory
    /// entry.
    #[cfg(all(feature = "kvm", target_os = "linux"))]
    const PROGRAM: [u8; 26] = [
        0xb8, 0x10, 0x00, 0x00, 0x00, 0x8e, 0xd8, 0x49, 0x89, 0xf0, 0x41, 0xc6, 0x00, 0x42, 0x49,
        0xc7, 0xc1, 0x00, 0x00, 0x20, 0x00, 0x41, 0xc6, 0x01, 0x37, 0xf4,
    ];

    #[test]
    fn test_gdt_descriptor_encoding() {
        // Three descriptors of the Linux 64-bit boot protocol. Long mode
        // does not check the descriptors it is entered with, a misencoded
        // one only shows up when the guest reloads it.
        let seg = |attr| SegRegVal {
            base: 0,
            limit: FLAT_LIMIT,
            selector: 0,
            attr,
        };
        assert_eq!(descriptor(&seg(CODE_ATTR)), 0x00af_9b00_0000_ffff);
        assert_eq!(descriptor(&seg(DATA_ATTR)), 0x00cf_9300_0000_ffff);
        assert_eq!(descriptor(&seg(TSS_ATTR)), 0x008f_8b00_0000_ffff);

        // Limit is taken as is without the granularity bit.
        assert_eq!(
            descriptor(&SegRegVal {
                base: 0x1234_5678,
                limit: 0xffff,
                selector: 0,
                attr: DATA_ATTR & !GRANULARITY,
            }),
            0x1240_9334_5678_ffff
        );
    }

    #[cfg(all(feature = "kvm", target_os = "linux"))]
    #[test]
    fn test_enter_long_mode() {
        // Run a real guest program in long mode and check rsi and page
        // tables.
        use std::io::Cursor;

        use crate::boot::bzimage::tests::bzimage;
        use crate::boot::{load_kernel, write_boot_params};
        use crate::hv::backend::kvm::hypervisor::KvmHv;
        use crate::hv::hypervisor::Hypervisor;
        use crate::hv::memory::{MemMapOption, VmMemory};
        use crate::hv::vcpu::{VmEntry, VmExit};
        use crate::hv::vm::Vm;

        let ram = GuestRam::new(&[(0, 4 * 1024 * 1024)]).expect("host pages");
        let hv = KvmHv::new().expect("open /dev/kvm");
        let vm = hv.create_vm().expect("guest");
        let mem = vm.create_vm_memory().expect("address space");
        for region in ram.regions() {
            mem.mem_map(region.gpa, region.size, region.hva, MemMapOption::default())
                .expect("map guest RAM");
        }

        // Program is placed at `ENTRY_64`, bytes ahead of it act as the 32-bit
        // entry.
        let mut payload = vec![0u8; ENTRY_64 as usize];
        payload.extend_from_slice(&PROGRAM);
        let kernel = load_kernel(&ram, &mut Cursor::new(bzimage(&payload))).expect("load");
        write_boot_params(&ram, &kernel, "console=ttyS0", None).expect("parameters");

        let mut cpu = vm.create_vcpu(0).expect("vcpu 0");
        // Kernel reads CPUID for its model and feature bits. `KVM_SET_SREGS`
        // writes `EFER` without checking the leaves.
        cpu.set_cpuid(&hv.supported_cpuid().expect("host CPUID"))
            .expect("model");
        enter_long_mode(&ram, &mut cpu, &kernel).expect("enter the kernel");

        assert_eq!(cpu.run(VmEntry::Run).expect("run"), VmExit::Halt);

        let mut byte = [0u8; 1];
        ram.read(BOOT_PARAMS, &mut byte).expect("read");
        assert_eq!(byte[0], 0x42, "rsi does not point at BOOT_PARAMS");
        ram.read(HIGH, &mut byte).expect("read");
        assert_eq!(byte[0], 0x37, "second 2 MiB page is not mapped");

        assert_eq!(
            cpu.get_sreg(SReg::Efer).expect("efer") & EFER_LMA,
            EFER_LMA,
            "EFER.LMA is clear after the run"
        );
        assert_eq!(
            cpu.get_seg_reg(SegReg::Cs).expect("cs").attr & CODE_LONG,
            CODE_LONG
        );
        assert_eq!(cpu.get_sreg(SReg::Cr0).expect("cr0") & CR0_PG, CR0_PG);
        assert_eq!(cpu.get_sreg(SReg::Cr4).expect("cr4") & CR4_PAE, CR4_PAE);
    }
}
