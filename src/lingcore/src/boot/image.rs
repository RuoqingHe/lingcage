// SPDX-FileCopyrightText: 2026 LingCage <opensource@lingcage.com>
//
// SPDX-License-Identifier: Apache-2.0

//! Loading Image of riscv64 kernel, a flat binary entered at its first
//! byte. It is loaded at `text_offset` above the start of RAM, with
//! initramfs placed at the top of RAM.

use std::io::{self, Read, Seek};

use thiserror::Error;

use crate::hv::arch::{MODE_S, Reg};
use crate::hv::vcpu::Vcpu;
use crate::mem::GuestRam;

/// Bytes of the header at the start of an Image, `struct riscv_image_header`
/// in `arch/riscv/include/asm/image.h` [1]:
///
/// ```c
/// struct riscv_image_header {
///     u32 code0;
///     u32 code1;
///     u64 text_offset;
///     u64 image_size;
///     u64 flags;
///     u32 version;
///     u32 res1;
///     u64 res2;
///     u64 magic;
///     u32 magic2;
///     u32 res3;
/// };
/// ```
///
/// `text_offset` is the load address above start of RAM, `image_size` is
/// the bytes taken by the kernel including bss.
///
/// [1]: https://elixir.bootlin.com/linux/v6.18/source/arch/riscv/include/asm/image.h
const HEADER: usize = 64;

/// Offsets of header fields we read.
const TEXT_OFFSET: usize = 8;
const IMAGE_SIZE: usize = 16;
const MAGIC2: usize = 56;

/// `RISCV_IMAGE_MAGIC2`, "RSC\x05".
const RISCV_IMAGE_MAGIC2: u32 = 0x0543_5352;

/// Alignment of the start of RAM, since early page tables of the kernel
/// map it with 2 MiB pages.
const ALIGN: u64 = 0x20_0000;

/// Page size. Initramfs is placed on page boundary.
const PAGE: u64 = 0x1000;

/// Errors thrown while loading a kernel.
#[derive(Debug, Error)]
pub enum Error {
    /// Image does not carry the Image magic.
    #[error("kernel image is not an Image")]
    NotImage,
    /// Failed to read the kernel image.
    #[error("failed to read kernel image")]
    ImageRead(#[source] io::Error),
    /// Start of RAM is not aligned to `ALIGN`.
    #[error("start of RAM is not aligned to {ALIGN:#x}")]
    Unaligned,
    /// Guest RAM does not cover the kernel at `text_offset` above the start.
    #[error("no guest RAM for kernel at text offset")]
    NoRoom,
    /// Initramfs does not fit between end of kernel and end of the RAM
    /// region which holds the kernel.
    #[error("no guest RAM for initramfs above the kernel")]
    NoRoomForInitrd,
    /// Failed to read the initramfs image.
    #[error("failed to read initramfs image")]
    InitrdRead(#[source] io::Error),
    /// vCPU refused the entry registers.
    #[error("vCPU refused the entry registers")]
    Vcpu(#[source] crate::hv::Error),
}

/// Result alias for kernel loading.
pub type Result<T, E = Error> = std::result::Result<T, E>;

/// Kernel loaded into guest RAM.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Kernel {
    /// Guest address of kernel entry point, which is its first byte.
    pub entry: u64,
    /// First guest address after the kernel, bss included.
    pub end: u64,
}

/// Load the Image in `image` into `ram` at `text_offset` above `base`,
/// the start of RAM.
pub fn load_kernel<F>(ram: &GuestRam, base: u64, image: &mut F) -> Result<Kernel>
where
    F: Read + Seek,
{
    if base % ALIGN != 0 {
        return Err(Error::Unaligned);
    }
    let mut bytes = Vec::new();
    image.rewind().map_err(Error::ImageRead)?;
    image.read_to_end(&mut bytes).map_err(Error::ImageRead)?;
    if bytes.len() < HEADER {
        return Err(Error::NotImage);
    }
    let field = |at: usize| u64::from_le_bytes(bytes[at..at + 8].try_into().unwrap());
    if u32::from_le_bytes(bytes[MAGIC2..MAGIC2 + 4].try_into().unwrap()) != RISCV_IMAGE_MAGIC2 {
        return Err(Error::NotImage);
    }
    let entry = base.checked_add(field(TEXT_OFFSET)).ok_or(Error::NoRoom)?;
    let taken = field(IMAGE_SIZE).max(bytes.len() as u64);
    let end = entry.checked_add(taken).ok_or(Error::NoRoom)?;
    if !ram.holds(entry, taken) {
        return Err(Error::NoRoom);
    }
    ram.write(entry, &bytes).map_err(|_| Error::NoRoom)?;
    Ok(Kernel { entry, end })
}

/// Initramfs loaded into guest RAM.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Initrd {
    /// Guest address of the image.
    pub addr: u64,
    /// Image size in bytes.
    pub size: u64,
}

/// Returns page-aligned address for an initramfs of `size` bytes, as
/// high as possible in the RAM region holding the kernel, so that RAM
/// above the kernel is left free.
fn initrd_address(ram: &GuestRam, kernel: &Kernel, size: u64) -> Result<u64> {
    let region = ram
        .regions()
        .into_iter()
        .find(|region| kernel.end > region.gpa && kernel.end <= region.gpa + region.size)
        .ok_or(Error::NoRoomForInitrd)?;
    let addr = (region.gpa + region.size)
        .checked_sub(size)
        .ok_or(Error::NoRoomForInitrd)?
        & !(PAGE - 1);
    if addr < kernel.end {
        return Err(Error::NoRoomForInitrd);
    }
    Ok(addr)
}

/// Load the initramfs in `image` into `ram` above `kernel`.
pub fn load_initrd<F>(ram: &GuestRam, kernel: &Kernel, image: &mut F) -> Result<Initrd>
where
    F: Read,
{
    let mut bytes = Vec::new();
    image.read_to_end(&mut bytes).map_err(Error::InitrdRead)?;
    let size = bytes.len() as u64;
    let addr = initrd_address(ram, kernel, size)?;
    ram.write(addr, &bytes)
        .map_err(|_| Error::NoRoomForInitrd)?;
    Ok(Initrd { addr, size })
}

/// Set up `vcpu` to enter `kernel` as hart `hart` in supervisor mode,
/// with hart id in `a0` and device tree address `fdt` in `a1`, as
/// required by `Documentation/arch/riscv/boot.rst`.
pub fn enter_kernel<V: Vcpu>(vcpu: &mut V, kernel: &Kernel, hart: u16, fdt: u64) -> Result<()> {
    vcpu.set_regs(&[
        (Reg::Pc, kernel.entry),
        (Reg::A0, u64::from(hart)),
        (Reg::A1, fdt),
        (Reg::Mode, MODE_S),
    ])
    .map_err(Error::Vcpu)
}

#[cfg(test)]
pub(crate) mod tests {
    use std::io::Cursor;

    use crate::boot::image::*;

    /// `text_offset` of an rv64 Image.
    const TEXT_OFFSET_RV64: u64 = 0x20_0000;

    /// Build an Image with `payload` after the header. The header starts
    /// with a jump over itself like `code0` of a real kernel does, so the
    /// payload gets executed from the entry.
    pub(crate) fn image(payload: &[u8]) -> Vec<u8> {
        let mut image = vec![0u8; HEADER];
        // `j 64`, encoded as `jal x0, 64`.
        image[..4].copy_from_slice(&0x0400_006fu32.to_le_bytes());
        image[TEXT_OFFSET..TEXT_OFFSET + 8].copy_from_slice(&TEXT_OFFSET_RV64.to_le_bytes());
        image[IMAGE_SIZE..IMAGE_SIZE + 8]
            .copy_from_slice(&((HEADER + payload.len()) as u64).to_le_bytes());
        image[MAGIC2..MAGIC2 + 4].copy_from_slice(&RISCV_IMAGE_MAGIC2.to_le_bytes());
        image.extend_from_slice(payload);
        image
    }

    #[test]
    fn test_load_kernel_at_text_offset() {
        const BASE: u64 = 0x4000_0000;
        let ram = GuestRam::new(&[(BASE, 4 << 20)]).expect("host pages");
        let payload = b"a kernel would be here".repeat(37);
        let kernel = load_kernel(&ram, BASE, &mut Cursor::new(image(&payload))).expect("load");

        assert_eq!(kernel.entry, BASE + TEXT_OFFSET_RV64);
        assert_eq!(
            kernel.end,
            kernel.entry + HEADER as u64 + payload.len() as u64
        );

        // Header is copied along with the payload, kernel is entered at it.
        let mut back = vec![0u8; HEADER + payload.len()];
        ram.read(kernel.entry, &mut back).expect("read it back");
        assert_eq!(
            &back[HEADER..],
            &payload[..],
            "payload does not follow the header"
        );
        assert_eq!(&back[..4], &0x0400_006fu32.to_le_bytes());
    }

    #[test]
    fn test_image_size_covers_bss() {
        const BASE: u64 = 0x4000_0000;
        let ram = GuestRam::new(&[(BASE, 4 << 20)]).expect("host pages");
        let mut bigger = image(b"payload");
        // `image_size` larger than the file, which is the bss of kernel.
        bigger[IMAGE_SIZE..IMAGE_SIZE + 8].copy_from_slice(&0x1_0000u64.to_le_bytes());
        let kernel = load_kernel(&ram, BASE, &mut Cursor::new(bigger)).expect("load");
        assert_eq!(kernel.end, kernel.entry + 0x1_0000);

        // `image_size` larger than the RAM is refused.
        let mut huge = image(b"payload");
        huge[IMAGE_SIZE..IMAGE_SIZE + 8].copy_from_slice(&(8u64 << 20).to_le_bytes());
        assert!(matches!(
            load_kernel(&ram, BASE, &mut Cursor::new(huge)),
            Err(Error::NoRoom)
        ));
    }

    #[test]
    fn test_reject_bad_image() {
        const BASE: u64 = 0x4000_0000;
        let ram = GuestRam::new(&[(BASE, 4 << 20)]).expect("host pages");

        // Zero the magic.
        let mut wrong = image(b"payload");
        wrong[MAGIC2] = 0;
        assert!(matches!(
            load_kernel(&ram, BASE, &mut Cursor::new(wrong)),
            Err(Error::NotImage)
        ));
        // Shorter than a header.
        assert!(matches!(
            load_kernel(&ram, BASE, &mut Cursor::new(vec![0u8; 16])),
            Err(Error::NotImage)
        ));
        // Base not on the 2 MiB grid.
        assert!(matches!(
            load_kernel(&ram, BASE + 0x1000, &mut Cursor::new(image(b"payload"))),
            Err(Error::Unaligned)
        ));
        // RAM ends below the text offset.
        let small = GuestRam::new(&[(BASE, 0x1000)]).expect("host pages");
        assert!(matches!(
            load_kernel(&small, BASE, &mut Cursor::new(image(b"payload"))),
            Err(Error::NoRoom)
        ));
    }

    #[test]
    fn test_initrd_at_top_of_ram() {
        const BASE: u64 = 0x4000_0000;
        const SIZE: u64 = 8 << 20;
        let ram = GuestRam::new(&[(BASE, SIZE)]).expect("host pages");
        let kernel = load_kernel(&ram, BASE, &mut Cursor::new(image(b"payload"))).expect("load");

        let archive = b"an initramfs would be here".repeat(100);
        let initrd = load_initrd(&ram, &kernel, &mut Cursor::new(archive.clone())).expect("load");
        assert_eq!(initrd.size, archive.len() as u64);
        assert_eq!(initrd.addr % PAGE, 0, "not page aligned");
        assert!(initrd.addr >= kernel.end, "below the end of the kernel");
        assert!(initrd.addr + initrd.size <= BASE + SIZE, "past end of RAM");
        assert!(
            BASE + SIZE - (initrd.addr + initrd.size) < PAGE,
            "not at top of RAM"
        );

        let mut back = vec![0u8; archive.len()];
        ram.read(initrd.addr, &mut back).expect("read it back");
        assert_eq!(back, archive, "image read back differs");

        // One which does not fit above the kernel.
        assert!(matches!(
            load_initrd(&ram, &kernel, &mut Cursor::new(vec![0u8; SIZE as usize])),
            Err(Error::NoRoomForInitrd)
        ));
    }

    #[cfg(all(feature = "kvm", target_os = "linux"))]
    #[test]
    fn test_enter_kernel_as_hart_zero() {
        // Check that a0 carries the hart id when the guest starts running.
        use crate::hv::backend::kvm::hypervisor::KvmHv;
        use crate::hv::hypervisor::Hypervisor;
        use crate::hv::memory::{MemMapOption, VmMemory};
        use crate::hv::vcpu::{VmEntry, VmExit};
        use crate::hv::vm::Vm;

        const BASE: u64 = 0x4000_0000;
        /// li t0, 0x2000 / sb a0, 0(t0) / j . : store hart id to an address
        /// without memory behind it, so the run exits as MMIO carrying the id.
        const PROGRAM: [u8; 8] = [0x89, 0x62, 0x23, 0x80, 0xa2, 0x00, 0x01, 0xa0];

        let ram = GuestRam::new(&[(BASE, 4 << 20)]).expect("host pages");
        let hv = KvmHv::new().expect("open /dev/kvm");
        let vm = hv.create_vm().expect("guest");
        let mem = vm.create_vm_memory().expect("address space");
        for region in ram.regions() {
            mem.mem_map(region.gpa, region.size, region.hva, MemMapOption::default())
                .expect("map guest RAM");
        }
        let kernel = load_kernel(&ram, BASE, &mut Cursor::new(image(&PROGRAM))).expect("load");

        let mut cpu = vm.create_vcpu(0).expect("vcpu 0");
        enter_kernel(&mut cpu, &kernel, 0, BASE).expect("enter the kernel");
        assert_eq!(
            cpu.run(VmEntry::Run).expect("run"),
            VmExit::Mmio {
                addr: 0x2000,
                write: Some(0),
                size: 1
            }
        );
        assert_eq!(cpu.get_reg(Reg::A1).expect("a1"), BASE);
    }
}
