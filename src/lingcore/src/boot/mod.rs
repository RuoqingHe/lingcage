// SPDX-FileCopyrightText: 2026 LingCage <opensource@lingcage.com>
//
// SPDX-License-Identifier: Apache-2.0

//! Direct boot, the VMM loads kernel image into guest RAM directly, no
//! firmware is needed in the guest.

use std::io::{Read, Seek};

use linux_loader::loader::KernelLoader;
use linux_loader::loader::bootparam::{
    E820_MAX_ENTRIES_ZEROPAGE, boot_e820_entry, boot_params, setup_header,
};
use linux_loader::loader::bzimage::BzImage;
use thiserror::Error;
use vm_memory::{ByteValued, GuestAddress, ReadVolatile};

use crate::mem::GuestRam;

/// Load address of the protected-mode kernel, 1 MiB as fixed by Linux
/// x86 boot protocol.
const LOAD_ADDRESS: u64 = 0x10_0000;

/// Guest address to write the `boot_params` page.
const BOOT_PARAMS: u64 = 0x7000;

/// Guest address to write the command line, `cmd_line_ptr` points here.
const CMDLINE: u64 = 0x2_0000;

/// End of usable low memory, 639 KiB. EBDA and ROM window between here
/// and `LOAD_ADDRESS` are excluded from the e820 map.
const LOW_MEMORY_END: u64 = 0x9_fc00;

/// e820 entry type for usable RAM.
const E820_RAM: u32 = 1;

/// `type_of_loader` for a loader without assigned ID.
const LOADER_OTHER: u8 = 0xff;

/// Errors thrown while loading a kernel.
#[derive(Debug, Error)]
pub enum Error {
    /// Image is not a bzImage accepted by the loader.
    #[error("kernel image is not a bzImage")]
    NotBzImage,
    /// Guest RAM does not cover `LOAD_ADDRESS` till the end of the image.
    #[error("no guest RAM for kernel at {LOAD_ADDRESS:#x}")]
    NoRoom,
    /// Guest RAM does not cover `BOOT_PARAMS` or `CMDLINE`.
    #[error("no guest RAM for boot parameters")]
    NoRoomForParams,
    /// More RAM ranges than e820 table could hold.
    #[error("memory layout needs more than {E820_MAX_ENTRIES_ZEROPAGE} e820 entries")]
    TooManyRanges,
    /// Command line contains NUL byte, which is the terminator.
    #[error("command line contains NUL byte")]
    CmdlineHasNul,
}

/// Result alias for kernel loading.
pub type Result<T, E = Error> = std::result::Result<T, E>;

/// Kernel loaded into guest RAM.
#[derive(Clone, Copy)]
pub struct Kernel {
    /// Guest address of kernel entry point.
    pub entry: u64,
    /// First guest address after the loaded kernel.
    pub end: u64,
    /// `setup_header` read from the image. `boot_params` is built from it,
    /// since decompressor reads its alignment and working size from these
    /// fields.
    setup: setup_header,
}

/// Load the bzImage in `image` into `ram` at `LOAD_ADDRESS`. Setup
/// sectors ahead of the kernel are not copied.
pub fn load_kernel<F>(ram: &GuestRam, image: &mut F) -> Result<Kernel>
where
    F: Read + Seek + ReadVolatile,
{
    let loaded = BzImage::load(
        ram.backing(),
        Some(GuestAddress(LOAD_ADDRESS)),
        image,
        Some(GuestAddress(LOAD_ADDRESS)),
    )
    .map_err(|err| match err {
        linux_loader::loader::Error::Bzimage(_) => Error::NotBzImage,
        _ => Error::NoRoom,
    })?;
    Ok(Kernel {
        entry: loaded.kernel_load.0,
        end: loaded.kernel_end,
        setup: loaded.setup_header.unwrap_or_default(),
    })
}

/// Returns `(addr, size)` ranges of `ram` to be reported as usable, with
/// `LOW_MEMORY_END..LOAD_ADDRESS` excluded.
fn ram_ranges(ram: &GuestRam) -> Vec<(u64, u64)> {
    let mut ranges = Vec::new();
    for region in ram.regions() {
        let (start, end) = (region.gpa, region.gpa + region.size);
        // Region spanning the firmware window is split into the part below
        // and the part above.
        for (from, to) in [
            (start, end.min(LOW_MEMORY_END)),
            (start.max(LOAD_ADDRESS), end),
        ] {
            if from < to {
                ranges.push((from, to - from));
            }
        }
    }
    ranges
}

/// Write `boot_params` to `BOOT_PARAMS` and `cmdline` to `CMDLINE`. The
/// parameters carry header of the image, command line pointer and e820
/// map of `ram`.
pub fn write_boot_params(ram: &GuestRam, kernel: &Kernel, cmdline: &str) -> Result<()> {
    if cmdline.as_bytes().contains(&0) {
        return Err(Error::CmdlineHasNul);
    }
    let mut params = boot_params {
        hdr: kernel.setup,
        ..Default::default()
    };
    // Keep `type_of_loader` if the image already sets it.
    if params.hdr.type_of_loader == 0 {
        params.hdr.type_of_loader = LOADER_OTHER;
    }
    params.hdr.cmd_line_ptr = CMDLINE as u32;
    params.hdr.cmdline_size = cmdline.len() as u32 + 1;

    let ranges = ram_ranges(ram);
    if ranges.len() > E820_MAX_ENTRIES_ZEROPAGE as usize {
        return Err(Error::TooManyRanges);
    }
    for (slot, &(addr, size)) in params.e820_table.iter_mut().zip(&ranges) {
        *slot = boot_e820_entry {
            addr,
            size,
            type_: E820_RAM,
        };
    }
    params.e820_entries = ranges.len() as u8;

    let mut line = cmdline.as_bytes().to_vec();
    line.push(0);
    ram.write(CMDLINE, &line)
        .map_err(|_| Error::NoRoomForParams)?;
    ram.write(BOOT_PARAMS, params.as_slice())
        .map_err(|_| Error::NoRoomForParams)
}

#[cfg(test)]
mod tests {
    use std::io::Cursor;

    use linux_loader::loader::bootparam::setup_header;
    use vm_memory::ByteValued;

    use crate::boot::*;

    /// "HdrS", boot protocol magic at offset 0x202.
    const HDRS: u32 = 0x5372_6448;
    /// Offset of `setup_header` in the image.
    const HEADER_AT: usize = 0x1f1;
    /// Setup sectors ahead of the kernel, boot sector not counted.
    const SETUP_SECTORS: u8 = 1;

    /// Build a bzImage with `payload` in place of the kernel.
    fn bzimage(payload: &[u8]) -> Vec<u8> {
        let setup = usize::from(SETUP_SECTORS + 1) * 512;
        let mut header = setup_header {
            setup_sects: SETUP_SECTORS,
            header: HDRS,
            // Boot protocol 2.06, loader refuses anything below 2.00.
            version: 0x0206,
            // LOADED_HIGH, required by the loader.
            loadflags: 0x01,
            code32_start: LOAD_ADDRESS as u32,
            ..Default::default()
        };
        let mut image = vec![0u8; setup + payload.len()];
        image[HEADER_AT..HEADER_AT + size_of::<setup_header>()]
            .copy_from_slice(header.as_mut_slice());
        image[setup..].copy_from_slice(payload);
        image
    }

    #[test]
    fn test_load_kernel_at_protocol_address() {
        let ram = GuestRam::new(&[(0, 2 * 1024 * 1024)]).expect("host pages");
        let payload = b"a kernel would be here".repeat(37);
        let kernel = load_kernel(&ram, &mut Cursor::new(bzimage(&payload))).expect("load");

        assert_eq!(kernel.entry, LOAD_ADDRESS);
        assert_eq!(kernel.end, LOAD_ADDRESS + payload.len() as u64);

        // Setup sectors are not copied, payload should be at LOAD_ADDRESS.
        let mut back = vec![0u8; payload.len()];
        ram.read(LOAD_ADDRESS, &mut back).expect("read it back");
        assert_eq!(back, payload, "payload is not at LOAD_ADDRESS");
        // Bytes below LOAD_ADDRESS should be untouched.
        let mut before = [0u8; 16];
        ram.read(LOAD_ADDRESS - 16, &mut before).expect("read");
        assert_eq!(before, [0u8; 16]);
    }

    #[test]
    fn test_reject_non_bzimage() {
        let ram = GuestRam::new(&[(0, 2 * 1024 * 1024)]).expect("host pages");

        // Zero the "HdrS" magic at 0x202.
        let mut image = bzimage(b"payload");
        image[HEADER_AT + 0x11] = 0;
        assert!(matches!(
            load_kernel(&ram, &mut Cursor::new(image)),
            Err(Error::NotBzImage)
        ));

        // RAM ends below LOAD_ADDRESS.
        let small = GuestRam::new(&[(0, 4096)]).expect("host pages");
        assert!(load_kernel(&small, &mut Cursor::new(bzimage(b"payload"))).is_err());
    }

    #[test]
    fn test_ram_ranges_exclude_firmware_window() {
        // One region spans the firmware window, another one is above 4G.
        let ram = GuestRam::new(&[(0, 0xc000_0000), (0x1_0000_0000, 0x1000)]).expect("host pages");
        assert_eq!(
            ram_ranges(&ram),
            [
                (0, LOW_MEMORY_END),
                (LOAD_ADDRESS, 0xc000_0000 - LOAD_ADDRESS),
                (0x1_0000_0000, 0x1000),
            ],
            "firmware window is reported as RAM"
        );

        // Region inside the window yields no range.
        let inside = GuestRam::new(&[(LOW_MEMORY_END, 0x1000)]).expect("host pages");
        assert_eq!(ram_ranges(&inside), []);
    }

    #[test]
    fn test_write_boot_params() {
        let ram = GuestRam::new(&[(0, 2 * 1024 * 1024)]).expect("host pages");
        let kernel = load_kernel(&ram, &mut Cursor::new(bzimage(b"payload"))).expect("load");
        write_boot_params(&ram, &kernel, "console=ttyS0 quiet").expect("write");

        let mut back = vec![0u8; size_of::<boot_params>()];
        ram.read(BOOT_PARAMS, &mut back).expect("read params back");
        let params = boot_params::from_slice(&back).expect("page of parameters");

        // Magic comes from header of the image. `boot_params` is packed, so
        // each field is copied out before comparing.
        let hdr = params.hdr;
        assert_eq!({ hdr.header }, HDRS);
        assert_eq!(hdr.setup_sects, SETUP_SECTORS);
        assert_eq!(hdr.type_of_loader, LOADER_OTHER);
        assert_eq!({ hdr.cmd_line_ptr }, CMDLINE as u32);
        assert_eq!({ hdr.cmdline_size }, 20);

        assert_eq!(params.e820_entries, 2);
        let low = params.e820_table[0];
        let high = params.e820_table[1];
        assert_eq!({ low.addr }, 0);
        assert_eq!({ low.size }, LOW_MEMORY_END);
        assert_eq!({ low.type_ }, E820_RAM);
        assert_eq!({ high.addr }, LOAD_ADDRESS);

        // Command line is at CMDLINE, NUL terminated.
        let mut line = [0u8; 20];
        ram.read(CMDLINE, &mut line).expect("read the command line");
        assert_eq!(&line, b"console=ttyS0 quiet\0");

        // NUL inside the command line is refused.
        assert!(matches!(
            write_boot_params(&ram, &kernel, "console=ttyS0\0quiet"),
            Err(Error::CmdlineHasNul)
        ));
    }
}
