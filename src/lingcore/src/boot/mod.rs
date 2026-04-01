// SPDX-FileCopyrightText: 2026 LingCage <opensource@lingcage.com>
//
// SPDX-License-Identifier: Apache-2.0

//! Direct boot, the VMM loads kernel image into guest RAM directly, no
//! firmware is needed in the guest.

use std::io::{Read, Seek};

use linux_loader::loader::KernelLoader;
use linux_loader::loader::bzimage::BzImage;
use thiserror::Error;
use vm_memory::{GuestAddress, ReadVolatile};

use crate::mem::GuestRam;

/// Load address of the protected-mode kernel, 1 MiB as fixed by Linux
/// x86 boot protocol.
const LOAD_ADDRESS: u64 = 0x10_0000;

/// Errors thrown while loading a kernel.
#[derive(Debug, Error)]
pub enum Error {
    /// Image is not a bzImage accepted by the loader.
    #[error("kernel image is not a bzImage")]
    NotBzImage,
    /// Guest RAM does not cover `LOAD_ADDRESS` till the end of the image.
    #[error("no guest RAM for kernel at {LOAD_ADDRESS:#x}")]
    NoRoom,
}

/// Result alias for kernel loading.
pub type Result<T, E = Error> = std::result::Result<T, E>;

/// Kernel loaded into guest RAM.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Kernel {
    /// Guest address of kernel entry point.
    pub entry: u64,
    /// First guest address after the loaded kernel.
    pub end: u64,
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
    })
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
}
