// SPDX-FileCopyrightText: 2026 LingCage <opensource@lingcage.com>
//
// SPDX-License-Identifier: Apache-2.0

//! Guest RAM, host memory mapped behind the guest physical address
//! space.
//!
//! RAM is a set of regions in ascending address order. A range not
//! covered by any region, the MMIO hole below 4G on x86 for example, is
//! not RAM, and an access into it is refused.

use thiserror::Error;
use vm_memory::mmap::FromRangesError;
use vm_memory::region::GuestRegionCollectionError;
use vm_memory::{Bytes, GuestAddress, GuestMemoryBackend, GuestMemoryMmap, GuestMemoryRegion};

/// Errors thrown while laying out or accessing guest RAM.
#[derive(Debug, Error)]
pub enum Error {
    /// Regions not in ascending address order. `new` does not sort them.
    #[error("regions are not in ascending guest address order")]
    Unsorted,
    /// Two regions cover one guest address.
    #[error("regions overlap")]
    Overlap,
    /// Failed to map host memory for a region.
    #[error("failed to map host memory for the guest")]
    Take,
    /// Access which starts outside the regions or runs past the end of one.
    #[error("{count:#x} bytes at guest address {gpa:#x} are not fully backed")]
    Unbacked {
        /// Guest address of the access.
        gpa: u64,
        /// Length of the access in bytes.
        count: usize,
    },
}

/// Result alias for guest RAM.
pub type Result<T, E = Error> = std::result::Result<T, E>;

/// One region of guest RAM, the guest physical range and the host
/// virtual address behind it, the arguments taken by
/// `VmMemory::mem_map`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Region {
    /// Guest physical address the region starts from.
    pub gpa: u64,
    /// Length of the region in bytes.
    pub size: u64,
    /// Host virtual address the region is mapped at.
    pub hva: usize,
}

/// Host memory behind the guest physical address space, held as
/// `vm_memory` regions.
pub struct GuestRam {
    inner: GuestMemoryMmap,
}

impl GuestRam {
    /// Map host memory for each `(gpa, size)` region. Regions must be in
    /// ascending address order without overlap. Other layout is refused
    /// instead of sorted.
    pub fn new(regions: &[(u64, u64)]) -> Result<Self> {
        let ranges = regions
            .iter()
            .map(|&(gpa, size)| (GuestAddress(gpa), size as usize))
            .collect::<Vec<_>>();
        let inner = GuestMemoryMmap::from_ranges(&ranges).map_err(|err| match err {
            FromRangesError::Collection(GuestRegionCollectionError::UnsortedMemoryRegions) => {
                Error::Unsorted
            }
            FromRangesError::Collection(GuestRegionCollectionError::MemoryRegionOverlap) => {
                Error::Overlap
            }
            _ => Error::Take,
        })?;
        Ok(GuestRam { inner })
    }

    /// Returns the regions in ascending address order.
    pub fn regions(&self) -> Vec<Region> {
        self.inner
            .iter()
            .map(|region| Region {
                gpa: region.start_addr().0,
                size: region.len(),
                hva: region.as_ptr() as usize,
            })
            .collect()
    }

    pub fn write(&self, gpa: u64, bytes: &[u8]) -> Result<()> {
        self.inner
            .write_slice(bytes, GuestAddress(gpa))
            .map_err(|_| Error::Unbacked {
                gpa,
                count: bytes.len(),
            })
    }

    /// Read from guest address `gpa` into `bytes`.
    pub fn read(&self, gpa: u64, bytes: &mut [u8]) -> Result<()> {
        self.inner
            .read_slice(bytes, GuestAddress(gpa))
            .map_err(|_| Error::Unbacked {
                gpa,
                count: bytes.len(),
            })
    }
}

#[cfg(test)]
mod tests {
    use crate::mem::*;

    const PAGE: u64 = 4096;
    /// Start of the hole below 4G left for devices.
    const HOLE: u64 = 0xc000_0000;

    #[test]
    fn test_layout_with_hole() {
        let ram = GuestRam::new(&[(0, HOLE), (0x1_0000_0000, 16 * PAGE)]).expect("host pages");
        let regions = ram.regions();
        assert_eq!(regions.len(), 2);
        assert_eq!(regions[0].gpa, 0);
        assert_eq!(regions[0].size, HOLE);
        assert_eq!(regions[1].gpa, 0x1_0000_0000);
        assert_ne!(regions[0].hva, 0);
        assert_ne!(regions[1].hva, 0);
        assert_ne!(regions[0].hva, regions[1].hva);

        // Access into the hole is `Unbacked`, not redirected to a region.
        let mut read = [0u8; 4];
        assert!(matches!(
            ram.read(HOLE, &mut read),
            Err(Error::Unbacked { gpa: HOLE, .. })
        ));
        // Access crossing the end of a region is refused too.
        assert!(ram.write(HOLE - 2, &[1, 2, 3, 4]).is_err());

        ram.write(0x1_0000_0000, b"seeded").expect("write");
        let mut back = [0u8; 6];
        ram.read(0x1_0000_0000, &mut back).expect("read");
        assert_eq!(&back, b"seeded");

        assert!(
            matches!(
                GuestRam::new(&[(0, 2 * PAGE), (PAGE, PAGE)]),
                Err(Error::Overlap)
            ),
            "overlapping regions accepted"
        );
        assert!(
            matches!(
                GuestRam::new(&[(0x1_0000_0000, PAGE), (0, PAGE)]),
                Err(Error::Unsorted)
            ),
            "regions out of address order accepted"
        );
    }

    #[cfg(all(feature = "kvm", target_os = "linux", target_arch = "x86_64"))]
    #[test]
    fn test_guest_runs_from_ram() {
        // Guest code below is x86 machine code writing a port.
        use crate::hv::backend::kvm::hypervisor::KvmHv;
        use crate::hv::hypervisor::Hypervisor;
        use crate::hv::memory::{MemMapOption, VmMemory};
        use crate::hv::vcpu::{Vcpu, VmEntry, VmExit};
        use crate::hv::vm::Vm;

        // The page which reset vector is in. A new vCPU starts there.
        const GPA: u64 = 0xffff_f000;
        let ram = GuestRam::new(&[(GPA, PAGE)]).expect("host pages");
        let code = [
            0xb0, 0x42, // mov al, 0x42
            0xe6, 0xf8, // out 0xf8, al
            0xf4, // hlt
        ];
        ram.write(GPA + 0xff0, &code).expect("write the code");

        let hv = KvmHv::new().expect("open /dev/kvm");
        let vm = hv.create_vm().expect("guest");
        let mem = vm.create_vm_memory().expect("address space");
        for region in ram.regions() {
            mem.mem_map(region.gpa, region.size, region.hva, MemMapOption::default())
                .expect("map");
        }

        let mut cpu = vm.create_vcpu(0).expect("vcpu 0");
        assert_eq!(
            cpu.run(VmEntry::Run).expect("run"),
            VmExit::Io {
                port: 0xf8,
                write: Some(0x42),
                size: 1
            },
            "guest did not run from the mapped RAM"
        );
    }
}
