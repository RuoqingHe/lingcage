// SPDX-FileCopyrightText: 2026 LingCage <opensource@lingcage.com>
//
// SPDX-License-Identifier: Apache-2.0

//! Guest RAM, host memory mapped behind the guest physical address
//! space.
//!
//! RAM is a set of regions in ascending address order. A range not
//! covered by any region, the MMIO hole below 4G on x86 for example, is
//! not RAM, and an access into it is refused.

use std::fs::File;
#[cfg(target_os = "linux")]
use std::io::{Seek, SeekFrom};
use std::sync::Arc;

use thiserror::Error;
use vm_memory::mmap::FromRangesError;
#[cfg(target_os = "linux")]
use vm_memory::mmap::MmapRegion;
use vm_memory::region::GuestRegionCollectionError;
use vm_memory::{Bytes, GuestAddress, GuestMemoryBackend, GuestMemoryMmap, GuestMemoryRegion};
#[cfg(target_os = "linux")]
use vm_memory::{FileOffset, GuestRegionMmap};

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
    /// Copy between guest RAM and a file stopped short.
    #[error("short copy between guest address {gpa:#x} and file")]
    Copy {
        /// Guest address of the copy.
        gpa: u64,
    },
    /// Template mapped by a clone covers less than RAM of the guest.
    #[error("template is shorter than {size:#x} bytes of guest RAM")]
    ShortTemplate {
        /// Bytes of RAM covered by the regions.
        size: u64,
    },
}

/// Result alias for guest RAM.
pub type Result<T, E = Error> = std::result::Result<T, E>;

#[cfg(target_os = "linux")]
mod fault;

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
#[derive(Clone)]
pub struct GuestRam {
    /// Shared with each vCPU thread. Unmapped when the last clone drops.
    inner: Arc<GuestMemoryMmap>,
    /// Watch taken by a file-backed mapping, so that a page truncated out of
    /// the image becomes a marked fault instead of a dead process.
    #[cfg(target_os = "linux")]
    watched: Option<Arc<fault::Watched>>,
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
        Ok(GuestRam {
            inner: Arc::new(inner),
            #[cfg(target_os = "linux")]
            watched: None,
        })
    }

    /// Map the RAM image in `template` for each `(gpa, size)` region, with
    /// the regions back to back in given order, as `MAP_PRIVATE`. A page is
    /// read from the file on first access, and a written page becomes a
    /// private copy of the guest, so the template is unchanged. The order is
    /// the same as returned by `regions` and written by
    /// `Machine::write_memory`. Template covering less than the regions is
    /// reported as `ShortTemplate`. A page mapped past the end of the file
    /// raises `SIGBUS` on its first access.
    #[cfg(target_os = "linux")]
    pub fn cloned_from(regions: &[(u64, u64)], template: &File) -> Result<Self> {
        let size = regions
            .iter()
            .try_fold(0u64, |total, &(_, size)| total.checked_add(size))
            .ok_or(Error::Take)?;
        if extent(template)? < size {
            return Err(Error::ShortTemplate { size });
        }

        let mut at = 0u64;
        let mut mapped = Vec::with_capacity(regions.len());
        for &(gpa, size) in regions {
            let size = usize::try_from(size).map_err(|_| Error::Take)?;
            let offset = FileOffset::new(template.try_clone().map_err(|_| Error::Take)?, at);
            let region = MmapRegion::build(
                Some(offset),
                size,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_NORESERVE | libc::MAP_PRIVATE,
            )
            .map_err(|_| Error::Take)?;
            mapped.push(GuestRegionMmap::new(region, GuestAddress(gpa)).ok_or(Error::Take)?);
            at = at.checked_add(size as u64).ok_or(Error::Take)?;
        }
        let inner = GuestMemoryMmap::from_regions(mapped).map_err(|err| match err {
            GuestRegionCollectionError::UnsortedMemoryRegions => Error::Unsorted,
            GuestRegionCollectionError::MemoryRegionOverlap => Error::Overlap,
            _ => Error::Take,
        })?;
        let inner = Arc::new(inner);
        let watched = fault::Watched::of(
            inner
                .iter()
                .map(|region| (region.as_ptr() as usize, region.len() as usize)),
        );
        Ok(GuestRam {
            inner,
            watched: Some(Arc::new(watched)),
        })
    }

    /// Returns whether a page of the RAM image went missing under the
    /// mapping. Handler put a zero page in its place, so the guest runs on
    /// over memory it no longer owns and the caller should end it.
    #[cfg(target_os = "linux")]
    pub fn faulted(&self) -> bool {
        self.watched.as_ref().is_some_and(|watched| watched.hit())
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

    /// Returns the regions as the `GuestMemoryMmap` taken by the kernel
    /// loader.
    #[cfg(all(feature = "boot", target_arch = "x86_64"))]
    pub(crate) fn backing(&self) -> &GuestMemoryMmap {
        &self.inner
    }

    pub fn write(&self, gpa: u64, bytes: &[u8]) -> Result<()> {
        self.inner
            .write_slice(bytes, GuestAddress(gpa))
            .map_err(|_| Error::Unbacked {
                gpa,
                count: bytes.len(),
            })
    }

    /// Returns whether `count` bytes from `gpa` are backed. Range crossing a
    /// hole between regions is not.
    pub fn holds(&self, gpa: u64, count: u64) -> bool {
        match usize::try_from(count) {
            Ok(count) => self.inner.check_range(GuestAddress(gpa), count),
            Err(_) => false,
        }
    }

    /// Read up to `count` bytes from `source` into guest RAM at `gpa`, with
    /// no buffer on host side. Returns the number of bytes read.
    pub fn fill_from(&self, gpa: u64, source: &mut File, count: usize) -> Result<usize> {
        self.inner
            .read_volatile_from(GuestAddress(gpa), source, count)
            .map_err(|_| Error::Copy { gpa })
    }

    /// Read `count` bytes from `source` into guest RAM at `gpa`. Count
    /// returned is only short once the source has run dry.
    pub fn fill_all_from(&self, gpa: u64, source: &mut File, count: usize) -> Result<usize> {
        // A single `read(2)` takes at most `MAX_RW_COUNT`, `0x7ffff000`
        // bytes (`rw_verify_area` in `fs/read_write.c`), so a region of
        // 2 GiB or more needs several reads.
        let mut filled = 0;
        while filled < count {
            let taken = self.fill_from(gpa + filled as u64, source, count - filled)?;
            if taken == 0 {
                break;
            }
            filled += taken;
        }
        Ok(filled)
    }

    /// Write `count` bytes of guest RAM at `gpa` to `sink`. Short write is
    /// reported as `Copy`.
    pub fn drain_to(&self, gpa: u64, sink: &mut File, count: usize) -> Result<()> {
        self.inner
            .write_all_volatile_to(GuestAddress(gpa), sink, count)
            .map_err(|_| Error::Copy { gpa })
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

/// Returns how far `template` reaches. A block device holds no length in
/// its metadata, so the end is sought out instead.
#[cfg(target_os = "linux")]
fn extent(template: &File) -> Result<u64> {
    let mut at = template;
    match at.metadata().map_err(|_| Error::Take)?.len() {
        0 => at.seek(SeekFrom::End(0)).map_err(|_| Error::Take),
        len => Ok(len),
    }
}

#[cfg(test)]
mod tests {
    use crate::mem::*;

    const PAGE: u64 = 4096;
    /// Start of the hole below 4G left for devices.
    const HOLE: u64 = 0xc000_0000;

    /// File holding `bytes`, opened for reading and writing, unlinked once
    /// opened.
    fn file_of(bytes: &[u8], tag: &str) -> std::fs::File {
        let path = std::env::temp_dir().join(format!(
            "lingcore-mem-{tag}-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        std::fs::write(&path, bytes).expect("write the file");
        let file = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(&path)
            .expect("open the file");
        std::fs::remove_file(&path).expect("remove the file");
        file
    }

    #[test]
    fn test_fill_and_drain_file() {
        const COUNT: usize = 4 << 20;
        let ram = GuestRam::new(&[(0, 8 << 20)]).expect("host pages");
        let mut source = file_of(&vec![0xa5u8; COUNT], "source");

        // 4 MiB from the file into guest RAM.
        assert_eq!(ram.fill_from(0, &mut source, COUNT).expect("fill"), COUNT);
        let mut landed = [0u8; 8];
        ram.read(COUNT as u64 - 8, &mut landed).expect("read back");
        assert_eq!(landed, [0xa5u8; 8]);

        // And 4 MiB back out to a file.
        let mut sink = file_of(&[], "sink");
        ram.drain_to(0, &mut sink, COUNT).expect("drain");
        assert_eq!(
            sink.metadata().expect("measure").len(),
            COUNT as u64,
            "sink is short"
        );
    }

    #[test]
    fn test_fill_short_source() {
        let ram = GuestRam::new(&[(0, 1 << 20)]).expect("host pages");
        let mut source = file_of(&[0xa5u8; 100], "dry");
        // Count returned is what the source had, not what was asked for.
        assert_eq!(ram.fill_from(0, &mut source, 4096).expect("fill"), 100);
    }

    #[cfg(unix)]
    #[test]
    fn test_fill_all_from_piecewise_source() {
        // Source gives a piece at a time, the same way a read of 2 GiB or
        // more does. It is one end of a socket pair, written from its own
        // thread, so the buffer between the two ends decides the piece
        // size.
        use std::io::Write;
        use std::os::unix::net::UnixStream;

        const COUNT: usize = 4 << 20;
        let ram = GuestRam::new(&[(0, 8 << 20)]).expect("host pages");
        let (reading, mut writing) = UnixStream::pair().expect("open a socket pair");
        let filling = std::thread::spawn(move || writing.write_all(&[0xa5u8; COUNT]));
        let mut source = File::from(std::os::fd::OwnedFd::from(reading));

        assert_eq!(
            ram.fill_all_from(0, &mut source, COUNT).expect("fill"),
            COUNT
        );
        let mut landed = [0u8; 8];
        ram.read(COUNT as u64 - 8, &mut landed).expect("read back");
        assert_eq!(landed, [0xa5u8; 8]);
        filling
            .join()
            .expect("writing thread")
            .expect("fill the socket");
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn test_clone_from_template() {
        const SIZE: u64 = 1 << 20;
        let template = file_of(&vec![0xa5u8; SIZE as usize], "template");
        let ram = GuestRam::cloned_from(&[(0, SIZE)], &template).expect("map the template");

        // The last page comes from the file, not from a fresh mapping.
        let mut landed = [0u8; 8];
        ram.read(SIZE - 8, &mut landed).expect("read back");
        assert_eq!(landed, [0xa5u8; 8]);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn test_reject_short_template() {
        const SIZE: u64 = 1 << 20;
        let template = file_of(&[0xa5u8; PAGE as usize], "short");
        assert!(matches!(
            GuestRam::cloned_from(&[(0, SIZE)], &template),
            Err(Error::ShortTemplate { size }) if size == SIZE
        ));
    }

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
