// SPDX-FileCopyrightText: 2026 LingCage <opensource@lingcage.com>
//
// SPDX-License-Identifier: Apache-2.0

//! Device bus, which maps a guest address to the device placed there
//! and the offset into it. Read of an unclaimed address returns all
//! ones, write to it is dropped.

use std::io;

use crate::devices::{Blob, Device, Error, Result};
use crate::hv;
use crate::hv::vcpu::VmExit;
use crate::vcpu::VmOps;

/// Device placed at `base` covering `size` bytes.
struct Placed {
    base: u64,
    size: u64,
    device: Box<dyn Device>,
}

/// Devices placed on the buses of a guest. x86 has a port space and an
/// MMIO space, port and MMIO address with same number are different
/// devices. Other architectures only have MMIO.
#[derive(Default)]
pub struct Bus {
    #[cfg(target_arch = "x86_64")]
    ports: Vec<Placed>,
    mmio: Vec<Placed>,
}

/// All ones for `size` bytes, which is what a read of unclaimed address
/// returns. x86 probe takes all ones as absent device.
fn floating(size: u8) -> u64 {
    match size {
        0 => 0,
        1..=7 => (1u64 << (size * 8)) - 1,
        _ => u64::MAX,
    }
}

/// Place `device` at `base` covering `size` bytes. The range must be
/// non-empty, fit the address space and not overlap with placed ones.
fn place(list: &mut Vec<Placed>, base: u64, size: u64, device: Box<dyn Device>) -> Result<()> {
    let end = base.checked_add(size).ok_or(Error::BadRange { base })?;
    if size == 0 {
        return Err(Error::BadRange { base });
    }
    if list.iter().any(|p| base < p.base + p.size && p.base < end) {
        return Err(Error::Overlap { base });
    }
    list.push(Placed { base, size, device });
    Ok(())
}

/// Returns the device covering `addr` and the offset into it.
fn find(list: &mut [Placed], addr: u64) -> Option<(&mut Box<dyn Device>, u64)> {
    for placed in list.iter_mut() {
        if addr >= placed.base && addr - placed.base < placed.size {
            let offset = addr - placed.base;
            return Some((&mut placed.device, offset));
        }
    }
    None
}

/// Read `size` bytes at `addr`, unclaimed address reads as all ones.
fn read(list: &mut [Placed], addr: u64, size: u8) -> u64 {
    match find(list, addr) {
        Some((device, offset)) => device.read(offset, size),
        None => floating(size),
    }
}

/// Write `size` bytes at `addr`, write to unclaimed address is dropped.
fn write(list: &mut [Placed], addr: u64, size: u8, value: u64) -> io::Result<Option<VmExit>> {
    match find(list, addr) {
        Some((device, offset)) => device.write(offset, size, value),
        None => Ok(None),
    }
}

/// Convert a failed device sink write to `hv::Error::Os`. Error without
/// errno is reported as zero.
fn sink_err(err: io::Error) -> hv::Error {
    hv::Error::Os {
        op: "device write",
        errno: err.raw_os_error().unwrap_or(0),
    }
}

impl Bus {
    /// Create an empty bus.
    pub fn new() -> Self {
        Bus::default()
    }

    /// Place `device` in port space at `base` covering `size` bytes.
    #[cfg(target_arch = "x86_64")]
    pub fn place_port(&mut self, base: u16, size: u16, device: Box<dyn Device>) -> Result<()> {
        place(&mut self.ports, u64::from(base), u64::from(size), device)
    }

    /// Place `device` in MMIO space at `base` covering `size` bytes.
    pub fn place_mmio(&mut self, base: u64, size: u64, device: Box<dyn Device>) -> Result<()> {
        place(&mut self.mmio, base, size, device)
    }

    /// Returns the placed devices in placement order, port space first on
    /// x86_64 and then MMIO.
    fn placed(&self) -> impl Iterator<Item = &Placed> {
        #[cfg(target_arch = "x86_64")]
        let all = self.ports.iter().chain(self.mmio.iter());
        #[cfg(not(target_arch = "x86_64"))]
        let all = self.mmio.iter();
        all
    }

    /// Mutable version of `placed`.
    fn placed_mut(&mut self) -> impl Iterator<Item = &mut Placed> {
        #[cfg(target_arch = "x86_64")]
        let all = self.ports.iter_mut().chain(self.mmio.iter_mut());
        #[cfg(not(target_arch = "x86_64"))]
        let all = self.mmio.iter_mut();
        all
    }

    /// Returns the number of placed devices.
    pub fn count(&self) -> usize {
        self.placed().count()
    }

    /// Returns state of each device in `placed` order. Stateless device
    /// contributes `None`, so that the list lines up with the bus.
    pub fn capture(&self) -> Result<Vec<Option<Blob>>> {
        self.placed()
            .map(|placed| placed.device.capture())
            .collect()
    }

    /// Restore the list returned by `capture`, a list of another length is
    /// reported as `State`.
    pub fn restore(&mut self, blobs: &[Option<Blob>]) -> Result<()> {
        if blobs.len() != self.placed().count() {
            return Err(Error::State);
        }
        for (placed, blob) in self.placed_mut().zip(blobs) {
            if let Some(blob) = blob {
                placed.device.restore(blob)?;
            }
        }
        Ok(())
    }
}

impl VmOps for Bus {
    #[cfg(target_arch = "x86_64")]
    fn read_port(&mut self, port: u16, size: u8) -> hv::Result<u32> {
        Ok(read(&mut self.ports, u64::from(port), size) as u32)
    }

    #[cfg(target_arch = "x86_64")]
    fn write_port(&mut self, port: u16, size: u8, value: u32) -> hv::Result<Option<VmExit>> {
        write(&mut self.ports, u64::from(port), size, u64::from(value)).map_err(sink_err)
    }

    fn read_mmio(&mut self, addr: u64, size: u8) -> hv::Result<u64> {
        Ok(read(&mut self.mmio, addr, size))
    }

    fn write_mmio(&mut self, addr: u64, size: u8, value: u64) -> hv::Result<Option<VmExit>> {
        write(&mut self.mmio, addr, size, value).map_err(sink_err)
    }
}

// Tests place devices in port space, which only x86 has.
#[cfg(all(test, target_arch = "x86_64"))]
mod tests {
    #[cfg(all(feature = "kvm", target_os = "linux"))]
    use std::io::Write;
    #[cfg(all(feature = "kvm", target_os = "linux"))]
    use std::sync::{Arc, Mutex};

    use crate::devices::bus::*;
    use crate::devices::serial::Serial;

    /// Sink for the test to read back after the run.
    #[cfg(all(feature = "kvm", target_os = "linux"))]
    #[derive(Clone)]
    struct Tap(Arc<Mutex<Vec<u8>>>);

    #[cfg(all(feature = "kvm", target_os = "linux"))]
    impl Write for Tap {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(buf);
            Ok(buf.len())
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    fn uart() -> Box<dyn Device> {
        Box::new(Serial::new(Vec::new()))
    }

    #[test]
    fn test_unclaimed_address_reads_ones() {
        let mut bus = Bus::new();
        bus.place_port(0x3f8, 8, uart()).expect("place the uart");

        // Unclaimed port reads as all ones at each access size.
        for size in [1u8, 2, 4] {
            assert_eq!(
                bus.read_port(0x80, size).expect("read"),
                floating(size) as u32,
                "unclaimed port does not read as all ones"
            );
        }
        assert_eq!(bus.read_mmio(0x2000, 8).expect("read"), u64::MAX);
        assert_eq!(bus.read_mmio(0x2000, 1).expect("read"), 0xff);
        // Port space and MMIO space are separate, uart at port 0x3f8 is not
        // at MMIO 0x3f8.
        assert_eq!(bus.read_mmio(0x3f8, 1).expect("read"), 0xff);

        // Write to unclaimed address is dropped.
        bus.write_port(0x80, 1, 0x42).expect("drop the write");
        bus.write_mmio(0x2000, 1, 0x42).expect("drop the write");
    }

    #[test]
    fn test_reject_overlapping_range() {
        let mut bus = Bus::new();
        bus.place_port(0x3f8, 8, uart()).expect("place the uart");

        // Ranges overlapping the uart at 0x3f8..0x400 are refused.
        for (base, size) in [(0x3f8, 8), (0x3ff, 8), (0x3f0, 16), (0x3fc, 1)] {
            assert!(
                matches!(
                    bus.place_port(base, size, uart()),
                    Err(Error::Overlap { .. })
                ),
                "overlapping range at {base:#x}..{:#x} is accepted",
                base + size
            );
        }
        // Ranges on either side are free.
        bus.place_port(0x3f0, 8, uart()).expect("range below");
        bus.place_port(0x400, 8, uart()).expect("range above");

        // Empty range, and range past the end of address space.
        assert!(matches!(
            bus.place_mmio(0x1000, 0, uart()),
            Err(Error::BadRange { .. })
        ));
        assert!(matches!(
            bus.place_mmio(u64::MAX, 2, uart()),
            Err(Error::BadRange { .. })
        ));
    }

    #[cfg(all(feature = "kvm", target_os = "linux", target_arch = "x86_64"))]
    #[test]
    fn test_guest_write_reaches_device() {
        // Run real guest code doing port and MMIO writes, check the sinks.
        use std::alloc::{Layout, alloc_zeroed, dealloc};

        use crate::hv::backend::kvm::hypervisor::KvmHv;
        use crate::hv::hypervisor::Hypervisor;
        use crate::hv::memory::{MemMapOption, VmMemory};
        use crate::hv::vcpu::VmExit;
        use crate::hv::vm::Vm;

        const PAGE: usize = 4096;
        /// Page holding the reset vector.
        const CODE: u64 = 0xffff_f000;

        // mov dx, 0x3f8 / mov al, 'h' / out dx, al / mov al, 'i' / out dx, al
        // in al, 0x80 / out dx, al / mov byte [0x2000], 'z' / hlt
        //
        // The `in` from unclaimed port 0x80 is echoed to the uart, so what the
        // read returned is recorded by the sink.
        let code = [
            0xba, 0xf8, 0x03, 0xb0, 0x68, 0xee, 0xb0, 0x69, 0xee, 0xe4, 0x80, 0xee, 0xc6, 0x06,
            0x00, 0x20, 0x7a, 0xf4,
        ];

        let ports = Tap(Arc::new(Mutex::new(Vec::new())));
        let window = Tap(Arc::new(Mutex::new(Vec::new())));
        let mut bus = Bus::new();
        bus.place_port(0x3f8, 8, Box::new(Serial::new(ports.clone())))
            .expect("uart in port space");
        bus.place_mmio(0x2000, 8, Box::new(Serial::new(window.clone())))
            .expect("uart in address space");

        let hv = KvmHv::new().expect("open /dev/kvm");
        let vm = hv.create_vm().expect("guest");
        let mem = vm.create_vm_memory().expect("address space");
        let layout = Layout::from_size_align(PAGE, PAGE).expect("page-aligned layout");
        // SAFETY: `layout` has non-zero size.
        let host = unsafe { alloc_zeroed(layout) };
        assert!(!host.is_null());
        // Near jump from reset vector at 0xfff0 to start of the page.
        let jump = [0xe9, 0x0d, 0xf0];
        // SAFETY: the allocation is one page, the jump fits at 0xff0 and `code`
        // fits below it.
        unsafe {
            std::ptr::copy_nonoverlapping(jump.as_ptr(), host.add(0xff0), jump.len());
            std::ptr::copy_nonoverlapping(code.as_ptr(), host, code.len());
        }
        mem.mem_map(CODE, PAGE as u64, host as usize, MemMapOption::default())
            .expect("map the reset vector");

        let mut cpu = vm.create_vcpu(0).expect("vcpu 0");
        assert_eq!(
            crate::vcpu::run(&mut cpu, &mut bus).expect("run"),
            VmExit::Halt
        );

        assert_eq!(
            ports.0.lock().unwrap().as_slice(),
            b"hi\xff",
            "uart in port space got other bytes"
        );
        assert_eq!(
            window.0.lock().unwrap().as_slice(),
            b"z",
            "uart in address space got other bytes"
        );

        // SAFETY: `host` came from `alloc_zeroed` with `layout`, and the VM
        // which maps it is dropped at the end of the scope.
        unsafe { dealloc(host, layout) };
    }
}
