// SPDX-FileCopyrightText: 2026 LingCage <opensource@lingcage.com>
//
// SPDX-License-Identifier: Apache-2.0

//! The run loop driving a vCPU, which dispatches its port and MMIO
//! accesses to `VmOps`.
//!
//! A read exits the guest before the value is known. The loop passes the
//! value from the device back through `VmEntry` on the next `run`. The
//! loop is generic over the backend, so there is no dispatch per exit.

use crate::hv::Result;
use crate::hv::vcpu::{Vcpu, VmEntry, VmExit};

/// Devices which the run loop dispatches guest accesses to.
///
/// A read returns the value seen by the guest. Error from any method
/// ends the run, so an address claimed by no device should return a
/// value instead of an error.
pub trait VmOps {
    /// Returns the value of a port read of `size` bytes.
    #[cfg(target_arch = "x86_64")]
    fn read_port(&mut self, port: u16, size: u8) -> Result<u32>;

    /// Handle a port write of `size` bytes. `Some` ends the run with that
    /// exit.
    #[cfg(target_arch = "x86_64")]
    fn write_port(&mut self, port: u16, size: u8, value: u32) -> Result<Option<VmExit>>;

    /// Returns the value of an MMIO read of `size` bytes.
    fn read_mmio(&mut self, addr: u64, size: u8) -> Result<u64>;

    /// Handle an MMIO write of `size` bytes. `Some` ends the run with that
    /// exit.
    fn write_mmio(&mut self, addr: u64, size: u8, value: u64) -> Result<Option<VmExit>>;
}

/// Run `vcpu` until it exits for a reason not handled by `bus`, and
/// return that exit.
///
/// Port and MMIO accesses are dispatched to `bus` and do not surface. A
/// halt, reset, shutdown, hypercall or `Interrupted` exit ends the call,
/// caller resumes by calling again.
pub fn run<V: Vcpu, B: VmOps>(vcpu: &mut V, bus: &mut B) -> Result<VmExit> {
    let mut entry = VmEntry::Run;
    loop {
        let exit = vcpu.run(entry)?;
        entry = match exit {
            #[cfg(target_arch = "x86_64")]
            VmExit::Io {
                port,
                write: Some(value),
                size,
            } => match bus.write_port(port, size, value)? {
                None => VmEntry::Run,
                Some(exit) => return Ok(exit),
            },
            #[cfg(target_arch = "x86_64")]
            VmExit::Io {
                port,
                write: None,
                size,
            } => VmEntry::Io {
                data: bus.read_port(port, size)?,
            },
            VmExit::Mmio {
                addr,
                write: Some(value),
                size,
            } => match bus.write_mmio(addr, size, value)? {
                None => VmEntry::Run,
                Some(exit) => return Ok(exit),
            },
            VmExit::Mmio {
                addr,
                write: None,
                size,
            } => VmEntry::Mmio {
                data: bus.read_mmio(addr, size)?,
            },
            other => return Ok(other),
        };
    }
}

#[cfg(all(test, feature = "kvm", target_os = "linux", target_arch = "x86_64"))]
mod tests {
    use std::alloc::{Layout, alloc_zeroed, dealloc};

    use crate::hv::Error;
    use crate::hv::backend::kvm::hypervisor::KvmHv;
    use crate::hv::hypervisor::Hypervisor;
    use crate::hv::memory::{MemMapOption, VmMemory};
    use crate::hv::vm::Vm;
    use crate::vcpu::*;

    const PAGE: usize = 4096;
    /// Page of the reset vector, mapped as code of the guest.
    const CODE: u64 = 0xffff_f000;
    /// Address with no memory behind. Access to it exits as MMIO.
    const DEVICE: u64 = 0x2000;

    /// One guest access as seen by the bus.
    #[derive(Debug, PartialEq, Eq)]
    enum Access {
        PortRead(u16, u8),
        PortWrite(u16, u8, u32),
        MmioRead(u64, u8),
        MmioWrite(u64, u8, u64),
    }

    /// `VmOps` which records each access and returns fixed values for reads.
    struct Recorder {
        seen: Vec<Access>,
        port_answer: u32,
        mmio_answer: u64,
        refuse: bool,
    }

    impl VmOps for Recorder {
        fn read_port(&mut self, port: u16, size: u8) -> Result<u32> {
            self.seen.push(Access::PortRead(port, size));
            Ok(self.port_answer)
        }

        fn write_port(&mut self, port: u16, size: u8, value: u32) -> Result<Option<VmExit>> {
            self.seen.push(Access::PortWrite(port, size, value));
            Ok(None)
        }

        fn read_mmio(&mut self, addr: u64, size: u8) -> Result<u64> {
            self.seen.push(Access::MmioRead(addr, size));
            if self.refuse {
                return Err(Error::Unregistered {
                    at: "at that address",
                });
            }
            Ok(self.mmio_answer)
        }

        fn write_mmio(&mut self, addr: u64, size: u8, value: u64) -> Result<Option<VmExit>> {
            self.seen.push(Access::MmioWrite(addr, size, value));
            Ok(None)
        }
    }

    /// Create a VM with `code` in one page at the reset vector. Returns the
    /// VM and the allocation of the page.
    fn guest(hv: &KvmHv, code: &[u8]) -> (impl Vm, *mut u8, Layout) {
        let vm = hv.create_vm().expect("guest");
        let mem = vm.create_vm_memory().expect("address space");
        let layout = Layout::from_size_align(PAGE, PAGE).expect("page-aligned layout");
        // SAFETY: `layout` has non-zero size.
        let host = unsafe { alloc_zeroed(layout) };
        assert!(!host.is_null());
        // Out of reset the vCPU fetches at 0xff0 of this page. The near jump
        // there lands at offset 0, so `code` gets the rest of the page.
        let jump = [0xe9, 0x0d, 0xf0];
        // SAFETY: the allocation is one page, the jump fits at 0xff0 and
        // `code` of the caller fits below it.
        unsafe {
            std::ptr::copy_nonoverlapping(jump.as_ptr(), host.add(0xff0), jump.len());
            std::ptr::copy_nonoverlapping(code.as_ptr(), host, code.len());
        }
        mem.mem_map(CODE, PAGE as u64, host as usize, MemMapOption::default())
            .expect("map the reset vector");
        (vm, host, layout)
    }

    /// mov al, 0x42 / out 0xf8, al / in al, 0xf9 / out 0xfa, al
    /// mov byte [0x2000], 0x37 / mov al, [0x2000] / out 0xfb, al / hlt
    const PROGRAM: [u8; 19] = [
        0xb0, 0x42, 0xe6, 0xf8, 0xe4, 0xf9, 0xe6, 0xfa, 0xc6, 0x06, 0x00, 0x20, 0x37, 0xa0, 0x00,
        0x20, 0xe6, 0xfb, 0xf4,
    ];

    #[test]
    fn test_dispatch_port_and_mmio() {
        // Run a guest program and compare accesses recorded by the bus.
        let hv = KvmHv::new().expect("open /dev/kvm");
        let (vm, host, layout) = guest(&hv, &PROGRAM);
        let mut cpu = vm.create_vcpu(0).expect("vcpu 0");
        let mut bus = Recorder {
            seen: Vec::new(),
            port_answer: 0x99,
            mmio_answer: 0x5a,
            refuse: false,
        };

        // The halt is returned, not handled.
        assert_eq!(run(&mut cpu, &mut bus).expect("run"), VmExit::Halt);
        assert_eq!(
            bus.seen,
            [
                Access::PortWrite(0xf8, 1, 0x42),
                Access::PortRead(0xf9, 1),
                // Value read from 0xf9 reached the guest, which writes it
                // to 0xfa.
                Access::PortWrite(0xfa, 1, 0x99),
                Access::MmioWrite(DEVICE, 1, 0x37),
                Access::MmioRead(DEVICE, 1),
                // Same for the MMIO read.
                Access::PortWrite(0xfb, 1, 0x5a),
            ]
        );

        // SAFETY: `host` came from `alloc_zeroed` with `layout`, and the VM
        // which maps it is dropped at the end of the scope.
        unsafe { dealloc(host, layout) };
    }

    #[test]
    fn test_stop_on_refused_read() {
        let hv = KvmHv::new().expect("open /dev/kvm");
        let (vm, host, layout) = guest(&hv, &PROGRAM);
        let mut cpu = vm.create_vcpu(0).expect("vcpu 0");
        let mut bus = Recorder {
            seen: Vec::new(),
            port_answer: 0x99,
            mmio_answer: 0,
            refuse: true,
        };

        assert!(run(&mut cpu, &mut bus).is_err(), "ran past refused read");
        // The refused read is the last access, loop stopped there.
        assert_eq!(bus.seen.last(), Some(&Access::MmioRead(DEVICE, 1)));

        // SAFETY: `host` came from `alloc_zeroed` with `layout`, and the VM
        // which maps it is dropped at the end of the scope.
        unsafe { dealloc(host, layout) };
    }
}
