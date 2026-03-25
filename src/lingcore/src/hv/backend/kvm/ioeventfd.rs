// SPDX-FileCopyrightText: 2026 LingCage <opensource@lingcage.com>
//
// SPDX-License-Identifier: Apache-2.0

//! Ioeventfds, the eventfds signalled by `KVM_IOEVENTFD` on guest
//! writes.

use std::sync::{Arc, Mutex};

use kvm_ioctls::{IoEventAddress, NoDatamatch, VmFd};
use vmm_sys_util::eventfd::{EFD_NONBLOCK, EventFd};

use crate::hv::backend::kvm::kvm_err;
use crate::hv::os::linux::ioeventfd::{IoeventFd, IoeventFdRegistry};
use crate::hv::{Error, Result};

/// Datamatch of an ioeventfd, at the width KVM compares it in.
/// `kvm-ioctls` takes `len` from the type. `Any` means `len` 0, a write
/// of any width.
enum Datamatch {
    Any,
    Byte(u8),
    Word(u16),
    Long(u32),
    Quad(u64),
}

impl Datamatch {
    /// Build the datamatch for `len` and `data`. `len` is not used without
    /// `data`.
    fn new(len: u8, data: Option<u64>) -> Result<Self> {
        match (data, len) {
            (None, _) => Ok(Datamatch::Any),
            (Some(d), 1) => Ok(Datamatch::Byte(d as u8)),
            (Some(d), 2) => Ok(Datamatch::Word(d as u16)),
            (Some(d), 4) => Ok(Datamatch::Long(d as u32)),
            (Some(d), 8) => Ok(Datamatch::Quad(d)),
            (Some(_), _) => Err(Error::Other("datamatch should be 1, 2, 4 or 8 bytes wide")),
        }
    }
}

/// Ioeventfd, the eventfd signalled by KVM on a guest write, together
/// with its binding. Deassign needs address, width and value of the
/// assign, so `bound` is kept until `deregister`.
pub struct KvmIoeventFd {
    eventfd: EventFd,
    bound: Mutex<Option<(u64, Datamatch)>>,
}

impl IoeventFd for KvmIoeventFd {}

/// Ioeventfd registry, which issues `KVM_IOEVENTFD` on the VM fd.
pub struct KvmIoeventFdRegistry {
    vm: Arc<VmFd>,
}

impl KvmIoeventFdRegistry {
    pub(in crate::hv::backend::kvm) fn new(vm: Arc<VmFd>) -> Self {
        KvmIoeventFdRegistry { vm }
    }
}

impl IoeventFdRegistry for KvmIoeventFdRegistry {
    type IoeventFd = KvmIoeventFd;

    fn create(&self) -> Result<KvmIoeventFd> {
        let eventfd = EventFd::new(EFD_NONBLOCK).map_err(kvm_err("eventfd"))?;
        Ok(KvmIoeventFd {
            eventfd,
            bound: Mutex::new(None),
        })
    }

    fn register(&self, fd: &KvmIoeventFd, gpa: u64, len: u8, data: Option<u64>) -> Result<()> {
        let datamatch = Datamatch::new(len, data)?;
        let addr = IoEventAddress::Mmio(gpa);
        match datamatch {
            Datamatch::Any => self.vm.register_ioevent(&fd.eventfd, &addr, NoDatamatch),
            Datamatch::Byte(d) => self.vm.register_ioevent(&fd.eventfd, &addr, d),
            Datamatch::Word(d) => self.vm.register_ioevent(&fd.eventfd, &addr, d),
            Datamatch::Long(d) => self.vm.register_ioevent(&fd.eventfd, &addr, d),
            Datamatch::Quad(d) => self.vm.register_ioevent(&fd.eventfd, &addr, d),
        }
        .map_err(kvm_err("KVM_IOEVENTFD"))?;
        *fd.bound.lock().unwrap() = Some((gpa, datamatch));
        Ok(())
    }

    fn deregister(&self, fd: &KvmIoeventFd) -> Result<()> {
        let (gpa, datamatch) = fd
            .bound
            .lock()
            .unwrap()
            .take()
            .ok_or(Error::Other("ioeventfd is not bound"))?;
        let addr = IoEventAddress::Mmio(gpa);
        match datamatch {
            Datamatch::Any => self.vm.unregister_ioevent(&fd.eventfd, &addr, NoDatamatch),
            Datamatch::Byte(d) => self.vm.unregister_ioevent(&fd.eventfd, &addr, d),
            Datamatch::Word(d) => self.vm.unregister_ioevent(&fd.eventfd, &addr, d),
            Datamatch::Long(d) => self.vm.unregister_ioevent(&fd.eventfd, &addr, d),
            Datamatch::Quad(d) => self.vm.unregister_ioevent(&fd.eventfd, &addr, d),
        }
        .map_err(kvm_err("KVM_IOEVENTFD"))
    }
}

#[cfg(test)]
mod tests {
    #[cfg(target_arch = "x86_64")]
    use std::alloc::{Layout, alloc_zeroed, dealloc};

    use crate::hv::backend::kvm::hypervisor::KvmHv;
    use crate::hv::backend::kvm::ioeventfd::*;
    #[cfg(target_arch = "x86_64")]
    use crate::hv::memory::{MemMapOption, VmMemory};
    #[cfg(target_arch = "x86_64")]
    use crate::hv::vcpu::{Vcpu, VmEntry, VmExit};
    use crate::hv::vm::Vm;

    #[cfg(target_arch = "x86_64")]
    const PAGE: usize = 4096;

    #[test]
    fn test_ioeventfd_registry() {
        let hv = KvmHv::new().expect("open /dev/kvm");
        let vm = hv.create_vm().expect("guest");
        let registry = vm.create_ioeventfd_registry().expect("registry");

        let eventfd = registry.create().expect("ioeventfd");
        registry
            .register(&eventfd, 0x1000, 4, None)
            .expect("bind at 0x1000");
        // Second `KVM_IOEVENTFD` at the address of a `len` 0 ioeventfd fails
        // with `EEXIST`.
        let clash = registry.create().expect("ioeventfd");
        assert!(
            registry.register(&clash, 0x1000, 4, None).is_err(),
            "second ioeventfd bound to the same address"
        );

        registry.deregister(&eventfd).expect("unbind");
        assert!(
            registry.deregister(&eventfd).is_err(),
            "same ioeventfd unbound twice"
        );

        // Ioeventfds with different datamatch values can share an address.
        // Each deassign names its own value.
        let seven = registry.create().expect("ioeventfd");
        let nine = registry.create().expect("ioeventfd");
        registry
            .register(&seven, 0x2000, 2, Some(7))
            .expect("bind on 7");
        registry
            .register(&nine, 0x2000, 2, Some(9))
            .expect("bind on 9");
        registry.deregister(&seven).expect("unbind 7");
        registry.deregister(&nine).expect("unbind 9");

        assert!(
            registry.register(&eventfd, 0x3000, 3, Some(1)).is_err(),
            "three-byte datamatch accepted"
        );
    }

    #[cfg(target_arch = "x86_64")]
    #[test]
    fn test_ioeventfd_avoids_mmio_exit() {
        // Guest write should signal the eventfd instead of exiting as
        // MMIO.
        let hv = KvmHv::new().expect("open /dev/kvm");
        let layout = Layout::from_size_align(PAGE, PAGE).expect("page-aligned layout");
        // No memory is mapped at `NOTIFY`. Write to it exits as MMIO unless an
        // ioeventfd is bound there.
        const NOTIFY: u64 = 0x8000;
        let code = [
            0xbb, 0x00, 0x80, // mov bx, 0x8000
            0xb0, 0x42, // mov al, 0x42
            0x88, 0x07, // mov [bx], al
            0xf4, // hlt
        ];

        // Build a guest with only the reset vector page mapped. Caller frees
        // `reset` once the guest is not run anymore.
        let guest = |hv: &KvmHv| {
            let vm = hv.create_vm().expect("guest");
            let mem = vm.create_vm_memory().expect("address space");
            // SAFETY: `layout` has non-zero size.
            let reset = unsafe { alloc_zeroed(layout) };
            assert!(!reset.is_null());
            // SAFETY: the allocation is one page and `code` fits at 0xff0.
            unsafe { std::ptr::copy_nonoverlapping(code.as_ptr(), reset.add(0xff0), code.len()) };
            mem.mem_map(
                0xffff_f000,
                PAGE as u64,
                reset as usize,
                MemMapOption::default(),
            )
            .expect("map the reset vector");
            (vm, mem, reset)
        };

        // Without ioeventfd, the write exits as MMIO.
        let (vm, _mem, reset) = guest(&hv);
        let mut cpu = vm.create_vcpu(0).expect("vcpu 0");
        assert_eq!(
            cpu.run(VmEntry::Run).expect("run"),
            VmExit::Mmio {
                addr: NOTIFY,
                write: Some(0x42),
                size: 1
            }
        );
        // SAFETY: `reset` came from `alloc_zeroed` with `layout`, and the
        // guest is not run anymore.
        unsafe { dealloc(reset, layout) };

        // With an ioeventfd bound at `NOTIFY`, KVM signals it instead of
        // exiting, guest runs on to `hlt`.
        let (vm, _mem, reset) = guest(&hv);
        let registry = vm.create_ioeventfd_registry().expect("registry");
        let eventfd = registry.create().expect("ioeventfd");
        registry
            .register(&eventfd, NOTIFY, 1, None)
            .expect("bind the ioeventfd");
        let mut cpu = vm.create_vcpu(0).expect("vcpu 0");
        assert_eq!(
            cpu.run(VmEntry::Run).expect("run"),
            VmExit::Halt,
            "write exited as MMIO"
        );
        assert_eq!(eventfd.eventfd.read().expect("ioeventfd signalled"), 1);
        // SAFETY: same as above.
        unsafe { dealloc(reset, layout) };
    }
}
