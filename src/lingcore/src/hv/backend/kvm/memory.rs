// SPDX-FileCopyrightText: 2026 LingCage <opensource@lingcage.com>
//
// SPDX-License-Identifier: Apache-2.0

//! Guest physical address space, as KVM memory slots.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, Mutex};

use kvm_bindings::{KVM_MEM_LOG_DIRTY_PAGES, KVM_MEM_READONLY, kvm_userspace_memory_region};
use kvm_ioctls::VmFd;

use crate::hv::backend::kvm::kvm_err;
use crate::hv::memory::{MemMapOption, VmMemory};
use crate::hv::{Error, Result};

/// Slot number and size of one mapped region. `KVM_GET_DIRTY_LOG` sizes
/// the bitmap according to the region.
#[derive(Clone, Copy)]
struct Slot {
    index: u32,
    size: u64,
}

/// Guest physical address space of one guest, as KVM memory slots.
/// `slots` maps each mapped guest address to its slot, since region
/// ioctls address a region by slot number.
pub struct KvmMemory {
    vm: Arc<VmFd>,
    next_slot: AtomicU32,
    slots: Mutex<HashMap<u64, Slot>>,
}

impl KvmMemory {
    /// Create the address space over VM fd `vm`, no slot in use yet.
    pub(in crate::hv::backend::kvm) fn new(vm: Arc<VmFd>) -> Self {
        KvmMemory {
            vm,
            next_slot: AtomicU32::new(0),
            slots: Mutex::new(HashMap::new()),
        }
    }
}

impl VmMemory for KvmMemory {
    fn mem_map(&self, gpa: u64, size: u64, hva: usize, opt: MemMapOption) -> Result<()> {
        let slot = self.next_slot.fetch_add(1, Ordering::SeqCst);
        let mut flags = 0u32;
        if opt.log_dirty {
            flags |= KVM_MEM_LOG_DIRTY_PAGES;
        }
        if !opt.write {
            flags |= KVM_MEM_READONLY;
        }
        let region = kvm_userspace_memory_region {
            slot,
            flags,
            guest_phys_addr: gpa,
            memory_size: size,
            userspace_addr: hva as u64,
        };
        // SAFETY: `hva` points to `size` bytes of host memory which stay
        // mapped as long as the region exists.
        unsafe {
            self.vm
                .set_user_memory_region(region)
                .map_err(kvm_err("KVM_SET_USER_MEMORY_REGION"))?
        };
        self.slots
            .lock()
            .unwrap()
            .insert(gpa, Slot { index: slot, size });
        Ok(())
    }

    fn get_dirty_log(&self, gpa: u64) -> Result<Vec<u64>> {
        let slot = *self
            .slots
            .lock()
            .unwrap()
            .get(&gpa)
            .ok_or(Error::Other("dirty log: no region at given guest address"))?;
        self.vm
            .get_dirty_log(slot.index, slot.size as usize)
            .map_err(kvm_err("KVM_GET_DIRTY_LOG"))
    }

    fn unmap(&self, gpa: u64, _size: u64) -> Result<()> {
        let slot = self
            .slots
            .lock()
            .unwrap()
            .remove(&gpa)
            .ok_or(Error::Other("unmap: no region at given guest address"))?;
        let region = kvm_userspace_memory_region {
            slot: slot.index,
            flags: 0,
            guest_phys_addr: gpa,
            memory_size: 0,
            userspace_addr: 0,
        };
        // SAFETY: zero `memory_size` deletes the slot, no host address is read.
        unsafe {
            self.vm
                .set_user_memory_region(region)
                .map_err(kvm_err("KVM_SET_USER_MEMORY_REGION"))?
        };
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::alloc::{Layout, alloc_zeroed, dealloc};

    use crate::hv::backend::kvm::hypervisor::KvmHv;
    use crate::hv::backend::kvm::memory::*;
    use crate::hv::hypervisor::Hypervisor;
    use crate::hv::vcpu::{Vcpu, VmEntry, VmExit};
    use crate::hv::vm::Vm;

    const PAGE: usize = 4096;

    #[test]
    fn test_map_unmap_guest_memory() {
        let hv = KvmHv::new().expect("open /dev/kvm");
        let vm = hv.create_vm().expect("guest");
        let mem = vm.create_vm_memory().expect("address space");

        let size = 2 * PAGE;
        let layout = Layout::from_size_align(size, PAGE).expect("page-aligned layout");
        // SAFETY: `layout` has non-zero size.
        let host = unsafe { alloc_zeroed(layout) };
        assert!(!host.is_null());

        let gpa = 0x1000_0000;
        mem.mem_map(gpa, size as u64, host as usize, MemMapOption::default())
            .expect("map");
        mem.unmap(gpa, size as u64).expect("unmap");
        mem.unmap(gpa, size as u64).expect_err("unmap again");

        // SAFETY: `host` came from `alloc_zeroed` with `layout` and is not
        // mapped into the guest anymore.
        unsafe { dealloc(host, layout) };
    }

    #[test]
    fn test_dirty_log_read_and_clear() {
        let hv = KvmHv::new().expect("open /dev/kvm");
        let vm = hv.create_vm().expect("guest");
        let mem = vm.create_vm_memory().expect("address space");

        // Reset state is real mode with `CS:IP` at 0xffff_fff0 and zero
        // `DS`, so `mov [0x1000], al` writes guest physical 0x1000.
        const CODE_GPA: u64 = 0xffff_f000;
        const DATA_GPA: u64 = 0x1000;
        let layout = Layout::from_size_align(PAGE, PAGE).expect("page-aligned layout");
        // SAFETY: `layout` has non-zero size.
        let code_page = unsafe { alloc_zeroed(layout) };
        // SAFETY: `layout` has non-zero size.
        let data_page = unsafe { alloc_zeroed(layout) };
        assert!(!code_page.is_null() && !data_page.is_null());
        let code = [
            0xb0, 0x42, // mov al, 0x42
            0xa2, 0x00, 0x10, // mov [0x1000], al
            0xf4, // hlt
        ];
        // SAFETY: `code_page` is one page and `code` fits in it at 0xff0.
        unsafe { std::ptr::copy_nonoverlapping(code.as_ptr(), code_page.add(0xff0), code.len()) };
        mem.mem_map(
            CODE_GPA,
            PAGE as u64,
            code_page as usize,
            MemMapOption::default(),
        )
        .expect("map the reset vector");
        mem.mem_map(
            DATA_GPA,
            PAGE as u64,
            data_page as usize,
            MemMapOption {
                log_dirty: true,
                ..Default::default()
            },
        )
        .expect("map tracked page");

        // Region mapped without `log_dirty` has no log.
        mem.get_dirty_log(CODE_GPA)
            .expect_err("dirty log of untracked region");
        assert_eq!(
            mem.get_dirty_log(DATA_GPA).expect("read the log"),
            [0],
            "page dirty before the guest ran"
        );

        let mut cpu = vm.create_vcpu(0).expect("vcpu 0");
        assert_eq!(cpu.run(VmEntry::Run).expect("run"), VmExit::Halt);
        // SAFETY: the vCPU has halted and `data_page` is still allocated.
        assert_eq!(unsafe { *data_page }, 0x42, "guest wrote the page");

        assert_eq!(
            mem.get_dirty_log(DATA_GPA).expect("read the log"),
            [1],
            "page written by the guest"
        );
        // First read cleared the bit.
        assert_eq!(
            mem.get_dirty_log(DATA_GPA).expect("read the log"),
            [0],
            "read did not clear the log"
        );

        mem.unmap(CODE_GPA, PAGE as u64).expect("unmap");
        mem.unmap(DATA_GPA, PAGE as u64).expect("unmap");
        // SAFETY: both came from `alloc_zeroed` with `layout` and are not
        // mapped into the guest anymore.
        unsafe {
            dealloc(code_page, layout);
            dealloc(data_page, layout);
        }
    }
}
