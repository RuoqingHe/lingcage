// SPDX-FileCopyrightText: 2026 LingCage <opensource@lingcage.com>
//
// SPDX-License-Identifier: Apache-2.0

//! KVM backend.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, Mutex};

use kvm_bindings::{
    KVM_API_VERSION, KVM_MEM_LOG_DIRTY_PAGES, KVM_MEM_READONLY, kvm_userspace_memory_region,
};
use kvm_ioctls::{Kvm, VmFd};

use crate::hv::memory::{MemMapOption, VmMemory};
use crate::hv::{Error, Result};

/// Map a `kvm_ioctls::Error` to `Error::Os` with operation `op`.
fn kvm_err(op: &'static str) -> impl Fn(kvm_ioctls::Error) -> Error {
    move |err| Error::Os {
        op,
        errno: err.errno(),
    }
}

/// Opened `/dev/kvm` handle.
pub struct KvmHv {
    kvm: Kvm,
}

impl KvmHv {
    /// Open `/dev/kvm`, refuse a kernel whose `KVM_GET_API_VERSION` is not
    /// `KVM_API_VERSION`.
    pub fn new() -> Result<Self> {
        let kvm = Kvm::new().map_err(kvm_err("open /dev/kvm"))?;
        // `get_api_version` returns the raw ioctl result, negative value
        // means failure with errno set.
        let version = kvm.get_api_version();
        if version < 0 {
            return Err(Error::Os {
                op: "KVM_GET_API_VERSION",
                errno: kvm_ioctls::Error::last().errno(),
            });
        }
        if version != KVM_API_VERSION as i32 {
            return Err(Error::ApiVersion(version));
        }
        Ok(KvmHv { kvm })
    }

    /// Create a guest through `KVM_CREATE_VM`, without vCPU or memory.
    pub fn create_vm(&self) -> Result<KvmVm> {
        let fd = self.kvm.create_vm().map_err(kvm_err("KVM_CREATE_VM"))?;
        Ok(KvmVm { fd: Arc::new(fd) })
    }
}

/// Guest handle, the VM fd returned by `KVM_CREATE_VM`. Parts created
/// from it share the fd.
pub struct KvmVm {
    fd: Arc<VmFd>,
}

impl KvmVm {
    /// Create the guest physical address space, no region mapped yet.
    pub fn create_vm_memory(&self) -> Result<KvmMemory> {
        Ok(KvmMemory {
            vm: Arc::clone(&self.fd),
            next_slot: AtomicU32::new(0),
            slots: Mutex::new(HashMap::new()),
        })
    }
}

/// Guest physical address space of one guest, as KVM memory slots.
/// `slots` maps each mapped guest address to the slot number given to
/// it, since `KVM_SET_USER_MEMORY_REGION` addresses a region by slot.
pub struct KvmMemory {
    vm: Arc<VmFd>,
    next_slot: AtomicU32,
    slots: Mutex<HashMap<u64, u32>>,
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
        self.slots.lock().unwrap().insert(gpa, slot);
        Ok(())
    }

    fn unmap(&self, gpa: u64, _size: u64) -> Result<()> {
        let slot = self
            .slots
            .lock()
            .unwrap()
            .remove(&gpa)
            .ok_or(Error::Other("unmap: no region at given guest address"))?;
        let region = kvm_userspace_memory_region {
            slot,
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
    use std::os::fd::AsRawFd;

    use crate::hv::backend::kvm::*;

    const PAGE: usize = 4096;

    #[test]
    fn test_open_kvm() {
        KvmHv::new().expect("/dev/kvm at the expected KVM API version");
    }

    #[test]
    fn test_create_guests() {
        let hv = KvmHv::new().expect("open /dev/kvm");
        let one = hv.create_vm().expect("first guest");
        let two = hv.create_vm().expect("second guest");
        assert_ne!(one.fd.as_raw_fd(), two.fd.as_raw_fd());
    }

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
}
