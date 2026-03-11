// SPDX-FileCopyrightText: 2026 LingCage <opensource@lingcage.com>
//
// SPDX-License-Identifier: Apache-2.0

//! KVM backend.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, Mutex};

use kvm_bindings::{
    KVM_API_VERSION, KVM_MEM_LOG_DIRTY_PAGES, KVM_MEM_READONLY, kvm_msi,
    kvm_userspace_memory_region,
};
#[cfg(target_arch = "x86_64")]
use kvm_bindings::{KVM_PIT_SPEAKER_DUMMY, kvm_pit_config};
use kvm_ioctls::{Cap, Kvm, VcpuFd, VmFd};
use vmm_sys_util::eventfd::{EFD_NONBLOCK, EventFd};

use crate::hv::irq::IrqSender;
use crate::hv::memory::{MemMapOption, VmMemory};
use crate::hv::{Error, Result};

/// Map a `kvm_ioctls::Error`, or the `io::Error` of an eventfd call, to
/// `Error::Os` with operation `op`.
fn kvm_err<E: Into<kvm_ioctls::Error>>(op: &'static str) -> impl Fn(E) -> Error {
    move |err| Error::Os {
        op,
        errno: err.into().errno(),
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

    /// Create the in-kernel irqchip (PIC, IOAPIC and LAPICs) through
    /// `KVM_CREATE_IRQCHIP`, and the i8254 PIT through `KVM_CREATE_PIT2`.
    #[cfg(target_arch = "x86_64")]
    pub fn enable_irqchip(&self) -> Result<()> {
        self.fd
            .create_irq_chip()
            .map_err(kvm_err("KVM_CREATE_IRQCHIP"))?;
        // `KVM_PIT_SPEAKER_DUMMY` registers a speaker stub at port 0x61 in
        // kernel, so guest write there does not exit to VMM.
        self.fd
            .create_pit2(kvm_pit_config {
                flags: KVM_PIT_SPEAKER_DUMMY,
                ..Default::default()
            })
            .map_err(kvm_err("KVM_CREATE_PIT2"))?;
        Ok(())
    }

    /// Create the vCPU with id `cpu_index` through `KVM_CREATE_VCPU`. A
    /// second vCPU with the same id fails with `EEXIST`.
    pub fn create_vcpu(&self, cpu_index: u16) -> Result<KvmVcpu> {
        let fd = self
            .fd
            .create_vcpu(u64::from(cpu_index))
            .map_err(kvm_err("KVM_CREATE_VCPU"))?;
        Ok(KvmVcpu { fd })
    }

    /// Bind a new eventfd to irqchip pin `pin` through `KVM_IRQFD` and
    /// return the sender which writes it. Pin is fixed for each sender.
    pub fn create_irq_sender(&self, pin: u8) -> Result<KvmIrqSender> {
        let eventfd = EventFd::new(EFD_NONBLOCK).map_err(kvm_err("eventfd"))?;
        self.fd
            .register_irqfd(&eventfd, u32::from(pin))
            .map_err(kvm_err("KVM_IRQFD"))?;
        Ok(KvmIrqSender { eventfd })
    }

    /// Create the MSI sender. Returns `Unsupported` without
    /// `KVM_CAP_SIGNAL_MSI`.
    pub fn create_msi_sender(&self) -> Result<KvmMsiSender> {
        if !self.fd.check_extension(Cap::SignalMsi) {
            return Err(Error::Unsupported("KVM_CAP_SIGNAL_MSI"));
        }
        Ok(KvmMsiSender {
            vm: Arc::clone(&self.fd),
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

/// vCPU handle, the fd returned by `KVM_CREATE_VCPU`.
pub struct KvmVcpu {
    // TODO: drop the attribute once running the vCPU reads this fd.
    #[cfg_attr(not(test), expect(dead_code, reason = "only the test reads the fd"))]
    fd: VcpuFd,
}

/// Legacy interrupt line, the eventfd bound to its pin by `KVM_IRQFD`.
/// `send` writes the fd and issues no ioctl on the VM fd. Binding is
/// not undone on drop, it ends together with the VM fd.
pub struct KvmIrqSender {
    eventfd: EventFd,
}

impl IrqSender for KvmIrqSender {
    fn send(&self) -> Result<()> {
        // Without resamplefd, KVM raises the line and lowers it for each write.
        self.eventfd.write(1).map_err(kvm_err("irqfd write"))
    }
}

/// Sender for message signalled interrupts. Address and data are passed
/// with each `send`, so all devices of a guest share one sender.
pub struct KvmMsiSender {
    vm: Arc<VmFd>,
}

impl KvmMsiSender {
    /// Deliver `data` to `addr` through `KVM_SIGNAL_MSI` on the calling
    /// thread.
    pub fn send(&self, addr: u64, data: u32) -> Result<()> {
        let msi = kvm_msi {
            address_lo: addr as u32,
            address_hi: (addr >> 32) as u32,
            data,
            ..Default::default()
        };
        self.vm.signal_msi(msi).map_err(kvm_err("KVM_SIGNAL_MSI"))?;
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

    #[cfg(target_arch = "x86_64")]
    #[test]
    fn test_irqchip_created_once() {
        let hv = KvmHv::new().expect("open /dev/kvm");
        let vm = hv.create_vm().expect("guest");
        vm.enable_irqchip().expect("in-kernel irqchip");
        // Second `KVM_CREATE_IRQCHIP` fails with `EEXIST`.
        vm.enable_irqchip().expect_err("irqchip again");
    }

    #[test]
    fn test_create_vcpus() {
        let hv = KvmHv::new().expect("open /dev/kvm");
        let vm = hv.create_vm().expect("guest");
        let cpu0 = vm.create_vcpu(0).expect("vcpu 0");
        let cpu1 = vm.create_vcpu(1).expect("vcpu 1");
        assert_ne!(cpu0.fd.as_raw_fd(), cpu1.fd.as_raw_fd());
        // Second `KVM_CREATE_VCPU` with the same id fails with `EEXIST`.
        assert!(vm.create_vcpu(0).is_err(), "vCPU 0 created a second time");
    }

    #[cfg(target_arch = "x86_64")]
    #[test]
    fn test_send_msi() {
        let hv = KvmHv::new().expect("open /dev/kvm");
        let vm = hv.create_vm().expect("guest");
        vm.enable_irqchip().expect("in-kernel irqchip");
        let msi = vm.create_msi_sender().expect("msi sender");

        // Without vCPU there is no LAPIC to deliver to. `KVM_SIGNAL_MSI`
        // returns -1, which shows as `EPERM` at the syscall boundary.
        assert!(
            msi.send(0xfee0_0000, 0x30).is_err(),
            "message delivered with no LAPIC to take it"
        );

        let _cpu0 = vm.create_vcpu(0).expect("vcpu 0");
        // Vector 0x30, fixed delivery, addressed to APIC id 0.
        msi.send(0xfee0_0000, 0x30).expect("deliver to vcpu 0");
    }

    #[cfg(target_arch = "x86_64")]
    #[test]
    fn test_legacy_irq_line() {
        let hv = KvmHv::new().expect("open /dev/kvm");
        let vm = hv.create_vm().expect("guest");
        // `KVM_IRQFD` fails with `EINVAL` before `KVM_CREATE_IRQCHIP`.
        assert!(
            vm.create_irq_sender(4).is_err(),
            "pin bound with no controller behind it"
        );

        vm.enable_irqchip().expect("in-kernel irqchip");
        let com1 = vm.create_irq_sender(4).expect("sender on IRQ 4");
        com1.send().expect("pulse");
        com1.send().expect("pulse again");
    }
}
