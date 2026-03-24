// SPDX-FileCopyrightText: 2026 LingCage <opensource@lingcage.com>
//
// SPDX-License-Identifier: Apache-2.0

//! `KvmVm`, the guest handle, and the parts created from it.

use std::sync::{Arc, Mutex};

#[cfg(target_arch = "x86_64")]
use kvm_bindings::{KVM_PIT_SPEAKER_DUMMY, kvm_pit_config};
use kvm_ioctls::{Cap, VmFd};
use vmm_sys_util::eventfd::{EFD_NONBLOCK, EventFd};

use crate::hv::backend::kvm::ioeventfd::KvmIoeventFdRegistry;
use crate::hv::backend::kvm::irq::{KvmIrqSender, KvmMsiSender, Routing};
use crate::hv::backend::kvm::kvm_err;
use crate::hv::backend::kvm::memory::KvmMemory;
use crate::hv::backend::kvm::vcpu::KvmVcpu;
use crate::hv::{Error, Result};

/// Guest handle, the VM fd returned by `KVM_CREATE_VM`. Parts created
/// from it share the fd.
pub struct KvmVm {
    pub(in crate::hv::backend::kvm) fd: Arc<VmFd>,
    pub(in crate::hv::backend::kvm) routing: Arc<Mutex<Routing>>,
}

impl KvmVm {
    /// Wrap `fd`. Routing table starts empty.
    pub(in crate::hv::backend::kvm) fn new(fd: VmFd) -> Self {
        KvmVm {
            fd: Arc::new(fd),
            routing: Arc::new(Mutex::new(Routing::default())),
        }
    }

    /// Create the guest physical address space, no region mapped yet.
    pub fn create_vm_memory(&self) -> Result<KvmMemory> {
        Ok(KvmMemory::new(Arc::clone(&self.fd)))
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
        Ok(KvmVcpu::new(
            fd,
            #[cfg(target_arch = "x86_64")]
            self.xsave_size(),
        ))
    }

    /// Returns XSAVE area size in bytes, as reported by `KVM_CAP_XSAVE2`, or
    /// `size_of::<kvm_xsave>()` on a kernel without the cap.
    #[cfg(target_arch = "x86_64")]
    fn xsave_size(&self) -> usize {
        let reported = self.fd.check_extension_int(Cap::Xsave2);
        if reported <= 0 {
            size_of::<kvm_bindings::kvm_xsave>()
        } else {
            reported as usize
        }
    }

    /// Bind a new eventfd to irqchip pin `pin` through `KVM_IRQFD` and
    /// return the sender which writes it. Pin is fixed for each sender.
    pub fn create_irq_sender(&self, pin: u8) -> Result<KvmIrqSender> {
        let eventfd = EventFd::new(EFD_NONBLOCK).map_err(kvm_err("eventfd"))?;
        {
            let mut routing = self.routing.lock().unwrap();
            routing.pins.insert(pin);
            routing.apply(&self.fd)?;
        }
        self.fd
            .register_irqfd(&eventfd, u32::from(pin))
            .map_err(kvm_err("KVM_IRQFD"))?;
        Ok(KvmIrqSender::new(eventfd))
    }

    /// Create the MSI sender. Returns `Unsupported` without
    /// `KVM_CAP_SIGNAL_MSI`.
    pub fn create_msi_sender(&self) -> Result<KvmMsiSender> {
        if !self.fd.check_extension(Cap::SignalMsi) {
            return Err(Error::Unsupported("KVM_CAP_SIGNAL_MSI"));
        }
        Ok(KvmMsiSender::new(
            Arc::clone(&self.fd),
            Arc::clone(&self.routing),
        ))
    }

    /// Create the ioeventfd registry.
    pub fn create_ioeventfd_registry(&self) -> KvmIoeventFdRegistry {
        KvmIoeventFdRegistry::new(Arc::clone(&self.fd))
    }
}

#[cfg(test)]
mod tests {
    use std::os::fd::AsRawFd;

    use crate::hv::backend::kvm::hypervisor::KvmHv;

    #[test]
    fn test_create_guests() {
        let hv = KvmHv::new().expect("open /dev/kvm");
        let one = hv.create_vm().expect("first guest");
        let two = hv.create_vm().expect("second guest");
        assert_ne!(one.fd.as_raw_fd(), two.fd.as_raw_fd());
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
}
