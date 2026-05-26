// SPDX-FileCopyrightText: 2026 LingCage <opensource@lingcage.com>
//
// SPDX-License-Identifier: Apache-2.0

//! riscv64 side of `KvmVm`, harts counted for the AIA, and the AIA once
//! created.

use std::sync::OnceLock;
use std::sync::atomic::{AtomicU32, Ordering};

use kvm_ioctls::VmFd;

use crate::hv::arch::Aia;
use crate::hv::backend::kvm::riscv64::aia::KvmAia;
use crate::hv::{Error, Result};

/// Platform of a riscv64 guest, its harts and the AIA.
#[derive(Default)]
pub(in crate::hv::backend::kvm) struct Platform {
    /// The AIA, once created by `enable_in_kernel_irqchip`.
    aia: OnceLock<KvmAia>,
    /// vCPUs created so far. The AIA is sized according to them.
    harts: AtomicU32,
}

impl Platform {
    /// Count a vCPU as a hart.
    pub(in crate::hv::backend::kvm) fn adopt(&self) {
        self.harts.fetch_add(1, Ordering::SeqCst);
    }

    /// Create the AIA placed by `aia` in `vm`, for the harts counted so far.
    /// KVM initializes one AIA per guest, a second one is refused.
    pub(in crate::hv::backend::kvm) fn create_aia(&self, vm: &VmFd, aia: &Aia) -> Result<()> {
        let made = KvmAia::new(vm, aia, self.harts.load(Ordering::SeqCst))?;
        if self.aia.set(made).is_err() {
            return Err(Error::Os {
                op: "KVM_CREATE_DEVICE",
                errno: libc::EEXIST,
            });
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use crate::hv::Cap;
    use crate::hv::arch::Aia;
    use crate::hv::backend::kvm::hypervisor::KvmHv;
    use crate::hv::hypervisor::Hypervisor;
    use crate::hv::vm::Vm;

    /// An AIA laid out the way a machine lays one out.
    const AIA: Aia = Aia {
        aplic: 0x0040_0000,
        imsic: 0x0400_0000,
        sources: 31,
        ids: 63,
    };

    #[test]
    fn test_irqchip_created_once() {
        let hv = KvmHv::new().expect("open /dev/kvm");
        let vm = hv.create_vm().expect("guest");
        let _cpu0 = vm.create_vcpu(0).expect("vcpu 0");
        vm.enable_in_kernel_irqchip(&AIA)
            .expect("in-kernel irqchip");
        // KVM initializes an AIA only once, a second one gets `EBUSY`.
        vm.enable_in_kernel_irqchip(&AIA)
            .expect_err("irqchip again");
    }

    #[test]
    fn test_capabilities() {
        let hv = KvmHv::new().expect("open /dev/kvm");
        let vm = hv.create_vm().expect("guest");
        let _cpu0 = vm.create_vcpu(0).expect("vcpu 0");

        // Ioeventfds and dirty logging do not depend on the irqchip.
        assert!(vm.capability(Cap::IoeventFd));
        assert!(vm.capability(Cap::DirtyLog));

        // Interrupt caps are reported once the AIA is in the kernel.
        assert!(!vm.capability(Cap::InKernelIrqChip));
        assert!(!vm.capability(Cap::IrqFd));
        vm.enable_in_kernel_irqchip(&AIA)
            .expect("in-kernel irqchip");
        assert!(vm.capability(Cap::InKernelIrqChip));
        assert!(vm.capability(Cap::IrqFd));
    }
}
