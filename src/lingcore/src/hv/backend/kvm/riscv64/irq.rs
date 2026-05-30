// SPDX-FileCopyrightText: 2026 LingCage <opensource@lingcage.com>
//
// SPDX-License-Identifier: Apache-2.0

//! Legacy interrupt line of a riscv64 guest, raised and lowered through
//! `KVM_IRQ_LINE`.

use std::sync::Arc;

use kvm_ioctls::VmFd;

use crate::hv::Result;
use crate::hv::backend::kvm::kvm_err;
use crate::hv::irq::IrqSender;

/// Legacy interrupt line, pulsed through `KVM_IRQ_LINE`. Note that an
/// irqfd on an APLIC source is asserted in `kvm_arch_set_irq_inatomic`
/// (`arch/riscv/kvm/vm.c`) but never deasserted, so a level triggered
/// source would pend again on each acknowledge.
pub struct KvmIrqSender {
    vm: Arc<VmFd>,
    pin: u32,
}

impl KvmIrqSender {
    /// Wrap `pin` of the guest behind `vm`.
    pub(in crate::hv::backend::kvm) fn new(vm: Arc<VmFd>, pin: u32) -> Self {
        KvmIrqSender { vm, pin }
    }
}

impl IrqSender for KvmIrqSender {
    fn send(&self) -> Result<()> {
        self.vm
            .set_irq_line(self.pin, true)
            .map_err(kvm_err("KVM_IRQ_LINE"))?;
        self.vm
            .set_irq_line(self.pin, false)
            .map_err(kvm_err("KVM_IRQ_LINE"))
    }
}

#[cfg(test)]
mod tests {
    use crate::hv::arch::Aia;
    use crate::hv::backend::kvm::hypervisor::KvmHv;
    use crate::hv::hypervisor::Hypervisor;
    use crate::hv::irq::IrqSender;
    use crate::hv::vm::Vm;

    #[test]
    fn test_legacy_irq_line() {
        let hv = KvmHv::new().expect("open /dev/kvm");
        let vm = hv.create_vm().expect("guest");
        let _cpu0 = vm.create_vcpu(0).expect("vcpu 0");
        // `KVM_IRQ_LINE` fails with `ENXIO` before the AIA exists.
        assert!(
            vm.create_irq_sender(1).is_err(),
            "source bound with no controller behind it"
        );

        vm.enable_in_kernel_irqchip(&Aia {
            aplic: 0x0040_0000,
            imsic: 0x0400_0000,
            sources: 31,
            ids: 63,
        })
        .expect("in-kernel irqchip");
        let com1 = vm.create_irq_sender(1).expect("sender on source 1");
        com1.send().expect("pulse");
        com1.send().expect("pulse again");
        // Source 0 is reserved, pulse on it gets `ENODEV`.
        assert!(
            vm.create_irq_sender(0)
                .expect("sender on source 0")
                .send()
                .is_err(),
            "pulsed the reserved source"
        );
    }
}
