// SPDX-FileCopyrightText: 2026 LingCage <opensource@lingcage.com>
//
// SPDX-License-Identifier: Apache-2.0

//! aarch64 side of `KvmVm`, the target its vCPUs are initialized with
//! and the GIC once created. A vCPU is unusable until
//! `KVM_ARM_VCPU_INIT` tells which CPU it emulates, so the preferred
//! target of the host is read once and every vCPU is initialized from
//! it.

use std::sync::OnceLock;
use std::sync::atomic::{AtomicU32, Ordering};

use kvm_bindings::{KVM_ARM_VCPU_POWER_OFF, KVM_ARM_VCPU_PSCI_0_2, kvm_vcpu_init};
use kvm_ioctls::{VcpuFd, VmFd};

use crate::hv::arch::Gic;
use crate::hv::backend::kvm::aarch64::gic::KvmGic;
use crate::hv::backend::kvm::kvm_err;
use crate::hv::{Error, Result};

/// Bits of one word of `kvm_vcpu_init::features`.
const FEATURE_BITS: u32 = 32;

/// Platform of an aarch64 guest, the target every vCPU is initialized
/// with and the GIC.
#[derive(Default)]
pub(in crate::hv::backend::kvm) struct Platform {
    /// Preferred target of the host, read on the first vCPU.
    target: OnceLock<kvm_vcpu_init>,
    /// The GIC, once created by `enable_in_kernel_irqchip`.
    gic: OnceLock<KvmGic>,
    /// vCPUs created so far. GIC needs a redistributor frame for
    /// each of them.
    vcpus: AtomicU32,
}

impl Platform {
    /// Initialize the vCPU named by `fd`, numbered `cpu_index`, with the
    /// preferred target of `vm`. PSCI 0.2 is asked for, so the guest resets
    /// and powers off through it. A vCPU other than 0 is left powered off,
    /// so that the guest starts it through PSCI, same as a riscv64 one waits
    /// for SBI HSM.
    pub(in crate::hv::backend::kvm) fn adopt(
        &self,
        cpu_index: u16,
        vm: &VmFd,
        fd: &VcpuFd,
    ) -> Result<()> {
        let mut init = match self.target.get() {
            Some(target) => *target,
            None => {
                let mut asked = kvm_vcpu_init::default();
                vm.get_preferred_target(&mut asked)
                    .map_err(kvm_err("KVM_ARM_PREFERRED_TARGET"))?;
                set(&mut asked, KVM_ARM_VCPU_PSCI_0_2);
                *self.target.get_or_init(|| asked)
            }
        };
        if cpu_index != 0 {
            set(&mut init, KVM_ARM_VCPU_POWER_OFF);
        }
        fd.vcpu_init(&init).map_err(kvm_err("KVM_ARM_VCPU_INIT"))?;
        self.vcpus.fetch_add(1, Ordering::SeqCst);
        Ok(())
    }

    /// Create the GIC placed by `gic` in `vm`. KVM initializes one GIC per
    /// guest, a second one is refused.
    pub(in crate::hv::backend::kvm) fn create_gic(&self, vm: &VmFd, gic: &Gic) -> Result<()> {
        let made = KvmGic::new(vm, gic, self.vcpus.load(Ordering::SeqCst))?;
        if self.gic.set(made).is_err() {
            return Err(Error::Os {
                op: "KVM_CREATE_DEVICE",
                errno: libc::EEXIST,
            });
        }
        Ok(())
    }

    /// Returns the GIC, or `Unsupported` with `op` before it is created.
    pub(in crate::hv::backend::kvm) fn gic(&self, op: &'static str) -> Result<&KvmGic> {
        self.gic.get().ok_or(Error::Unsupported(op))
    }
}

/// Set feature bit `bit` of `init`.
fn set(init: &mut kvm_vcpu_init, bit: u32) {
    init.features[(bit / FEATURE_BITS) as usize] |= 1 << (bit % FEATURE_BITS);
}

#[cfg(test)]
mod tests {
    use crate::hv::backend::kvm::aarch64::vm::*;

    #[test]
    fn test_feature_bit_set_in_its_word() {
        let mut init = kvm_vcpu_init::default();
        set(&mut init, 0);
        set(&mut init, 33);
        assert_eq!(init.features[0], 1);
        assert_eq!(init.features[1], 2);
    }

    #[test]
    fn test_vcpu_init_with_preferred_target() {
        use crate::hv::backend::kvm::hypervisor::KvmHv;
        use crate::hv::hypervisor::Hypervisor;
        use crate::hv::vm::Vm;

        // A vCPU without the init refuses `KVM_GET_ONE_REG`, so creating
        // one is enough to show the init ran.
        let hv = KvmHv::new().expect("open /dev/kvm");
        let vm = hv.create_vm().expect("guest");
        vm.create_vcpu(0).expect("vcpu 0");
        vm.create_vcpu(1).expect("vcpu 1");
    }
}
