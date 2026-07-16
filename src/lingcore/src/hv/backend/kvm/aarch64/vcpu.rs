// SPDX-FileCopyrightText: 2026 LingCage <opensource@lingcage.com>
//
// SPDX-License-Identifier: Apache-2.0

//! Registers of an aarch64 vCPU, read and written by their one-register
//! id.

use kvm_bindings::{KVM_REG_ARM_CORE, KVM_REG_ARM64, KVM_REG_SIZE_U64};
use kvm_ioctls::VcpuFd;

use crate::hv::Result;
use crate::hv::arch::Reg;
use crate::hv::backend::kvm::onereg::{get_reg, set_reg};

/// `u32` words of one core register. A core register is addressed by
/// the offset of its field in `struct kvm_regs`, counted in `u32`, and
/// every field of `user_pt_regs` is a `u64`.
const WORDS: u64 = 2;

/// Returns the one-register id of core register `reg`.
pub(in crate::hv::backend::kvm) fn core_id(reg: Reg) -> u64 {
    KVM_REG_ARM64 | KVM_REG_SIZE_U64 | u64::from(KVM_REG_ARM_CORE) | (reg as u64 * WORDS)
}

/// Read core register `reg` of the vCPU named by `fd`.
pub(in crate::hv::backend::kvm) fn core_reg(fd: &VcpuFd, reg: Reg) -> Result<u64> {
    get_reg(fd, core_id(reg))
}

/// Write core registers in `vals`, in order, to the vCPU named by `fd`.
pub(in crate::hv::backend::kvm) fn set_core_regs(fd: &VcpuFd, vals: &[(Reg, u64)]) -> Result<()> {
    for &(reg, val) in vals {
        set_reg(fd, core_id(reg), val)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use crate::hv::backend::kvm::aarch64::vcpu::*;

    #[test]
    fn test_core_id_of_first_and_last_field() {
        // Ids of `arch/arm64/include/uapi/asm/kvm.h`. `X0` is
        // `KVM_REG_ARM_CORE_REG(regs.regs[0])` and the offset counts
        // `u32`.
        assert_eq!(core_id(Reg::X0), 0x6030_0000_0010_0000);
        assert_eq!(core_id(Reg::X1), 0x6030_0000_0010_0002);
        assert_eq!(core_id(Reg::Sp), 0x6030_0000_0010_003e);
        assert_eq!(core_id(Reg::Pc), 0x6030_0000_0010_0040);
        assert_eq!(core_id(Reg::Pstate), 0x6030_0000_0010_0042);
    }

    #[test]
    fn test_core_regs_round_trip() {
        use crate::hv::backend::kvm::hypervisor::KvmHv;
        use crate::hv::hypervisor::Hypervisor;
        use crate::hv::vcpu::Vcpu;
        use crate::hv::vm::Vm;

        let hv = KvmHv::new().expect("open /dev/kvm");
        let vm = hv.create_vm().expect("guest");
        let mut cpu = vm.create_vcpu(0).expect("vcpu 0");
        cpu.set_regs(&[(Reg::X0, 0x1234), (Reg::Pc, 0x4020_0000)])
            .expect("write core registers");
        assert_eq!(cpu.get_reg(Reg::X0).expect("read x0"), 0x1234);
        assert_eq!(cpu.get_reg(Reg::Pc).expect("read pc"), 0x4020_0000);
    }
}
