// SPDX-FileCopyrightText: 2026 LingCage <opensource@lingcage.com>
//
// SPDX-License-Identifier: Apache-2.0

//! KVM backend parts of a riscv64 guest. The `cfg` is on the
//! declaration in `kvm/mod.rs`. One-register ioctls are issued on a raw
//! descriptor, since `RegList` caps the list at 200 ids, which is fewer
//! than a kernel names.

/// Registers read by id.
pub(in crate::hv::backend::kvm) mod vcpu;

use std::os::fd::AsRawFd;

use kvm_bindings::{KVM_REG_RISCV, KVM_REG_SIZE_U64, KVMIO, kvm_one_reg};
use vmm_sys_util::ioctl::ioctl_with_ref;
use vmm_sys_util::ioctl_iow_nr;

use crate::hv::{Error, Result};

ioctl_iow_nr!(KVM_GET_ONE_REG, KVMIO, 0xab, kvm_one_reg);
ioctl_iow_nr!(KVM_SET_ONE_REG, KVMIO, 0xac, kvm_one_reg);

/// Returns the id of 64-bit register `index` of `kind`, a
/// `KVM_REG_RISCV_*` type with its subtype.
pub(in crate::hv::backend::kvm) const fn reg_id(kind: u32, index: u64) -> u64 {
    KVM_REG_RISCV as u64 | KVM_REG_SIZE_U64 | kind as u64 | index
}

/// Returns errno of the ioctl which just failed.
fn last_errno() -> i32 {
    std::io::Error::last_os_error().raw_os_error().unwrap_or(0)
}

/// Read register `id` of the vCPU named by `fd`, at most eight bytes
/// wide.
pub(in crate::hv::backend::kvm) fn get_reg(fd: &impl AsRawFd, id: u64) -> Result<u64> {
    let mut value = 0u64;
    let reg = kvm_one_reg {
        id,
        addr: std::ptr::from_mut(&mut value) as u64,
    };
    // SAFETY: `KVM_GET_ONE_REG` reads `reg` and writes the width of the
    // register, eight bytes at most, at `addr`, which points at `value`
    // during the call.
    let ret = unsafe { ioctl_with_ref(fd, KVM_GET_ONE_REG(), &reg) };
    if ret < 0 {
        return Err(Error::Os {
            op: "KVM_GET_ONE_REG",
            errno: last_errno(),
        });
    }
    Ok(value)
}

/// Write `value` to register `id` of the vCPU named by `fd`, at most
/// eight bytes wide.
pub(in crate::hv::backend::kvm) fn set_reg(fd: &impl AsRawFd, id: u64, value: u64) -> Result<()> {
    let reg = kvm_one_reg {
        id,
        addr: std::ptr::from_ref(&value) as u64,
    };
    // SAFETY: `KVM_SET_ONE_REG` reads `reg` and the width of the register,
    // eight bytes at most, at `addr`, which points at `value` during the
    // call.
    let ret = unsafe { ioctl_with_ref(fd, KVM_SET_ONE_REG(), &reg) };
    if ret < 0 {
        return Err(Error::Os {
            op: "KVM_SET_ONE_REG",
            errno: last_errno(),
        });
    }
    Ok(())
}
