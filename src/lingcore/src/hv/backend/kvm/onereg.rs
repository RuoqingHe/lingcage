// SPDX-FileCopyrightText: 2026 LingCage <opensource@lingcage.com>
//
// SPDX-License-Identifier: Apache-2.0

//! The one-register ioctls, which aarch64 and riscv64 both read and
//! write their registers through. They are issued on a raw descriptor,
//! since `RegList` caps the list at 200 ids, which is fewer than a
//! kernel has.

use std::os::fd::AsRawFd;

#[cfg(target_arch = "riscv64")]
use kvm_bindings::{KVM_REG_SIZE_MASK, KVM_REG_SIZE_SHIFT};
use kvm_bindings::{KVMIO, kvm_one_reg, kvm_reg_list};
#[cfg(target_arch = "riscv64")]
use vmm_sys_util::ioctl::ioctl_with_mut_ptr;
use vmm_sys_util::ioctl::ioctl_with_ref;
use vmm_sys_util::{ioctl_iow_nr, ioctl_iowr_nr};

use crate::hv::{Error, Result};

ioctl_iow_nr!(KVM_GET_ONE_REG, KVMIO, 0xab, kvm_one_reg);
ioctl_iow_nr!(KVM_SET_ONE_REG, KVMIO, 0xac, kvm_one_reg);
ioctl_iowr_nr!(KVM_GET_REG_LIST, KVMIO, 0xb0, kvm_reg_list);

/// Returns width of register `id` in bytes. Only a state capture reads
/// a register it does not know the width of.
#[cfg(target_arch = "riscv64")]
pub(in crate::hv::backend::kvm) fn width(id: u64) -> usize {
    1 << ((id & KVM_REG_SIZE_MASK) >> KVM_REG_SIZE_SHIFT)
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

/// Returns the ids named by `KVM_GET_REG_LIST` for the vCPU named by
/// `fd`. Call with no room fails with `E2BIG` and sets `n` to the count.
/// Only a state capture walks the whole list.
#[cfg(target_arch = "riscv64")]
pub(in crate::hv::backend::kvm) fn reg_list(fd: &impl AsRawFd) -> Result<Vec<u64>> {
    let mut list: Vec<u64> = vec![0];
    // SAFETY: `KVM_GET_REG_LIST` reads `n` from the first word and writes
    // it back, then fills `n` ids after it if the room named by the first
    // word is there. `list` holds `n + 1` words during the call.
    let probed = unsafe { ioctl_with_mut_ptr(fd, KVM_GET_REG_LIST(), list.as_mut_ptr()) };
    if probed >= 0 {
        return Ok(Vec::new());
    }
    if last_errno() != libc::E2BIG {
        return Err(Error::Os {
            op: "KVM_GET_REG_LIST",
            errno: last_errno(),
        });
    }
    let count = list[0] as usize;
    list = vec![0; 1 + count];
    list[0] = count as u64;
    // SAFETY: same as above, with the room asked by the count.
    let filled = unsafe { ioctl_with_mut_ptr(fd, KVM_GET_REG_LIST(), list.as_mut_ptr()) };
    if filled < 0 {
        return Err(Error::Os {
            op: "KVM_GET_REG_LIST",
            errno: last_errno(),
        });
    }
    list.truncate(1 + list[0] as usize);
    Ok(list[1..].to_vec())
}
