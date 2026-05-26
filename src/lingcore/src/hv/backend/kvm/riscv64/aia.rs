// SPDX-FileCopyrightText: 2026 LingCage <opensource@lingcage.com>
//
// SPDX-License-Identifier: Apache-2.0

//! The AIA as a `KVM_DEV_TYPE_RISCV_AIA` device.

use kvm_bindings::{
    KVM_DEV_RISCV_AIA_ADDR_APLIC, KVM_DEV_RISCV_AIA_CONFIG_HART_BITS, KVM_DEV_RISCV_AIA_CONFIG_IDS,
    KVM_DEV_RISCV_AIA_CONFIG_SRCS, KVM_DEV_RISCV_AIA_CTRL_INIT, KVM_DEV_RISCV_AIA_GRP_ADDR,
    KVM_DEV_RISCV_AIA_GRP_CONFIG, KVM_DEV_RISCV_AIA_GRP_CTRL, kvm_create_device, kvm_device_attr,
    kvm_device_type_KVM_DEV_TYPE_RISCV_AIA,
};
use kvm_ioctls::{DeviceFd, VmFd};

use crate::hv::Result;
use crate::hv::arch::{Aia, IMSIC_SIZE, hart_index_bits};
use crate::hv::backend::kvm::kvm_err;

/// AIA of one guest, held as its device fd.
pub(in crate::hv::backend::kvm) struct KvmAia {
    device: DeviceFd,
}

impl KvmAia {
    /// Create and initialize the AIA of `vm` placed at `aia` for `harts`
    /// vCPUs, which should exist already, since the init refuses one still
    /// being created.
    pub(in crate::hv::backend::kvm) fn new(vm: &VmFd, aia: &Aia, harts: u32) -> Result<Self> {
        let mut request = kvm_create_device {
            type_: kvm_device_type_KVM_DEV_TYPE_RISCV_AIA,
            fd: 0,
            flags: 0,
        };
        let device = vm
            .create_device(&mut request)
            .map_err(kvm_err("KVM_CREATE_DEVICE"))?;
        let made = KvmAia { device };
        made.set(
            KVM_DEV_RISCV_AIA_GRP_CONFIG,
            u64::from(KVM_DEV_RISCV_AIA_CONFIG_SRCS),
            &aia.sources,
        )?;
        made.set(
            KVM_DEV_RISCV_AIA_GRP_CONFIG,
            u64::from(KVM_DEV_RISCV_AIA_CONFIG_IDS),
            &aia.ids,
        )?;
        made.set(
            KVM_DEV_RISCV_AIA_GRP_CONFIG,
            u64::from(KVM_DEV_RISCV_AIA_CONFIG_HART_BITS),
            &hart_index_bits(harts),
        )?;
        made.set(
            KVM_DEV_RISCV_AIA_GRP_ADDR,
            u64::from(KVM_DEV_RISCV_AIA_ADDR_APLIC),
            &aia.aplic,
        )?;
        // `KVM_DEV_RISCV_AIA_ADDR_IMSIC(n)` is `1 + n`.
        for hart in 0..harts {
            made.set(
                KVM_DEV_RISCV_AIA_GRP_ADDR,
                u64::from(1 + hart),
                &(aia.imsic + u64::from(hart) * IMSIC_SIZE),
            )?;
        }
        made.set(
            KVM_DEV_RISCV_AIA_GRP_CTRL,
            u64::from(KVM_DEV_RISCV_AIA_CTRL_INIT),
            &0u32,
        )?;
        Ok(made)
    }

    /// Write `value` to attribute `attr` of `group`. KVM reads the value at
    /// the width taken by the attribute, `u32` for config, `u64` for
    /// address, `unsigned long` for IMSIC register.
    fn set<T>(&self, group: u32, attr: u64, value: &T) -> Result<()> {
        let request = kvm_device_attr {
            group,
            attr,
            addr: std::ptr::from_ref(value) as u64,
            flags: 0,
        };
        self.device
            .set_device_attr(&request)
            .map_err(kvm_err("KVM_SET_DEVICE_ATTR"))
    }
}
