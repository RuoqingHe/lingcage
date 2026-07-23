// SPDX-FileCopyrightText: 2026 LingCage <opensource@lingcage.com>
//
// SPDX-License-Identifier: Apache-2.0

//! The GIC as a `KVM_DEV_TYPE_ARM_VGIC_V3` device, the interrupt
//! controller of an aarch64 guest.

use kvm_bindings::{
    KVM_DEV_ARM_VGIC_CTRL_INIT, KVM_DEV_ARM_VGIC_GRP_ADDR, KVM_DEV_ARM_VGIC_GRP_CTRL,
    KVM_DEV_ARM_VGIC_GRP_NR_IRQS, KVM_VGIC_V3_ADDR_TYPE_DIST, KVM_VGIC_V3_ADDR_TYPE_REDIST,
    kvm_create_device, kvm_device_attr, kvm_device_type_KVM_DEV_TYPE_ARM_VGIC_V3,
};
use kvm_ioctls::{DeviceFd, VmFd};

use crate::hv::arch::{Gic, PRIVATE_IDS};
use crate::hv::backend::kvm::aarch64::gicstate::GicState;
use crate::hv::backend::kvm::kvm_err;
use crate::hv::{Result, StateBlob};

/// Interrupt ids of the guest, the private ones of each vCPU plus the
/// SPIs. KVM wants a multiple of 32, 64 at the least.
const ID_STEP: u32 = 32;

/// GIC of one guest, its device fd and the shape it was created with.
/// The fd stays open for the life of the guest, closing it would stop
/// the controller.
pub(in crate::hv::backend::kvm) struct KvmGic {
    device: DeviceFd,
    vcpus: u32,
    ids: u32,
}

impl KvmGic {
    /// Create and initialize the GIC of `vm` placed by `gic` for `vcpus`
    /// vCPUs, which should exist already, since KVM needs a redistributor
    /// frame for each of them and the init refuses one still being
    /// created.
    pub(in crate::hv::backend::kvm) fn new(vm: &VmFd, gic: &Gic, vcpus: u32) -> Result<Self> {
        let mut request = kvm_create_device {
            type_: kvm_device_type_KVM_DEV_TYPE_ARM_VGIC_V3,
            fd: 0,
            flags: 0,
        };
        let device = vm
            .create_device(&mut request)
            .map_err(kvm_err("KVM_CREATE_DEVICE"))?;
        let made = KvmGic {
            device,
            vcpus,
            ids: ids(gic.sources),
        };
        made.set(
            KVM_DEV_ARM_VGIC_GRP_ADDR,
            u64::from(KVM_VGIC_V3_ADDR_TYPE_DIST),
            &gic.dist,
        )?;
        // KVM maps one region from this address, a frame per vCPU.
        made.set(
            KVM_DEV_ARM_VGIC_GRP_ADDR,
            u64::from(KVM_VGIC_V3_ADDR_TYPE_REDIST),
            &gic.redist,
        )?;
        made.set(KVM_DEV_ARM_VGIC_GRP_NR_IRQS, 0, &ids(gic.sources))?;
        made.set(
            KVM_DEV_ARM_VGIC_GRP_CTRL,
            u64::from(KVM_DEV_ARM_VGIC_CTRL_INIT),
            &0u32,
        )?;
        Ok(made)
    }

    /// Capture the state of this GIC as a `StateBlob`.
    pub(in crate::hv::backend::kvm) fn capture(&self) -> Result<StateBlob> {
        GicState::capture(&self.device, self.vcpus, self.ids)
    }

    /// Restore a blob captured by `capture` into this GIC.
    pub(in crate::hv::backend::kvm) fn restore(&self, blob: &StateBlob) -> Result<()> {
        GicState::restore(&self.device, blob)
    }

    /// Write `value` to attribute `attr` of `group`. KVM reads the value at
    /// the width taken by the attribute, `u32` for the count and `u64` for
    /// an address.
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

/// Returns the interrupt id count for `sources` SPIs, rounded up to the
/// step KVM wants, two steps at the least.
fn ids(sources: u32) -> u32 {
    let wanted = PRIVATE_IDS + sources;
    wanted.div_ceil(ID_STEP).max(2) * ID_STEP
}

#[cfg(test)]
mod tests {
    use crate::hv::backend::kvm::aarch64::gic::*;

    #[test]
    fn test_ids_rounded_to_step() {
        assert_eq!(ids(0), 64);
        assert_eq!(ids(31), 64);
        assert_eq!(ids(32), 64);
        assert_eq!(ids(33), 96);
        assert_eq!(ids(224), 256);
    }
}
