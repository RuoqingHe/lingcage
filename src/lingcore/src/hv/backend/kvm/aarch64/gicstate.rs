// SPDX-FileCopyrightText: 2026 LingCage <opensource@lingcage.com>
//
// SPDX-License-Identifier: Apache-2.0

//! GIC state as a `StateBlob`. It carries the distributor registers,
//! the redistributor registers of each vCPU and the CPU interface
//! system registers, the set `KVM_DEV_ARM_VGIC_GRP_*` gives access to.

use kvm_bindings::{
    KVM_DEV_ARM_VGIC_CPUID_SHIFT, KVM_DEV_ARM_VGIC_GRP_CPU_SYSREGS, KVM_DEV_ARM_VGIC_GRP_DIST_REGS,
    KVM_DEV_ARM_VGIC_GRP_REDIST_REGS, kvm_device_attr,
};
use kvm_ioctls::DeviceFd;

use crate::hv::backend::kvm::kvm_err;
use crate::hv::{Arch, Backend, Error, Result, StateBlob};

/// Layout version of `StateBlob::data`, `restore` refuses others.
const STATE_VERSION: u32 = 1;

/// Distributor registers of a GICv3, from
/// `include/linux/irqchip/arm-gic-v3.h`. Each one is 32 bits, and the
/// ones with a range hold a word per bit or per byte of the interrupt
/// ids, so such a range is walked in words.
const GICD_CTLR: u32 = 0x0000;
const GICD_STATUSR: u32 = 0x0010;
const GICD_IGROUPR: u32 = 0x0080;
const GICD_ISENABLER: u32 = 0x0100;
const GICD_ISPENDR: u32 = 0x0200;
const GICD_ISACTIVER: u32 = 0x0300;
const GICD_IPRIORITYR: u32 = 0x0400;
const GICD_ICFGR: u32 = 0x0c00;

/// Redistributor registers of a GICv3. The ones from `GICR_IGROUPR0`
/// sit on the SGI page, a frame above the RD page.
const GICR_CTLR: u32 = 0x0000;
const GICR_STATUSR: u32 = 0x0010;
const GICR_WAKER: u32 = 0x0014;
const SGI_PAGE: u32 = 0x1_0000;
const GICR_IGROUPR0: u32 = SGI_PAGE + 0x0080;
const GICR_ISENABLER0: u32 = SGI_PAGE + 0x0100;
const GICR_ISPENDR0: u32 = SGI_PAGE + 0x0200;
const GICR_ISACTIVER0: u32 = SGI_PAGE + 0x0300;
const GICR_IPRIORITYR0: u32 = SGI_PAGE + 0x0400;
const GICR_ICFGR0: u32 = SGI_PAGE + 0x0c00;

/// CPU interface system registers of a GICv3, at `op0` 3 and `op1` 0,
/// then `crn`, `crm` and `op2`. Only the first active priority register
/// of each group is here, since KVM offers five priority bits and
/// refuses the ones above it.
const ICC_REGS: [(u32, u32, u32, &str); 9] = [
    (4, 6, 0, "icc_pmr_el1"),
    (12, 8, 3, "icc_bpr0_el1"),
    (12, 8, 4, "icc_ap0r0_el1"),
    (12, 9, 0, "icc_ap1r0_el1"),
    (12, 12, 3, "icc_bpr1_el1"),
    (12, 12, 4, "icc_ctlr_el1"),
    (12, 12, 5, "icc_sre_el1"),
    (12, 12, 6, "icc_igrpen0_el1"),
    (12, 12, 7, "icc_igrpen1_el1"),
];

/// Interrupt ids one 32-bit word covers when the register holds a bit
/// per id, and when it holds a byte per id.
const IDS_PER_BIT_WORD: u32 = 32;
const IDS_PER_BYTE_WORD: u32 = 4;

/// Interrupt ids one word of `ICFGR` covers, two bits each.
const IDS_PER_CFG_WORD: u32 = 16;

/// Private interrupt ids of a vCPU, the SGIs and the PPIs. The
/// distributor holds no word for them.
const PRIVATE_IDS: u32 = 32;

/// GIC state as captured, distributor and redistributor registers by
/// their offset and the CPU interface registers by their name. Missing
/// field takes its default.
#[derive(Default, serde::Serialize, serde::Deserialize)]
#[serde(default)]
pub(in crate::hv::backend::kvm) struct GicState {
    /// Distributor register offset to value.
    dist: Vec<(u32, u32)>,
    /// Redistributor register of a vCPU, its index, offset and value.
    redist: Vec<(u32, u32, u32)>,
    /// CPU interface register of a vCPU, its index, name and value.
    cpu: Vec<(u32, String, u64)>,
}

/// Returns the offsets of the distributor registers which hold `ids`
/// interrupt ids, the private ones left out as the distributor does.
fn dist_offsets(ids: u32) -> Vec<u32> {
    let mut out = vec![GICD_CTLR, GICD_STATUSR];
    let shared = ids.saturating_sub(PRIVATE_IDS);
    for (base, per_word) in [
        (GICD_IGROUPR, IDS_PER_BIT_WORD),
        (GICD_ISENABLER, IDS_PER_BIT_WORD),
        (GICD_ISPENDR, IDS_PER_BIT_WORD),
        (GICD_ISACTIVER, IDS_PER_BIT_WORD),
        (GICD_IPRIORITYR, IDS_PER_BYTE_WORD),
        (GICD_ICFGR, IDS_PER_CFG_WORD),
    ] {
        let first = PRIVATE_IDS / per_word;
        let words = shared.div_ceil(per_word);
        for word in 0..words {
            out.push(base + (first + word) * size_of::<u32>() as u32);
        }
    }
    out
}

/// Returns the offsets of the redistributor registers of one vCPU. The
/// private ids of a vCPU take one word each, or eight of `IPRIORITYR`
/// and two of `ICFGR`.
fn redist_offsets() -> Vec<u32> {
    let mut out = vec![GICR_CTLR, GICR_STATUSR, GICR_WAKER];
    out.extend([
        GICR_IGROUPR0,
        GICR_ISENABLER0,
        GICR_ISPENDR0,
        GICR_ISACTIVER0,
    ]);
    for word in 0..PRIVATE_IDS / IDS_PER_BYTE_WORD {
        out.push(GICR_IPRIORITYR0 + word * size_of::<u32>() as u32);
    }
    for word in 0..PRIVATE_IDS / IDS_PER_CFG_WORD {
        out.push(GICR_ICFGR0 + word * size_of::<u32>() as u32);
    }
    out
}

/// Returns the attribute of `offset` for the vCPU numbered `cpu`.
fn attr_of(cpu: u32, offset: u32) -> u64 {
    (u64::from(cpu) << KVM_DEV_ARM_VGIC_CPUID_SHIFT) | u64::from(offset)
}

/// Returns the system register encoding of the CPU interface register
/// at `crn`, `crm` and `op2`, as `KVM_DEV_ARM_VGIC_SYSREG` builds it.
/// `op0` is 3 and `op1` is 0 for every one of them.
fn sysreg(crn: u32, crm: u32, op2: u32) -> u32 {
    (3 << 14) | (crn << 7) | (crm << 3) | op2
}

impl GicState {
    /// Capture the state of `device` for `vcpus` vCPUs and `ids`
    /// interrupt ids as a `StateBlob`.
    pub(in crate::hv::backend::kvm) fn capture(
        device: &DeviceFd,
        vcpus: u32,
        ids: u32,
    ) -> Result<StateBlob> {
        let mut state = GicState::default();
        for offset in dist_offsets(ids) {
            let mut value = 0u32;
            get(
                device,
                KVM_DEV_ARM_VGIC_GRP_DIST_REGS,
                attr_of(0, offset),
                &mut value,
            )?;
            state.dist.push((offset, value));
        }
        for cpu in 0..vcpus {
            for offset in redist_offsets() {
                let mut value = 0u32;
                get(
                    device,
                    KVM_DEV_ARM_VGIC_GRP_REDIST_REGS,
                    attr_of(cpu, offset),
                    &mut value,
                )?;
                state.redist.push((cpu, offset, value));
            }
            for (crn, crm, op2, name) in ICC_REGS {
                let mut value = 0u64;
                get(
                    device,
                    KVM_DEV_ARM_VGIC_GRP_CPU_SYSREGS,
                    attr_of(cpu, sysreg(crn, crm, op2)),
                    &mut value,
                )?;
                state.cpu.push((cpu, name.to_string(), value));
            }
        }
        let data = serde_json::to_vec(&state).map_err(|_| Error::Capture {
            part: "interrupt chip",
        })?;
        Ok(StateBlob {
            backend: Backend::Kvm,
            arch: Arch::Aarch64,
            version: STATE_VERSION,
            data,
        })
    }

    /// Restore `blob` into `device`. Blob of another backend, arch or
    /// layout version is refused. `GICD_CTLR` goes in last, so that the
    /// distributor is enabled only once its lines are written.
    pub(in crate::hv::backend::kvm) fn restore(device: &DeviceFd, blob: &StateBlob) -> Result<()> {
        if blob.backend != Backend::Kvm || blob.arch != Arch::Aarch64 {
            return Err(Error::Restore {
                part: "interrupt chip",
            });
        }
        if blob.version != STATE_VERSION {
            return Err(Error::Restore {
                part: "interrupt chip",
            });
        }
        let state: GicState = serde_json::from_slice(&blob.data).map_err(|_| Error::Restore {
            part: "interrupt chip",
        })?;
        for (cpu, offset, value) in &state.redist {
            set(
                device,
                KVM_DEV_ARM_VGIC_GRP_REDIST_REGS,
                attr_of(*cpu, *offset),
                value,
            )?;
        }
        for (cpu, name, value) in &state.cpu {
            let Some((crn, crm, op2, _)) = ICC_REGS.iter().find(|(.., known)| known == name) else {
                continue;
            };
            set(
                device,
                KVM_DEV_ARM_VGIC_GRP_CPU_SYSREGS,
                attr_of(*cpu, sysreg(*crn, *crm, *op2)),
                value,
            )?;
        }
        for (offset, value) in state.dist.iter().filter(|(at, _)| *at != GICD_CTLR) {
            set(
                device,
                KVM_DEV_ARM_VGIC_GRP_DIST_REGS,
                attr_of(0, *offset),
                value,
            )?;
        }
        for (offset, value) in state.dist.iter().filter(|(at, _)| *at == GICD_CTLR) {
            set(
                device,
                KVM_DEV_ARM_VGIC_GRP_DIST_REGS,
                attr_of(0, *offset),
                value,
            )?;
        }
        Ok(())
    }
}

/// Read attribute `attr` of `group` into `value`.
fn get<T>(device: &DeviceFd, group: u32, attr: u64, value: &mut T) -> Result<()> {
    let mut request = kvm_device_attr {
        group,
        attr,
        addr: std::ptr::from_mut(value) as u64,
        flags: 0,
    };
    // SAFETY: `addr` points at `value`, which is as wide as the
    // attribute and outlives the call.
    unsafe { device.get_device_attr(&mut request) }.map_err(kvm_err("KVM_GET_DEVICE_ATTR"))
}

/// Write `value` to attribute `attr` of `group`.
fn set<T>(device: &DeviceFd, group: u32, attr: u64, value: &T) -> Result<()> {
    let request = kvm_device_attr {
        group,
        attr,
        addr: std::ptr::from_ref(value) as u64,
        flags: 0,
    };
    device
        .set_device_attr(&request)
        .map_err(kvm_err("KVM_SET_DEVICE_ATTR"))
}

#[cfg(test)]
mod tests {
    use crate::hv::backend::kvm::aarch64::gicstate::*;

    #[test]
    fn test_dist_offsets_cover_shared_ids() {
        let offsets = dist_offsets(64);
        assert!(offsets.contains(&GICD_CTLR));
        // 32 shared ids take one word of a bit per id, eight of a byte
        // per id and two of two bits per id.
        assert_eq!(
            offsets.iter().filter(|at| **at == GICD_IGROUPR + 4).count(),
            1
        );
        assert_eq!(
            offsets
                .iter()
                .filter(|at| **at >= GICD_IPRIORITYR && **at < GICD_ICFGR)
                .count(),
            8
        );
    }

    #[test]
    fn test_attr_carries_vcpu_index() {
        assert_eq!(attr_of(0, 0x100), 0x100);
        assert_eq!(attr_of(2, 0x100), (2 << 32) | 0x100);
    }

    #[test]
    fn test_sysreg_encoding() {
        // `ICC_CTLR_EL1` is `op0` 3, `op1` 0, `crn` 12, `crm` 12, `op2` 4,
        // and `ICC_PMR_EL1` sits at `crn` 4 instead.
        assert_eq!(sysreg(12, 12, 4), (3 << 14) | (12 << 7) | (12 << 3) | 4);
        assert_eq!(sysreg(4, 6, 0), (3 << 14) | (4 << 7) | (6 << 3));
    }
}
