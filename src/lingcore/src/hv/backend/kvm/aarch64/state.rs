// SPDX-FileCopyrightText: 2026 LingCage <opensource@lingcage.com>
//
// SPDX-License-Identifier: Apache-2.0

//! vCPU state as a `StateBlob`. It carries the registers named by
//! `KVM_GET_REG_LIST` keyed by id, encoded through `serde_json`. An id
//! gives the field by its offset in `struct kvm_regs` or by its system
//! register encoding, both of which the ABI fixes, so a name table
//! would add nothing.

use std::collections::BTreeMap;

use kvm_bindings::kvm_mp_state;
use kvm_ioctls::VcpuFd;
use log::warn;

use crate::hv::backend::kvm::kvm_err;
use crate::hv::backend::kvm::onereg::{get_reg, reg_list, set_reg, width};
use crate::hv::{Arch, Backend, Error, Result, StateBlob};

/// Layout version of `StateBlob::data`, `restore` refuses others.
const STATE_VERSION: u32 = 1;

/// vCPU state as captured. `regs` holds a register of eight bytes or
/// fewer and `wide` the rest, the vector registers among them, both
/// keyed by id. Missing field takes its default.
#[derive(Default, serde::Serialize, serde::Deserialize)]
#[serde(default)]
pub(in crate::hv::backend::kvm) struct VcpuState {
    regs: BTreeMap<u64, u64>,
    wide: BTreeMap<u64, Vec<u8>>,
    mp_state: u32,
}

/// Report a register refused by KVM and return `Partial` for it.
/// `Partial` names the low word of the id, which holds the encoding.
fn refused(id: u64, err: Error) -> Error {
    warn!("register {id:#x} refused on restore: {err}");
    Error::Partial {
        op: "KVM_SET_ONE_REG",
        index: id as u32,
    }
}

impl VcpuState {
    /// Capture state of the vCPU behind `fd` as a `StateBlob`.
    pub(in crate::hv::backend::kvm) fn capture(fd: &VcpuFd) -> Result<StateBlob> {
        let mut state = VcpuState {
            mp_state: fd
                .get_mp_state()
                .map_err(kvm_err("KVM_GET_MP_STATE"))?
                .mp_state,
            ..Default::default()
        };
        for id in reg_list(fd)? {
            if width(id) <= size_of::<u64>() {
                state.regs.insert(id, get_reg(fd, id)?);
            } else {
                let mut bytes = vec![0u8; width(id)];
                fd.get_one_reg(id, &mut bytes)
                    .map_err(kvm_err("KVM_GET_ONE_REG"))?;
                state.wide.insert(id, bytes);
            }
        }
        let data = serde_json::to_vec(&state).map_err(|_| Error::Capture { part: "vCPU" })?;
        Ok(StateBlob {
            backend: Backend::Kvm,
            arch: Arch::Aarch64,
            version: STATE_VERSION,
            data,
        })
    }

    /// Restore `blob` into the vCPU behind `fd`. Blob of another backend,
    /// arch or layout version is refused. Register refused by KVM is
    /// reported as `Partial`.
    pub(in crate::hv::backend::kvm) fn restore(fd: &VcpuFd, blob: &StateBlob) -> Result<()> {
        if blob.backend != Backend::Kvm || blob.arch != Arch::Aarch64 {
            return Err(Error::Restore { part: "vCPU" });
        }
        if blob.version != STATE_VERSION {
            return Err(Error::Restore { part: "vCPU" });
        }
        let state: VcpuState =
            serde_json::from_slice(&blob.data).map_err(|_| Error::Restore { part: "vCPU" })?;
        for (&id, &value) in &state.regs {
            set_reg(fd, id, value).map_err(|err| refused(id, err))?;
        }
        for (&id, bytes) in &state.wide {
            fd.set_one_reg(id, bytes)
                .map_err(kvm_err("KVM_SET_ONE_REG"))
                .map_err(|err| refused(id, err))?;
        }
        fd.set_mp_state(kvm_mp_state {
            mp_state: state.mp_state,
        })
        .map_err(kvm_err("KVM_SET_MP_STATE"))
    }
}

#[cfg(test)]
mod tests {
    use crate::hv::arch::Reg;
    use crate::hv::backend::kvm::hypervisor::KvmHv;
    use crate::hv::hypervisor::Hypervisor;
    use crate::hv::vcpu::Vcpu;
    use crate::hv::vm::Vm;
    use crate::hv::{Arch, Backend, Error};

    #[test]
    fn test_vcpu_capture_restore() {
        let hv = KvmHv::new().expect("open /dev/kvm");
        let vm = hv.create_vm().expect("guest");
        let mut cpu = vm.create_vcpu(0).expect("vcpu 0");

        cpu.set_regs(&[(Reg::Pc, 0x4020_0000), (Reg::X1, 0xdead_beef)])
            .expect("seed the registers");
        let blob = cpu.get_state().expect("capture");
        assert_eq!(blob.backend, Backend::Kvm);
        assert_eq!(blob.arch, Arch::Aarch64);

        // Overwrite the seeded registers, then restore the blob.
        cpu.set_regs(&[(Reg::Pc, 0), (Reg::X1, 0)])
            .expect("clobber");
        assert_eq!(cpu.get_reg(Reg::X1).expect("x1"), 0);
        cpu.set_state(&blob).expect("restore");
        assert_eq!(cpu.get_reg(Reg::Pc).expect("pc"), 0x4020_0000);
        assert_eq!(cpu.get_reg(Reg::X1).expect("x1"), 0xdead_beef);
    }

    #[test]
    fn test_reject_blob_of_another_arch() {
        let hv = KvmHv::new().expect("open /dev/kvm");
        let vm = hv.create_vm().expect("guest");
        let mut cpu = vm.create_vcpu(0).expect("vcpu 0");
        let mut blob = cpu.get_state().expect("capture");

        blob.arch = Arch::Riscv64;
        assert!(matches!(
            cpu.set_state(&blob),
            Err(Error::Restore { part: "vCPU" })
        ));
    }
}
