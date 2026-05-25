// SPDX-FileCopyrightText: 2026 LingCage <opensource@lingcage.com>
//
// SPDX-License-Identifier: Apache-2.0

//! vCPU state as a `StateBlob`. It carries core registers by name and
//! every other register named by `KVM_GET_REG_LIST` by id, encoded
//! through `serde_json`.

use std::collections::BTreeMap;

use kvm_bindings::{
    KVM_REG_RISCV_CONFIG, KVM_REG_RISCV_CORE, KVM_REG_RISCV_ISA_EXT, KVM_REG_RISCV_SBI_EXT,
    KVM_REG_RISCV_TIMER, KVM_REG_RISCV_TYPE_MASK, KVM_RISCV_TIMER_STATE_OFF, kvm_mp_state,
    kvm_riscv_timer,
};
use kvm_ioctls::VcpuFd;
use log::warn;

use crate::hv::backend::kvm::kvm_err;
use crate::hv::backend::kvm::riscv64::{get_reg, index, kind, reg_id, reg_list, set_reg, width};
use crate::hv::{Arch, Backend, Error, Result, StateBlob};

/// Layout version of `StateBlob::data`, `restore` refuses others.
const STATE_VERSION: u32 = 1;

/// Id of the timer `state` register. Writing `OFF` to a timer already
/// off is refused (`kvm_riscv_vcpu_timer_cancel`), and timer of a new
/// vCPU is off. `ON` re-arms the timer, so it is written on its own.
const TIMER_STATE: u64 = reg_id(
    KVM_REG_RISCV_TIMER,
    (std::mem::offset_of!(kvm_riscv_timer, state) / size_of::<u64>()) as u64,
);

/// Names of core registers in `kvm_riscv_core` order, same as `Reg`.
pub(in crate::hv::backend::kvm) const CORE: [&str; 33] = [
    "pc", "ra", "sp", "gp", "tp", "t0", "t1", "t2", "s0", "s1", "a0", "a1", "a2", "a3", "a4", "a5",
    "a6", "a7", "s2", "s3", "s4", "s5", "s6", "s7", "s8", "s9", "s10", "s11", "t3", "t4", "t5",
    "t6", "mode",
];

/// vCPU state as captured. `core` is keyed by register name, `regs` and
/// `wide` (over eight bytes, the vector registers) are keyed by id.
/// Missing field takes its default.
#[derive(Default, serde::Serialize, serde::Deserialize)]
#[serde(default)]
pub(in crate::hv::backend::kvm) struct VcpuState {
    core: BTreeMap<String, u64>,
    regs: BTreeMap<u64, u64>,
    wide: BTreeMap<u64, Vec<u8>>,
    mp_state: u32,
}

/// Returns whether `id` is a register a vCPU takes before the others,
/// namely the config, ISA extensions and SBI extensions. Enabling an
/// extension resets floating point registers, so they go in first.
fn shaping(id: u64) -> bool {
    matches!(
        kind(id) & KVM_REG_RISCV_TYPE_MASK,
        KVM_REG_RISCV_CONFIG | KVM_REG_RISCV_ISA_EXT | KVM_REG_RISCV_SBI_EXT
    )
}

/// Report a register refused by KVM and return `Partial` for it.
/// `Partial` names the low word of the id, which holds type and index.
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
            if kind(id) == KVM_REG_RISCV_CORE {
                let name = CORE
                    .get(index(id) as usize)
                    .ok_or(Error::Capture { part: "vCPU" })?;
                state.core.insert((*name).to_string(), get_reg(fd, id)?);
            } else if width(id) <= size_of::<u64>() {
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
            arch: Arch::Riscv64,
            version: STATE_VERSION,
            data,
        })
    }

    /// Restore `blob` into the vCPU behind `fd`. Blob of another backend,
    /// arch or layout version is refused. Shaping registers go in first.
    /// Register refused by KVM is reported as `Partial`.
    pub(in crate::hv::backend::kvm) fn restore(fd: &VcpuFd, blob: &StateBlob) -> Result<()> {
        if blob.backend != Backend::Kvm || blob.arch != Arch::Riscv64 {
            return Err(Error::Restore { part: "vCPU" });
        }
        if blob.version != STATE_VERSION {
            return Err(Error::Restore { part: "vCPU" });
        }
        let state: VcpuState =
            serde_json::from_slice(&blob.data).map_err(|_| Error::Restore { part: "vCPU" })?;

        for (&id, &value) in state.regs.iter().filter(|(id, _)| shaping(**id)) {
            set_reg(fd, id, value).map_err(|err| refused(id, err))?;
        }
        for (&id, &value) in state.regs.iter().filter(|(id, _)| !shaping(**id)) {
            if id == TIMER_STATE && value == u64::from(KVM_RISCV_TIMER_STATE_OFF) {
                continue;
            }
            set_reg(fd, id, value).map_err(|err| refused(id, err))?;
        }
        for (&id, bytes) in &state.wide {
            fd.set_one_reg(id, bytes)
                .map_err(kvm_err("KVM_SET_ONE_REG"))
                .map_err(|err| refused(id, err))?;
        }
        for (name, &value) in &state.core {
            let Some(slot) = CORE.iter().position(|known| known == name) else {
                warn!("core register {name} unknown to this build, skipped");
                continue;
            };
            let id = reg_id(KVM_REG_RISCV_CORE, slot as u64);
            set_reg(fd, id, value).map_err(|err| refused(id, err))?;
        }
        fd.set_mp_state(kvm_mp_state {
            mp_state: state.mp_state,
        })
        .map_err(kvm_err("KVM_SET_MP_STATE"))
    }
}

#[cfg(test)]
mod tests {
    use crate::hv::arch::{ConfigReg, Reg};
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

        cpu.set_regs(&[(Reg::Pc, 0x4020_0000), (Reg::A1, 0xdead_beef)])
            .expect("seed the registers");
        let blob = cpu.get_state().expect("capture");
        assert_eq!(blob.backend, Backend::Kvm);
        assert_eq!(blob.arch, Arch::Riscv64);

        // Overwrite the seeded registers, then restore the blob.
        cpu.set_regs(&[(Reg::Pc, 0), (Reg::A1, 0)])
            .expect("clobber");
        assert_eq!(cpu.get_reg(Reg::A1).expect("a1"), 0);
        cpu.set_state(&blob).expect("restore");
        assert_eq!(cpu.get_reg(Reg::Pc).expect("pc"), 0x4020_0000);
        assert_eq!(cpu.get_reg(Reg::A1).expect("a1"), 0xdead_beef);

        // Blob carries the timer and the ISA together with the rest.
        let text: serde_json::Value =
            serde_json::from_slice(&blob.data).expect("decode the blob as JSON");
        assert_eq!(text["core"]["pc"], serde_json::Value::from(0x4020_0000u64));
        assert!(
            text["regs"].as_object().expect("registers by id").len() > 20,
            "too few registers beyond the core ones"
        );

        // Blob of another backend, or a later layout, is refused before
        // decoding.
        let mut alien = blob.clone();
        alien.backend = Backend::Mshv;
        assert!(
            cpu.set_state(&alien).is_err(),
            "state of another backend accepted"
        );
        let mut newer = blob.clone();
        newer.version += 1;
        assert!(cpu.set_state(&newer).is_err(), "unknown layout accepted");

        // Fields are read by name. Dropped field takes default and unknown
        // field is ignored.
        let mut text: serde_json::Value =
            serde_json::from_slice(&blob.data).expect("decode the blob as JSON");
        let core = text["core"].as_object_mut().expect("core registers");
        core.remove("a1").expect("field to drop");
        core.insert("something_later".into(), serde_json::Value::from(7));
        let mut edited = blob.clone();
        edited.data = serde_json::to_vec(&text).expect("re-encode");
        cpu.set_state(&edited).expect("restore with other fields");
        assert_eq!(cpu.get_reg(Reg::Pc).expect("pc"), 0x4020_0000);
        assert_eq!(
            cpu.get_reg(Reg::A1).expect("a1"),
            0xdead_beef,
            "dropped core register was written"
        );
    }

    #[test]
    fn test_refused_register_reported() {
        let hv = KvmHv::new().expect("open /dev/kvm");
        let vm = hv.create_vm().expect("guest");
        let mut cpu = vm.create_vcpu(0).expect("vcpu 0");
        let timebase = cpu.get_config(ConfigReg::Timebase).expect("timebase");

        // Timer frequency is the one of the host. Another value is refused,
        // and the refusal names the register.
        let blob = cpu.get_state().expect("capture");
        let mut text: serde_json::Value =
            serde_json::from_slice(&blob.data).expect("decode the blob as JSON");
        let regs = text["regs"].as_object_mut().expect("registers by id");
        let (id, _) = regs
            .iter()
            .find(|(_, value)| value.as_u64() == Some(timebase))
            .map(|(id, value)| (id.clone(), value.clone()))
            .expect("frequency among the registers");
        regs.insert(id.clone(), serde_json::Value::from(timebase + 1));
        let mut edited = blob.clone();
        edited.data = serde_json::to_vec(&text).expect("re-encode");
        let low = id.parse::<u64>().expect("id") as u32;
        assert!(
            matches!(
                cpu.set_state(&edited),
                Err(Error::Partial {
                    op: "KVM_SET_ONE_REG",
                    index
                }) if index == low
            ),
            "refused register not reported"
        );
    }
}
