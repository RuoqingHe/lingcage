// SPDX-FileCopyrightText: 2026 LingCage <opensource@lingcage.com>
//
// SPDX-License-Identifier: Apache-2.0

//! Guest clock as a `StateBlob`, `kvm_clock_data` from `KVM_GET_CLOCK`
//! plus the host instant it was read at.

#![cfg(target_arch = "x86_64")]

use kvm_bindings::{KVM_CLOCK_REALTIME, kvm_clock_data};
use kvm_ioctls::VmFd;

use crate::hv::backend::kvm::kvm_err;
use crate::hv::{Arch, Backend, Error, Result, StateBlob};

/// Layout version of `StateBlob::data`, `decode` refuses other versions.
const STATE_VERSION: u32 = 1;

/// Clock state as captured in a blob, fields are the ones of
/// `kvm_clock_data`. `realtime` is the host clock at capture time, KVM
/// only reports it (with `KVM_CLOCK_REALTIME` set in `flags`) while its
/// master clock runs.
#[derive(Default, serde::Serialize, serde::Deserialize)]
#[serde(default)]
pub(in crate::hv::backend::kvm) struct ClockState {
    clock: u64,
    flags: u32,
    realtime: u64,
    host_tsc: u64,
}

impl ClockState {
    /// Capture the clock of the guest behind `fd` as a `StateBlob`.
    pub(in crate::hv::backend::kvm) fn capture(fd: &VmFd) -> Result<StateBlob> {
        let clock = fd.get_clock().map_err(kvm_err("KVM_GET_CLOCK"))?;
        let state = ClockState {
            clock: clock.clock,
            flags: clock.flags,
            realtime: clock.realtime,
            host_tsc: clock.host_tsc,
        };
        let data =
            serde_json::to_vec(&state).map_err(|_| Error::Other("failed to encode clock state"))?;
        Ok(StateBlob {
            backend: Backend::Kvm,
            arch: Arch::X86_64,
            version: STATE_VERSION,
            data,
        })
    }

    /// Decode `blob`. Blob of another backend, arch or layout version is
    /// refused.
    fn decode(blob: &StateBlob) -> Result<Self> {
        if blob.backend != Backend::Kvm || blob.arch != Arch::X86_64 {
            return Err(Error::Other("state blob from another backend or arch"));
        }
        if blob.version != STATE_VERSION {
            return Err(Error::Other("state blob version not supported"));
        }
        serde_json::from_slice(&blob.data).map_err(|_| Error::Other("failed to decode clock state"))
    }

    /// Restore the clock behind `fd` to the captured value. `flags` is zero,
    /// so `KVM_SET_CLOCK` writes the value as is.
    pub(in crate::hv::backend::kvm) fn restore(fd: &VmFd, blob: &StateBlob) -> Result<()> {
        let state = ClockState::decode(blob)?;
        let clock = kvm_clock_data {
            clock: state.clock,
            flags: 0,
            ..Default::default()
        };
        fd.set_clock(&clock).map_err(kvm_err("KVM_SET_CLOCK"))
    }

    /// Restore the clock behind `fd`, advanced by the host time elapsed
    /// since the capture. With `KVM_CLOCK_REALTIME` set, `KVM_SET_CLOCK`
    /// adds the difference between `realtime` and the host clock at ioctl
    /// time, forward only. Blob without `realtime` is refused as
    /// `Unsupported`, since a difference measured from zero would advance
    /// the clock by the age of the epoch.
    pub(in crate::hv::backend::kvm) fn restore_elapsed(fd: &VmFd, blob: &StateBlob) -> Result<()> {
        let state = ClockState::decode(blob)?;
        if state.flags & KVM_CLOCK_REALTIME == 0 || state.realtime == 0 {
            return Err(Error::Unsupported("set_clock_elapsed"));
        }
        let clock = kvm_clock_data {
            clock: state.clock,
            flags: KVM_CLOCK_REALTIME,
            realtime: state.realtime,
            ..Default::default()
        };
        fd.set_clock(&clock).map_err(kvm_err("KVM_SET_CLOCK"))
    }
}

#[cfg(test)]
mod tests {
    use std::time::{SystemTime, UNIX_EPOCH};

    use kvm_bindings::KVM_CLOCK_REALTIME;

    use crate::hv::backend::kvm::hypervisor::KvmHv;
    use crate::hv::hypervisor::Hypervisor;
    use crate::hv::vm::Vm;
    use crate::hv::{Error, StateBlob};

    /// Allowance in ns for the ioctls between a restore and the read after
    /// it.
    const SLACK: u64 = 1_000_000_000;

    fn reseal(blob: &StateBlob, edit: impl FnOnce(&mut serde_json::Value)) -> StateBlob {
        let mut text: serde_json::Value =
            serde_json::from_slice(&blob.data).expect("decode the blob as JSON");
        edit(&mut text);
        StateBlob {
            data: serde_json::to_vec(&text).expect("re-encode"),
            ..blob.clone()
        }
    }

    fn reading(blob: &StateBlob) -> u64 {
        let text: serde_json::Value =
            serde_json::from_slice(&blob.data).expect("decode the blob as JSON");
        text["clock"].as_u64().expect("clock")
    }

    #[test]
    fn test_clock_capture_restore() {
        /// Clock value written by the test, well past the one of a new guest.
        const SEALED: u64 = 42 * 1_000_000_000;
        /// Host time in ns by which `realtime` of the clone is backdated.
        const AWAY: u64 = 10 * 1_000_000_000;

        let hv = KvmHv::new().expect("open /dev/kvm");
        let vm = hv.create_vm().expect("guest");
        let blob = vm.get_clock().expect("capture");

        let sealed = reseal(&blob, |text| {
            text["clock"] = serde_json::Value::from(SEALED);
        });
        vm.set_clock(&sealed).expect("restore");
        let now = reading(&vm.get_clock().expect("capture"));
        assert!(
            (SEALED..SEALED + SLACK).contains(&now),
            "clock read {now} after a restore to {SEALED}"
        );

        // The clone case. `realtime` is backdated by `AWAY`, so KVM adds
        // `AWAY` at restore. The field is written instead of captured, since a
        // host on paravirtualised clock has no master clock to report it.
        let taken_at = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("host time since the epoch")
            .as_nanos() as u64;
        let backdated = reseal(&blob, |text| {
            text["clock"] = serde_json::Value::from(SEALED);
            text["flags"] = serde_json::Value::from(KVM_CLOCK_REALTIME);
            text["realtime"] = serde_json::Value::from(taken_at - AWAY);
        });
        vm.set_clock_elapsed(&backdated).expect("restore");
        let now = reading(&vm.get_clock().expect("capture"));
        assert!(
            (SEALED + AWAY..SEALED + AWAY + SLACK).contains(&now),
            "clock read {now} after a restore to {SEALED} advanced by {AWAY} ns"
        );
    }

    #[test]
    fn test_reject_elapsed_without_realtime() {
        let hv = KvmHv::new().expect("open /dev/kvm");
        let vm = hv.create_vm().expect("guest");
        let blob = vm.get_clock().expect("capture");

        // Blob without `realtime`, as captured by a host without master clock.
        let blind = reseal(&blob, |text| {
            text["flags"] = serde_json::Value::from(0);
            text["realtime"] = serde_json::Value::from(0);
        });
        assert!(
            matches!(vm.set_clock_elapsed(&blind), Err(Error::Unsupported(_))),
            "clock advanced without realtime"
        );
        vm.set_clock(&blind).expect("restore");
    }
}
