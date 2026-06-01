// SPDX-FileCopyrightText: 2026 LingCage <opensource@lingcage.com>
//
// SPDX-License-Identifier: Apache-2.0

//! Guest clock as a `StateBlob`. The `time` register of a vCPU together
//! with its frequency and the host instant it was read at. KVM keeps
//! one time offset per guest, so reading of any vCPU is the reading of
//! the guest.

use std::os::fd::AsRawFd;
use std::time::{SystemTime, UNIX_EPOCH};

use kvm_bindings::{KVM_REG_RISCV_TIMER, kvm_riscv_timer};

use crate::hv::backend::kvm::riscv64::{get_reg, reg_id, set_reg};
use crate::hv::{Arch, Backend, Error, Result, StateBlob};

/// Layout version of `StateBlob::data`, `decode` refuses other versions.
const STATE_VERSION: u32 = 1;

/// Id of the timer register `field` of `kvm_riscv_timer`.
fn timer(field: usize) -> u64 {
    reg_id(KVM_REG_RISCV_TIMER, (field / size_of::<u64>()) as u64)
}

/// Clock state as captured in a blob. `realtime` is the host clock at
/// capture time in nanoseconds since the epoch.
#[derive(Default, serde::Serialize, serde::Deserialize)]
#[serde(default)]
pub(in crate::hv::backend::kvm) struct ClockState {
    time: u64,
    frequency: u64,
    realtime: u64,
}

/// Returns the host clock in nanoseconds since the epoch.
fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|since| since.as_nanos() as u64)
        .unwrap_or(0)
}

impl ClockState {
    /// Capture the clock of the guest which vCPU `fd` runs in.
    pub(in crate::hv::backend::kvm) fn capture(fd: &impl AsRawFd) -> Result<StateBlob> {
        let state = ClockState {
            time: get_reg(fd, timer(std::mem::offset_of!(kvm_riscv_timer, time)))?,
            frequency: get_reg(fd, timer(std::mem::offset_of!(kvm_riscv_timer, frequency)))?,
            realtime: now(),
        };
        let data = serde_json::to_vec(&state).map_err(|_| Error::Capture { part: "clock" })?;
        Ok(StateBlob {
            backend: Backend::Kvm,
            arch: Arch::Riscv64,
            version: STATE_VERSION,
            data,
        })
    }

    /// Decode `blob`. Blob of another backend, arch or layout version, or
    /// one captured at a timebase other than that of `fd`, is refused.
    fn decode(fd: &impl AsRawFd, blob: &StateBlob) -> Result<Self> {
        if blob.backend != Backend::Kvm || blob.arch != Arch::Riscv64 {
            return Err(Error::Restore { part: "clock" });
        }
        if blob.version != STATE_VERSION {
            return Err(Error::Restore { part: "clock" });
        }
        let state: ClockState =
            serde_json::from_slice(&blob.data).map_err(|_| Error::Restore { part: "clock" })?;
        // Clock restored at another rate would run at another rate.
        let frequency = get_reg(fd, timer(std::mem::offset_of!(kvm_riscv_timer, frequency)))?;
        if state.frequency != frequency {
            return Err(Error::Restore { part: "clock" });
        }
        Ok(state)
    }

    /// Restore the clock to the captured value.
    pub(in crate::hv::backend::kvm) fn restore(fd: &impl AsRawFd, blob: &StateBlob) -> Result<()> {
        let state = ClockState::decode(fd, blob)?;
        set_reg(
            fd,
            timer(std::mem::offset_of!(kvm_riscv_timer, time)),
            state.time,
        )
    }

    /// Restore the clock advanced by the host time elapsed since capture,
    /// forward only. Blob without `realtime` is refused as `Unsupported`.
    pub(in crate::hv::backend::kvm) fn restore_elapsed(
        fd: &impl AsRawFd,
        blob: &StateBlob,
    ) -> Result<()> {
        let state = ClockState::decode(fd, blob)?;
        if state.realtime == 0 {
            return Err(Error::Unsupported("set_clock_elapsed"));
        }
        let elapsed = u128::from(now().saturating_sub(state.realtime));
        let ticks = (elapsed * u128::from(state.frequency) / 1_000_000_000) as u64;
        set_reg(
            fd,
            timer(std::mem::offset_of!(kvm_riscv_timer, time)),
            state.time.wrapping_add(ticks),
        )
    }
}

#[cfg(test)]
mod tests {
    use crate::hv::backend::kvm::hypervisor::KvmHv;
    use crate::hv::hypervisor::Hypervisor;
    use crate::hv::vm::Vm;
    use crate::hv::{Error, StateBlob};

    /// Allowance in ticks for the ioctls between a restore and the read
    /// after it, one second at a 10 MHz timebase.
    const SLACK: u64 = 10_000_000;

    fn reseal(blob: &StateBlob, edit: impl FnOnce(&mut serde_json::Value)) -> StateBlob {
        let mut text: serde_json::Value =
            serde_json::from_slice(&blob.data).expect("decode the blob as JSON");
        edit(&mut text);
        StateBlob {
            data: serde_json::to_vec(&text).expect("re-encode"),
            ..blob.clone()
        }
    }

    fn reading(blob: &StateBlob, field: &str) -> u64 {
        let text: serde_json::Value =
            serde_json::from_slice(&blob.data).expect("decode the blob as JSON");
        text[field].as_u64().expect(field)
    }

    #[test]
    fn test_clock_capture_restore() {
        /// Clock value written by the test, well past the one of a new guest.
        const SEALED: u64 = 1 << 40;
        /// Host time in ns by which `realtime` of the clone is backdated.
        const AWAY: u64 = 10 * 1_000_000_000;

        let hv = KvmHv::new().expect("open /dev/kvm");
        let vm = hv.create_vm().expect("guest");
        // Clock is read through a vCPU, so a guest without vCPU has no
        // clock to report.
        assert!(
            matches!(vm.get_clock(), Err(Error::Unsupported(_))),
            "clock reported with no vCPU behind it"
        );
        let _cpu0 = vm.create_vcpu(0).expect("vcpu 0");
        let blob = vm.get_clock().expect("capture");
        let frequency = reading(&blob, "frequency");
        assert_ne!(frequency, 0, "no timebase");

        let sealed = reseal(&blob, |text| {
            text["time"] = serde_json::Value::from(SEALED);
        });
        vm.set_clock(&sealed).expect("restore");
        let now = reading(&vm.get_clock().expect("capture"), "time");
        assert!(
            (SEALED..SEALED + SLACK).contains(&now),
            "clock read {now} after a restore to {SEALED}"
        );

        // The clone case. `realtime` is backdated by `AWAY`, so the restore
        // adds `AWAY` worth of ticks.
        let taken_at = reading(&blob, "realtime");
        let backdated = reseal(&blob, |text| {
            text["time"] = serde_json::Value::from(SEALED);
            text["realtime"] = serde_json::Value::from(taken_at - AWAY);
        });
        vm.set_clock_elapsed(&backdated).expect("restore");
        let now = reading(&vm.get_clock().expect("capture"), "time");
        let away = AWAY / 1_000_000_000 * frequency;
        assert!(
            (SEALED + away..SEALED + away + SLACK).contains(&now),
            "clock read {now} after a restore to {SEALED} advanced by {away} ticks"
        );

        // Blob from another timebase is refused.
        let foreign = reseal(&blob, |text| {
            text["frequency"] = serde_json::Value::from(frequency + 1);
        });
        assert!(vm.set_clock(&foreign).is_err(), "another timebase accepted");
    }

    #[test]
    fn test_reject_elapsed_without_realtime() {
        let hv = KvmHv::new().expect("open /dev/kvm");
        let vm = hv.create_vm().expect("guest");
        let _cpu0 = vm.create_vcpu(0).expect("vcpu 0");
        let blob = vm.get_clock().expect("capture");

        let blind = reseal(&blob, |text| {
            text["realtime"] = serde_json::Value::from(0);
        });
        assert!(
            matches!(vm.set_clock_elapsed(&blind), Err(Error::Unsupported(_))),
            "clock advanced without realtime"
        );
        vm.set_clock(&blind).expect("restore");
    }
}
