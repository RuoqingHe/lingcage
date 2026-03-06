// SPDX-FileCopyrightText: 2026 LingCage <opensource@lingcage.com>
//
// SPDX-License-Identifier: Apache-2.0

//! The `Vcpu` trait, exit reasons and the entry action for next `run`.

use crate::hv::{Error, Result, StateBlob};

/// Reason a vCPU exited, mapped by the backend from the native exit.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VmExit {
    /// x86 port I/O, `write` is `Some` for OUT and `None` for IN. Other
    /// architectures have no I/O space and report the access as `Mmio`.
    #[cfg(target_arch = "x86_64")]
    Io {
        /// Port accessed.
        port: u16,
        /// Value written, `None` for a read.
        write: Option<u32>,
        /// Access width in bytes.
        size: u8,
    },
    /// MMIO access, `write` is `Some` for a store.
    Mmio {
        /// Guest physical address accessed.
        addr: u64,
        /// Value written, `None` for a load.
        write: Option<u64>,
        /// Access width in bytes.
        size: u8,
    },
    /// Triple fault or power-off requested by the guest.
    Shutdown,
    /// Reset requested by the guest.
    Reboot,
    /// vCPU halted until an interrupt arrives (x86 `HLT`, aarch64 `WFI`).
    /// KVM only reports this to userspace without in-kernel irqchip.
    Halt,
    /// `run` returned on a signal or `hv_vcpus_exit`, re-enter the guest.
    Interrupted,
    /// Paravirtual hypercall.
    Hypercall {
        /// Hypercall number.
        nr: u64,
        /// Hypercall arguments.
        args: [u64; 6],
    },
    /// Breakpoint or single step debug event.
    Debug,
    /// Native exit reason not mapped above, carries the raw value.
    Unknown(u64),
}

/// Action for the next `run`, carrying the value of a pending read.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VmEntry {
    /// Resume the guest.
    Run,
    /// Reset the guest.
    Reboot,
    /// Power the guest off.
    Shutdown,
    /// Complete a pending port IN with `data`.
    #[cfg(target_arch = "x86_64")]
    Io { data: u32 },
    /// Complete a pending MMIO read with `data`.
    Mmio { data: u64 },
}

/// One virtual CPU. It is owned and run by a single thread, so the trait
/// is `Send` but not `Sync`.
pub trait Vcpu: Send {
    /// Run the vCPU until the next exit. Value for a pending `Io` or `Mmio`
    /// read is passed in `entry` on the following call.
    fn run(&mut self, entry: VmEntry) -> Result<VmExit>;

    /// Read one general register.
    #[cfg(target_arch = "x86_64")]
    fn get_reg(&self, reg: crate::hv::arch::Reg) -> Result<u64>;

    /// Set general registers in one batch.
    #[cfg(target_arch = "x86_64")]
    fn set_regs(&mut self, vals: &[(crate::hv::arch::Reg, u64)]) -> Result<()>;

    /// Read a segment register, decoded into `SegRegVal`.
    #[cfg(target_arch = "x86_64")]
    fn get_seg_reg(&self, reg: crate::hv::arch::SegReg) -> Result<crate::hv::arch::SegRegVal>;

    /// Set control and model specific registers in one batch.
    #[cfg(target_arch = "x86_64")]
    fn set_sregs(&mut self, sregs: &[(crate::hv::arch::SReg, u64)]) -> Result<()>;

    /// Capture the vCPU state as a `StateBlob`. Default returns
    /// `Unsupported`.
    fn get_state(&self) -> Result<StateBlob> {
        Err(Error::Unsupported("get_state"))
    }

    /// Restore a blob captured by `get_state` on the same backend and
    /// architecture. Default returns `Unsupported`.
    fn set_state(&mut self, _state: &StateBlob) -> Result<()> {
        Err(Error::Unsupported("set_state"))
    }
}
