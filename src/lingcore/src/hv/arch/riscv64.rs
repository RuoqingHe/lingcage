// SPDX-FileCopyrightText: 2026 LingCage <opensource@lingcage.com>
//
// SPDX-License-Identifier: Apache-2.0

//! riscv64 register ids.

/// Core registers, `pc`, the 31 general purpose registers and privilege
/// mode, in the order of `kvm_riscv_core`. Each one is a `u64`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Reg {
    /// Program counter.
    Pc,
    /// Return address.
    Ra,
    /// Stack pointer.
    Sp,
    /// Global pointer.
    Gp,
    /// Thread pointer.
    Tp,
    T0,
    T1,
    T2,
    /// Saved register, also the frame pointer.
    S0,
    S1,
    /// First argument, hart id at kernel entry.
    A0,
    /// Second argument, device tree address at kernel entry.
    A1,
    A2,
    A3,
    A4,
    A5,
    A6,
    A7,
    S2,
    S3,
    S4,
    S5,
    S6,
    S7,
    S8,
    S9,
    S10,
    S11,
    T3,
    T4,
    T5,
    T6,
    /// Privilege mode, `MODE_S` or `MODE_U`.
    Mode,
}

/// `Reg::Mode` value for supervisor mode, the mode a kernel is entered
/// with.
pub const MODE_S: u64 = 1;

/// `Reg::Mode` value for user mode.
pub const MODE_U: u64 = 0;

/// Configuration of a vCPU, each one is a `u64`. Values come from the
/// host and become read-only once the vCPU has run. Device tree
/// describes the CPU with them.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ConfigReg {
    /// Single letter extensions as a bitmask, bit 0 for `a`.
    Isa,
    /// `satp.MODE` the guest may set, 8 for Sv39, 9 for Sv48, 10 for Sv57.
    SatpMode,
    /// Ticks of the `time` CSR per second.
    Timebase,
    /// Block size of Zicbom cache operations in bytes. Zero if the extension
    /// is absent.
    CbomBlockSize,
    /// Block size of Zicboz `cbo.zero` in bytes. Zero if the extension is
    /// absent.
    CbozBlockSize,
}
