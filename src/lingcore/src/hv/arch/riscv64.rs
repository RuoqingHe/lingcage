// SPDX-FileCopyrightText: 2026 LingCage <opensource@lingcage.com>
//
// SPDX-License-Identifier: Apache-2.0

//! riscv64 register ids and placement of the AIA.

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

/// Placement of the AIA, the interrupt controller of a riscv64 guest:
/// the APLIC, the IMSIC file of hart 0 and the wired sources. Hart `n`
/// has its file `n` pages above the one of hart 0.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Aia {
    /// Guest address of APLIC register block, `APLIC_SIZE` bytes.
    pub aplic: u64,
    /// Guest address of IMSIC file of hart 0, `IMSIC_SIZE` bytes.
    pub imsic: u64,
    /// Wired interrupt sources. Sources are numbered from 1 to `sources`.
    pub sources: u32,
    /// Interrupt identities held by each IMSIC file, 63 or one below a
    /// multiple of 64, up to 2047.
    pub ids: u32,
}

/// Bytes of APLIC register block.
pub const APLIC_SIZE: u64 = 0x4000;

/// Bytes of one IMSIC file.
pub const IMSIC_SIZE: u64 = 0x1000;

/// Returns the number of hart index bits in an MSI address for `harts`
/// harts. The count covers the highest hart index, at least one.
pub fn hart_index_bits(harts: u32) -> u32 {
    let highest = harts.saturating_sub(1);
    (u32::BITS - highest.leading_zeros()).max(1)
}

#[cfg(test)]
mod tests {
    use crate::hv::arch::riscv64::*;

    #[test]
    fn test_hart_index_bits() {
        assert_eq!(hart_index_bits(1), 1);
        assert_eq!(hart_index_bits(2), 1);
        assert_eq!(hart_index_bits(3), 2);
        assert_eq!(hart_index_bits(4), 2);
        assert_eq!(hart_index_bits(5), 3);
        assert_eq!(hart_index_bits(16), 4);
        assert_eq!(hart_index_bits(17), 5);
    }
}
