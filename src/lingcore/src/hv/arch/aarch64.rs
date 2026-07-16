// SPDX-FileCopyrightText: 2026 LingCage <opensource@lingcage.com>
//
// SPDX-License-Identifier: Apache-2.0

//! aarch64 register ids and placement of the GIC.

/// Core registers, the 31 general purpose registers, the stack pointer,
/// the program counter and the processor state, in the order of
/// `struct user_pt_regs`. Each one is a `u64`, so the field at index `n`
/// starts at byte `8 * n`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Reg {
    /// First argument, device tree address at kernel entry.
    X0,
    X1,
    X2,
    X3,
    X4,
    X5,
    X6,
    X7,
    X8,
    X9,
    X10,
    X11,
    X12,
    X13,
    X14,
    X15,
    X16,
    X17,
    X18,
    X19,
    X20,
    X21,
    X22,
    X23,
    X24,
    X25,
    X26,
    X27,
    X28,
    /// Frame pointer.
    X29,
    /// Link register.
    X30,
    /// Stack pointer of the entered exception level.
    Sp,
    /// Program counter.
    Pc,
    /// Processor state, `PSTATE_EL1H` at kernel entry.
    Pstate,
}

/// `Reg::Pstate` value for EL1h with debug, abort, IRQ and FIQ masked,
/// the state a kernel is entered in, `PSR_MODE_EL1h` with the four
/// masks of `arch/arm64/include/uapi/asm/ptrace.h`.
pub const PSTATE_EL1H: u64 = 0x3c5;

/// Placement of the GIC, the interrupt controller of an aarch64 guest:
/// the distributor, the redistributor of vCPU 0 and the wired sources.
/// vCPU `n` has its redistributor `n` frames above the one of vCPU 0.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Gic {
    /// Guest address of distributor register block, `DIST_SIZE` bytes.
    pub dist: u64,
    /// Guest address of redistributor frame of vCPU 0.
    pub redist: u64,
    /// Wired interrupt sources, the SPIs. Sources are numbered from 0.
    pub sources: u32,
}

/// Bytes of the distributor register block.
pub const DIST_SIZE: u64 = 0x1_0000;

/// Bytes of the redistributor frame of one vCPU, the RD and SGI pages.
pub const REDIST_SIZE: u64 = 0x2_0000;

/// Interrupt ids taken by the private sources of a vCPU, the SGIs and
/// the PPIs. SPI `n` is interrupt id `PRIVATE_IDS + n`.
pub const PRIVATE_IDS: u32 = 32;

/// Returns bytes taken by the redistributor frames of `vcpus`.
pub fn redist_room(vcpus: u16) -> u64 {
    REDIST_SIZE * u64::from(vcpus)
}

#[cfg(test)]
mod tests {
    use crate::hv::arch::aarch64::*;

    #[test]
    fn test_reg_index_of_user_pt_regs() {
        // Fields are `u64` and contiguous, so the byte offset of each is
        // eight times its position in the struct.
        assert_eq!(Reg::X0 as u64, 0);
        assert_eq!(Reg::X30 as u64, 30);
        assert_eq!(Reg::Sp as u64, 31);
        assert_eq!(Reg::Pc as u64, 32);
        assert_eq!(Reg::Pstate as u64, 33);
    }

    #[test]
    fn test_redist_room() {
        assert_eq!(redist_room(1), REDIST_SIZE);
        assert_eq!(redist_room(4), 4 * REDIST_SIZE);
    }
}
