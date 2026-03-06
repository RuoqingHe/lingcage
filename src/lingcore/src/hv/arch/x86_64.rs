// SPDX-FileCopyrightText: 2026 LingCage <opensource@lingcage.com>
//
// SPDX-License-Identifier: Apache-2.0

//! x86_64 register ids.
//!
//! The ids are backend neutral, KVM maps them to `kvm_regs` and
//! `kvm_sregs`.

/// General purpose registers plus `RIP` and `RFLAGS`, each one is a
/// `u64`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Reg {
    /// Accumulator.
    Rax,
    /// Base.
    Rbx,
    /// Counter.
    Rcx,
    /// Data.
    Rdx,
    /// Source index.
    Rsi,
    /// Destination index.
    Rdi,
    /// Stack pointer.
    Rsp,
    /// Base pointer.
    Rbp,
    R8,
    R9,
    R10,
    R11,
    R12,
    R13,
    R14,
    R15,
    /// Instruction pointer.
    Rip,
    /// Status and control flags.
    Rflags,
}

/// Control and model specific registers, each one is a `u64`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SReg {
    /// Protected mode, paging and FPU control bits.
    Cr0,
    /// Page-fault linear address.
    Cr2,
    /// Top level page table address and PCID.
    Cr3,
    /// Paging and protection feature enables.
    Cr4,
    /// Task priority.
    Cr8,
    /// Extended feature enables, long mode, `SYSCALL` and NX.
    Efer,
    /// Local APIC base address and mode bits.
    ApicBase,
}

/// Segment registers, value is a `SegRegVal`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SegReg {
    /// Code segment.
    Cs,
    /// Data segment.
    Ds,
    /// Extra segment.
    Es,
    /// Extra segment.
    Fs,
    /// Extra segment, `SWAPGS` swaps its base.
    Gs,
    /// Stack segment.
    Ss,
    /// Task register.
    Tr,
    /// Local descriptor table register.
    Ldtr,
}

/// Descriptor table registers, value is a `DtRegVal`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DtReg {
    /// Global descriptor table.
    Gdt,
    /// Interrupt descriptor table.
    Idt,
}

/// Decoded segment register.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct SegRegVal {
    /// Linear base address.
    pub base: u64,
    /// Limit, in bytes or in pages according to the granularity bit.
    pub limit: u32,
    pub selector: u16,
    /// Packed access rights.
    pub attr: u16,
}

/// Decoded descriptor table register.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct DtRegVal {
    /// Linear base address.
    pub base: u64,
    /// Table length in bytes, minus one.
    pub limit: u16,
}
