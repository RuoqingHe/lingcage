// SPDX-FileCopyrightText: 2026 LingCage <opensource@lingcage.com>
//
// SPDX-License-Identifier: Apache-2.0

//! Hypervisor backends.
//!
//! KVM is the backend implemented by lingcore. `Backend` also names the
//! others so that a VMM built on the crate can select one.

pub mod arch;
pub mod backend;
pub mod hypervisor;
pub mod irq;
pub mod memory;
pub mod os;
pub mod vcpu;
pub mod vm;

use thiserror::Error;

/// Errors thrown by a hypervisor backend.
#[derive(Debug, Error)]
pub enum Error {
    /// Operation not supported by the backend, irqfd on HVF for example.
    #[error("Unsupported by backend: {0}")]
    Unsupported(&'static str),
    /// Register id is not defined for this architecture or backend.
    #[error("Invalid register for this arch/backend")]
    BadRegister,
    /// Hypervisor call failed, with its errno.
    #[error("{op} failed: errno {errno}")]
    Os {
        /// Operation which failed.
        op: &'static str,
        /// Errno of the failed call.
        errno: i32,
    },
    /// Batch call stopped by the backend at entry `index`.
    #[error("{op} stopped at entry {index:#x}")]
    Partial {
        /// Operation which stopped.
        op: &'static str,
        /// Index of the entry refused by the backend.
        index: u32,
    },
    /// KVM API version reported by the kernel, when it is not
    /// `KVM_API_VERSION`.
    #[error("Unsupported KVM API version: {0}")]
    ApiVersion(i32),
    /// Failed to encode state of `part` into a blob.
    #[error("failed to capture {part} state")]
    Capture {
        /// Part of the guest being captured.
        part: &'static str,
    },
    /// Failed to decode blob for `part`, or the blob names another backend,
    /// arch or format version.
    #[error("failed to restore {part} state")]
    Restore {
        /// Part of the guest the blob is for.
        part: &'static str,
    },
    /// No registration at the place named by `at`.
    #[error("no registration {at}")]
    Unregistered {
        /// Place looked up, as named by the caller.
        at: &'static str,
    },
    /// More entries than one call to the host takes.
    #[error("too many {of} in one call")]
    Overfull {
        /// Kind of entry there are too many of.
        of: &'static str,
    },
    /// Console sink refused a write.
    #[error("console sink write failed")]
    Console,
}

pub type Result<T, E = Error> = std::result::Result<T, E>;

/// Hypervisor backend a VM is created on.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum Backend {
    /// KVM on Linux.
    Kvm,
    /// Microsoft Hypervisor on Linux.
    Mshv,
    /// Hypervisor.framework on macOS.
    Hvf,
    /// Windows Hypervisor Platform on Windows.
    Whp,
}

/// Guest CPU architecture.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum Arch {
    /// 64-bit x86.
    X86_64,
    /// 64-bit Arm.
    Aarch64,
    /// 64-bit RISC-V.
    Riscv64,
}

/// Capability a backend may have. Device setup queries it to choose
/// between a kernel fast path and emulation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Cap {
    /// MSI injection from an eventfd through `KVM_IRQFD`.
    IrqFd,
    /// Ioeventfd write consumed in the kernel through `KVM_IOEVENTFD`.
    IoeventFd,
    /// Interrupt controller emulated in the kernel.
    InKernelIrqChip,
    /// Dirty page logging on guest memory.
    DirtyLog,
}

/// Readiness to wait on a descriptor for. Descriptor waited on for a
/// readiness the caller does not act on is reported ready on each wait.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Interest {
    /// Bytes are ready to read.
    Read,
    /// Write would not block.
    Write,
    /// Readable or writable.
    Both,
}

/// State captured from a guest, a vCPU, an irqchip or the clock for
/// example, as bytes in the layout of the backend which wrote them,
/// tagged with that backend, the architecture and the layout version.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct StateBlob {
    /// Backend which captured `data`.
    pub backend: Backend,
    /// Architecture of the guest `data` was captured from.
    pub arch: Arch,
    /// Layout version of `data`, private to the backend.
    pub version: u32,
    /// State bytes in layout of the backend.
    pub data: Vec<u8>,
}
