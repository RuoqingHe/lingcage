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
    /// Other failure, described by a message.
    #[error("{0}")]
    Other(&'static str),
}

pub type Result<T, E = Error> = std::result::Result<T, E>;

/// Hypervisor backend a VM is created on.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
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

/// State captured from a guest, a vCPU, an irqchip or the clock for
/// example, as bytes in the layout of the backend which wrote them,
/// tagged with that backend, the architecture and the layout version.
#[derive(Debug, Clone, PartialEq, Eq)]
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
