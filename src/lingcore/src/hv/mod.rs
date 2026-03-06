// SPDX-FileCopyrightText: 2026 LingCage <opensource@lingcage.com>
//
// SPDX-License-Identifier: Apache-2.0

//! Hypervisor backends.
//!
//! KVM is the backend implemented by lingcore. `Backend` also names the
//! others so that a VMM built on the crate can select one.

pub mod arch;

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
    /// Hypervisor call failed with this errno.
    #[error("Hypervisor call failed: errno {0}")]
    Os(i32),
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
    /// Placeholder backend for tests.
    Stub,
}

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
    /// Debug event, breakpoint or single step.
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
