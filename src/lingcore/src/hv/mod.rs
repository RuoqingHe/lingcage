// SPDX-FileCopyrightText: 2026 LingCage <opensource@lingcage.com>
//
// SPDX-License-Identifier: Apache-2.0

//! Hypervisor backends.
//!
//! KVM is the backend implemented by lingcore. `Backend` also names the
//! others so that a VMM built on the crate can select one.

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
