// SPDX-FileCopyrightText: 2026 LingCage <opensource@lingcage.com>
//
// SPDX-License-Identifier: Apache-2.0

//! Hypervisor backends.
//!
//! KVM is the backend implemented by lingcore. `Backend` also names the
//! others so that a VMM built on the crate can select one.

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
