// SPDX-FileCopyrightText: 2026 LingCage <opensource@lingcage.com>
//
// SPDX-License-Identifier: Apache-2.0

//! Kernel-side MSI injection with an eventfd bound to an MSI through
//! `KVM_IRQFD`.

use std::os::fd::AsFd;

use crate::hv::Result;

/// eventfd bound to an MSI through `KVM_IRQFD`. Writing it injects the
/// interrupt in kernel without involving the VMM. Device writes it
/// through `AsFd`.
pub trait IrqFd: AsFd + Send + Sync {
    /// Set the MSI address.
    fn set_addr(&self, addr: u64) -> Result<()>;

    /// Set the MSI data.
    fn set_data(&self, data: u32) -> Result<()>;

    /// Mask or unmask the interrupt.
    fn set_masked(&self, masked: bool) -> Result<()>;
}
