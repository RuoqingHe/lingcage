// SPDX-FileCopyrightText: 2026 LingCage <opensource@lingcage.com>
//
// SPDX-License-Identifier: Apache-2.0

//! Interrupt injection.

#[cfg(target_os = "linux")]
use crate::hv::Error;
use crate::hv::Result;

/// Sender for a legacy line. Trigger mode is set on the irqchip and the
/// routing instead of per send.
pub trait IrqSender: Send + Sync {
    /// Deliver one interrupt on the line.
    fn send(&self) -> Result<()>;
}

/// Sender for message signalled interrupts.
pub trait MsiSender: Send + Sync {
    /// eventfd type returned by the backend from `create_irqfd`.
    #[cfg(target_os = "linux")]
    type IrqFd: IrqFd;

    /// Inject an MSI from the calling thread.
    fn send(&self, addr: u64, data: u32) -> Result<()>;

    /// Open an eventfd for the kernel to inject from. Default returns
    /// `Unsupported`.
    #[cfg(target_os = "linux")]
    fn create_irqfd(&self) -> Result<Self::IrqFd> {
        Err(Error::Unsupported("create_irqfd"))
    }
}

/// eventfd bound to an MSI through `KVM_IRQFD`. Writing it injects the
/// interrupt in kernel without involving the VMM.
#[cfg(target_os = "linux")]
pub trait IrqFd: Send + Sync {
    /// Set the MSI address.
    fn set_addr(&self, addr: u64) -> Result<()>;

    /// Set the MSI data.
    fn set_data(&self, data: u32) -> Result<()>;

    /// Mask or unmask the interrupt.
    fn set_masked(&self, masked: bool) -> Result<()>;
}
