// SPDX-FileCopyrightText: 2026 LingCage <opensource@lingcage.com>
//
// SPDX-License-Identifier: Apache-2.0

//! Interrupt injection.

use crate::hv::Result;

/// Sender for a legacy line. Trigger mode is set on the irqchip and the
/// routing instead of per send.
pub trait IrqSender: Send + Sync {
    /// Deliver one interrupt on the line.
    fn send(&self) -> Result<()>;
}

/// Sender for message signalled interrupts.
pub trait MsiSender: Send + Sync {
    /// Inject an MSI from the calling thread.
    fn send(&self, addr: u64, data: u32) -> Result<()>;
}
