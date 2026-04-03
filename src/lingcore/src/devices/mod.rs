// SPDX-FileCopyrightText: 2026 LingCage <opensource@lingcage.com>
//
// SPDX-License-Identifier: Apache-2.0

//! Guest devices, addressed by register offset. The machine layout
//! places a device in x86 port space or in an MMIO window.

use thiserror::Error;

pub mod bus;
pub mod serial;

/// Errors thrown while placing a device on the bus.
#[derive(Debug, Error)]
pub enum Error {
    /// Range is empty or runs past the end of address space.
    #[error("no device can be placed in range at {base:#x}")]
    BadRange {
        /// Start of the range.
        base: u64,
    },
    /// Range overlaps with a device already placed.
    #[error("device already placed at {base:#x}")]
    Overlap {
        /// Start of the range.
        base: u64,
    },
}

/// Result alias for placing devices.
pub type Result<T, E = Error> = std::result::Result<T, E>;

/// Device on the bus, addressed by offset from its base. A device is
/// driven by one thread through the run loop, so it is `Send` but not
/// `Sync`.
pub trait Device: Send {
    /// Returns the value of a read of `size` bytes at `offset`.
    fn read(&mut self, offset: u64, size: u8) -> u64;

    /// Handle a write of `size` bytes at `offset`.
    fn write(&mut self, offset: u64, size: u8, value: u64) -> std::io::Result<()>;
}
