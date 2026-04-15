// SPDX-FileCopyrightText: 2026 LingCage <opensource@lingcage.com>
//
// SPDX-License-Identifier: Apache-2.0

//! Guest devices, addressed by register offset. The machine layout
//! places a device in x86 port space or in an MMIO window.

use std::io;
use std::sync::{Arc, Mutex};

use thiserror::Error;

use crate::hv::vcpu::VmExit;

pub mod bus;
pub mod i8042;
pub mod serial;
#[cfg(feature = "virtio")]
pub mod virtio;

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

    /// Handle a write of `size` bytes at `offset`. Returns `Some` for a
    /// write which stops the guest.
    fn write(&mut self, offset: u64, size: u8, value: u64) -> io::Result<Option<VmExit>>;
}

/// Device taking bytes from outside of the guest, console input for
/// example.
pub trait Receive: Send + Sync {
    /// Queue `bytes` for the guest to read.
    fn receive(&self, bytes: &[u8]) -> io::Result<()>;
}

/// Device behind a mutex, which is reached from outside the bus as well
/// as through it. Lock of the bus only covers a device reached through
/// the bus.
pub struct Shared<D>(Arc<Mutex<D>>);

impl<D> Shared<D> {
    /// Wrap `device`, a clone shares it.
    pub fn new(device: D) -> Self {
        Shared(Arc::new(Mutex::new(device)))
    }

    /// Run `f` with the device locked.
    pub fn with<R>(&self, f: impl FnOnce(&mut D) -> R) -> R {
        f(&mut self.0.lock().unwrap())
    }
}

impl<D> Clone for Shared<D> {
    fn clone(&self) -> Self {
        Shared(Arc::clone(&self.0))
    }
}

impl<D: Device> Device for Shared<D> {
    fn read(&mut self, offset: u64, size: u8) -> u64 {
        self.with(|device| device.read(offset, size))
    }

    fn write(&mut self, offset: u64, size: u8, value: u64) -> io::Result<Option<VmExit>> {
        self.with(|device| device.write(offset, size, value))
    }
}
