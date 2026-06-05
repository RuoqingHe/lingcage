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
pub mod pm1;
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
    #[error("failed to encode or decode device state")]
    State,
    /// `Blob::kind` is another kind of device.
    #[error("state of {found} device restored into {wanted} device")]
    WrongState {
        /// Kind of device the blob was captured from.
        found: String,
        /// Kind of device restoring it.
        wanted: &'static str,
    },
    /// `Blob::version` is not the layout version this build reads.
    #[error("{kind} device does not support state layout version {version}")]
    WrongVersion {
        /// Kind of the device.
        kind: &'static str,
        /// Layout version the blob was written with.
        version: u32,
    },
    /// `Blob::data` carries a queue count which the device does not have.
    #[error("state with {found} queues restored into device with {wanted} queues")]
    WrongQueues {
        /// Queue count the blob was captured with.
        found: usize,
        /// Queue count the device has.
        wanted: usize,
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

    /// Capture device state as a `Blob`. Default returns `None`, a stateless
    /// device is skipped on restore.
    fn capture(&self) -> Result<Option<Blob>> {
        Ok(None)
    }

    /// Restore a blob returned by `capture` on the same kind of device.
    /// Default returns `WrongState`.
    fn restore(&mut self, blob: &Blob) -> Result<()> {
        Err(Error::WrongState {
            found: blob.kind.clone(),
            wanted: "stateless",
        })
    }

    /// Handle the work left after a `restore`, once all blobs are applied.
    /// Default is a no-op.
    fn restored(&mut self) {}
}

/// State captured from a device, bytes in the layout of the device
/// itself, tagged with device kind and layout version.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct Blob {
    /// Kind of device `data` was captured from.
    pub kind: String,
    /// Layout version of `data`, private to device kind.
    pub version: u32,
    /// State bytes in layout of the device.
    pub data: Vec<u8>,
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

    fn capture(&self) -> Result<Option<Blob>> {
        self.with(|device| device.capture())
    }

    fn restore(&mut self, blob: &Blob) -> Result<()> {
        self.with(|device| device.restore(blob))
    }

    fn restored(&mut self) {
        self.with(|device| device.restored())
    }
}
