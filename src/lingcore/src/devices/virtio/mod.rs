// SPDX-FileCopyrightText: 2026 LingCage <opensource@lingcage.com>
//
// SPDX-License-Identifier: Apache-2.0

//! Virtio devices and the virtqueue a driver reaches them by.
//!
//! Ring indices, chain links, buffer addresses and lengths are written by
//! the guest, [`queue`] checks them before a device sees a chain.

use thiserror::Error;

pub mod queue;

use crate::devices::virtio::queue::Queue;
use crate::mem::GuestRam;

/// Errors thrown while reading a virtqueue.
#[derive(Debug, PartialEq, Eq, Error)]
pub enum Error {
    /// Queue size is zero, over 32768 or not a power of two, which are the
    /// limits set by section 2.7 of virtio 1.2.
    #[error("queue size {size} is not supported")]
    BadSize {
        /// Size refused.
        size: u16,
    },
    /// Descriptor index at or beyond the end of the table.
    #[error("descriptor {index} is outside of table with size {size}")]
    BadIndex {
        /// Index in the chain.
        index: u16,
        /// Size of the table.
        size: u16,
    },
    /// Chain with more descriptors than the table holds, which is a loop.
    #[error("chain is longer than its table of size {size}")]
    ChainTooLong {
        /// Size of the table.
        size: u16,
    },
    /// Descriptor with `VIRTQ_DESC_F_INDIRECT` set. Indirect table is not
    /// supported.
    #[error("indirect descriptors are not supported")]
    Indirect,
    /// Buffer outside of guest RAM, or across a hole in it.
    #[error("buffer of {len} bytes at {addr:#x} is not backed")]
    Unbacked {
        /// Guest address of the buffer.
        addr: u64,
        /// Length of the buffer in bytes.
        len: u32,
    },
    /// Ring or descriptor table access outside of guest RAM.
    #[error("ring access at {gpa:#x} is not backed")]
    Ring {
        /// Guest address of the access.
        gpa: u64,
    },
}

/// Result alias for virtqueue access.
pub type Result<T, E = Error> = std::result::Result<T, E>;

/// Device behind a transport, with its kind, its features and the work
/// done when a queue is notified. Transport runs the handshake and checks
/// the chains.
pub trait Device: Send {
    /// Returns the device ID, as numbered in section 5 of virtio 1.2.
    fn device_id(&self) -> u32;

    /// Returns features offered besides `VIRTIO_F_VERSION_1`. Default offers
    /// none.
    fn features(&self) -> u64 {
        0
    }

    /// Returns the number of virtqueues. Default is one.
    fn queue_count(&self) -> u16 {
        1
    }

    /// Returns the largest queue size accepted. Default is 256.
    fn queue_size_max(&self) -> u16 {
        256
    }

    /// Returns a read of `size` bytes at `offset` of configuration space.
    /// Default returns zero.
    fn read_config(&mut self, _offset: u64, _size: u8) -> u64 {
        0
    }

    /// Handle a write of `size` bytes at `offset` of configuration space.
    /// Default drops it.
    fn write_config(&mut self, _offset: u64, _size: u8, _value: u64) {}

    /// Handle a notification on queue `index`. Pop chains from `queue` and
    /// report each of them as used.
    fn notify(&mut self, index: u16, queue: &mut Queue, ram: &GuestRam) -> Result<()>;
}
