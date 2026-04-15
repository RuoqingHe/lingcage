// SPDX-FileCopyrightText: 2026 LingCage <opensource@lingcage.com>
//
// SPDX-License-Identifier: Apache-2.0

//! Virtio devices and the virtqueue a driver reaches them by.
//!
//! Ring indices, chain links, buffer addresses and lengths are written by
//! the guest, [`queue`] checks them before a device sees a chain.

use thiserror::Error;

pub mod queue;

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
