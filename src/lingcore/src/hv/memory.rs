// SPDX-FileCopyrightText: 2026 LingCage <opensource@lingcage.com>
//
// SPDX-License-Identifier: Apache-2.0

//! Guest physical address space.

use crate::hv::Result;

/// Permission and dirty tracking flags of one guest mapping.
#[derive(Debug, Clone, Copy)]
pub struct MemMapOption {
    /// Guest reads are allowed.
    pub read: bool,
    /// Guest writes are allowed.
    pub write: bool,
    /// Guest execution is allowed.
    pub exec: bool,
    /// Record pages written by the guest. Backend without the capability
    /// returns `Unsupported`.
    pub log_dirty: bool,
}

impl Default for MemMapOption {
    /// Readable, writable and executable, dirty tracking off.
    fn default() -> Self {
        MemMapOption {
            read: true,
            write: true,
            exec: true,
            log_dirty: false,
        }
    }
}

/// Guest physical address space, which maps host virtual ranges at guest
/// physical addresses. Shared by threads of the VM, so it is `Send` and
/// `Sync`.
pub trait VmMemory: Send + Sync {
    /// Map `size` bytes of host memory at `hva` into the guest at `gpa`.
    fn mem_map(&self, gpa: u64, size: u64, hva: usize, opt: MemMapOption) -> Result<()>;

    /// Unmap the region mapped at `gpa`.
    fn unmap(&self, gpa: u64, size: u64) -> Result<()>;
}
