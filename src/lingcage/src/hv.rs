// SPDX-FileCopyrightText: 2026 LingCage <opensource@lingcage.com>
//
// SPDX-License-Identifier: Apache-2.0

//! Hypervisor handle, opened once per process.

use crate::error::Result;

/// Returns next vsock context id for a guest from a process-wide counter,
/// unique within the process only. Two LingCage processes on one host can
/// collide, so a host-wide allocator has to take it over.
pub(crate) fn next_cid() -> u64 {
    static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(3);
    NEXT.fetch_add(1, std::sync::atomic::Ordering::SeqCst)
}

/// Hypervisor of this host, which is opened once per process.
pub struct Hv(lingcore::hv::backend::kvm::hypervisor::KvmHv);

impl Hv {
    /// Open the hypervisor of this host.
    pub fn open() -> Result<Self> {
        let hv = lingcore::hv::backend::kvm::hypervisor::KvmHv::new()
            .map_err(lingcore::machine::Error::from)
            .map_err(crate::error::Error::Lingcore)?;
        Ok(Hv(hv))
    }

    /// Returns the `lingcore` handle used to assemble sandboxes.
    pub(crate) fn core(&self) -> &lingcore::hv::backend::kvm::hypervisor::KvmHv {
        &self.0
    }
}
