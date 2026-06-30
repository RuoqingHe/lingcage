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
    /// Open the hypervisor of this host. On glibc host, heap trimming of
    /// the process is disabled, since the trim path opens a `/proc` file
    /// and that syscall is outside the allowlists of confined threads.
    pub fn open() -> Result<Self> {
        keep_heap();
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

/// Disable malloc trim, since heap of a VMM is not returned page by page
/// anyway.
#[cfg(target_env = "gnu")]
fn keep_heap() {
    // SAFETY: no pointer is passed to `mallopt`, only integer arguments.
    unsafe { libc::mallopt(libc::M_TRIM_THRESHOLD, -1) };
}

#[cfg(not(target_env = "gnu"))]
fn keep_heap() {}
