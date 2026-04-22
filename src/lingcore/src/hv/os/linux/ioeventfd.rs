// SPDX-FileCopyrightText: 2026 LingCage <opensource@lingcage.com>
//
// SPDX-License-Identifier: Apache-2.0

//! Kernel-side ioeventfds. An eventfd is bound to a guest address
//! through `KVM_IOEVENTFD`.

use std::time::Duration;

use crate::hv::Result;

/// eventfd signalled by the kernel on a guest write to the address it
/// is bound to. The write does not exit to VMM.
pub trait IoeventFd: Send + Sync {
    /// Wait at most `within` for a signal. Returns the accumulated count
    /// cleared by the read, or `None` once `within` elapses.
    fn wait(&self, within: Duration) -> Result<Option<u64>>;

    /// Signal the eventfd from VMM side, a `wait` on it returns.
    fn signal(&self) -> Result<()>;
}

/// Registry of ioeventfds supported by a backend. Without one, an
/// ioeventfd write reaches the device as `VmExit::Mmio`.
pub trait IoeventFdRegistry: Send + Sync {
    /// eventfd type returned by the backend from `create`.
    type IoeventFd: IoeventFd;

    /// Open an eventfd not bound to any address yet.
    fn create(&self) -> Result<Self::IoeventFd>;

    /// Bind `fd` to a guest write at `gpa`. With `data` set, only a write
    /// of `len` bytes carrying that value signals it, otherwise a write of
    /// any width does.
    fn register(&self, fd: &Self::IoeventFd, gpa: u64, len: u8, data: Option<u64>) -> Result<()>;

    /// Unbind `fd`.
    fn deregister(&self, fd: &Self::IoeventFd) -> Result<()>;
}
