// SPDX-FileCopyrightText: 2026 LingCage <opensource@lingcage.com>
//
// SPDX-License-Identifier: Apache-2.0

//! Kernel-side ioeventfds. An eventfd is bound to a guest address
//! through `KVM_IOEVENTFD`.

use crate::hv::Result;

/// eventfd signalled by the kernel on a guest write to the address it
/// is bound to. The write does not exit to VMM.
pub trait IoeventFd: Send + Sync {}

/// Registry of ioeventfds supported by a backend. Without one, an
/// ioeventfd write reaches the device as `VmExit::Mmio`.
pub trait IoeventFdRegistry: Send + Sync {
    /// eventfd type returned by the backend from `create`.
    type IoeventFd: IoeventFd;

    /// Open an eventfd not bound to any address yet.
    fn create(&self) -> Result<Self::IoeventFd>;

    /// Bind `fd` to a guest write of `len` bytes at `gpa`. With `data` set,
    /// only a write of that value signals it.
    fn register(&self, fd: &Self::IoeventFd, gpa: u64, len: u8, data: Option<u64>) -> Result<()>;

    /// Unbind `fd`.
    fn deregister(&self, fd: &Self::IoeventFd) -> Result<()>;
}
