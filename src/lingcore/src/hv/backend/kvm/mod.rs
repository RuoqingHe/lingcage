// SPDX-FileCopyrightText: 2026 LingCage <opensource@lingcage.com>
//
// SPDX-License-Identifier: Apache-2.0

//! KVM backend.

use kvm_bindings::KVM_API_VERSION;
use kvm_ioctls::{Kvm, VmFd};

use crate::hv::{Error, Result};

/// Map a `kvm_ioctls::Error` to `Error::Os` with operation `op`.
fn kvm_err(op: &'static str) -> impl Fn(kvm_ioctls::Error) -> Error {
    move |err| Error::Os {
        op,
        errno: err.errno(),
    }
}

/// Opened `/dev/kvm` handle.
pub struct KvmHv {
    kvm: Kvm,
}

impl KvmHv {
    /// Open `/dev/kvm`, refuse a kernel whose `KVM_GET_API_VERSION` is not
    /// `KVM_API_VERSION`.
    pub fn new() -> Result<Self> {
        let kvm = Kvm::new().map_err(kvm_err("open /dev/kvm"))?;
        // `get_api_version` returns the raw ioctl result, negative value
        // means failure with errno set.
        let version = kvm.get_api_version();
        if version < 0 {
            return Err(Error::Os {
                op: "KVM_GET_API_VERSION",
                errno: kvm_ioctls::Error::last().errno(),
            });
        }
        if version != KVM_API_VERSION as i32 {
            return Err(Error::ApiVersion(version));
        }
        Ok(KvmHv { kvm })
    }

    /// Create a guest through `KVM_CREATE_VM`, without vCPU or memory.
    pub fn create_vm(&self) -> Result<KvmVm> {
        let fd = self.kvm.create_vm().map_err(kvm_err("KVM_CREATE_VM"))?;
        Ok(KvmVm { fd })
    }
}

/// Guest handle, the VM fd returned by `KVM_CREATE_VM`.
pub struct KvmVm {
    // TODO: drop the attribute once vCPU or memory setup uses the fd.
    #[cfg_attr(not(test), expect(dead_code, reason = "only the test reads the fd"))]
    fd: VmFd,
}

#[cfg(test)]
mod tests {
    use std::os::fd::AsRawFd;

    use crate::hv::backend::kvm::*;

    #[test]
    fn test_open_kvm() {
        KvmHv::new().expect("/dev/kvm at the expected KVM API version");
    }

    #[test]
    fn test_create_guests() {
        let hv = KvmHv::new().expect("open /dev/kvm");
        let one = hv.create_vm().expect("first guest");
        let two = hv.create_vm().expect("second guest");
        assert_ne!(one.fd.as_raw_fd(), two.fd.as_raw_fd());
    }
}
