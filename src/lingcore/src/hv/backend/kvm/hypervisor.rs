// SPDX-FileCopyrightText: 2026 LingCage <opensource@lingcage.com>
//
// SPDX-License-Identifier: Apache-2.0

//! The `KvmHv` handle, which opens `/dev/kvm` and creates guests.

#[cfg(target_arch = "x86_64")]
use std::sync::Arc;

use kvm_bindings::KVM_API_VERSION;
#[cfg(target_arch = "x86_64")]
use kvm_bindings::KVM_MAX_CPUID_ENTRIES;
use kvm_ioctls::Kvm;

#[cfg(target_arch = "x86_64")]
use crate::hv::arch::CpuidEntry;
#[cfg(target_arch = "x86_64")]
use crate::hv::backend::kvm::cpuid::from_kvm;
use crate::hv::backend::kvm::kvm_err;
use crate::hv::backend::kvm::vm::KvmVm;
use crate::hv::hypervisor::Hypervisor;
use crate::hv::{Error, Result};

/// Opened `/dev/kvm` handle.
pub struct KvmHv {
    kvm: Kvm,
    /// MSR indices from `KVM_GET_MSR_INDEX_LIST`, only read once per open.
    #[cfg(target_arch = "x86_64")]
    msrs: Arc<[u32]>,
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
        #[cfg(target_arch = "x86_64")]
        let msrs = kvm
            .get_msr_index_list()
            .map_err(kvm_err("KVM_GET_MSR_INDEX_LIST"))?
            .as_slice()
            .into();
        Ok(KvmHv {
            kvm,
            #[cfg(target_arch = "x86_64")]
            msrs,
        })
    }
}

impl Hypervisor for KvmHv {
    type Vm = KvmVm;

    #[cfg(target_arch = "x86_64")]
    fn supported_cpuid(&self) -> Result<Vec<CpuidEntry>> {
        let cpuid = self
            .kvm
            .get_supported_cpuid(KVM_MAX_CPUID_ENTRIES)
            .map_err(kvm_err("KVM_GET_SUPPORTED_CPUID"))?;
        Ok(cpuid.as_slice().iter().map(from_kvm).collect())
    }

    fn create_vm(&self) -> Result<KvmVm> {
        let fd = self.kvm.create_vm().map_err(kvm_err("KVM_CREATE_VM"))?;
        Ok(KvmVm::new(
            fd,
            #[cfg(target_arch = "x86_64")]
            Arc::clone(&self.msrs),
        ))
    }
}

#[cfg(test)]
mod tests {
    use crate::hv::backend::kvm::hypervisor::*;

    #[test]
    fn test_open_kvm() {
        KvmHv::new().expect("/dev/kvm at the expected KVM API version");
    }
}
