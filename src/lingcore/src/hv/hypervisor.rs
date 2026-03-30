// SPDX-FileCopyrightText: 2026 LingCage <opensource@lingcage.com>
//
// SPDX-License-Identifier: Apache-2.0

//! Opened hypervisor handle.

#[cfg(target_arch = "x86_64")]
use crate::hv::arch::CpuidEntry;
#[cfg(all(feature = "kvm", target_os = "linux"))]
use crate::hv::backend::kvm::hypervisor::KvmHv;
use crate::hv::vm::Vm;
use crate::hv::{Backend, Error, Result};

/// Opened hypervisor, `/dev/kvm` for example, opened once per process.
pub trait Hypervisor {
    /// VM type of the backend.
    type Vm: Vm;

    /// Create a VM without vCPU, memory or device yet.
    fn create_vm(&self) -> Result<Self::Vm>;

    /// Returns CPUID leaves the hypervisor supports for a guest. The list
    /// a vCPU takes through `Vcpu::set_cpuid` is drawn from it.
    #[cfg(target_arch = "x86_64")]
    fn supported_cpuid(&self) -> Result<Vec<CpuidEntry>>;
}

/// Opened hypervisor of a backend. Variants carried by a build depend on
/// its features and host, so the enum is `non_exhaustive`.
#[non_exhaustive]
pub enum AnyHv {
    /// KVM on Linux.
    #[cfg(all(feature = "kvm", target_os = "linux"))]
    Kvm(KvmHv),
}

/// Open `backend`. KVM is the only backend implemented. The others, and
/// KVM in a build without it, return `Unsupported` naming the backend.
pub fn open(backend: Backend) -> Result<AnyHv> {
    match backend {
        #[cfg(all(feature = "kvm", target_os = "linux"))]
        Backend::Kvm => Ok(AnyHv::Kvm(KvmHv::new()?)),
        #[cfg(not(all(feature = "kvm", target_os = "linux")))]
        Backend::Kvm => Err(Error::Unsupported("kvm")),
        Backend::Mshv => Err(Error::Unsupported("mshv")),
        Backend::Hvf => Err(Error::Unsupported("hvf")),
        Backend::Whp => Err(Error::Unsupported("whp")),
    }
}

#[cfg(test)]
mod tests {
    use crate::hv::hypervisor::*;

    #[cfg(all(feature = "kvm", target_os = "linux"))]
    #[test]
    fn test_open_kvm_backend() {
        match open(Backend::Kvm).expect("/dev/kvm") {
            AnyHv::Kvm(hv) => {
                hv.create_vm().expect("KVM_CREATE_VM");
            }
        }
    }

    #[test]
    fn test_reject_backend_not_built() {
        assert!(matches!(
            open(Backend::Mshv),
            Err(Error::Unsupported("mshv"))
        ));
    }
}
