// SPDX-FileCopyrightText: 2026 LingCage <opensource@lingcage.com>
//
// SPDX-License-Identifier: Apache-2.0

//! KVM backend, one module per trait module of `hv`.

pub mod hypervisor;
pub mod ioeventfd;
pub mod irq;
pub mod memory;
/// The one-register ioctls, shared by the architectures which use them.
#[cfg(any(target_arch = "aarch64", target_arch = "riscv64"))]
mod onereg;
pub mod vcpu;
pub mod vm;

/// Preferred target and the vCPUs initialized from it.
#[cfg(target_arch = "aarch64")]
mod aarch64;
/// One-register access, AIA and riscv64 state blobs.
#[cfg(target_arch = "riscv64")]
mod riscv64;
/// CPUID conversion, MSR batch and x86_64 state blobs.
#[cfg(target_arch = "x86_64")]
mod x86_64;

use crate::hv::Error;

/// Map a `kvm_ioctls::Error`, or the `io::Error` of an eventfd call, to
/// `Error::Os` with operation `op`.
fn kvm_err<E: Into<kvm_ioctls::Error>>(op: &'static str) -> impl Fn(E) -> Error {
    move |err| Error::Os {
        op,
        errno: err.into().errno(),
    }
}
