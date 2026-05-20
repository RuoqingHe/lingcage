// SPDX-FileCopyrightText: 2026 LingCage <opensource@lingcage.com>
//
// SPDX-License-Identifier: Apache-2.0

//! KVM backend, one module per trait module of `hv`.

pub mod hypervisor;
pub mod ioeventfd;
pub mod irq;
pub mod memory;
pub mod vcpu;
pub mod vm;

/// One-register access and riscv64 vCPU registers.
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
