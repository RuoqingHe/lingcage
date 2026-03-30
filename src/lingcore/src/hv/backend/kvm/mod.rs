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

/// Serialized guest clock state, private to this backend.
mod clock;
/// `CpuidEntry` to and from `kvm_cpuid_entry2`, private to this backend.
mod cpuid;
/// Serialized interrupt controller state, private to this backend.
mod irqchip;
/// Serialized vCPU state, private to this backend.
mod state;

use crate::hv::Error;

/// Map a `kvm_ioctls::Error`, or the `io::Error` of an eventfd call, to
/// `Error::Os` with operation `op`.
fn kvm_err<E: Into<kvm_ioctls::Error>>(op: &'static str) -> impl Fn(E) -> Error {
    move |err| Error::Os {
        op,
        errno: err.into().errno(),
    }
}
