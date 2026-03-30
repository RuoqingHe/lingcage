// SPDX-FileCopyrightText: 2026 LingCage <opensource@lingcage.com>
//
// SPDX-License-Identifier: Apache-2.0

//! KVM backend parts of an x86_64 guest. CPUID conversion, the MSR
//! batch, and vCPU, irqchip and clock state blobs. The `cfg` is on the
//! declaration in `kvm/mod.rs` instead of in each file.

/// Serialized guest clock state.
pub(in crate::hv::backend::kvm) mod clock;
/// `CpuidEntry` to and from `kvm_cpuid_entry2`.
pub(in crate::hv::backend::kvm) mod cpuid;
/// Serialized interrupt controller state.
pub(in crate::hv::backend::kvm) mod irqchip;
/// Serialized vCPU state.
pub(in crate::hv::backend::kvm) mod state;

/// Largest batch accepted by `KVM_GET_MSRS` and `KVM_SET_MSRS`, the
/// kernel refuses `nmsrs` of `MAX_IO_MSRS` (256) or more.
pub(in crate::hv::backend::kvm) const MSR_BATCH: usize = 255;
