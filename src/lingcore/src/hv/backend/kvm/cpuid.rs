// SPDX-FileCopyrightText: 2026 LingCage <opensource@lingcage.com>
//
// SPDX-License-Identifier: Apache-2.0

//! Converting `CpuidEntry` to and from `kvm_cpuid_entry2`.

#![cfg(target_arch = "x86_64")]

use kvm_bindings::{KVM_CPUID_FLAG_SIGNIFCANT_INDEX, kvm_cpuid_entry2};

use crate::hv::arch::CpuidEntry;

/// Map a `kvm_cpuid_entry2` to a `CpuidEntry`. `index` is `Some` only if
/// `KVM_CPUID_FLAG_SIGNIFCANT_INDEX` is set in `flags`.
pub(in crate::hv::backend::kvm) fn from_kvm(entry: &kvm_cpuid_entry2) -> CpuidEntry {
    CpuidEntry {
        function: entry.function,
        index: (entry.flags & KVM_CPUID_FLAG_SIGNIFCANT_INDEX != 0).then_some(entry.index),
        eax: entry.eax,
        ebx: entry.ebx,
        ecx: entry.ecx,
        edx: entry.edx,
    }
}

/// Map a `CpuidEntry` to `kvm_cpuid_entry2`, a `Some` index sets
/// `KVM_CPUID_FLAG_SIGNIFCANT_INDEX`.
pub(in crate::hv::backend::kvm) fn to_kvm(entry: &CpuidEntry) -> kvm_cpuid_entry2 {
    kvm_cpuid_entry2 {
        function: entry.function,
        index: entry.index.unwrap_or(0),
        flags: match entry.index {
            Some(_) => KVM_CPUID_FLAG_SIGNIFCANT_INDEX,
            None => 0,
        },
        eax: entry.eax,
        ebx: entry.ebx,
        ecx: entry.ecx,
        edx: entry.edx,
        ..Default::default()
    }
}
