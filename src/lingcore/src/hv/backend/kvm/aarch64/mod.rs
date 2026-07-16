// SPDX-FileCopyrightText: 2026 LingCage <opensource@lingcage.com>
//
// SPDX-License-Identifier: Apache-2.0

//! KVM backend parts of an aarch64 guest. The `cfg` is on the
//! declaration in `kvm/mod.rs`.

/// Preferred target of the host and the vCPUs initialized from it.
pub(in crate::hv::backend::kvm) mod vm;
