// SPDX-FileCopyrightText: 2026 LingCage <opensource@lingcage.com>
//
// SPDX-License-Identifier: Apache-2.0

//! Backend implementations, one per hypervisor.

#[cfg(all(feature = "kvm", target_os = "linux"))]
pub mod kvm;
