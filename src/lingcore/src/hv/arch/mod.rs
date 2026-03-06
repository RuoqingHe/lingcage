// SPDX-FileCopyrightText: 2026 LingCage <opensource@lingcage.com>
//
// SPDX-License-Identifier: Apache-2.0

//! Register ids of each architecture.
//!
//! The module of host architecture is compiled and re-exported as
//! `arch::*`. Rest of the crate refers to `Reg` and `SReg` through it.

#[cfg(target_arch = "x86_64")]
mod x86_64;
#[cfg(target_arch = "x86_64")]
pub use crate::hv::arch::x86_64::*;
