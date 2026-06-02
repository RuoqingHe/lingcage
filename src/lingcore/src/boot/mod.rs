// SPDX-FileCopyrightText: 2026 LingCage <opensource@lingcage.com>
//
// SPDX-License-Identifier: Apache-2.0

//! Direct boot, the VMM loads kernel image into guest RAM directly
//! without firmware. x86_64 takes a bzImage while riscv64 takes an
//! Image.

#[cfg(target_arch = "x86_64")]
pub(crate) mod bzimage;
#[cfg(target_arch = "riscv64")]
pub(crate) mod image;
#[cfg(target_arch = "x86_64")]
mod mode;

#[cfg(target_arch = "x86_64")]
pub use crate::boot::bzimage::*;
#[cfg(target_arch = "riscv64")]
pub use crate::boot::image::*;
