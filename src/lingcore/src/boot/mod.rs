// SPDX-FileCopyrightText: 2026 LingCage <opensource@lingcage.com>
//
// SPDX-License-Identifier: Apache-2.0

//! Direct boot, the VMM loads kernel image into guest RAM directly, no
//! firmware is needed in the guest.

pub(crate) mod bzimage;
mod mode;

pub use crate::boot::bzimage::*;
