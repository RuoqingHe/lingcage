// SPDX-FileCopyrightText: 2026 LingCage <opensource@lingcage.com>
//
// SPDX-License-Identifier: Apache-2.0

//! VMM built on top of `lingcore`. `lcp` is the guest protocol shared
//! between host and guest agent. Process model, control API and policy
//! are placed in this crate.

#[cfg(feature = "lcp")]
pub mod lcp;
