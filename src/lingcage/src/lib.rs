// SPDX-FileCopyrightText: 2026 LingCage <opensource@lingcage.com>
//
// SPDX-License-Identifier: Apache-2.0

//! VMM built on top of `lingcore`. `lcp` is the guest protocol shared
//! between host and guest agent, `agent` is the agent itself and
//! `template` holds the sealed spawn sources. Process model, control API
//! and policy are placed in this crate.

// Machine layer of `lingcore` only supports Linux on x86_64 and riscv64,
// modules built on top of it are gated accordingly.
#[cfg(feature = "agent")]
pub mod agent;
#[cfg(all(
    feature = "template",
    target_os = "linux",
    any(target_arch = "x86_64", target_arch = "riscv64")
))]
pub mod error;
#[cfg(feature = "lcp")]
pub mod lcp;
#[cfg(all(
    feature = "template",
    target_os = "linux",
    any(target_arch = "x86_64", target_arch = "riscv64")
))]
pub mod template;

#[cfg(all(
    feature = "template",
    target_os = "linux",
    any(target_arch = "x86_64", target_arch = "riscv64")
))]
pub use error::{Error, Result};
