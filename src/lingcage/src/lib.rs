// SPDX-FileCopyrightText: 2026 LingCage <opensource@lingcage.com>
//
// SPDX-License-Identifier: Apache-2.0

//! VMM built on top of `lingcore`. `lcp` is the guest protocol shared
//! between host and guest agent, `agent` is the agent itself and
//! `template` holds the sealed spawn sources. Process model, control API
//! and policy are placed in this crate.

#[cfg(feature = "agent")]
pub mod agent;
#[cfg(feature = "template")]
pub mod error;
#[cfg(feature = "lcp")]
pub mod lcp;
#[cfg(feature = "template")]
pub mod template;

#[cfg(feature = "template")]
pub use error::{Error, Result};
