// SPDX-FileCopyrightText: 2026 LingCage <opensource@lingcage.com>
//
// SPDX-License-Identifier: Apache-2.0

//! Building blocks for VMMs running agentic workloads, which means many
//! short-lived guests cloned from a template to run untrusted code.
//!
//! `lingcore` is a library instead of a VMM. Each component is gated
//! behind a Cargo feature.

#[cfg(feature = "devices")]
pub mod devices;
#[cfg(feature = "hv")]
pub mod hv;
#[cfg(feature = "mem")]
pub mod mem;
#[cfg(feature = "vcpu")]
pub mod vcpu;
