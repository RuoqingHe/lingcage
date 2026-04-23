// SPDX-FileCopyrightText: 2026 LingCage <opensource@lingcage.com>
//
// SPDX-License-Identifier: Apache-2.0

//! Building blocks for VMMs running agentic workloads, which means many
//! short-lived guests cloned from a template to run untrusted code.
//!
//! `lingcore` is a library instead of a VMM. Each component is gated
//! behind a Cargo feature.

// linux-loader only carries the bzImage loader for x86_64.
#[cfg(all(feature = "boot", target_arch = "x86_64"))]
pub mod boot;
#[cfg(feature = "devices")]
pub mod devices;
#[cfg(feature = "hv")]
pub mod hv;
// Boot tables are of a PC and the ioeventfds are eventfds.
#[cfg(all(feature = "machine", target_os = "linux", target_arch = "x86_64"))]
pub mod machine;
#[cfg(feature = "mem")]
pub mod mem;
// seccomp is Linux specific and syscall numbers are x86_64 specific.
#[cfg(all(feature = "seccomp", target_os = "linux", target_arch = "x86_64"))]
pub mod seccomp;
#[cfg(feature = "vcpu")]
pub mod vcpu;
