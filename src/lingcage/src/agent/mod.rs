// SPDX-FileCopyrightText: 2026 LingCage <opensource@lingcage.com>
//
// SPDX-License-Identifier: Apache-2.0

//! Guest agent of LingCage sandbox, a static binary without runtime
//! dependencies. It connects to host over vsock, applies identity received
//! on each connection and runs commands on separate stream connections.

pub mod connect;
pub mod diag;
pub mod guest;

/// Start time of the process, `guest::ready` measures `init_ms` from it.
pub static START: std::sync::OnceLock<std::time::Instant> = std::sync::OnceLock::new();
