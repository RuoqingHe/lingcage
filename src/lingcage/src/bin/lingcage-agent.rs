// SPDX-FileCopyrightText: 2026 LingCage <opensource@lingcage.com>
//
// SPDX-License-Identifier: Apache-2.0

//! Guest agent of LingCage sandbox, a static binary with no runtime
//! dependency. It connects to host on vsock port 1, applies identity from
//! each connection and runs commands on separate stream connections.

// Agent runs in a Linux guest only.
#[cfg(target_os = "linux")]
fn main() {
    lingcage::agent::run();
}

#[cfg(not(target_os = "linux"))]
fn main() {}
