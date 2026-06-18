// SPDX-FileCopyrightText: 2026 LingCage <opensource@lingcage.com>
//
// SPDX-License-Identifier: Apache-2.0

//! Guest agent of LingCage sandbox, a static binary without runtime
//! dependencies. It connects to host over vsock, applies identity received
//! on each connection and runs commands on separate stream connections.

pub mod connect;
pub mod diag;
pub mod exec;
pub mod guest;
pub mod session;

/// Start time of the process, `guest::ready` measures `init_ms` from it.
pub static START: std::sync::OnceLock<std::time::Instant> = std::sync::OnceLock::new();

/// Host port which the control channel connects to.
#[cfg(target_os = "linux")]
const CONTROL_PORT: u32 = 1;

/// Run the agent forever. Connection lost across a clone is closed and
/// reconnected, identity is applied again on the new connection.
#[cfg(target_os = "linux")]
pub fn run() -> ! {
    START.get_or_init(std::time::Instant::now);
    let system = session::System {
        connect: &connect::connect,
        identify: &guest::apply,
    };
    loop {
        match connect::connect(CONTROL_PORT) {
            Ok(mut control) => {
                if let Err(err) = session::serve(&mut control, &system) {
                    diag::line(format_args!("lingcage-agent: control session ended: {err}"));
                }
            }
            Err(err) => diag::line(format_args!(
                "lingcage-agent: failed to connect to host: {err}"
            )),
        }
    }
}
