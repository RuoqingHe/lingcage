// SPDX-FileCopyrightText: 2026 LingCage <opensource@lingcage.com>
//
// SPDX-License-Identifier: Apache-2.0

//! Diagnostics of the agent, written to the non-blocking log connection
//! on port 2 if host listens there, otherwise to console. A line is
//! dropped if connection is full, and written to console if write fails.

use std::fmt::Arguments;
use std::io::Write as _;
use std::sync::Mutex;

/// Log connection of the current session, set once connected.
static SINK: Mutex<Option<std::fs::File>> = Mutex::new(None);

/// Route diagnostics to the log connection, set to non-blocking so that
/// a full connection only drops a line instead of blocking the session.
pub fn route(conn: std::fs::File) {
    use std::os::fd::AsRawFd as _;
    // SAFETY: `conn` is open, and F_SETFL needs no pointer argument.
    if unsafe { libc::fcntl(conn.as_raw_fd(), libc::F_SETFL, libc::O_NONBLOCK) } == -1 {
        eprintln!(
            "lingcage-agent: log connection not kept, failed to set O_NONBLOCK: {}",
            std::io::Error::last_os_error()
        );
        return;
    }
    *SINK.lock().expect("diag sink") = Some(conn);
}

/// Route diagnostics to console again after the session ended.
pub fn route_off() {
    *SINK.lock().expect("diag sink") = None;
}

/// Write one diagnostic line to the log connection, fall back to console
/// if there is no connection or the write fails.
pub fn line(args: Arguments<'_>) {
    let mut sink = SINK.lock().expect("diag sink");
    if let Some(conn) = sink.as_mut() {
        match writeln!(conn, "{args}") {
            Ok(()) => return,
            // Drop the line if connection is full.
            Err(err) if err.kind() == std::io::ErrorKind::WouldBlock => return,
            Err(_) => *sink = None,
        }
    }
    eprintln!("{args}");
}

#[cfg(test)]
mod tests {
    #[test]
    fn test_line_written_to_connection() {
        let (mut host, guest) = std::os::unix::net::UnixStream::pair().expect("pair");
        let guest: std::fs::File = std::os::fd::OwnedFd::from(guest).into();
        crate::agent::diag::route(guest);
        crate::agent::diag::line(format_args!("one line"));
        crate::agent::diag::route_off();
        let mut text = String::new();
        host.set_read_timeout(Some(std::time::Duration::from_secs(2)))
            .expect("deadline");
        use std::io::Read as _;
        host.read_to_string(&mut text).expect("read line");
        assert_eq!(text, "one line\n");
    }
}
