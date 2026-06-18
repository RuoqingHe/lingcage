// SPDX-FileCopyrightText: 2026 LingCage <opensource@lingcage.com>
//
// SPDX-License-Identifier: Apache-2.0

//! Protocol core, which serves one session of the control channel over
//! any descriptor-backed stream.

#![cfg(target_os = "linux")]

use std::fs::File;
use std::io::{self, Read, Write};
use std::os::fd::AsRawFd;

use crate::lcp::{ErrorPayload, Frame, Identified, Identify, Ping, Pong, flags, kind};

/// Host port of the log connection.
const LOG_PORT: u32 = 2;

/// Idle poll timeout, the loop just polls again when it expires.
const IDLE_POLL_MS: libc::c_int = 30_000;

/// Connect and identity hooks of a session, replaceable in tests.
pub struct System<'a> {
    /// Connect to the given host port, returns the connection.
    pub connect: &'a (dyn Fn(u32) -> io::Result<File> + Sync + 'a),
    /// Apply the identity, returns the hostname actually in effect.
    pub identify: &'a (dyn Fn(&Identify) -> String + Sync + 'a),
}

/// Serve one session, sends READY first then handles frames until the
/// connection ends. Caller should reconnect on the returned error.
pub fn serve<S>(control: &mut S, system: &System<'_>) -> Result<(), crate::lcp::Error>
where
    S: Read + Write + AsRawFd,
{
    arm_sigchld();
    // Log connection is best-effort. If there is no listener on the log
    // port, diagnostics stay on the console according to the one-way log
    // port's contract.
    if let Ok(conn) = (system.connect)(LOG_PORT) {
        crate::agent::diag::route(conn);
    }
    crate::agent::diag::line(format_args!("lingcage-agent: control session up"));
    let ready = Frame::with_payload(
        0,
        kind::READY,
        flags::SESSION_START,
        &crate::agent::guest::ready(),
    )?;
    ready.write_to(&mut *control)?;
    let result = session(control, system);
    crate::agent::diag::route_off();
    result
}

/// Frame loop of one session, runs on the state set up by `serve`.
fn session<S>(control: &mut S, system: &System<'_>) -> Result<(), crate::lcp::Error>
where
    S: Read + Write + AsRawFd,
{
    loop {
        let mut set = [libc::pollfd {
            fd: control.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        }];
        if poll(&mut set, IDLE_POLL_MS).map_err(crate::lcp::Error::Io)? == 0 {
            continue;
        }
        let revents = set[0].revents;
        if revents & libc::POLLIN != 0 {
            let frame = Frame::read_from(&mut *control)?;
            dispatch(&frame, &mut *control, system)?;
        } else if revents & (libc::POLLERR | libc::POLLHUP | libc::POLLNVAL) != 0 {
            return Err(crate::lcp::Error::Truncated);
        }
    }
}

/// Handle one frame, replies are written to the control channel.
fn dispatch<W: Write>(
    frame: &Frame,
    control: &mut W,
    system: &System<'_>,
) -> Result<(), crate::lcp::Error> {
    match frame.kind {
        kind::IDENTIFY => {
            let identify: Identify = match frame.payload() {
                Ok(identify) => identify,
                Err(_) => return bad_payload(control, frame.id),
            };
            let identified = Identified {
                hostname: (system.identify)(&identify),
            };
            Frame::with_payload(frame.id, kind::IDENTIFIED, 0, &identified)?
                .write_to(&mut *control)?;
        }
        kind::PING => {
            let ping: Ping = match frame.payload() {
                Ok(ping) => ping,
                Err(_) => return bad_payload(control, frame.id),
            };
            Frame::with_payload(frame.id, kind::PONG, 0, &Pong { nonce: ping.nonce })?
                .write_to(&mut *control)?;
        }
        kind::SHUTDOWN => crate::agent::guest::power_off(),
        other => {
            let message = format!("unknown frame kind {other}");
            error_frame(&mut *control, frame.id, "proto.unknown-kind", &message)?;
        }
    }
    Ok(())
}

/// Send ERROR frame for bad payload and finish the dispatch.
fn bad_payload<W: Write>(control: &mut W, id: u32) -> Result<(), crate::lcp::Error> {
    error_frame(
        control,
        id,
        "proto.bad-payload",
        "payload can not be decoded",
    )
}

/// Send an ERROR frame with given `code` and `message`.
fn error_frame<W: Write>(
    control: &mut W,
    id: u32,
    code: &str,
    message: &str,
) -> Result<(), crate::lcp::Error> {
    let payload = ErrorPayload {
        code: code.to_string(),
        message: message.to_string(),
    };
    Frame::with_payload(id, kind::ERROR, 0, &payload)?.write_to(control)
}

/// Wrapper of poll(2) which treats EINTR as a timeout.
fn poll(set: &mut [libc::pollfd], timeout: libc::c_int) -> io::Result<libc::c_int> {
    let count = libc::nfds_t::try_from(set.len()).expect("poll set fits nfds_t");
    // SAFETY: `set` is a valid slice and `count` is its length.
    let n = unsafe { libc::poll(set.as_mut_ptr(), count, timeout) };
    if n == -1 {
        let err = io::Error::last_os_error();
        if err.kind() == io::ErrorKind::Interrupted {
            // Interrupted by SIGCHLD, treat it as a timeout so that the
            // loop comes round its top right away.
            return Ok(0);
        }
        return Err(err);
    }
    Ok(n)
}

/// Install empty SIGCHLD handler without SA_RESTART, so that child exit
/// interrupts the poll instead of restarting it, and the loop comes
/// round its top right away instead of waiting for the poll interval.
fn arm_sigchld() {
    // SAFETY: a zeroed sigaction is a valid empty sigaction.
    let mut action: libc::sigaction = unsafe { std::mem::zeroed() };
    action.sa_sigaction = on_sigchld as *const () as libc::sighandler_t;
    // SAFETY: `action` is a valid sigaction with an empty handler.
    unsafe { libc::sigaction(libc::SIGCHLD, &action, std::ptr::null_mut()) };
}

extern "C" fn on_sigchld(_: libc::c_int) {}

#[cfg(test)]
mod tests {
    use std::fs::File;
    use std::os::unix::net::UnixStream;
    use std::sync::Mutex;
    use std::time::Duration;
    use std::{io, thread};

    use crate::agent::session::{System, serve};
    use crate::lcp::{ErrorPayload, Frame, Identified, Identify, Ping, Pong, Ready, flags, kind};

    /// Connect closure for tests which do not need streams.
    fn unbound(port: u32) -> io::Result<File> {
        Err(io::Error::new(
            io::ErrorKind::NotFound,
            format!("port {port} is not bound"),
        ))
    }

    /// Identify hook for tests which do not send IDENTIFY.
    fn unapplied(_: &Identify) -> String {
        "unused".to_string()
    }

    /// Run `act` as the host side of one session, returns the result of
    /// the session. READY frame is passed to `act`.
    fn session(
        system: &System<'_>,
        act: impl FnOnce(&mut UnixStream, Frame),
    ) -> Result<(), crate::lcp::Error> {
        let (mut host, mut guest) = UnixStream::pair().expect("socket pair");
        host.set_read_timeout(Some(Duration::from_secs(15)))
            .expect("read deadline");
        thread::scope(|scope| {
            let serving = scope.spawn(move || serve(&mut guest, system));
            let ready = Frame::read_from(&mut host).expect("READY frame");
            act(&mut host, ready);
            drop(host);
            serving.join().expect("session panicked")
        })
    }

    #[test]
    fn test_identify_after_ready() {
        let seen = Mutex::new(None);
        let system = System {
            connect: &unbound,
            identify: &|identity: &Identify| {
                *seen.lock().expect("record") = Some(identity.clone());
                "applied-host".to_string()
            },
        };
        let ended = session(&system, |host, ready| {
            assert_eq!(ready.kind, kind::READY);
            assert_eq!(ready.flags, flags::SESSION_START);
            let ready: Ready = ready.payload().expect("READY payload");
            assert_eq!(
                ready.agent,
                format!("lingcage-agent {}", env!("CARGO_PKG_VERSION"))
            );
            assert!(
                ready.uptime > 0.0,
                "uptime should be read from /proc/uptime"
            );
            assert!(
                !ready.boot_id.is_empty(),
                "boot id should be read from /proc"
            );

            let identify = Identify {
                hostname: "sandbox-7".to_string(),
                machine_id: "ab".repeat(16),
                generation: 3,
                entropy: [7u8; 32],
                unix_nanos: 0,
            };
            Frame::with_payload(1, kind::IDENTIFY, 0, &identify)
                .expect("IDENTIFY frame")
                .write_to(host)
                .expect("send IDENTIFY");
            let answered = Frame::read_from(host).expect("IDENTIFIED frame");
            assert_eq!(answered.kind, kind::IDENTIFIED);
            assert_eq!(answered.id, 1);
            let answered: Identified = answered.payload().expect("IDENTIFIED payload");
            assert_eq!(answered.hostname, "applied-host");
        });
        assert!(matches!(ended, Err(crate::lcp::Error::Truncated)));
        let seen = seen.lock().expect("record").clone().expect("apply ran");
        assert_eq!(seen.hostname, "sandbox-7");
        assert_eq!(seen.generation, 3);
        assert_eq!(seen.entropy, [7u8; 32]);
    }

    #[test]
    fn test_ping_pong() {
        let system = System {
            connect: &unbound,
            identify: &unapplied,
        };
        let ended = session(&system, |host, _ready| {
            Frame::with_payload(9, kind::PING, 0, &Ping { nonce: 99 })
                .expect("PING frame")
                .write_to(host)
                .expect("send PING");
            let answered = Frame::read_from(host).expect("PONG frame");
            assert_eq!(answered.kind, kind::PONG);
            assert_eq!(answered.id, 9);
            let answered: Pong = answered.payload().expect("PONG payload");
            assert_eq!(answered.nonce, 99);
        });
        assert!(matches!(ended, Err(crate::lcp::Error::Truncated)));
    }

    #[test]
    fn test_unknown_kind_error() {
        let system = System {
            connect: &unbound,
            identify: &unapplied,
        };
        let ended = session(&system, |host, _ready| {
            Frame::new(5, 0xbeef, Vec::new())
                .write_to(host)
                .expect("send garbage frame");
            let answered = Frame::read_from(host).expect("ERROR frame");
            assert_eq!(answered.kind, kind::ERROR);
            assert_eq!(answered.id, 5);
            let answered: ErrorPayload = answered.payload().expect("ERROR payload");
            assert_eq!(answered.code, "proto.unknown-kind");
        });
        assert!(matches!(ended, Err(crate::lcp::Error::Truncated)));
    }
}
