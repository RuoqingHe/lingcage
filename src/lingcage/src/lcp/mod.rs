// SPDX-FileCopyrightText: 2026 LingCage <opensource@lingcage.com>
//
// SPDX-License-Identifier: Apache-2.0

//! LingCage guest protocol: frames sent over the control connection
//! between host and guest agent.
//!
//! A frame consists of length, id, type and flags, followed by payload:
//!
//! ```text
//! +---------+---------+--------+--------+=============+
//! | len u32 | id  u32 | t u16  | fl u8  |   payload   |
//! +---------+---------+--------+--------+=============+
//! ```
//!
//! All integers are big-endian. `len` counts everything after itself and
//! is capped at [`MAX_FRAME`]. Payload of a typed message is JSON, message
//! types are numbered in [`kind`] and corresponding payload structs are
//! defined below. Bulk data is transferred raw over stream connections
//! specified by [`Exec`], each of them starts with a nonce of [`NONCE`]
//! bytes.

use std::collections::BTreeMap;
use std::io::{Read, Write};

use thiserror::Error;

/// Maximum frame size in bytes, length field included. Only messages go
/// over control connection, bulk data is transferred over stream
/// connections instead, so one frame would not occupy the channel for long.
pub const MAX_FRAME: u32 = 64 * 1024;

/// Size of fixed header in bytes: length, id, type and flags.
const HEADER: usize = 11;

/// Bytes counted by `len` besides payload, which are id, type and flags.
const COUNTED: u32 = 7;

/// Errors thrown while reading or writing a frame.
#[derive(Debug, Error)]
pub enum Error {
    /// Failed to read from or write to the connection.
    #[error("failed to read or write connection")]
    Io(#[source] std::io::Error),
    /// Connection closed before a complete frame is read.
    #[error("connection closed in the middle of a frame")]
    Truncated,
    /// Frame of {0} bytes exceeds `MAX_FRAME` limit.
    #[error("frame of {0} bytes exceeds the limit")]
    Overfull(u32),
    /// Failed to encode or decode payload as JSON of the message type.
    #[error("failed to code payload as JSON of the message type")]
    Json(#[source] serde_json::Error),
}

/// Result alias for frame IO.
pub type Result<T> = std::result::Result<T, Error>;

/// Flag bits of a frame.
pub mod flags {
    /// First frame of a session.
    pub const SESSION_START: u8 = 1;
    /// Last frame of an exchange.
    pub const TERMINAL: u8 = 2;
    /// Connection will be closed after this frame.
    pub const SHUTDOWN: u8 = 4;
}

/// A single frame, header fields plus payload bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Frame {
    /// Correlation and session id, which is allocated by host.
    pub id: u32,
    /// Message type.
    pub kind: u16,
    /// Flag bits, defined in [`flags`].
    pub flags: u8,
    /// Payload bytes, JSON for a typed message.
    pub payload: Vec<u8>,
}

impl Frame {
    /// Create a frame with no flags set.
    pub fn new(id: u32, kind: u16, payload: Vec<u8>) -> Self {
        Frame {
            id,
            kind,
            flags: 0,
            payload,
        }
    }

    /// Create a frame with `value` serialized to JSON as payload.
    pub fn with_payload<T: serde::Serialize>(
        id: u32,
        kind: u16,
        flags: u8,
        value: &T,
    ) -> Result<Self> {
        let payload = serde_json::to_vec(value).map_err(Error::Json)?;
        Ok(Frame {
            id,
            kind,
            flags,
            payload,
        })
    }

    /// Decode payload as JSON into `T`.
    pub fn payload<'a, T: serde::Deserialize<'a>>(&'a self) -> Result<T> {
        serde_json::from_slice(&self.payload).map_err(Error::Json)
    }

    /// Write the frame to `out`.
    pub fn write_to(&self, out: &mut impl Write) -> Result<()> {
        let len = u32::try_from(self.payload.len())
            .unwrap_or(MAX_FRAME)
            .saturating_add(COUNTED);
        if len > MAX_FRAME {
            return Err(Error::Overfull(len));
        }
        let mut header = [0u8; HEADER];
        header[..4].copy_from_slice(&len.to_be_bytes());
        header[4..8].copy_from_slice(&self.id.to_be_bytes());
        header[8..10].copy_from_slice(&self.kind.to_be_bytes());
        header[10] = self.flags;
        out.write_all(&header).map_err(Error::Io)?;
        out.write_all(&self.payload).map_err(Error::Io)?;
        out.flush().map_err(Error::Io)
    }

    /// Read one frame from `from`, returns `Truncated` if connection is closed
    /// before the length field or in the middle of a frame.
    pub fn read_from(from: &mut impl Read) -> Result<Self> {
        let mut header = [0u8; HEADER];
        let mut read = 0;
        while read < header.len() {
            match from.read(&mut header[read..]) {
                Ok(0) => return Err(Error::Truncated),
                Ok(n) => read += n,
                Err(err) if err.kind() == std::io::ErrorKind::Interrupted => {}
                Err(err) => return Err(Error::Io(err)),
            }
        }
        let len = u32::from_be_bytes(header[..4].try_into().expect("four bytes"));
        if !(COUNTED..=MAX_FRAME).contains(&len) {
            return Err(Error::Overfull(len));
        }
        let mut payload = vec![0u8; (len - COUNTED) as usize];
        from.read_exact(&mut payload).map_err(|err| {
            if err.kind() == std::io::ErrorKind::UnexpectedEof {
                Error::Truncated
            } else {
                Error::Io(err)
            }
        })?;
        Ok(Frame {
            id: u32::from_be_bytes(header[4..8].try_into().expect("four bytes")),
            kind: u16::from_be_bytes(header[8..10].try_into().expect("two bytes")),
            flags: header[10],
            payload,
        })
    }
}

/// Protocol generation, which is carried in [`Ready`]. Host rejects an
/// agent whose protocol generation is newer than its own.
pub const PROTOCOL: u16 = 1;

/// Size of the nonce in bytes, which agent writes first on a stream
/// connection in big-endian, before actual stream data. Host attaches the
/// stream once the nonce matches the [`Stream`] specified in `Exec`, a
/// connection opening with an unknown nonce is closed.
pub const NONCE: usize = 8;

/// Message types, 16 bits, new ones are only appended.
pub mod kind {
    /// Agent is up, first frame of each connection, guest to host.
    pub const READY: u16 = 1;
    /// Identity of the sandbox, host to guest.
    pub const IDENTIFY: u16 = 2;
    /// Identity has been applied, guest to host.
    pub const IDENTIFIED: u16 = 3;
    /// Liveness check, either direction.
    pub const PING: u16 = 4;
    /// Reply to liveness check, either direction.
    pub const PONG: u16 = 5;
    /// Command to run, with its streams specified.
    pub const EXEC: u16 = 6;
    /// Command has started, with its pid.
    pub const EXEC_STARTED: u16 = 7;
    /// Command failed to start, with the reason attached.
    pub const EXEC_FAILED: u16 = 8;
    /// Command has exited, with its status.
    pub const EXEC_EXIT: u16 = 9;
    /// Signal to send to a running command.
    pub const EXEC_SIGNAL: u16 = 10;
    /// New PTY size for a running command.
    pub const EXEC_RESIZE: u16 = 11;
    /// Request to power off the guest.
    pub const SHUTDOWN: u16 = 12;
    /// Frame rejected by agent, with the reason in payload.
    pub const ERROR: u16 = 0xffff;
}

/// Agent is up, first frame of each connection, guest to host.
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct Ready {
    /// Agent version string, e.g. `lingcage-agent 0.1.0`.
    pub agent: String,
    /// Protocol generation of the agent, [`PROTOCOL`] at its build time.
    pub protocol: u16,
    /// Uptime of the guest in seconds, read from `/proc/uptime`.
    pub uptime: f64,
    /// Milliseconds elapsed since agent started, measured by the agent itself.
    pub init_ms: u64,
    /// Content of `/proc/sys/kernel/random/boot_id` read by the agent.
    pub boot_id: String,
}

/// Identity of the sandbox, sent by host to guest on each connection.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct Identify {
    /// Hostname to be set in the guest.
    pub hostname: String,
    /// Value to write to `/etc/machine-id`.
    pub machine_id: String,
    /// Generation of this connection, assigned by host. A frame carrying a
    /// different generation belongs to an earlier connection.
    pub generation: u64,
    /// Fresh entropy to be mixed into guest entropy pool before reseeding.
    pub entropy: [u8; 32],
    /// Wall clock time of host at handshake, in nanoseconds since Unix epoch.
    pub unix_nanos: u64,
}

/// Identity has been applied, guest to host.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct Identified {
    /// Hostname currently in effect, read back after setting.
    pub hostname: String,
}

/// Liveness check, either direction.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct Ping {
    /// Nonce value to be echoed back.
    pub nonce: u64,
}

/// Reply to liveness check, either direction.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct Pong {
    /// Nonce value echoed from the corresponding `Ping`.
    pub nonce: u64,
}

/// Size of pseudo-terminal, also used as payload of `EXEC_RESIZE`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct PtySize {
    /// Number of rows of the terminal.
    pub rows: u16,
    /// Number of columns of the terminal.
    pub cols: u16,
}

/// A stream connection of a command, which contains the host port for
/// agent to connect to and the nonce to write first.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct Stream {
    /// Host port to connect to, randomly allocated by host and used only once.
    pub port: u32,
    /// Nonce to write first on the connection, [`NONCE`] bytes in big-endian.
    pub nonce: u64,
}

/// Command to run, host to guest. Its streams are raw connections, one for
/// each direction.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct Exec {
    /// Program to run, looked up in `PATH` if it is a relative path.
    pub program: String,
    /// Arguments to the program, not including program name.
    pub args: Vec<String>,
    /// Environment variables for the command, replacing those of the agent.
    pub env: BTreeMap<String, String>,
    /// Working directory, defaults to that of the agent if not set.
    pub cwd: Option<String>,
    /// User to run the command as, defaults to root if not set.
    pub user: Option<String>,
    /// PTY size to run under, not set for a command without terminal.
    pub pty: Option<PtySize>,
    /// Maximum time the command may run in milliseconds, unbounded if not set.
    /// Milliseconds are used since a limit under one second would be floored
    /// to zero in seconds, which the agent would treat as a kill on next pass.
    pub timeout_ms: Option<u64>,
    /// Stream for stdin of the command, `/dev/null` is used if not set.
    pub stdin: Option<Stream>,
    /// Stream to receive stdout of the command.
    pub stdout: Stream,
    /// Stream to receive stderr of the command.
    pub stderr: Stream,
}

/// Command is now running, guest to host.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct ExecStarted {
    /// Pid of the command process in the guest.
    pub pid: u32,
}

/// Reason a command failed to start, mapped from the errno of `execve`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Failure {
    /// `ENOENT`, program does not exist.
    NotFound,
    /// `EACCES`, program is not executable.
    Permission,
    /// `ENOEXEC`, program is not in an executable format supported by kernel.
    Format,
    /// Any other errno, actual value is carried in `ExecFailed::errno`.
    Other,
}

/// Command failed to start, guest to host, sent instead of `EXEC_STARTED`.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct ExecFailed {
    /// Failure reason mapped from the errno.
    pub reason: Failure,
    /// Errno of the step which failed.
    pub errno: i32,
}

/// Command has exited, guest to host. Either `code` or `signal` is set.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct ExecExit {
    /// Exit code if the command exited normally.
    pub code: Option<i32>,
    /// Signal number if the command was killed by a signal.
    pub signal: Option<i32>,
    /// Set if agent killed the command on `timeout_ms` limit of `Exec`, since
    /// host can not distinguish such a kill from others by timing alone.
    #[serde(default)]
    pub timed_out: bool,
}

/// Signal to send to a running command, host to guest.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct Signal {
    /// Signal number, which is sent to the process group of the command.
    pub signal: i32,
}

/// Refuse the frame with given id.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct ErrorPayload {
    /// Stable machine-readable error code, e.g. `frame.unknown-kind`.
    pub code: String,
    /// Human-readable description of the error.
    pub message: String,
}

#[cfg(test)]
mod tests {
    use crate::lcp::*;

    #[test]
    fn test_frame_round_trip() {
        let frame = Frame {
            id: 42,
            kind: 6,
            flags: flags::SESSION_START | flags::TERMINAL,
            payload: b"payload".to_vec(),
        };
        let mut wire = Vec::new();
        frame.write_to(&mut wire).expect("write the frame");

        // Make sure `len` counts id, type, flags and payload.
        assert_eq!(
            u32::from_be_bytes(wire[..4].try_into().expect("four bytes")),
            COUNTED + 7
        );
        let back = Frame::read_from(&mut wire.as_slice()).expect("read frame back");
        assert_eq!(back, frame);
    }

    #[test]
    fn test_empty_payload_round_trip() {
        let frame = Frame::new(1, 4, Vec::new());
        let mut wire = Vec::new();
        frame.write_to(&mut wire).expect("write the frame");
        let back = Frame::read_from(&mut wire.as_slice()).expect("read it back");
        assert_eq!(back, frame);
    }

    #[test]
    fn test_frame_size_cap() {
        // Frame at `MAX_FRAME` passes, one byte over is rejected.
        let full = Frame::new(1, 6, vec![0u8; (MAX_FRAME - COUNTED) as usize]);
        let mut wire = Vec::new();
        full.write_to(&mut wire).expect("write frame at the cap");
        assert_eq!(
            Frame::read_from(&mut wire.as_slice())
                .expect("read it back")
                .payload
                .len(),
            full.payload.len()
        );

        let over = Frame::new(1, 6, vec![0u8; (MAX_FRAME - COUNTED + 1) as usize]);
        assert!(matches!(
            over.write_to(&mut Vec::new()),
            Err(Error::Overfull(n)) if n == MAX_FRAME + 1
        ));
        let mut wire = Vec::new();
        wire.extend_from_slice(&(MAX_FRAME + 1).to_be_bytes());
        wire.extend_from_slice(&[0u8; 7]);
        assert!(matches!(
            Frame::read_from(&mut wire.as_slice()),
            Err(Error::Overfull(n)) if n == MAX_FRAME + 1
        ));
    }

    #[test]
    fn test_truncated_frame() {
        let mut wire = Vec::new();
        Frame::new(1, 6, vec![7u8; 64])
            .write_to(&mut wire)
            .expect("write the frame");
        wire.truncate(20);
        assert!(matches!(
            Frame::read_from(&mut wire.as_slice()),
            Err(Error::Truncated)
        ));
        // Connection closed before the length field is also `Truncated`.
        assert!(matches!(
            Frame::read_from(&mut [0u8; 3].as_slice()),
            Err(Error::Truncated)
        ));
    }

    #[test]
    fn test_exec_round_trip() {
        let exec = Exec {
            program: "python".to_string(),
            args: vec!["-c".to_string(), "print(1)".to_string()],
            env: BTreeMap::from([("PATH".to_string(), "/bin".to_string())]),
            cwd: Some("/work".to_string()),
            user: None,
            pty: Some(PtySize { rows: 24, cols: 80 }),
            timeout_ms: Some(30_000),
            stdin: None,
            stdout: Stream {
                port: 0x9a3f_1c02,
                nonce: 0x0123_4567_89ab_cdef,
            },
            stderr: Stream {
                port: 7,
                nonce: u64::MAX,
            },
        };
        let frame =
            Frame::with_payload(9, kind::EXEC, flags::SESSION_START, &exec).expect("code payload");
        let back: Exec = frame.payload().expect("decode payload");
        assert_eq!(back, exec);
    }

    #[test]
    fn test_failure_kebab_case() {
        let failed = ExecFailed {
            reason: Failure::NotFound,
            errno: 2,
        };
        let frame = Frame::with_payload(3, kind::EXEC_FAILED, 0, &failed).expect("code it");
        assert_eq!(
            std::str::from_utf8(&frame.payload).expect("utf-8"),
            r#"{"reason":"not-found","errno":2}"#
        );
        assert_eq!(frame.payload::<ExecFailed>().expect("decode it"), failed);
    }

    #[test]
    fn test_identify_round_trip() {
        let identify = Identify {
            hostname: "lc-1".to_string(),
            machine_id: "0".repeat(32),
            generation: 0xfeed,
            entropy: [0xab; 32],
            unix_nanos: 1_700_000_000_000_000_000,
        };
        let frame = Frame::with_payload(1, kind::IDENTIFY, 0, &identify).expect("code it");
        assert_eq!(frame.payload::<Identify>().expect("decode it"), identify);
    }

    #[test]
    fn test_reject_bad_json_payload() {
        let frame = Frame::new(1, 6, b"not json".to_vec());
        assert!(matches!(frame.payload::<Vec<u32>>(), Err(Error::Json(_))));
        let frame = Frame::with_payload(1, 6, 0, &vec![1u32, 2]).expect("code payload");
        assert_eq!(
            frame.payload::<Vec<u32>>().expect("decode payload"),
            vec![1, 2]
        );
    }
}
