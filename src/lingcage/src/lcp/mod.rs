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
//! is capped at [`MAX_FRAME`]. Payload of a typed message is JSON.

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
