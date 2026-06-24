// SPDX-FileCopyrightText: 2026 LingCage <opensource@lingcage.com>
//
// SPDX-License-Identifier: Apache-2.0

//! Reading from guest under one deadline shared by all reads, instead
//! of a timeout per read. Socket read timeout is armed per read, a
//! guest sending one byte within each timeout could keep the handshake
//! open indefinitely. Timeout of each read is set from the time left.

use std::io::Read;
use std::os::unix::net::UnixStream;
use std::time::Instant;

use crate::error::{Error, Result};

/// Stream wrapper with one deadline shared by all reads.
pub(crate) struct Until<'a> {
    stream: &'a UnixStream,
    deadline: Instant,
}

impl<'a> Until<'a> {
    /// Create a wrapper which reads `stream` until `deadline`.
    pub(crate) fn new(stream: &'a UnixStream, deadline: Instant) -> Until<'a> {
        Until { stream, deadline }
    }
}

impl Read for Until<'_> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let left = self.deadline.saturating_duration_since(Instant::now());
        if left.is_zero() {
            return Err(std::io::Error::from(std::io::ErrorKind::TimedOut));
        }
        self.stream.set_read_timeout(Some(left))?;
        self.stream.read(buf)
    }
}

/// Read one frame from `stream` before `deadline`, returns
/// `Error::Timeout` with `what` attached once the deadline passes.
pub(crate) fn frame(
    stream: &UnixStream,
    deadline: Instant,
    what: &'static str,
) -> Result<crate::lcp::Frame> {
    let mut until = Until::new(stream, deadline);
    match crate::lcp::Frame::read_from(&mut until) {
        Ok(frame) => Ok(frame),
        Err(crate::lcp::Error::Io(err))
            if matches!(
                err.kind(),
                std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
            ) =>
        {
            Err(Error::Timeout(what))
        }
        Err(err) => Err(Error::Protocol(err)),
    }
}

#[cfg(test)]
mod tests {
    use std::io::Write as _;
    use std::time::Duration;

    use crate::deadline::*;

    #[test]
    fn test_silent_stream_timeout() {
        let (ours, _theirs) = UnixStream::pair().expect("socket pair");
        let refused = frame(&ours, Instant::now() + Duration::from_millis(50), "a frame");
        assert!(matches!(refused, Err(Error::Timeout("a frame"))));
    }

    #[test]
    fn test_byte_by_byte_timeout() {
        // Receiving one byte per read does not extend the deadline.
        let (ours, mut theirs) = UnixStream::pair().expect("socket pair");
        let mut wire = Vec::new();
        crate::lcp::Frame::new(1, crate::lcp::kind::PING, vec![0u8; 64])
            .write_to(&mut wire)
            .expect("encode frame");
        let dribbling = std::thread::spawn(move || {
            for byte in wire {
                if theirs.write_all(&[byte]).is_err() {
                    return;
                }
                std::thread::sleep(Duration::from_millis(20));
            }
        });
        let deadline = Instant::now() + Duration::from_millis(100);
        let refused = frame(&ours, deadline, "a frame");
        assert!(
            matches!(refused, Err(Error::Timeout(_))),
            "frame sent byte by byte passed deadline: {refused:?}"
        );
        assert!(
            Instant::now() < deadline + Duration::from_millis(500),
            "read returned long after deadline"
        );
        dribbling.join().expect("sender thread panicked");
    }

    #[test]
    fn test_full_frame_read() {
        let (ours, mut theirs) = UnixStream::pair().expect("socket pair");
        let sent = crate::lcp::Frame::new(7, crate::lcp::kind::PONG, b"payload".to_vec());
        sent.write_to(&mut theirs).expect("send the frame");
        let read =
            frame(&ours, Instant::now() + Duration::from_secs(5), "a frame").expect("read frame");
        assert_eq!(read, sent);
    }
}
