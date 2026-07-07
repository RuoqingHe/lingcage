// SPDX-FileCopyrightText: 2026 LingCage <opensource@lingcage.com>
//
// SPDX-License-Identifier: Apache-2.0

//! Host end of virtio-net device. `Carrier` carries frames of a guest
//! in both directions, `Framed` is a carrier over a stream socket.
//!
//! The program assembling the machine chooses the host end. A frame not
//! taken by the host end in time is finished by `Carrier::resume`, the
//! next one is left in the ring of the guest until then.

use std::io::{self, Read, Write};
use std::os::fd::{AsRawFd, OwnedFd, RawFd};
use std::os::unix::net::UnixStream;
use std::path::Path;

use log::warn;

use crate::devices::virtio::net::frame::{self, MAX_FRAME, PREFIX};
use crate::hv::Interest;

/// Host end which carries frames of a guest in both directions.
pub trait Carrier: Send {
    /// Read one frame into `into`, returns `None` if no complete frame is
    /// received yet. Frame longer than `into` is dropped.
    fn take(&mut self, into: &mut [u8]) -> io::Result<Option<usize>>;

    /// Write one frame to the host end. Returns `false` while the last frame
    /// is still going out, caller keeps the frame and offers it again once
    /// [`Carrier::resume`] returns `true`. Frame over `MAX_FRAME` is
    /// dropped.
    fn give(&mut self, frame: &[u8]) -> io::Result<bool>;

    /// Write the rest of a frame which the host end only took part of.
    /// Returns `true` once no frame is going out.
    fn resume(&mut self) -> io::Result<bool>;

    /// Returns the descriptor frames go through and the readiness to wait
    /// on it for.
    fn outside(&self) -> Vec<(RawFd, Interest)>;

    /// Returns longest time the host end can wait before it has work no
    /// descriptor reports, a timer of a stack for example. Default has
    /// none.
    fn wake_after(&self) -> Option<std::time::Duration> {
        None
    }
}

/// Carrier over a stream socket, each frame has a length prefix ahead.
pub struct Framed {
    stream: UnixStream,
    /// Bytes of the frame being read, prefix first.
    arriving: Vec<u8>,
    /// Bytes of the frame being written, prefix first.
    leaving: Vec<u8>,
    /// Bytes of `leaving` written so far.
    written: usize,
}

impl Framed {
    /// Connect to the socket at `at`.
    pub fn connect(at: &Path) -> io::Result<Self> {
        Framed::over(UnixStream::connect(at)?)
    }

    /// Take a socket already opened by the caller.
    pub fn held(socket: OwnedFd) -> io::Result<Self> {
        Framed::over(UnixStream::from(socket))
    }

    fn over(stream: UnixStream) -> io::Result<Self> {
        // Blocking read or write would stall the device thread.
        stream.set_nonblocking(true)?;
        Ok(Framed {
            stream,
            arriving: Vec::with_capacity(PREFIX + MAX_FRAME),
            leaving: Vec::new(),
            written: 0,
        })
    }

    /// Write the rest of `leaving`. Returns `true` once all written out.
    fn push(&mut self) -> io::Result<bool> {
        while self.written < self.leaving.len() {
            match self.stream.write(&self.leaving[self.written..]) {
                Ok(0) => return Err(io::ErrorKind::WriteZero.into()),
                Ok(taken) => self.written += taken,
                Err(err) if err.kind() == io::ErrorKind::WouldBlock => return Ok(false),
                Err(err) if err.kind() == io::ErrorKind::Interrupted => {}
                Err(err) => return Err(err),
            }
        }
        self.leaving.clear();
        self.written = 0;
        Ok(true)
    }

    /// Read until `arriving` holds `want` bytes. Returns `false` while fewer
    /// bytes have arrived.
    fn pull(&mut self, want: usize) -> io::Result<bool> {
        while self.arriving.len() < want {
            let mut byte = [0u8; 4096];
            let room = (want - self.arriving.len()).min(byte.len());
            match self.stream.read(&mut byte[..room]) {
                Ok(0) => return Err(io::ErrorKind::UnexpectedEof.into()),
                Ok(taken) => self.arriving.extend_from_slice(&byte[..taken]),
                Err(err) if err.kind() == io::ErrorKind::WouldBlock => return Ok(false),
                Err(err) if err.kind() == io::ErrorKind::Interrupted => {}
                Err(err) => return Err(err),
            }
        }
        Ok(true)
    }
}

impl Carrier for Framed {
    fn take(&mut self, into: &mut [u8]) -> io::Result<Option<usize>> {
        if !self.pull(PREFIX)? {
            return Ok(None);
        }
        let mut prefix = [0u8; PREFIX];
        prefix.copy_from_slice(&self.arriving[..PREFIX]);
        let Some(len) = frame::length(prefix) else {
            // Prefix refused by `frame::length` means the stream is out of
            // sync, stop reading it.
            return Err(io::ErrorKind::InvalidData.into());
        };
        if !self.pull(PREFIX + len)? {
            return Ok(None);
        }
        if into.len() < len {
            // Frame which does not fit is dropped instead of truncated.
            warn!("frame of {len} bytes dropped, does not fit in buffer");
            self.arriving.clear();
            return Ok(None);
        }
        into[..len].copy_from_slice(&self.arriving[PREFIX..PREFIX + len]);
        self.arriving.clear();
        Ok(Some(len))
    }

    fn give(&mut self, frame: &[u8]) -> io::Result<bool> {
        if !self.leaving.is_empty() {
            // Second frame written behind an unfinished one would be
            // spliced into it. Caller keeps this one until `resume`
            // returns `true`.
            return Ok(false);
        }
        if frame.len() > MAX_FRAME {
            // Overlong frame left in the ring would block the frames
            // behind it, so it is dropped.
            warn!(
                "frame of {} bytes dropped, longer than MAX_FRAME",
                frame.len()
            );
            return Ok(true);
        }
        self.leaving.extend_from_slice(&frame::lay(frame.len()));
        self.leaving.extend_from_slice(frame);
        self.push()?;
        Ok(true)
    }

    fn resume(&mut self) -> io::Result<bool> {
        if self.leaving.is_empty() {
            return Ok(true);
        }
        self.push()
    }

    fn outside(&self) -> Vec<(RawFd, Interest)> {
        // `arriving` has room for a frame, so `Read` is reported no matter
        // there is a buffer in the guest or not. `Net::outside` drops it
        // while a frame waits for a buffer.
        let interest = if self.leaving.is_empty() {
            Interest::Read
        } else {
            Interest::Both
        };
        vec![(self.stream.as_raw_fd(), interest)]
    }
}

// Socket buffers are shrunk through `libc::setsockopt`.
#[cfg(all(test, target_os = "linux"))]
mod tests {
    use std::ffi::c_int;

    use crate::devices::virtio::net::carrier::*;

    /// Returns a `Framed` over one end of a socket pair and the other end,
    /// with `SO_SNDBUF` of the first and `SO_RCVBUF` of the second set to
    /// `room` bytes.
    fn paired(room: c_int) -> (Framed, UnixStream) {
        let (ours, theirs) = UnixStream::pair().expect("socket pair");
        for (stream, option) in [(&ours, libc::SO_SNDBUF), (&theirs, libc::SO_RCVBUF)] {
            // SAFETY: `room` is a `c_int` and its size is passed as the
            // option length.
            let set = unsafe {
                libc::setsockopt(
                    stream.as_raw_fd(),
                    libc::SOL_SOCKET,
                    option,
                    std::ptr::addr_of!(room).cast(),
                    size_of::<c_int>() as libc::socklen_t,
                )
            };
            assert_eq!(set, 0, "setsockopt failed");
        }
        theirs.set_nonblocking(true).expect("set nonblocking");
        (Framed::over(ours).expect("wrap one end"), theirs)
    }

    /// Returns bytes ready to read at `far`, or none on `WouldBlock`.
    fn heard(far: &mut UnixStream) -> Vec<u8> {
        let mut said = vec![0u8; 8192];
        match far.read(&mut said) {
            Ok(taken) => said[..taken].to_vec(),
            Err(err) if err.kind() == io::ErrorKind::WouldBlock => Vec::new(),
            Err(err) => panic!("read failed: {err}"),
        }
    }

    #[test]
    fn test_frame_length_prefix() {
        let (mut carrier, mut far) = paired(65536);
        assert!(carrier.give(b"a frame").expect("give the frame"));
        let mut wanted = frame::lay(7).to_vec();
        wanted.extend_from_slice(b"a frame");
        assert_eq!(heard(&mut far), wanted);
    }

    #[test]
    fn test_take_whole_frame() {
        let (mut carrier, mut far) = paired(65536);
        far.write_all(&frame::lay(5)).expect("write the prefix");
        far.write_all(b"hello").expect("send the frame");

        let mut into = vec![0u8; MAX_FRAME];
        assert_eq!(carrier.take(&mut into).expect("take the frame"), Some(5));
        assert_eq!(&into[..5], b"hello");
        assert_eq!(carrier.take(&mut into).expect("take again"), None);
    }

    #[test]
    fn test_take_frame_in_pieces() {
        let (mut carrier, mut far) = paired(65536);
        let mut into = vec![0u8; MAX_FRAME];

        far.write_all(&frame::lay(5)[..2]).expect("half the prefix");
        assert_eq!(carrier.take(&mut into).expect("take"), None);
        far.write_all(&frame::lay(5)[2..]).expect("rest of prefix");
        assert_eq!(carrier.take(&mut into).expect("take"), None);
        far.write_all(&[1, 2, 3]).expect("part of the frame");
        assert_eq!(carrier.take(&mut into).expect("take"), None);

        far.write_all(&[4, 5]).expect("rest of the frame");
        assert_eq!(carrier.take(&mut into).expect("take the frame"), Some(5));
        assert_eq!(&into[..5], &[1, 2, 3, 4, 5]);
    }

    #[test]
    fn test_refuse_frame_while_sending() {
        // Buffers hold less than a frame, so the first write stops short.
        let (mut carrier, _far) = paired(1024);
        let big = vec![0xa5u8; MAX_FRAME];

        assert!(carrier.give(&big).expect("give the first frame"));
        assert!(
            !carrier.leaving.is_empty(),
            "first frame went out in one go"
        );
        assert_eq!(
            carrier.outside(),
            vec![(carrier.stream.as_raw_fd(), Interest::Both)],
            "Write was not waited on with a frame going out"
        );

        assert!(
            !carrier.give(b"one more").expect("give a second frame"),
            "second frame taken behind an unfinished one"
        );
        assert_eq!(
            carrier.leaving.len(),
            PREFIX + MAX_FRAME,
            "second frame appended to leaving"
        );
    }

    #[test]
    fn test_drop_overlong_frame() {
        let (mut carrier, mut far) = paired(65536);
        assert!(
            carrier
                .give(&vec![0u8; MAX_FRAME + 1])
                .expect("give an overlong frame"),
            "overlong frame not dropped"
        );
        assert!(heard(&mut far).is_empty(), "overlong frame was written");
        assert!(carrier.leaving.is_empty());
    }

    #[test]
    fn test_resume_partial_write() {
        let (mut carrier, mut far) = paired(1024);
        let big = vec![0xa5u8; MAX_FRAME];
        assert!(carrier.give(&big).expect("give the first frame"));
        assert!(!carrier.leaving.is_empty(), "frame went out in one go");

        // Reading at `far` makes room for the rest.
        let mut taken = 0;
        for _ in 0..10_000 {
            taken += heard(&mut far).len();
            if carrier.resume().expect("resume") {
                break;
            }
        }
        assert!(carrier.leaving.is_empty(), "frame did not finish going out");
        taken += heard(&mut far).len();
        assert_eq!(taken, PREFIX + MAX_FRAME, "far end read a different length");

        // With `leaving` empty, next frame is taken.
        assert!(carrier.give(b"one more").expect("give the next frame"));
    }

    #[test]
    fn test_read_interest_while_idle() {
        let (carrier, _far) = paired(65536);
        assert_eq!(
            carrier.outside(),
            vec![(carrier.stream.as_raw_fd(), Interest::Read)]
        );
    }

    #[test]
    fn test_reject_bad_length_prefix() {
        let (mut carrier, mut far) = paired(65536);
        far.write_all(&u32::MAX.to_be_bytes())
            .expect("write a bad prefix");
        let mut into = vec![0u8; MAX_FRAME];
        assert_eq!(
            carrier
                .take(&mut into)
                .expect_err("bad prefix accepted")
                .kind(),
            io::ErrorKind::InvalidData
        );
    }

    #[test]
    fn test_drop_frame_without_room() {
        let (mut carrier, mut far) = paired(65536);
        far.write_all(&frame::lay(5)).expect("write the prefix");
        far.write_all(b"hello").expect("send the frame");

        let mut cramped = [0u8; 4];
        assert_eq!(carrier.take(&mut cramped).expect("take"), None);
        // Dropped frame is gone from the stream, not left half read.
        let mut into = vec![0u8; MAX_FRAME];
        assert_eq!(carrier.take(&mut into).expect("take again"), None);
    }
}
