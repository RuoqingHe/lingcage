// SPDX-FileCopyrightText: 2026 LingCage <opensource@lingcage.com>
//
// SPDX-License-Identifier: Apache-2.0

//! Host end of a vsock connection. The device is given an [`Endpoint`]
//! by the embedding program, a port not served by it is refused.

use std::io::{self, Read, Write};
use std::os::unix::net::UnixStream;
use std::path::PathBuf;

/// Host stream of one connection, read without blocking through
/// [`read`].
pub trait Stream: Read + Write + Send {}

impl<S: Read + Write + Send> Stream for S {}

/// Host side which a guest port connects to.
pub trait Endpoint: Send {
    /// Open a connection to `port`. Returns `None` for a port not served.
    fn connect(&self, port: u32) -> Option<Box<dyn Stream>>;
}

/// Endpoint which connects each port to Unix socket `<prefix>_<port>`.
pub struct Sockets {
    prefix: PathBuf,
}

impl Sockets {
    /// Create the endpoint for sockets named after `prefix`.
    pub fn new(prefix: impl Into<PathBuf>) -> Self {
        Sockets {
            prefix: prefix.into(),
        }
    }

    /// Returns path of the socket for `port`.
    fn named(&self, port: u32) -> PathBuf {
        let mut path = self.prefix.clone().into_os_string();
        path.push(format!("_{port}"));
        PathBuf::from(path)
    }
}

impl Endpoint for Sockets {
    fn connect(&self, port: u32) -> Option<Box<dyn Stream>> {
        let stream = UnixStream::connect(self.named(port)).ok()?;
        // Blocking read would stall the thread which serves other connections.
        stream.set_nonblocking(true).ok()?;
        Some(Box::new(stream))
    }
}

/// Endpoint which serves no port.
pub struct Closed;

impl Endpoint for Closed {
    fn connect(&self, _port: u32) -> Option<Box<dyn Stream>> {
        None
    }
}

/// Write `bytes` to `stream`. Returns count written, zero on
/// `WouldBlock`.
pub fn write(stream: &mut dyn Stream, bytes: &[u8]) -> io::Result<usize> {
    match stream.write(bytes) {
        Ok(taken) => Ok(taken),
        Err(err) if err.kind() == io::ErrorKind::WouldBlock => Ok(0),
        Err(err) => Err(err),
    }
}

/// Read from `stream` into `into`. Returns zero on `WouldBlock`.
pub fn read(stream: &mut dyn Stream, into: &mut [u8]) -> io::Result<usize> {
    match stream.read(into) {
        Ok(taken) => Ok(taken),
        Err(err) if err.kind() == io::ErrorKind::WouldBlock => Ok(0),
        Err(err) => Err(err),
    }
}
