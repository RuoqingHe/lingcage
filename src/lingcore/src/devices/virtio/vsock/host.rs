// SPDX-FileCopyrightText: 2026 LingCage <opensource@lingcage.com>
//
// SPDX-License-Identifier: Apache-2.0

//! Host end of a vsock connection. The device is given an [`Endpoint`]
//! by the embedding program, a port not served by it is refused.
//!
//! Host process connects with the line `CONNECT <port>`, [`acknowledge`]
//! replies `OK <port>` once the connection is open.

use std::io::{self, Read, Write};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::PathBuf;

use log::warn;

/// First word of an incoming connection line, matched case insensitive.
const CONNECT: &str = "connect";

/// First word of the reply to an incoming connection taken by the guest.
const TAKEN: &str = "OK";

/// Longest incoming connection line accepted, longer one is dropped.
const LINE: usize = 32;

/// Incoming connections held half way through their line, also the most
/// `admit` accepts in one call. The oldest ones are dropped beyond this
/// count.
const ARRIVALS: usize = 64;

/// Host stream of one connection, read and written without blocking.
pub trait Stream: Read + Write + Send {}

impl<S: Read + Write + Send> Stream for S {}

/// Host side which a guest port connects to, also the source of incoming
/// connections.
pub trait Endpoint: Send {
    /// Open a connection to `port`. Returns `None` for a port not served.
    fn connect(&self, port: u32) -> Option<Box<dyn Stream>>;

    /// Returns the guest port named by an incoming connection together with
    /// its stream, or `None` while no incoming connection has finished its
    /// line.
    fn incoming(&mut self) -> Option<(u32, Box<dyn Stream>)>;
}

/// Endpoint which connects each port to Unix socket `<prefix>_<port>`.
/// Incoming connections are accepted on `<prefix>` itself when it is
/// bound by `Sockets::listening`.
pub struct Sockets {
    prefix: PathBuf,
    /// Socket to accept incoming connections on. `None` for an endpoint
    /// created by `new`.
    listener: Option<UnixListener>,
    /// Incoming connections with the line read so far. A line may arrive in
    /// pieces across calls to `incoming`.
    arriving: Vec<(UnixStream, Vec<u8>)>,
}

impl Sockets {
    /// Create the endpoint for sockets named after `prefix`.
    pub fn new(prefix: impl Into<PathBuf>) -> Self {
        Sockets {
            prefix: prefix.into(),
            listener: None,
            arriving: Vec::new(),
        }
    }

    /// Create the endpoint like `new` does, and bind `prefix` itself for
    /// incoming connections. A name already bound is refused instead of
    /// unlinked, since it may belong to another guest.
    pub fn listening(prefix: impl Into<PathBuf>) -> io::Result<Self> {
        let prefix = prefix.into();
        let listener = UnixListener::bind(&prefix)?;
        // Blocking accept would stall the thread which serves connections.
        listener.set_nonblocking(true)?;
        Ok(Sockets {
            prefix,
            listener: Some(listener),
            arriving: Vec::new(),
        })
    }

    /// Returns path of the socket for `port`.
    fn named(&self, port: u32) -> PathBuf {
        let mut path = self.prefix.clone().into_os_string();
        path.push(format!("_{port}"));
        PathBuf::from(path)
    }

    /// Accept incoming connections waiting on the listener, at most
    /// `ARRIVALS`, and drop the oldest ones held beyond `ARRIVALS`.
    fn admit(&mut self) {
        let Some(listener) = &self.listener else {
            return;
        };
        let mut arrived = Vec::new();
        while arrived.len() < ARRIVALS {
            match listener.accept() {
                Ok((stream, _)) => match stream.set_nonblocking(true) {
                    Ok(()) => arrived.push((stream, Vec::new())),
                    Err(err) => warn!("incoming connection dropped, set_nonblocking failed: {err}"),
                },
                Err(err) if err.kind() == io::ErrorKind::WouldBlock => break,
                Err(err) => {
                    warn!("failed to accept on incoming connection socket: {err}");
                    break;
                }
            }
        }
        self.arriving.extend(arrived);
        // Oldest incoming connections are the least likely to finish their
        // line.
        let over = self.arriving.len().saturating_sub(ARRIVALS);
        if over > 0 {
            warn!("{over} oldest incoming connections dropped to make room");
            self.arriving.drain(..over);
        }
    }

    /// Returns the port named by the first incoming connection with a
    /// complete line, together with its stream. Incoming connection which
    /// named no port, reached `LINE` or closed is dropped.
    fn spoken(&mut self) -> Option<(u32, UnixStream)> {
        let mut index = 0;
        while index < self.arriving.len() {
            let (stream, line) = &mut self.arriving[index];
            if !fill(stream, line) {
                index += 1;
                continue;
            }
            let (stream, line) = self.arriving.remove(index);
            match port_named(&line) {
                Some(port) => return Some((port, stream)),
                None => warn!("incoming connection names no port, dropped"),
            }
        }
        None
    }
}

impl Endpoint for Sockets {
    fn connect(&self, port: u32) -> Option<Box<dyn Stream>> {
        let stream = UnixStream::connect(self.named(port)).ok()?;
        // Blocking read would stall the thread which serves other connections.
        stream.set_nonblocking(true).ok()?;
        Some(Box::new(stream))
    }

    fn incoming(&mut self) -> Option<(u32, Box<dyn Stream>)> {
        self.admit();
        let (port, stream) = self.spoken()?;
        Some((port, Box::new(stream)))
    }
}

/// Endpoint which serves no port.
pub struct Closed;

impl Endpoint for Closed {
    fn connect(&self, _port: u32) -> Option<Box<dyn Stream>> {
        None
    }

    fn incoming(&mut self) -> Option<(u32, Box<dyn Stream>)> {
        None
    }
}

/// Read `line` from `stream` one byte at a time, so that bytes after the
/// newline stay in the stream for the connection. Returns `true` once
/// the line ended, reached `LINE`, or the stream closed.
fn fill(stream: &mut UnixStream, line: &mut Vec<u8>) -> bool {
    let mut byte = [0u8; 1];
    loop {
        match stream.read(&mut byte) {
            // Closed before the line ended.
            Ok(0) => return true,
            Ok(_) => {
                line.push(byte[0]);
                if byte[0] == b'\n' || line.len() >= LINE {
                    return true;
                }
            }
            // Rest of the line comes on a later call.
            Err(err) if err.kind() == io::ErrorKind::WouldBlock => return false,
            Err(err) => {
                warn!("incoming connection dropped, failed to read: {err}");
                return true;
            }
        }
    }
}

/// Returns the port named by an incoming connection line, or `None` if
/// the line is not `CONNECT <port>`.
fn port_named(line: &[u8]) -> Option<u32> {
    let mut words = std::str::from_utf8(line).ok()?.split_whitespace();
    if !words.next()?.eq_ignore_ascii_case(CONNECT) {
        return None;
    }
    words.next()?.parse().ok()
}

/// Write `OK <port>` to `stream`, the reply to an incoming connection
/// taken by the guest. The whole line is written in one call, otherwise
/// a partial line would be taken as bytes of the guest.
pub fn acknowledge(stream: &mut dyn Stream, port: u32) -> io::Result<()> {
    stream.write_all(format!("{TAKEN} {port}\n").as_bytes())
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

#[cfg(test)]
mod tests {
    use crate::devices::virtio::vsock::host::*;

    /// Returns a fresh socket path under temp dir.
    fn unbound(tag: &str) -> PathBuf {
        let path = std::env::temp_dir().join(format!(
            "lingcore-connect-{tag}-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        // Leftover of a previous interrupted run would make the bind fail.
        match std::fs::remove_file(&path) {
            Ok(()) => {}
            Err(err) if err.kind() == io::ErrorKind::NotFound => {}
            Err(err) => panic!("failed to remove {path:?}: {err}"),
        }
        path
    }

    /// Returns an endpoint bound at a fresh path, together with the path to
    /// unlink.
    fn listening(tag: &str) -> (Sockets, PathBuf) {
        let path = unbound(tag);
        let sockets = Sockets::listening(&path).expect("bind incoming connection socket");
        (sockets, path)
    }

    /// Connect to `path` and write `line`.
    fn connect(path: &PathBuf, line: &[u8]) -> UnixStream {
        let mut stream = UnixStream::connect(path).expect("connect in");
        stream.write_all(line).expect("name a port");
        stream
    }

    #[test]
    fn test_connect_only_endpoint_no_incoming() {
        let mut sockets = Sockets::new("/nowhere");
        assert!(sockets.incoming().is_none());
        assert!(Closed.incoming().is_none());
    }

    #[test]
    fn test_incoming_names_port() {
        let (mut sockets, path) = listening("named");
        let _held = connect(&path, b"CONNECT 1234\n");
        let (port, _stream) = sockets.incoming().expect("port named");
        assert_eq!(port, 1234);
        // The only incoming connection was taken, next call finds none.
        assert!(sockets.incoming().is_none());
        std::fs::remove_file(&path).expect("remove the socket");
    }

    #[test]
    fn test_incoming_line_in_pieces() {
        let (mut sockets, path) = listening("pieces");
        let mut stream = connect(&path, b"CONNECT ");
        assert!(sockets.incoming().is_none());
        stream.write_all(b"7\n").expect("finish the line");
        let (port, _stream) = sockets.incoming().expect("port named");
        assert_eq!(port, 7);
        std::fs::remove_file(&path).expect("remove the socket");
    }

    #[test]
    fn test_bytes_after_line_kept() {
        let (mut sockets, path) = listening("past");
        let _held = connect(&path, b"CONNECT 9\nhello");
        let (port, mut stream) = sockets.incoming().expect("port named");
        assert_eq!(port, 9);
        let mut said = [0u8; 5];
        assert_eq!(stream.read(&mut said).expect("read what follows"), 5);
        assert_eq!(&said, b"hello");
        std::fs::remove_file(&path).expect("remove the socket");
    }

    #[test]
    fn test_reject_line_without_port() {
        let (mut sockets, path) = listening("nonsense");
        let _held = connect(&path, b"hello there\n");
        assert!(sockets.incoming().is_none());
        // Incoming connection was dropped instead of held.
        assert!(sockets.incoming().is_none());
        std::fs::remove_file(&path).expect("remove the socket");
    }

    #[test]
    fn test_reject_overlong_line() {
        let (mut sockets, path) = listening("long");
        let _held = connect(&path, &[b'x'; LINE * 2]);
        assert!(sockets.incoming().is_none());
        std::fs::remove_file(&path).expect("remove the socket");
    }

    #[test]
    fn test_drop_closed_before_line_ends() {
        let (mut sockets, path) = listening("gone");
        drop(connect(&path, b"CONNECT"));
        assert!(sockets.incoming().is_none());
        assert!(sockets.arriving.is_empty());
        std::fs::remove_file(&path).expect("remove the socket");
    }

    #[test]
    fn test_oldest_dropped_beyond_arrivals() {
        let (mut sockets, path) = listening("room");
        // Connected but silent, so none of them finishes a line.
        let silent: Vec<UnixStream> = (0..ARRIVALS)
            .map(|_| UnixStream::connect(&path).expect("connect in"))
            .collect();
        assert!(sockets.incoming().is_none());
        assert_eq!(sockets.arriving.len(), ARRIVALS);

        // One over `ARRIVALS`. Oldest one is dropped and the newest one,
        // which names a port, is taken.
        let _newest = connect(&path, b"CONNECT 5\n");
        assert_eq!(sockets.incoming().expect("port named").0, 5);
        assert_eq!(sockets.arriving.len(), ARRIVALS - 1);

        drop(silent);
        std::fs::remove_file(&path).expect("remove the socket");
    }

    #[test]
    fn test_acknowledge_with_port() {
        let (mut ours, mut theirs) = UnixStream::pair().expect("pair of ends");
        acknowledge(&mut ours, 4321).expect("acknowledge incoming connection");
        let mut said = [0u8; 8];
        theirs.read_exact(&mut said).expect("read the answer");
        assert_eq!(&said, b"OK 4321\n");
    }
}
