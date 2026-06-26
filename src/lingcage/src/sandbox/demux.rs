// SPDX-FileCopyrightText: 2026 LingCage <opensource@lingcage.com>
//
// SPDX-License-Identifier: Apache-2.0

//! Demux of sandbox control connection. Each connection has one reader
//! thread, frames are routed to pending requests by id, writes share one
//! lock.

use std::collections::HashMap;
use std::fs::File;
use std::os::fd::{AsRawFd, OwnedFd};
use std::os::unix::net::{UnixListener, UnixStream};
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::sync::{Arc, Mutex, mpsc};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use crate::error::{Error, Result};
use crate::lcp;
use crate::sandbox::{Identity, draw};

/// First request id. Host side uses odd ids, incremented by 2.
const FIRST_ID: u32 = 1;

/// Maximum time a frame write may take. The write holds the connection
/// lock, without this timeout a guest which stops reading would block
/// other callers indefinitely.
const WRITE_WITHIN: Duration = Duration::from_secs(5);

/// Live connection, holding the stream read by reader thread, the file
/// frames are written to, and the generation set during handshake.
struct Link {
    stream: Arc<UnixStream>,
    out: File,
    generation: u64,
}

/// Control connection of a sandbox. It keeps pending requests, id counter,
/// the live connection and the threads serving it.
pub struct Demux {
    /// Answer channel of each pending request, with the generation it was
    /// registered on.
    pending: Mutex<HashMap<u32, (u64, mpsc::Sender<lcp::Frame>)>>,
    next_id: AtomicU32,
    link: Mutex<Option<Link>>,
    /// Identity sent to guest on each connection.
    identity: Identity,
    listener: UnixListener,
    stop: AtomicBool,
    reader: Mutex<Option<JoinHandle<()>>>,
}

impl Demux {
    /// Create a demux on the control listener. First connection is accepted
    /// by `identify_first`.
    pub fn new(listener: UnixListener, identity: Identity) -> Demux {
        Demux {
            pending: Mutex::new(HashMap::new()),
            next_id: AtomicU32::new(FIRST_ID),
            link: Mutex::new(None),
            identity,
            listener,
            stop: AtomicBool::new(false),
            reader: Mutex::new(None),
        }
    }

    /// Allocate a new request id.
    fn next(&self) -> u32 {
        self.next_id.fetch_add(2, Ordering::Relaxed)
    }

    /// Send `frame` with a new id, returns the id and the answer channel.
    /// The channel is closed once the connection used by this request ends
    /// or is replaced.
    pub fn request(&self, mut frame: lcp::Frame) -> Result<(u32, mpsc::Receiver<lcp::Frame>)> {
        let mut link = self.link.lock().unwrap();
        let link = link
            .as_mut()
            .ok_or(Error::Protocol(lcp::Error::Truncated))?;
        let id = self.next();
        frame.id = id;
        let (tx, rx) = mpsc::channel();
        self.pending
            .lock()
            .unwrap()
            .insert(id, (link.generation, tx));
        if let Err(err) = frame.write_to(&mut link.out) {
            self.pending.lock().unwrap().remove(&id);
            return Err(Error::Protocol(err));
        }
        Ok((id, rx))
    }

    /// Send one request and wait for its answer for at most `within`, so a
    /// guest which keeps the connection open but writes no reply only costs
    /// the caller that much time.
    pub fn ask(&self, frame: lcp::Frame, within: Duration) -> Result<lcp::Frame> {
        let (id, rx) = self.request(frame)?;
        let answer = rx.recv_timeout(within).map_err(|err| match err {
            mpsc::RecvTimeoutError::Timeout => Error::Timeout("answer from agent"),
            mpsc::RecvTimeoutError::Disconnected => Error::Protocol(lcp::Error::Truncated),
        });
        self.complete(id);
        answer
    }

    /// Write `frame` to live connection, no answer channel registered.
    pub fn tell(&self, frame: lcp::Frame) -> Result<()> {
        let mut link = self.link.lock().unwrap();
        let link = link
            .as_mut()
            .ok_or(Error::Protocol(lcp::Error::Truncated))?;
        frame.write_to(&mut link.out).map_err(Error::Protocol)
    }

    /// Write a one-way frame with empty payload, using a new id.
    pub fn tell_with_new_id(&self, kind: u16, flags: u8) -> Result<()> {
        let id = self.next();
        self.tell(lcp::Frame {
            id,
            kind,
            flags,
            payload: Vec::new(),
        })
    }

    /// Unregister request with given id.
    pub fn complete(&self, id: u32) {
        self.pending.lock().unwrap().remove(&id);
    }

    /// Close answer channels of requests made on `generation`, and drop the
    /// connection if it is still the live one. Otherwise a request written
    /// to a connection without reader would wait for an answer forever.
    fn fail(&self, generation: u64) {
        self.pending
            .lock()
            .unwrap()
            .retain(|_, (made_on, _)| *made_on != generation);
        let mut link = self.link.lock().unwrap();
        if link
            .as_ref()
            .is_some_and(|live| live.generation == generation)
        {
            *link = None;
        }
    }

    /// Accept the first connection and run the handshake as generation 1.
    /// Returns hostname from IDENTIFIED frame of guest.
    pub fn identify_first(self: &Arc<Self>, deadline: Instant) -> Result<String> {
        let stream = accept_within(&self.listener, deadline, "incoming connection from agent")?;
        let hostname = identify(&stream, &self.identity, 1, deadline)?;
        self.install(stream, 1)?;
        Ok(hostname)
    }

    /// Install `stream` as the live connection, replacing the old one.
    /// Requests made on old connection are failed, and its reader thread
    /// exits as the stream is shut down.
    fn install(self: &Arc<Self>, stream: UnixStream, generation: u64) -> Result<()> {
        stream.set_read_timeout(None).map_err(Error::Io)?;
        stream
            .set_write_timeout(Some(WRITE_WITHIN))
            .map_err(Error::Io)?;
        let stream = Arc::new(stream);
        let out = File::from(OwnedFd::from(stream.try_clone().map_err(Error::Io)?));
        let reader = std::thread::spawn({
            let demux = Arc::clone(self);
            let reading = Arc::clone(&stream);
            move || demux.read_loop(&reading, generation)
        });
        let old = {
            let mut link = self.link.lock().unwrap();
            *self.reader.lock().unwrap() = Some(reader);
            link.replace(Link {
                stream,
                out,
                generation,
            })
        };
        if let Some(old) = old {
            // Old reader would fail its requests when it exits, but
            // clear them here right away so that callers do not have to
            // wait for the reader to notice.
            self.fail(old.generation);
            if let Err(err) = old.stream.shutdown(std::net::Shutdown::Both) {
                log::debug!("failed to shut down replaced connection: {err}");
            }
        }
        Ok(())
    }

    /// Route incoming frames until the connection ends, then close answer
    /// channels of requests made on this connection.
    fn read_loop(&self, stream: &UnixStream, generation: u64) {
        loop {
            match lcp::Frame::read_from(&mut &*stream) {
                Ok(frame) => self.route(frame, generation),
                Err(err) => {
                    self.fail(generation);
                    log::debug!("control connection {generation} ended: {err}");
                    return;
                }
            }
        }
    }

    /// Deliver one frame to the pending request with matching id.
    fn route(&self, frame: lcp::Frame, generation: u64) {
        let pending = self.pending.lock().unwrap();
        match pending.get(&frame.id) {
            Some((made_on, tx)) if *made_on == generation => {
                if let Err(unsent) = tx.send(frame) {
                    log::warn!("no waiter for answer of request {}", unsent.0.id);
                }
            }
            _ => log::debug!("no waiter for frame of request {}", frame.id),
        }
    }

    /// Stop the threads and close remaining answer channels.
    pub fn stop(&self) {
        self.stop.store(true, Ordering::SeqCst);
        if let Some(link) = self.link.lock().unwrap().take()
            && let Err(err) = link.stream.shutdown(std::net::Shutdown::Both)
        {
            log::debug!("failed to shut down control connection: {err}");
        }
        if let Some(reader) = self.reader.lock().unwrap().take()
            && reader.join().is_err()
        {
            log::warn!("reader thread panicked");
        }
        self.pending.lock().unwrap().clear();
    }
}

/// Accept one connection on `listener`, returns `Error::Timeout` if
/// `deadline` is reached first.
pub fn accept_within(
    listener: &UnixListener,
    deadline: Instant,
    what: &'static str,
) -> Result<UnixStream> {
    loop {
        let left = deadline.saturating_duration_since(Instant::now());
        if left.is_zero() {
            return Err(Error::Timeout(what));
        }
        let mut polled = libc::pollfd {
            fd: listener.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        };
        let ms = i32::try_from(left.as_millis()).unwrap_or(i32::MAX);
        // SAFETY: `polled` is a valid pollfd and stays alive during the call.
        let ready = unsafe { libc::poll(&mut polled, 1, ms) };
        match ready.cmp(&0) {
            std::cmp::Ordering::Greater => {
                return listener
                    .accept()
                    .map(|(stream, _)| stream)
                    .map_err(Error::Io);
            }
            std::cmp::Ordering::Equal => return Err(Error::Timeout(what)),
            std::cmp::Ordering::Less => {
                let err = std::io::Error::last_os_error();
                if err.kind() != std::io::ErrorKind::Interrupted {
                    return Err(Error::Io(err));
                }
            }
        }
    }
}

/// Nanoseconds since Unix epoch, used as `unix_nanos` of IDENTIFY frame.
fn nanos_now() -> u64 {
    u64::try_from(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|span| span.as_nanos())
            .unwrap_or(0),
    )
    .unwrap_or(u64::MAX)
}

/// Run the handshake (READY, IDENTIFY, IDENTIFIED) on a fresh connection.
/// Returns the hostname the guest sends in IDENTIFIED.
fn identify(
    stream: &UnixStream,
    identity: &Identity,
    generation: u64,
    deadline: Instant,
) -> Result<String> {
    let first = crate::deadline::frame(stream, deadline, "ready frame")?;
    if first.kind != lcp::kind::READY || first.flags & lcp::flags::SESSION_START == 0 {
        return Err(Error::Agent {
            what: format!(
                "first frame is of kind {} with flags {:#04x}",
                first.kind, first.flags
            ),
        });
    }
    let ready: lcp::Ready = first.payload().map_err(Error::Protocol)?;
    if ready.protocol > lcp::PROTOCOL {
        return Err(Error::Agent {
            what: format!(
                "agent protocol is {} but this build is {}",
                ready.protocol,
                lcp::PROTOCOL
            ),
        });
    }
    log::debug!(
        "agent {} up in {} ms, boot id {}",
        ready.agent,
        ready.init_ms,
        ready.boot_id
    );
    let mut entropy = [0u8; 32];
    draw(&mut entropy)?;
    let identify = lcp::Identify {
        hostname: identity.hostname.clone(),
        machine_id: identity.machine_id.clone(),
        generation,
        entropy,
        unix_nanos: nanos_now(),
    };
    let frame = lcp::Frame::with_payload(first.id, lcp::kind::IDENTIFY, 0, &identify)
        .map_err(Error::Protocol)?;
    frame.write_to(&mut &*stream).map_err(Error::Protocol)?;
    let answer = crate::deadline::frame(stream, deadline, "identified frame")?;
    if answer.kind != lcp::kind::IDENTIFIED {
        return Err(Error::Agent {
            what: format!("handshake got kind {} instead of IDENTIFIED", answer.kind),
        });
    }
    let identified: lcp::Identified = answer.payload().map_err(Error::Protocol)?;
    Ok(identified.hostname)
}

#[cfg(test)]
mod tests {
    use std::io::Write as _;
    use std::path::PathBuf;
    use std::sync::atomic::AtomicUsize;

    use crate::sandbox::demux::*;

    /// Counter to make test socket dirs unique within one process.
    static DIRS: AtomicUsize = AtomicUsize::new(0);

    /// Identity of the guest used in tests.
    fn identity() -> Identity {
        Identity {
            cid: 3,
            hostname: "test".to_string(),
            machine_id: "0".repeat(32),
        }
    }

    /// Returns a demux on a new control socket and the dir to clean up.
    fn demux(tag: &str) -> (Arc<Demux>, PathBuf) {
        let dir = std::env::temp_dir().join(format!(
            "lingcage-demux-{tag}-{}-{}",
            std::process::id(),
            DIRS.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir_all(&dir).expect("create test dir");
        let at = dir.join("vs_1");
        let listener = UnixListener::bind(&at).expect("bind control socket");
        (Arc::new(Demux::new(listener, identity())), dir)
    }

    /// READY frame of an agent with protocol version `protocol`.
    fn ready(protocol: u16) -> lcp::Frame {
        lcp::Frame::with_payload(
            7,
            lcp::kind::READY,
            lcp::flags::SESSION_START,
            &lcp::Ready {
                agent: "test-agent".to_string(),
                protocol,
                uptime: 1.0,
                init_ms: 0,
                boot_id: "boot".to_string(),
            },
        )
        .expect("build ready frame")
    }

    #[test]
    fn test_route_interleaved_answers() {
        let (demux, dir) = demux("route");
        let (ours, mut theirs) = UnixStream::pair().expect("socket pair");
        demux.install(ours, 1).expect("install connection");
        let (first_id, first_rx) = demux
            .request(lcp::Frame::new(0, lcp::kind::PING, b"one".to_vec()))
            .expect("send first request");
        let (second_id, second_rx) = demux
            .request(lcp::Frame::new(0, lcp::kind::PING, b"two".to_vec()))
            .expect("send second request");
        assert_eq!((first_id, second_id), (1, 3), "ids are odd from 1");

        let one = lcp::Frame::read_from(&mut theirs).expect("read first request");
        let two = lcp::Frame::read_from(&mut theirs).expect("read second request");
        assert_eq!((one.id, two.id), (first_id, second_id));
        assert_eq!(
            (one.payload, two.payload),
            (b"one".to_vec(), b"two".to_vec())
        );

        // Answer the second request first, routing should still match by id.
        lcp::Frame::new(second_id, lcp::kind::PONG, b"second".to_vec())
            .write_to(&mut theirs)
            .expect("answer second request");
        lcp::Frame::new(first_id, lcp::kind::PONG, b"first".to_vec())
            .write_to(&mut theirs)
            .expect("answer first request");
        let second = second_rx
            .recv_timeout(Duration::from_secs(5))
            .expect("receive second answer");
        let first = first_rx
            .recv_timeout(Duration::from_secs(5))
            .expect("receive first answer");
        assert_eq!(second.payload, b"second");
        assert_eq!(first.payload, b"first");

        demux.stop();
        std::fs::remove_dir_all(&dir).expect("remove test dir");
    }

    #[test]
    fn test_dead_connection_dropped() {
        // Link should be cleared after the reader thread exits.
        let (demux, dir) = demux("dead");
        let (ours, theirs) = UnixStream::pair().expect("socket pair");
        demux.install(ours, 1).expect("install connection");
        // Close the guest end, reader thread should exit and drop the link.
        drop(theirs);
        let deadline = Instant::now() + Duration::from_secs(5);
        while demux.link.lock().unwrap().is_some() {
            assert!(Instant::now() < deadline, "dead connection is still live");
            std::thread::sleep(Duration::from_millis(10));
        }
        let refused = demux.request(lcp::Frame::new(0, lcp::kind::PING, Vec::new()));
        assert!(
            matches!(refused, Err(Error::Protocol(lcp::Error::Truncated))),
            "request sent on connection without reader: {refused:?}"
        );
        demux.stop();
        std::fs::remove_dir_all(&dir).expect("remove test dir");
    }

    #[test]
    fn test_reject_non_ready_first_frame() {
        let (ours, mut theirs) = UnixStream::pair().expect("socket pair");
        lcp::Frame::new(1, lcp::kind::PING, Vec::new())
            .write_to(&mut theirs)
            .expect("send non-ready frame");
        let refused = identify(
            &ours,
            &identity(),
            1,
            Instant::now() + Duration::from_secs(5),
        );
        assert!(
            matches!(refused, Err(Error::Agent { .. })),
            "non-ready first frame passed handshake"
        );
    }

    #[test]
    fn test_reject_newer_protocol() {
        let (ours, mut theirs) = UnixStream::pair().expect("socket pair");
        ready(lcp::PROTOCOL + 1)
            .write_to(&mut theirs)
            .expect("send ready");
        let refused = identify(
            &ours,
            &identity(),
            1,
            Instant::now() + Duration::from_secs(5),
        );
        assert!(
            matches!(refused, Err(Error::Agent { .. })),
            "newer protocol passed handshake"
        );
    }

    #[test]
    fn test_dribbled_frame_timeout() {
        // Deadline applies to a frame sent byte by byte.
        let (ours, mut theirs) = UnixStream::pair().expect("socket pair");
        let wire = {
            let mut wire = Vec::new();
            ready(lcp::PROTOCOL)
                .write_to(&mut wire)
                .expect("code ready");
            wire
        };
        let dribbling = std::thread::spawn(move || {
            for byte in wire {
                if theirs.write_all(&[byte]).is_err() {
                    return;
                }
                std::thread::sleep(Duration::from_millis(20));
            }
        });
        let deadline = Instant::now() + Duration::from_millis(100);
        let refused = identify(&ours, &identity(), 1, deadline);
        assert!(
            matches!(refused, Err(Error::Timeout(_))),
            "frame sent byte by byte passed deadline: {refused:?}"
        );
        assert!(
            Instant::now() < deadline + Duration::from_millis(500),
            "handshake did not stop at deadline"
        );
        dribbling.join().expect("dribbling agent panicked");
    }

    #[test]
    fn test_silent_connection_timeout() {
        let (ours, _theirs) = UnixStream::pair().expect("socket pair");
        let deadline = Instant::now() + Duration::from_millis(50);
        let refused = identify(&ours, &identity(), 1, deadline);
        assert!(
            matches!(refused, Err(Error::Timeout(_))),
            "silent connection did not time out"
        );
    }

    #[test]
    fn test_request_without_connection() {
        // Request without live connection should be a protocol error.
        let (demux, dir) = demux("nolink");
        let refused = demux.request(lcp::Frame::new(0, lcp::kind::PING, Vec::new()));
        assert!(matches!(
            refused,
            Err(Error::Protocol(lcp::Error::Truncated))
        ));
        demux.stop();
        std::fs::remove_dir_all(&dir).expect("remove test dir");
    }
}
