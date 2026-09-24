// SPDX-FileCopyrightText: 2026 LingCage <opensource@lingcage.com>
//
// SPDX-License-Identifier: Apache-2.0

//! Console output a vCPU writes without waiting on a reader. `Backlog` is
//! the sink given to the machine, and `Output` writes the kept bytes out on
//! a thread of the caller.

use std::collections::VecDeque;
use std::io::{self, Write};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::os::unix::fs::OpenOptionsExt;
use std::sync::{Arc, Mutex};

use log::{debug, warn};

/// Bytes kept while the descriptor takes none. Past this count the oldest
/// bytes are dropped.
const BACKLOG: usize = 64 << 10;

/// Console sink of a guest, given to the machine. A write goes to the
/// descriptor while the backlog is empty and it takes bytes, and is kept
/// otherwise. Once the output ended, a write is dropped.
pub struct Backlog(Arc<Inner>);

/// Host end of a backlog, writing kept bytes to a descriptor without waiting
/// on a reader. The caller polls `wake_fd`, and `descriptor` while it is
/// `Some`, and calls `write_out` once either is ready.
pub struct Output {
    inner: Arc<Inner>,
    /// Last write would have blocked, so the descriptor is waited on.
    full: bool,
}

/// State shared by an output and its backlogs.
struct Inner {
    state: Mutex<State>,
    target: Target,
    /// eventfd written once bytes are kept.
    wake: OwnedFd,
}

/// Bytes kept, and the count of bytes dropped.
struct State {
    /// Bytes the descriptor did not take yet, oldest first.
    bytes: VecDeque<u8>,
    /// Count of bytes dropped, past `BACKLOG` or once the output ended.
    dropped: u64,
    /// Error the descriptor failed with, logged on drop.
    failed: Option<io::Error>,
    /// Set once the descriptor failed or the output was dropped. Bytes are
    /// dropped then.
    ended: bool,
}

/// Descriptor written to. A write to it does not wait on a reader.
enum Target {
    /// Pipe or terminal opened again through `/proc/self/fd` with
    /// `O_NONBLOCK`. Flags of the descriptor stay as they are.
    Reopened(OwnedFd),
    /// Descriptor not opened again. `O_NONBLOCK` is set on the descriptor
    /// itself, and `Output` restores `flags` on drop.
    Flagged { fd: RawFd, flags: libc::c_int },
}

impl Target {
    /// Target for the descriptor `fd`.
    fn of(fd: RawFd) -> io::Result<Target> {
        // SAFETY: a zeroed stat is filled by `fstat` before use.
        let mut stat: libc::stat = unsafe { std::mem::zeroed() };
        // SAFETY: `stat` is a valid stat to fill.
        if unsafe { libc::fstat(fd, &mut stat) } == -1 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: `isatty` takes a descriptor and touches no memory.
        let terminal = unsafe { libc::isatty(fd) } == 1;
        // Only pipe or terminal is opened again. File opened again would write
        // from offset 0. Socket cannot be opened.
        if stat.st_mode & libc::S_IFMT != libc::S_IFIFO && !terminal {
            return Target::flagged(fd);
        }
        // `/dev/tty` opened again is the controlling terminal of this
        // process. `/dev/ptmx` opened again makes a new terminal.
        if stat.st_rdev == libc::makedev(5, 0) || stat.st_rdev == libc::makedev(5, 2) {
            debug!("descriptor {fd} is /dev/tty or a pty master, not opened again");
            return Target::flagged(fd);
        }
        // Flags belong to an open file description. This one is new, so
        // `O_NONBLOCK` does not reach other users of the descriptor.
        let reopened = std::fs::OpenOptions::new()
            .write(true)
            .custom_flags(libc::O_NONBLOCK)
            .open(format!("/proc/self/fd/{fd}"));
        match reopened {
            Ok(file) => Ok(Target::Reopened(OwnedFd::from(file))),
            Err(err) => {
                // Reopen is refused for a descriptor of another user, a FIFO
                // with no reader or no `/proc`.
                debug!("descriptor {fd} not opened again: {err}");
                Target::flagged(fd)
            }
        }
    }

    /// Target for the descriptor `fd` with `O_NONBLOCK` set on it.
    fn flagged(fd: RawFd) -> io::Result<Target> {
        // SAFETY: `fcntl` takes a descriptor and a command.
        let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
        if flags == -1 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: `fcntl` takes a descriptor, a command and the flags to set.
        if unsafe { libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) } == -1 {
            return Err(io::Error::last_os_error());
        }
        Ok(Target::Flagged { fd, flags })
    }

    /// Write `bytes` and return the count written. It fails with
    /// `WouldBlock` instead of waiting on a reader.
    fn write(&self, bytes: &[u8]) -> io::Result<usize> {
        // SAFETY: `bytes` is valid for reads of its length.
        let written = unsafe { libc::write(self.fd(), bytes.as_ptr().cast(), bytes.len()) };
        if written < 0 {
            return Err(io::Error::last_os_error());
        }
        if written == 0 {
            return Err(io::ErrorKind::WriteZero.into());
        }
        Ok(written as usize)
    }

    /// Returns the descriptor written to.
    fn fd(&self) -> RawFd {
        match self {
            Target::Reopened(fd) => fd.as_raw_fd(),
            Target::Flagged { fd, .. } => *fd,
        }
    }
}

impl State {
    /// End output on `err`. Output logs `err` and counts kept bytes on drop.
    fn fail(&mut self, err: io::Error) {
        self.failed = Some(err);
        self.ended = true;
    }
}

impl Write for Backlog {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let inner = &self.0;
        let mut state = inner.state.lock().unwrap();
        let mut rest = buf;
        // A vCPU writes while the backlog is empty.
        if state.bytes.is_empty() {
            while !rest.is_empty() && !state.ended {
                match inner.target.write(rest) {
                    Ok(count) => rest = &rest[count..],
                    Err(err) if err.kind() == io::ErrorKind::Interrupted => {}
                    Err(err) if err.kind() == io::ErrorKind::WouldBlock => break,
                    Err(err) => state.fail(err),
                }
            }
        }
        if state.ended {
            state.dropped += rest.len() as u64;
            return Ok(buf.len());
        }
        // Past `BACKLOG` the oldest bytes are dropped, kept ones first.
        let was_empty = state.bytes.is_empty();
        let over = (state.bytes.len() + rest.len()).saturating_sub(BACKLOG);
        let old = over.min(state.bytes.len());
        state.bytes.drain(..old);
        state.bytes.extend(&rest[over - old..]);
        state.dropped += over as u64;
        if was_empty && !state.bytes.is_empty() {
            let one = 1u64.to_ne_bytes();
            // SAFETY: `one` is 8 bytes, the width an eventfd write takes. A
            // write fails only on a full count, and the eventfd is readable
            // then as well, so the result is ignored.
            unsafe { libc::write(inner.wake.as_raw_fd(), one.as_ptr().cast(), 8) };
        }
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

/// Returns a new eventfd.
fn eventfd() -> io::Result<OwnedFd> {
    // SAFETY: `eventfd(2)` takes a count and flags and returns a descriptor
    // or -1.
    let fd = unsafe { libc::eventfd(0, libc::EFD_NONBLOCK | libc::EFD_CLOEXEC) };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: `fd` was just opened and has no other owner.
    Ok(unsafe { OwnedFd::from_raw_fd(fd) })
}

impl Output {
    /// Output to `fd`, opened again before any allowlist goes on. Otherwise
    /// `fd` gets `O_NONBLOCK` until output is dropped. Caller keeps one
    /// output per descriptor, `fd` open and SIGPIPE ignored.
    pub fn new(fd: RawFd) -> io::Result<Self> {
        // Eventfd goes first, so a failure does not change the flags of `fd`.
        let wake = eventfd()?;
        let state = State {
            bytes: VecDeque::new(),
            dropped: 0,
            failed: None,
            ended: false,
        };
        Ok(Output {
            inner: Arc::new(Inner {
                state: Mutex::new(state),
                target: Target::of(fd)?,
                wake,
            }),
            full: false,
        })
    }

    /// Returns a sink keeping bytes for this output, to give the machine.
    /// Sink of a dropped output writes nothing, so the caller keeps the
    /// output while the machine runs.
    pub fn backlog(&self) -> Backlog {
        Backlog(Arc::clone(&self.inner))
    }

    /// Returns an eventfd readable once bytes are kept.
    pub fn wake_fd(&self) -> RawFd {
        self.inner.wake.as_raw_fd()
    }

    /// Returns the descriptor to poll for writing. It is `None` unless the
    /// descriptor took no more bytes on the last `write_out`.
    pub fn descriptor(&self) -> Option<RawFd> {
        if self.full {
            Some(self.inner.target.fd())
        } else {
            None
        }
    }

    /// Write kept bytes until none is left or the descriptor takes no more.
    pub fn write_out(&mut self) {
        let mut count = [0u8; 8];
        // SAFETY: `count` is 8 bytes, the width an eventfd read fills. A read
        // of an eventfd at zero fails with `EAGAIN`, so the result is ignored.
        unsafe { libc::read(self.wake_fd(), count.as_mut_ptr().cast(), 8) };
        let mut state = self.inner.state.lock().unwrap();
        self.full = false;
        while !state.ended {
            let (front, _) = state.bytes.as_slices();
            if front.is_empty() {
                break;
            }
            match self.inner.target.write(front) {
                Ok(written) => {
                    state.bytes.drain(..written);
                }
                Err(err) if err.kind() == io::ErrorKind::Interrupted => {}
                Err(err) if err.kind() == io::ErrorKind::WouldBlock => {
                    self.full = true;
                    break;
                }
                Err(err) => state.fail(err),
            }
        }
    }
}

impl Drop for Output {
    fn drop(&mut self) {
        // Kept bytes and bytes given to a backlog later are dropped.
        let mut state = self.inner.state.lock().unwrap();
        state.dropped += state.bytes.len() as u64;
        state.ended = true;
        // Stderr may share the flags, so they are restored before the lines
        // below.
        if let Target::Flagged { fd, flags } = self.inner.target {
            // SAFETY: `fcntl` takes a descriptor, a command and the flags to
            // set.
            unsafe { libc::fcntl(fd, libc::F_SETFL, flags) };
        }
        if let Some(err) = &state.failed {
            warn!("console output dropped, write failed: {err}");
        }
        if state.dropped > 0 {
            warn!("{} bytes of console output dropped", state.dropped);
        }
    }
}

#[cfg(test)]
mod tests {
    use std::fs::File;
    use std::io::Read;
    use std::os::unix::net::UnixStream;

    use crate::devices::backlog::*;

    /// Returns both ends of a pipe and the count of bytes it takes.
    fn pipe() -> (File, File, usize) {
        let mut fds = [0; 2];
        // SAFETY: `fds` is a valid array of two descriptors.
        assert_eq!(unsafe { libc::pipe2(fds.as_mut_ptr(), libc::O_CLOEXEC) }, 0);
        // SAFETY: both descriptors were just opened and have no other owner.
        let (reader, writer) = unsafe { (File::from_raw_fd(fds[0]), File::from_raw_fd(fds[1])) };
        // The kernel rounds the size up to a page.
        // SAFETY: `fcntl` takes a descriptor, a command and a size.
        let size = unsafe { libc::fcntl(writer.as_raw_fd(), libc::F_SETPIPE_SZ, 4096) };
        assert!(size >= 4096, "pipe size {size}");
        (reader, writer, size as usize)
    }

    /// Returns `true` if `fd` is readable at once.
    fn readable(fd: RawFd) -> bool {
        let mut poll = libc::pollfd {
            fd,
            events: libc::POLLIN,
            revents: 0,
        };
        // SAFETY: `poll` is one valid pollfd.
        unsafe { libc::poll(&mut poll, 1, 0) == 1 }
    }

    /// Read what `reader` holds without waiting.
    fn take(reader: &mut File) -> Vec<u8> {
        let mut taken = Vec::new();
        let mut chunk = [0u8; 4096];
        while readable(reader.as_raw_fd()) {
            let count = reader.read(&mut chunk).expect("read the pipe");
            taken.extend_from_slice(&chunk[..count]);
        }
        taken
    }

    #[test]
    fn test_written_at_once_while_taken() {
        // A pipe with room takes the bytes from the vCPU itself, and the
        // output is not woken.
        let (mut reader, writer, _) = pipe();
        let output = Output::new(writer.as_raw_fd()).expect("output");
        let Target::Reopened(fd) = &output.inner.target else {
            panic!("pipe not opened again");
        };
        // SAFETY: `fcntl` takes a descriptor and a command.
        let flags = unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_GETFL) };
        assert_ne!(flags & libc::O_NONBLOCK, 0, "reopened pipe blocks");
        // SAFETY: `fcntl` takes a descriptor and a command.
        let flags = unsafe { libc::fcntl(output.wake_fd(), libc::F_GETFD) };
        assert_ne!(flags & libc::FD_CLOEXEC, 0, "eventfd leaks across exec");
        output.backlog().write_all(b"boot").expect("write");
        assert_eq!(take(&mut reader), b"boot");
        assert!(!readable(output.wake_fd()), "output woken");
        assert_eq!(output.descriptor(), None);
    }

    #[test]
    fn test_kept_while_full_then_written_out() {
        let (mut reader, writer, size) = pipe();
        let mut output = Output::new(writer.as_raw_fd()).expect("output");
        let mut backlog = output.backlog();
        let mut bytes: Vec<u8> = (0..size + 100).map(|at| at as u8).collect();
        for byte in &bytes {
            backlog.write_all(&[*byte]).expect("write");
        }
        // The first kept byte wakes the output, the rest do not add to it.
        let mut count = [0u8; 8];
        // SAFETY: `count` is 8 bytes, the width an eventfd read fills.
        let read = unsafe { libc::read(output.wake_fd(), count.as_mut_ptr().cast(), 8) };
        assert_eq!(read, 8);
        assert_eq!(u64::from_ne_bytes(count), 1);
        output.write_out();
        assert!(output.descriptor().is_some(), "full pipe not waited on");
        let mut taken = take(&mut reader);
        // A byte written once the pipe has room goes after the kept ones.
        backlog.write_all(b"z").expect("write");
        bytes.push(b'z');
        output.write_out();
        assert_eq!(output.descriptor(), None);
        taken.extend(take(&mut reader));
        assert_eq!(taken, bytes);
    }

    #[test]
    fn test_oldest_dropped_past_backlog() {
        let (mut reader, writer, size) = pipe();
        let mut output = Output::new(writer.as_raw_fd()).expect("output");
        let bytes: Vec<u8> = (0..size + BACKLOG + 10).map(|at| at as u8).collect();
        output.backlog().write_all(&bytes).expect("write");
        let dropped = output.inner.state.lock().unwrap().dropped;
        assert_eq!(dropped, 10);
        let mut taken = Vec::new();
        for _ in 0..100 {
            taken.extend(take(&mut reader));
            output.write_out();
            if output.descriptor().is_none() {
                break;
            }
        }
        assert_eq!(output.descriptor(), None, "backlog not written out");
        taken.extend(take(&mut reader));
        // What the pipe took comes first, then the newest `BACKLOG` bytes.
        assert_eq!(&taken[..size], &bytes[..size]);
        assert_eq!(&taken[size..], &bytes[size + 10..]);
    }

    #[test]
    fn test_closed_reader_drops_output() {
        // The guest runs on, and its later output is counted as dropped.
        let (reader, writer, _) = pipe();
        drop(reader);
        let output = Output::new(writer.as_raw_fd()).expect("output");
        let mut backlog = output.backlog();
        backlog.write_all(b"lost").expect("write");
        backlog.write_all(b"too").expect("write");
        let failed = output.inner.state.lock().unwrap().failed.is_some();
        assert!(failed, "failure not kept for the log");
        let dropped = output.inner.state.lock().unwrap().dropped;
        assert_eq!(dropped, 7);
    }

    #[test]
    fn test_socket_written_by_vcpu() {
        // A socket is not opened again, so the flag goes on the descriptor
        // itself, and the vCPU writes it.
        let (near, far) = UnixStream::pair().expect("socket pair");
        let output = Output::new(near.as_raw_fd()).expect("output");
        assert!(matches!(output.inner.target, Target::Flagged { .. }));
        output.backlog().write_all(b"hello").expect("write");
        assert!(readable(far.as_raw_fd()), "socket not written at once");
    }

    #[test]
    fn test_terminal_opened_again() {
        let mut master = -1;
        let mut slave = -1;
        // SAFETY: both out-pointers are valid, the rest may be null.
        let opened = unsafe {
            libc::openpty(
                &mut master,
                &mut slave,
                std::ptr::null_mut(),
                std::ptr::null(),
                std::ptr::null(),
            )
        };
        assert_eq!(opened, 0, "openpty");
        // SAFETY: both descriptors were just opened and have no other owner.
        let (_master, slave) = unsafe { (File::from_raw_fd(master), File::from_raw_fd(slave)) };
        let output = Output::new(slave.as_raw_fd()).expect("output");
        assert!(matches!(output.inner.target, Target::Reopened(_)));
    }

    #[test]
    fn test_master_not_opened_again() {
        // A master opened again would be a new terminal.
        let mut master = -1;
        let mut slave = -1;
        // SAFETY: both out-pointers are valid, the rest may be null.
        let opened = unsafe {
            libc::openpty(
                &mut master,
                &mut slave,
                std::ptr::null_mut(),
                std::ptr::null(),
                std::ptr::null(),
            )
        };
        assert_eq!(opened, 0, "openpty");
        // SAFETY: both descriptors were just opened and have no other owner.
        let (master, _slave) = unsafe { (File::from_raw_fd(master), File::from_raw_fd(slave)) };
        let output = Output::new(master.as_raw_fd()).expect("output");
        assert!(matches!(output.inner.target, Target::Flagged { .. }));
    }

    #[test]
    fn test_refused_reopen_sets_flag() {
        // A FIFO with no reader is not opened again, so the flag goes on the
        // descriptor itself until the output is dropped.
        let at = std::env::temp_dir().join(format!("lingcore-fifo-{}", std::process::id()));
        let path = std::ffi::CString::new(at.to_str().expect("path")).expect("path");
        // SAFETY: `path` is a valid C string.
        assert_eq!(unsafe { libc::mkfifo(path.as_ptr(), 0o600) }, 0, "mkfifo");
        let both = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(&at)
            .expect("open");
        let writer = std::fs::OpenOptions::new()
            .write(true)
            .open(&at)
            .expect("open");
        std::fs::remove_file(&at).expect("remove the FIFO");
        // `both` is the only reader, it is closed before the reopen.
        drop(both);
        let fd = writer.as_raw_fd();
        // SAFETY: `fcntl` takes a descriptor and a command.
        let before = unsafe { libc::fcntl(fd, libc::F_GETFL) };
        let output = Output::new(fd).expect("output");
        assert!(matches!(output.inner.target, Target::Flagged { .. }));
        // SAFETY: as above.
        let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
        assert_ne!(flags & libc::O_NONBLOCK, 0);
        drop(output);
        // SAFETY: as above.
        let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
        assert_eq!(flags, before);
    }

    #[test]
    fn test_kept_bytes_dropped_with_output() {
        let (_reader, writer, size) = pipe();
        let output = Output::new(writer.as_raw_fd()).expect("output");
        let inner = Arc::clone(&output.inner);
        let mut backlog = output.backlog();
        backlog.write_all(&vec![1u8; size + 5]).expect("write");
        drop(output);
        backlog.write_all(b"late").expect("write");
        assert_eq!(inner.state.lock().unwrap().dropped, 9);
    }
}
