// SPDX-FileCopyrightText: 2026 LingCage <opensource@lingcage.com>
//
// SPDX-License-Identifier: Apache-2.0

//! Connecting to host over vsock, with a timeout on connect.

#![cfg(target_os = "linux")]

use std::fs::File;
use std::io;
use std::os::fd::FromRawFd;
use std::time::{Duration, Instant};

/// Maximum time a connect may take.
const TIMEOUT: Duration = Duration::from_secs(5);

/// Connect to host listener on `port`. The returned connection is set to
/// blocking mode and will be closed on exec.
pub fn connect(port: u32) -> io::Result<File> {
    // SAFETY: `socket` takes no pointer, it returns a descriptor or -1.
    let fd = unsafe {
        libc::socket(
            libc::AF_VSOCK,
            libc::SOCK_STREAM | libc::SOCK_NONBLOCK | libc::SOCK_CLOEXEC,
            0,
        )
    };
    if fd == -1 {
        return Err(io::Error::last_os_error());
    }
    let addr = libc::sockaddr_vm {
        svm_family: libc::sa_family_t::try_from(libc::AF_VSOCK).expect("small domain"),
        svm_reserved1: 0,
        svm_port: port,
        svm_cid: libc::VMADDR_CID_HOST,
        svm_zero: [0; 4],
    };
    // SAFETY: `addr` is a valid sockaddr_vm and length passed is its size.
    let rc = unsafe {
        libc::connect(
            fd,
            (&raw const addr).cast::<libc::sockaddr>(),
            libc::socklen_t::try_from(size_of::<libc::sockaddr_vm>()).expect("small address"),
        )
    };
    let result = match rc {
        0 => Ok(()),
        _ => {
            let err = io::Error::last_os_error();
            if err.raw_os_error() == Some(libc::EINPROGRESS) {
                wait_writable(fd).and_then(|()| pending_error(fd))
            } else {
                Err(err)
            }
        }
    };
    if let Err(err) = result.and_then(|()| set_blocking(fd)) {
        // SAFETY: `fd` is owned here and not wrapped in a File.
        unsafe { libc::close(fd) };
        return Err(err);
    }
    // SAFETY: `fd` is an open and connected descriptor which is owned here.
    Ok(unsafe { File::from_raw_fd(fd) })
}

/// Wait for a connecting socket to become writable, up to `TIMEOUT`.
fn wait_writable(fd: libc::c_int) -> io::Result<()> {
    let deadline = Instant::now() + TIMEOUT;
    loop {
        let left = deadline.saturating_duration_since(Instant::now());
        if left.is_zero() {
            return Err(timed_out());
        }
        let mut slot = libc::pollfd {
            fd,
            events: libc::POLLOUT,
            revents: 0,
        };
        let ms = libc::c_int::try_from(left.as_millis()).expect("5 s deadline fits in c_int");
        // SAFETY: `slot` is a valid pollfd, and only one entry is passed.
        let n = unsafe { libc::poll(&mut slot, 1, ms) };
        if n == -1 {
            let err = io::Error::last_os_error();
            if err.kind() == io::ErrorKind::Interrupted {
                continue;
            }
            return Err(err);
        }
        if n == 0 {
            return Err(timed_out());
        }
        return Ok(());
    }
}

/// Returns pending error of a connecting socket, `Ok` once connected.
fn pending_error(fd: libc::c_int) -> io::Result<()> {
    let mut value: libc::c_int = 0;
    let mut len = libc::socklen_t::try_from(size_of::<libc::c_int>()).expect("small value");
    // SAFETY: both pointers are valid and `len` is set to size of `value`.
    let rc = unsafe {
        libc::getsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_ERROR,
            (&raw mut value).cast::<libc::c_void>(),
            &mut len,
        )
    };
    if rc == -1 {
        return Err(io::Error::last_os_error());
    }
    match value {
        0 => Ok(()),
        code => Err(io::Error::from_raw_os_error(code)),
    }
}

/// Clear O_NONBLOCK, since stdio of an exec'd command should be blocking.
fn set_blocking(fd: libc::c_int) -> io::Result<()> {
    // SAFETY: `fd` is open, F_GETFL needs no third argument.
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
    if flags == -1 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: `fd` is open, only O_NONBLOCK is cleared from the flags.
    if unsafe { libc::fcntl(fd, libc::F_SETFL, flags & !libc::O_NONBLOCK) } == -1 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// Returns the error for a timed out connect.
fn timed_out() -> io::Error {
    io::Error::new(io::ErrorKind::TimedOut, "connect timed out after 5 s")
}
