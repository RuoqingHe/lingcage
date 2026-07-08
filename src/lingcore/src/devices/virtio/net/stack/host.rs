// SPDX-FileCopyrightText: 2026 LingCage <opensource@lingcage.com>
//
// SPDX-License-Identifier: Apache-2.0

//! Host side sockets of the stack, a connect which does not block, and
//! resolvers of the host.

use std::io;
use std::net::{Ipv4Addr, SocketAddrV4, TcpStream};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};

/// Start a TCP connect to `to` without blocking. Connect is still in
/// progress on return, `connected` tells once it is done.
pub fn connect(to: SocketAddrV4) -> io::Result<TcpStream> {
    // SAFETY: `socket` takes no pointer, it returns a descriptor or -1.
    let fd = unsafe {
        libc::socket(
            libc::AF_INET,
            libc::SOCK_STREAM | libc::SOCK_NONBLOCK | libc::SOCK_CLOEXEC,
            0,
        )
    };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: `fd` was just returned by `socket` and is owned from here.
    let owned = unsafe { OwnedFd::from_raw_fd(fd) };
    let addr = libc::sockaddr_in {
        sin_family: libc::AF_INET as libc::sa_family_t,
        sin_port: to.port().to_be(),
        sin_addr: libc::in_addr {
            s_addr: u32::from_ne_bytes(to.ip().octets()),
        },
        sin_zero: [0; 8],
    };
    // SAFETY: `addr` is a valid sockaddr_in and the length given is its
    // size.
    let rc = unsafe {
        libc::connect(
            owned.as_raw_fd(),
            (&raw const addr).cast::<libc::sockaddr>(),
            std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t,
        )
    };
    if rc == -1 {
        let err = io::Error::last_os_error();
        if err.raw_os_error() != Some(libc::EINPROGRESS) {
            return Err(err);
        }
    }
    Ok(TcpStream::from(owned))
}

/// Returns whether the connect on `stream` is done. Error is the failure
/// of the connect.
pub fn connected(stream: &TcpStream) -> io::Result<bool> {
    match stream.peer_addr() {
        Ok(_) => Ok(true),
        // Not connected yet, or the connect failed. `SO_ERROR` tells which.
        Err(err) if err.kind() == io::ErrorKind::NotConnected => match stream.take_error()? {
            Some(failed) => Err(failed),
            None => Ok(false),
        },
        Err(err) => Err(err),
    }
}

/// Returns IPv4 resolvers named in `/etc/resolv.conf`, in order.
pub fn resolvers() -> Vec<Ipv4Addr> {
    let Ok(text) = std::fs::read_to_string("/etc/resolv.conf") else {
        return Vec::new();
    };
    text.lines()
        .filter_map(|line| {
            let mut words = line.split_whitespace();
            if words.next()? != "nameserver" {
                return None;
            }
            words.next()?.parse().ok()
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use std::net::TcpListener;

    use crate::devices::virtio::net::stack::host::*;

    #[test]
    fn test_connect_completes_on_loopback() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let to = match listener.local_addr().unwrap() {
            std::net::SocketAddr::V4(to) => to,
            other => panic!("loopback bound {other}"),
        };
        let stream = connect(to).unwrap();
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
        while !connected(&stream).unwrap() {
            assert!(
                std::time::Instant::now() < deadline,
                "connect took too long"
            );
            std::thread::sleep(std::time::Duration::from_millis(5));
        }
        listener.accept().unwrap();
    }

    #[test]
    fn test_connect_refused_is_reported() {
        // No listener is on the port once it is dropped.
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let to = match listener.local_addr().unwrap() {
            std::net::SocketAddr::V4(to) => to,
            other => panic!("loopback bound {other}"),
        };
        drop(listener);
        let stream = connect(to).unwrap();
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
        loop {
            match connected(&stream) {
                Ok(false) => std::thread::sleep(std::time::Duration::from_millis(5)),
                Ok(true) => panic!("connected to a closed port"),
                Err(err) => {
                    assert_eq!(err.kind(), io::ErrorKind::ConnectionRefused);
                    break;
                }
            }
            assert!(
                std::time::Instant::now() < deadline,
                "refusal took too long"
            );
        }
    }
}
