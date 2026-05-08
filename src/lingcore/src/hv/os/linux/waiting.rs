// SPDX-FileCopyrightText: 2026 LingCage <opensource@lingcage.com>
//
// SPDX-License-Identifier: Apache-2.0

//! Waiting on several descriptors at once through `poll(2)`.
//!
//! One thread serves a device with several rings, or a socket besides
//! its rings, by waiting on all the descriptors together.

use std::os::fd::RawFd;
use std::time::Duration;

use crate::hv::{Error, Result};

/// Descriptors to wait on, each with the token `ready` reports it with.
///
/// Descriptors are borrowed instead of owned, caller keeps them open
/// while a wait is running.
///
/// The set is passed to `poll(2)` on each wait, so cost of a wait is
/// linear to the number of descriptors.
#[derive(Default)]
pub struct Waiting {
    waited: Vec<(RawFd, u64)>,
}

impl Waiting {
    /// Create an empty set.
    pub fn new() -> Self {
        Waiting::default()
    }

    /// Add `fd`, reported as `token` once ready.
    pub fn add(&mut self, fd: RawFd, token: u64) {
        self.waited.push((fd, token));
    }

    /// Number of descriptors.
    pub fn len(&self) -> usize {
        self.waited.len()
    }

    /// Returns whether the set is empty. `ready` returns at once on an
    /// empty set.
    pub fn is_empty(&self) -> bool {
        self.waited.is_empty()
    }

    /// Wait at most `within` for a descriptor to become ready and fill
    /// `ready` with tokens of the ready ones. `ready` is left empty once
    /// `within` elapses.
    pub fn ready(&self, within: Duration, ready: &mut Vec<u64>) -> Result<()> {
        ready.clear();
        if self.waited.is_empty() {
            return Ok(());
        }
        let mut waiting: Vec<libc::pollfd> = self
            .waited
            .iter()
            .map(|(fd, _)| libc::pollfd {
                fd: *fd,
                events: libc::POLLIN,
                revents: 0,
            })
            .collect();
        let milliseconds = i32::try_from(within.as_millis()).unwrap_or(i32::MAX);
        // SAFETY: `waiting` holds initialized `pollfd`s, and the length passed
        // is its own.
        let count = unsafe {
            libc::poll(
                waiting.as_mut_ptr(),
                waiting.len() as libc::nfds_t,
                milliseconds,
            )
        };
        if count < 0 {
            return Err(Error::Other("failed to wait on several descriptors"));
        }
        for (slot, polled) in waiting.iter().enumerate() {
            // Hung up descriptor is reported ready. poll(2) sets `POLLHUP`
            // and `POLLERR` even if they are not in `events`.
            if polled.revents & (libc::POLLIN | libc::POLLHUP | libc::POLLERR) != 0 {
                ready.push(self.waited[slot].1);
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};

    use crate::hv::os::linux::waiting::*;

    /// Non-blocking eventfd standing in for an ioeventfd, no backend needed.
    struct Eventfd(OwnedFd);

    impl Eventfd {
        fn new() -> Self {
            // SAFETY: `eventfd(2)` takes an initial count and flags, returns
            // a descriptor or -1.
            let fd = unsafe { libc::eventfd(0, libc::EFD_NONBLOCK) };
            assert!(fd >= 0, "eventfd");
            // SAFETY: `fd` was just opened and has no other owner.
            Eventfd(unsafe { OwnedFd::from_raw_fd(fd) })
        }

        fn signal(&self) {
            let one = 1u64.to_ne_bytes();
            // SAFETY: `one` is 8 bytes, the width an eventfd write takes.
            let wrote = unsafe { libc::write(self.0.as_raw_fd(), one.as_ptr().cast(), 8) };
            assert_eq!(wrote, 8, "signal");
        }

        fn take(&self) {
            let mut count = [0u8; 8];
            // SAFETY: `count` is 8 bytes, the width an eventfd read fills.
            let read = unsafe { libc::read(self.0.as_raw_fd(), count.as_mut_ptr().cast(), 8) };
            assert_eq!(read, 8, "take the count");
        }

        fn fd(&self) -> std::os::fd::RawFd {
            self.0.as_raw_fd()
        }
    }

    #[test]
    fn test_quiet_descriptor_times_out() {
        let quiet = Eventfd::new();
        let mut waiting = Waiting::new();
        waiting.add(quiet.fd(), 7);
        let mut ready = vec![99];
        waiting
            .ready(Duration::from_millis(20), &mut ready)
            .expect("wait");
        assert!(ready.is_empty(), "quiet descriptor reported ready");
    }

    #[test]
    fn test_ready_reports_token() {
        // `ready` reports the token given in `add`, not the descriptor.
        let first = Eventfd::new();
        let second = Eventfd::new();
        let mut waiting = Waiting::new();
        waiting.add(first.fd(), 10);
        waiting.add(second.fd(), 20);

        second.signal();
        let mut ready = Vec::new();
        waiting
            .ready(Duration::from_millis(200), &mut ready)
            .expect("wait");
        assert_eq!(ready, vec![20], "wrong descriptor named");

        // The read clears the count, so next wait times out.
        second.take();
        waiting
            .ready(Duration::from_millis(20), &mut ready)
            .expect("wait");
        assert!(ready.is_empty(), "signal reported twice");
    }

    #[test]
    fn test_ready_reports_all_signalled() {
        let first = Eventfd::new();
        let second = Eventfd::new();
        let mut waiting = Waiting::new();
        waiting.add(first.fd(), 10);
        waiting.add(second.fd(), 20);
        assert_eq!(waiting.len(), 2);

        first.signal();
        second.signal();
        let mut ready = Vec::new();
        waiting
            .ready(Duration::from_millis(200), &mut ready)
            .expect("wait");
        ready.sort_unstable();
        assert_eq!(ready, vec![10, 20], "signal left unreported");
    }

    #[test]
    fn test_empty_set_returns_at_once() {
        // poll(2) with no descriptor sleeps through the timeout, `ready`
        // returns at once instead.
        let waiting = Waiting::new();
        assert!(waiting.is_empty());
        let started = std::time::Instant::now();
        let mut ready = Vec::new();
        waiting
            .ready(Duration::from_secs(30), &mut ready)
            .expect("wait");
        assert!(ready.is_empty());
        assert!(started.elapsed() < Duration::from_secs(1), "it waited");
    }
}
