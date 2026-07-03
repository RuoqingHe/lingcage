// SPDX-FileCopyrightText: 2026 LingCage <opensource@lingcage.com>
//
// SPDX-License-Identifier: Apache-2.0

//! The `SIGBUS` raised by a file-backed guest mapping, and the handler
//! which keeps the host process alive through it.
//!
//! A clone maps its RAM image as `MAP_PRIVATE`, so a page truncated out
//! of that file raises `SIGBUS` on the thread touching it, and the
//! default action ends the process together with all other guests in
//! it. The handler puts a zero page over the address instead and marks
//! the mapping, so the thread runs on and the owner of the machine gets
//! to know its memory is gone.
//!
//! The handler is installed before any thread installs its allowlist,
//! and it only calls `mmap`, which is on each allowlist.

use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

/// Mappings watched at the same time. A machine takes one entry per
/// region, and the entries are freed together with the memory.
const WATCHED: usize = 64;

/// Bytes of the page used to repair a fault.
const PAGE: usize = 4096;

/// One watched mapping, the host range, and whether a fault landed in
/// it.
struct Watch {
    taken: AtomicBool,
    start: AtomicUsize,
    len: AtomicUsize,
    hit: AtomicBool,
}

impl Watch {
    /// A free entry. A const function, since a constant of a type with
    /// interior mutability is copied on each use.
    const fn free() -> Watch {
        Watch {
            taken: AtomicBool::new(false),
            start: AtomicUsize::new(0),
            len: AtomicUsize::new(0),
            hit: AtomicBool::new(false),
        }
    }
}

static WATCHES: [Watch; WATCHED] = [const { Watch::free() }; WATCHED];

/// Entries held by one `GuestRam`, freed when the memory unmaps.
pub(crate) struct Watched {
    slots: Vec<usize>,
}

impl Watched {
    /// Watch each `(host address, length)` of a file-backed mapping. Range
    /// past the room of the table is left unwatched, and a fault in it ends
    /// the process as before.
    pub(crate) fn of(ranges: impl Iterator<Item = (usize, usize)>) -> Watched {
        arm();
        let mut slots = Vec::new();
        for (start, len) in ranges {
            for (at, watch) in WATCHES.iter().enumerate() {
                if watch
                    .taken
                    .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
                    .is_err()
                {
                    continue;
                }
                watch.hit.store(false, Ordering::Release);
                watch.len.store(len, Ordering::Release);
                // Start is written last, so the handler reads either a complete
                // entry or a free one.
                watch.start.store(start, Ordering::Release);
                slots.push(at);
                break;
            }
        }
        Watched { slots }
    }

    /// Returns whether a fault landed in one of the ranges.
    pub(crate) fn hit(&self) -> bool {
        self.slots
            .iter()
            .any(|&at| WATCHES[at].hit.load(Ordering::Acquire))
    }
}

impl Drop for Watched {
    fn drop(&mut self) {
        for &at in &self.slots {
            WATCHES[at].start.store(0, Ordering::Release);
            WATCHES[at].len.store(0, Ordering::Release);
            WATCHES[at].taken.store(false, Ordering::Release);
        }
    }
}

/// Install the handler once for the process.
fn arm() {
    static ONCE: std::sync::Once = std::sync::Once::new();
    ONCE.call_once(|| {
        // SAFETY: a zeroed sigaction is a valid empty sigaction.
        let mut action: libc::sigaction = unsafe { std::mem::zeroed() };
        action.sa_sigaction = on_bus as *const () as libc::sighandler_t;
        action.sa_flags = libc::SA_SIGINFO;
        // SAFETY: `action` names a live handler for the length of the call.
        unsafe { libc::sigaction(libc::SIGBUS, &action, std::ptr::null_mut()) };
    });
}

/// Put a zero page over the faulting address of a watched mapping and
/// mark it. Fault outside of all watched mappings ends the process, same
/// as the default action, since a handler which returns would fault
/// again on the same instruction.
extern "C" fn on_bus(
    _signal: libc::c_int,
    info: *mut libc::siginfo_t,
    _context: *mut libc::c_void,
) {
    // SAFETY: the kernel hands a live siginfo with SA_SIGINFO.
    let at = unsafe { (*info).si_addr() } as usize;
    for watch in &WATCHES {
        if !watch.taken.load(Ordering::Acquire) {
            continue;
        }
        let start = watch.start.load(Ordering::Acquire);
        let len = watch.len.load(Ordering::Acquire);
        if start == 0 || at < start || at - start >= len {
            continue;
        }
        let page = at & !(PAGE - 1);
        // SAFETY: the page is inside a mapping owned by this process, and
        // MAP_FIXED only replaces that page.
        let placed = unsafe {
            libc::mmap(
                page as *mut libc::c_void,
                PAGE,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_FIXED | libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
                -1,
                0,
            )
        };
        if placed != libc::MAP_FAILED {
            watch.hit.store(true, Ordering::Release);
            return;
        }
        break;
    }
    // SAFETY: `_exit` takes no pointer and ends the process here.
    unsafe { libc::_exit(128 + libc::SIGBUS) };
}

#[cfg(test)]
mod tests {
    use crate::mem::fault::*;

    #[test]
    fn test_watch_slot_taken_and_freed() {
        let taken = WATCHES
            .iter()
            .filter(|w| w.taken.load(Ordering::Acquire))
            .count();
        let watched = Watched::of([(0x1000, 0x2000)].into_iter());
        assert_eq!(
            WATCHES
                .iter()
                .filter(|w| w.taken.load(Ordering::Acquire))
                .count(),
            taken + 1
        );
        assert!(!watched.hit());
        drop(watched);
        assert_eq!(
            WATCHES
                .iter()
                .filter(|w| w.taken.load(Ordering::Acquire))
                .count(),
            taken
        );
    }

    #[test]
    fn test_zero_page_over_truncated_mapping() {
        // Truncate a mapped file, touch the lost page, check the handler
        // ran.
        use std::io::Write as _;
        use std::os::fd::AsRawFd as _;

        let mut file = tempfile();
        file.write_all(&[0x5a; PAGE * 2]).expect("fill file");
        // SAFETY: the length and the descriptor belong to this file.
        let at = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                PAGE * 2,
                libc::PROT_READ,
                libc::MAP_PRIVATE,
                file.as_raw_fd(),
                0,
            )
        };
        assert_ne!(at, libc::MAP_FAILED, "mapping failed");
        let watched = Watched::of([(at as usize, PAGE * 2)].into_iter());
        file.set_len(PAGE as u64).expect("truncate file");
        // SAFETY: the address is the second page of a live mapping, which
        // the file no longer covers.
        let read = unsafe { std::ptr::read_volatile((at as usize + PAGE) as *const u8) };
        assert_eq!(read, 0, "page placed by the handler is not zeroed");
        assert!(watched.hit(), "fault not marked");
        // SAFETY: the mapping belongs to this test and is unused past here.
        unsafe { libc::munmap(at, PAGE * 2) };
    }

    /// Temporary file for the test.
    fn tempfile() -> std::fs::File {
        let path = std::env::temp_dir().join(format!("lingcore-fault-{}", std::process::id()));
        let file = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(true)
            .open(&path)
            .expect("open test file");
        std::fs::remove_file(&path).expect("unlink test file");
        file
    }
}
