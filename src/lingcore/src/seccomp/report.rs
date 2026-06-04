// SPDX-FileCopyrightText: 2026 LingCage <opensource@lingcage.com>
//
// SPDX-License-Identifier: Apache-2.0

//! The `SIGSYS` handler which names the thread and the syscall refused
//! by an allowlist.
//!
//! The handler reads a thread-local `Cell`, fills a buffer on its own
//! stack and calls `write` and `_exit`, both on each allowlist. Log
//! facade is not used, since a record allocates and takes a lock,
//! neither is async-signal-safe.

use std::cell::Cell;

/// `si_code` of a `SIGSYS` raised by seccomp, from
/// `include/uapi/asm-generic/siginfo.h`.
const SYS_SECCOMP: libc::c_int = 1;

/// Exit status for a process ended by `SIGSYS`, 128 plus the signal
/// number, same as reported by a shell.
const KILLED_BY_SIGSYS: libc::c_int = 128 + libc::SIGSYS;

/// Room for a report in bytes, more than the longest one.
const ROOM: usize = 96;

thread_local! {
    /// Name of the calling thread for the report. `None` until `arm` runs.
    static TAG: Cell<Option<&'static str>> = const { Cell::new(None) };
}

/// Set `tag` as the name of the calling thread and register the
/// handler. Registering is `rt_sigaction`, which is on no allowlist, so
/// it has to run before the allowlist is installed. Handler is
/// process-wide, `TAG` is per thread.
pub(in crate::seccomp) fn arm(tag: &'static str) -> std::io::Result<()> {
    TAG.with(|held| held.set(Some(tag)));
    // SAFETY: a zeroed `sigaction` with an `SA_SIGINFO` handler and an
    // empty mask is valid, and both pointers outlive the call.
    let put_on = unsafe {
        let mut action: libc::sigaction = std::mem::zeroed();
        action.sa_flags = libc::SA_SIGINFO;
        let entry: Handler = handler;
        action.sa_sigaction = entry as libc::sighandler_t;
        libc::sigaction(libc::SIGSYS, &raw const action, std::ptr::null_mut())
    };
    if put_on < 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(())
}

/// Signature of a handler registered with `SA_SIGINFO`.
type Handler = extern "C" fn(libc::c_int, *mut libc::siginfo_t, *mut libc::c_void);

/// `siginfo_t` as filled by the kernel for `SIGSYS`. The three `int`
/// header comes first, then `_sigsys` from
/// `include/uapi/asm-generic/siginfo.h`. The union holding `_sigsys` is
/// pointer aligned, so it starts four bytes past the header. `repr(C)`
/// places `si_call_addr` the same way.
#[repr(C)]
struct Refused {
    si_signo: libc::c_int,
    si_errno: libc::c_int,
    si_code: libc::c_int,
    si_call_addr: *mut libc::c_void,
    si_syscall: libc::c_int,
    si_arch: libc::c_uint,
}

/// Write the thread name and the refused syscall number to stderr, then
/// end the process with `KILLED_BY_SIGSYS`.
extern "C" fn handler(signo: libc::c_int, info: *mut libc::siginfo_t, _context: *mut libc::c_void) {
    // SAFETY: `info` points at the `siginfo_t` filled by the kernel, and
    // `Refused` is no longer than `siginfo_t`.
    let refused = unsafe { &*info.cast::<Refused>() };
    let mut line = Line {
        text: [0; ROOM],
        filled: 0,
    };
    line.put(b"lingcore: the ");
    line.put(TAG.with(Cell::get).unwrap_or("unnamed").as_bytes());
    // `si_syscall` is only filled when `si_code` is `SYS_SECCOMP`.
    if signo == libc::SIGSYS && refused.si_code == SYS_SECCOMP {
        line.put(b" thread was refused syscall ");
        line.put_number(refused.si_syscall);
    } else {
        line.put(b" thread took signal ");
        line.put_number(signo);
        line.put(b", not from seccomp");
    }
    line.put(b"\n");
    // Short writes are continued. Failed write ends the report.
    let mut said = 0;
    while said < line.filled {
        // SAFETY: `line.text` is initialized for its length and outlives the
        // call.
        let took = unsafe { libc::write(2, line.text[said..].as_ptr().cast(), line.filled - said) };
        if took <= 0 {
            break;
        }
        said += took as usize;
    }
    // SAFETY: `_exit` takes no pointer and does not return.
    unsafe { libc::_exit(KILLED_BY_SIGSYS) };
}

/// Report buffer on the stack of the handler. Bytes past `ROOM` are
/// dropped.
struct Line {
    text: [u8; ROOM],
    filled: usize,
}

impl Line {
    /// Append `bytes`, truncated to the room left.
    fn put(&mut self, bytes: &[u8]) {
        let room = ROOM - self.filled;
        let taken = bytes.len().min(room);
        self.text[self.filled..self.filled + taken].copy_from_slice(&bytes[..taken]);
        self.filled += taken;
    }

    /// Append `value` in decimal.
    fn put_number(&mut self, value: libc::c_int) {
        if value < 0 {
            self.put(b"-");
        }
        let mut left = value.unsigned_abs();
        let mut digits = [0u8; 10];
        let mut written = 0;
        loop {
            digits[written] = b'0' + (left % 10) as u8;
            left /= 10;
            written += 1;
            if left == 0 {
                break;
            }
        }
        while written > 0 {
            written -= 1;
            self.put(&digits[written..written + 1]);
        }
    }
}

#[cfg(test)]
pub(in crate::seccomp) mod tests {
    use crate::seccomp::report::*;

    /// A child as it ended, the standard error it wrote and the status it
    /// exited with, `None` for a child ended by a signal.
    pub(in crate::seccomp) struct Ended {
        /// All that the child wrote to standard error.
        pub said: String,
        /// Exit status of the child.
        pub code: Option<libc::c_int>,
    }

    /// Run `work` in a forked child with its standard error as a pipe, and
    /// read back what it wrote and how it ended. The child holds the locks
    /// of the threads left behind by fork, so `work` must not allocate.
    pub(in crate::seccomp) fn ended_in_a_child<F: FnOnce()>(work: F) -> Ended {
        use std::io::Read;
        use std::os::fd::FromRawFd;

        let mut ends = [0; 2];
        // SAFETY: `pipe` fills the two-element array given to it, which
        // outlives the call.
        let opened = unsafe { libc::pipe(ends.as_mut_ptr()) };
        assert_eq!(opened, 0, "open pipe for the child");
        let [reading, writing] = ends;

        // SAFETY: `fork` takes no pointer.
        let child = unsafe { libc::fork() };
        assert!(child >= 0, "fork a child");
        if child == 0 {
            // SAFETY: both descriptors come from `pipe`, and the child holds
            // the only copy of each.
            unsafe {
                libc::close(reading);
                libc::dup2(writing, libc::STDERR_FILENO);
                libc::close(writing);
            }
            // Catching the panic keeps the child from unwinding into the suite
            // as a second harness. It does not make a panicking `work` safe,
            // since the panic allocates before this catches it.
            let ran = std::panic::catch_unwind(std::panic::AssertUnwindSafe(work));
            // SAFETY: `_exit` takes no pointer and does not return.
            unsafe { libc::_exit(if ran.is_ok() { STOOD } else { PANICKED }) };
        }

        // SAFETY: the descriptor comes from `pipe` and the parent holds the
        // only copy, `File` owns it from here.
        unsafe { libc::close(writing) };
        // SAFETY: `reading` comes from the same `pipe` and the parent holds
        // its only copy, `File` owns it from here.
        let mut pipe = unsafe { std::fs::File::from_raw_fd(reading) };
        // The read ends when the child does, and it has no deadline. A
        // child which neither writes nor exits holds the suite here.
        let mut said = Vec::new();
        pipe.read_to_end(&mut said)
            .expect("read output of the child");

        let mut status = 0;
        // SAFETY: `waitpid` fills the given status, which outlives the call.
        let waited = unsafe { libc::waitpid(child, &raw mut status, 0) };
        assert_eq!(waited, child, "wait for child");
        let ended = Ended {
            said: String::from_utf8_lossy(&said).to_string(),
            code: libc::WIFEXITED(status).then(|| libc::WEXITSTATUS(status)),
        };
        assert_ne!(
            ended.code,
            Some(PANICKED),
            "work panicked in the child:\n{}",
            ended.said
        );
        ended
    }

    /// Status a child exits with when `work` returned, and the one when
    /// `work` panicked. Both are different from the `KILLED_BY_SIGSYS`
    /// used by the handler to end a child.
    const STOOD: libc::c_int = 1;
    const PANICKED: libc::c_int = 2;

    #[test]
    fn test_refused_fits_in_siginfo() {
        // `Refused` fits in `siginfo_t`, the buffer read by the handler.
        assert!(
            size_of::<Refused>() <= size_of::<libc::siginfo_t>(),
            "Refused is {} bytes, siginfo_t {}",
            size_of::<Refused>(),
            size_of::<libc::siginfo_t>()
        );
    }

    #[test]
    fn test_report_sigsys_not_from_seccomp() {
        // A `SIGSYS` with `si_code` other than `SYS_SECCOMP` is reported
        // by signal number only. It is raised by hand in a child and read
        // from its stderr.
        let ended = ended_in_a_child(|| {
            arm("vcpu").expect("register handler");
            // SAFETY: `raise` takes no pointer, the handler is registered.
            unsafe { libc::raise(libc::SIGSYS) };
        });

        let owed = format!("took signal {}, not from seccomp", libc::SIGSYS);
        let said = &ended.said;
        assert!(said.contains(&owed), "stderr was:\n{said}");
        assert_eq!(
            ended.code,
            Some(KILLED_BY_SIGSYS),
            "exit status is not 128 + SIGSYS"
        );
    }

    #[test]
    fn test_line_stops_at_room() {
        // `put` and `put_number` stop at `ROOM`.
        let mut line = Line {
            text: [0; ROOM],
            filled: 0,
        };
        line.put(&[b'x'; ROOM * 2]);
        assert_eq!(line.filled, ROOM, "put wrote past ROOM");
        line.put_number(libc::c_int::MIN);
        assert_eq!(line.filled, ROOM, "put_number wrote past ROOM");
    }

    #[test]
    fn test_put_number_decimal() {
        // `put_number` writes decimal, with a sign for negative value.
        let mut line = Line {
            text: [0; ROOM],
            filled: 0,
        };
        line.put_number(41);
        line.put(b" ");
        line.put_number(-1);
        assert_eq!(&line.text[..line.filled], b"41 -1");
    }
}
