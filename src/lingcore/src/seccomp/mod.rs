// SPDX-FileCopyrightText: 2026 LingCage <opensource@lingcage.com>
//
// SPDX-License-Identifier: Apache-2.0

//! Per-thread syscall allowlists of the threads running a guest.
//!
//! Filter is installed from inside a thread and stays until the thread
//! exits. It only bounds syscalls of that thread, descriptors and memory
//! still belong to the process.

use std::collections::BTreeMap;

use seccompiler::{
    SeccompAction, SeccompCmpArgLen, SeccompCmpOp, SeccompCondition, SeccompFilter, SeccompRule,
    TargetArch,
};
use thiserror::Error;

/// Errors thrown while assembling an allowlist or installing it on a
/// thread.
#[derive(Debug, Error)]
pub enum Error {
    /// Failed to compile the allowlist to a BPF program.
    #[error("failed to assemble the syscall allowlist")]
    Assemble(#[source] seccompiler::BackendError),
    /// Kernel refused the program.
    #[error("failed to install the syscall allowlist")]
    Install(#[source] seccompiler::Error),
}

/// Result alias for the seccomp module.
pub type Result<T, E = Error> = std::result::Result<T, E>;

// TODO: Allowlist for the thread assembling a guest is not defined yet.
/// Kind of thread, which selects its allowlist.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Thread {
    /// Runs a vCPU and writes the console. Console sink which needs more
    /// than `write` needs a wider list.
    Vcpu,
    /// Waits on an ioeventfd, serves the rings and raises the line of the
    /// device.
    Device,
}

/// Action on a syscall outside of the allowlist.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Refusal {
    /// `SIGSYS` to the process.
    Trap,
    /// Call returns `ENOSYS` and the thread continues.
    Errno,
}

/// Syscalls in each allowlist, `brk` and the `mmap` family for the
/// allocator, `futex` for a hold, `rt_sigreturn` for a kick, `exit`, and
/// `write`.
///
/// Not listed: process creation, sockets, `ptrace`, `openat`, `mount`
/// and module loading.
const COMMON: &[libc::c_long] = &[
    libc::SYS_brk,
    libc::SYS_exit,
    libc::SYS_futex,
    libc::SYS_madvise,
    libc::SYS_mmap,
    libc::SYS_mprotect,
    libc::SYS_mremap,
    libc::SYS_munmap,
    libc::SYS_restart_syscall,
    libc::SYS_rt_sigprocmask,
    libc::SYS_rt_sigreturn,
    libc::SYS_sched_yield,
    libc::SYS_sigaltstack,
    libc::SYS_write,
];

/// Index of `request` in `ioctl(fd, request, ...)`.
const IOCTL_REQUEST: u8 = 1;

/// `KVM_RUN` is `_IO(KVMIO, 0x80)` with `KVMIO` 0xAE, from
/// `include/uapi/linux/kvm.h`.
const KVM_RUN: u64 = 0xae80;

impl Thread {
    /// Returns the syscalls needed by this thread beyond `COMMON`, with the
    /// conditions on their arguments. Empty rule list allows the syscall
    /// unconditionally.
    fn extras(self) -> Result<BTreeMap<i64, Vec<SeccompRule>>> {
        match self {
            // `ioctl` for `KVM_RUN` only, other request is refused.
            Thread::Vcpu => {
                let enter = SeccompRule::new(vec![
                    SeccompCondition::new(
                        IOCTL_REQUEST,
                        SeccompCmpArgLen::Dword,
                        SeccompCmpOp::Eq,
                        KVM_RUN,
                    )
                    .map_err(Error::Assemble)?,
                ])
                .map_err(Error::Assemble)?;
                Ok(BTreeMap::from([(libc::SYS_ioctl, vec![enter])]))
            }
            // The ioeventfd is polled and read, the disk is sought, read,
            // written and flushed.
            Thread::Device => Ok(BTreeMap::from([
                (libc::SYS_fdatasync, Vec::new()),
                (libc::SYS_lseek, Vec::new()),
                (libc::SYS_poll, Vec::new()),
                (libc::SYS_read, Vec::new()),
            ])),
        }
    }
}

/// Assembled allowlist of a thread kind. Assembling is separated from
/// installing, so that a list which fails to assemble is reported by
/// the caller starting the threads.
#[derive(Clone)]
pub struct Filter(seccompiler::BpfProgram);

impl Filter {
    /// Assemble the allowlist for `thread`, with `refusal` as the action on
    /// a syscall outside of it.
    pub fn new(thread: Thread, refusal: Refusal) -> Result<Self> {
        let mut rules: BTreeMap<i64, Vec<SeccompRule>> =
            COMMON.iter().map(|&number| (number, Vec::new())).collect();
        rules.extend(thread.extras()?);
        let refused = match refusal {
            Refusal::Trap => SeccompAction::Trap,
            Refusal::Errno => SeccompAction::Errno(libc::ENOSYS as u32),
        };
        let filter = SeccompFilter::new(rules, refused, SeccompAction::Allow, TargetArch::x86_64)
            .map_err(Error::Assemble)?;
        seccompiler::BpfProgram::try_from(filter)
            .map(Filter)
            .map_err(Error::Assemble)
    }

    /// Install the allowlist on the calling thread, it stays until the
    /// thread exits. Call it from inside the thread, before the guest runs.
    pub fn confine(&self) -> Result<()> {
        seccompiler::apply_filter(&self.0).map_err(Error::Install)
    }
}

#[cfg(test)]
mod tests {
    use crate::seccomp::*;

    /// Return value and errno of a syscall, so that a refusal (`ENOSYS`) is
    /// distinguished from a call which the kernel ran and failed (`EBADF`).
    type Answer = (libc::c_long, i32);

    /// Run `work` on a new thread under the allowlist of `thread` with
    /// `Refusal::Errno` and return its result. No assert runs inside, since
    /// a panic under the allowlist would need syscalls it refuses.
    fn under<T, F>(thread: Thread, work: F) -> T
    where
        F: FnOnce() -> T + Send + 'static,
        T: Send + 'static,
    {
        std::thread::spawn(move || {
            let filter = Filter::new(thread, Refusal::Errno).expect("assemble allowlist");
            filter.confine().expect("install allowlist");
            work()
        })
        .join()
        .expect("join confined thread")
    }

    /// Returns the last errno without further syscall.
    fn errno() -> i32 {
        std::io::Error::last_os_error()
            .raw_os_error()
            .unwrap_or_default()
    }

    #[test]
    fn test_extras_disjoint_from_common() {
        for thread in [Thread::Vcpu, Thread::Device] {
            for number in thread.extras().expect("assemble extras").keys() {
                assert!(
                    !COMMON.contains(number),
                    "{thread:?} names syscall {number}, which COMMON already allows"
                );
            }
        }
    }

    #[test]
    fn test_refuse_syscall_off_list() {
        let (allowed, refused, left) = under(Thread::Vcpu, || {
            // SAFETY: zero-length write to stderr from a valid pointer.
            let allowed = unsafe { libc::write(2, [].as_ptr(), 0) };
            // SAFETY: `socket` takes no pointer, it returns a descriptor or -1.
            let refused = unsafe { libc::socket(libc::AF_INET, libc::SOCK_STREAM, 0) };
            (allowed, refused, errno())
        });
        assert_eq!(allowed, 0, "allowed write got refused");
        assert_eq!(refused, -1, "socket opened on a confined thread");
        assert_eq!(left, libc::ENOSYS, "socket failed for other reason");
    }

    #[test]
    fn test_vcpu_thread_ioctl_only_kvm_run() {
        // vCPU thread keeps `ioctl` for `KVM_RUN` only, `TIOCGWINSZ` on
        // the same syscall is refused by the argument condition. Both name
        // a closed descriptor, so `EBADF` shows the kernel ran the call.
        let (entering, terminal): (Answer, Answer) = under(Thread::Vcpu, || {
            // SAFETY: -1 is not an open descriptor, the kernel fails the call
            // before reading the third argument.
            let entering = unsafe { libc::ioctl(-1, KVM_RUN as _, 0) };
            let entering = (entering as libc::c_long, errno());
            // SAFETY: same as above.
            let terminal = unsafe { libc::ioctl(-1, libc::TIOCGWINSZ as _, 0) };
            (entering, (terminal as libc::c_long, errno()))
        });
        assert_eq!(
            entering,
            (-1, libc::EBADF),
            "KVM_RUN did not reach the kernel"
        );
        assert_eq!(
            terminal,
            (-1, libc::ENOSYS),
            "TIOCGWINSZ was allowed on a vCPU thread"
        );
    }

    #[test]
    fn test_device_thread_refuses_kvm_run() {
        // `KVM_RUN` is refused on a device thread, `lseek` reaches the
        // kernel.
        let (entering, seeking): (Answer, Answer) = under(Thread::Device, || {
            // SAFETY: -1 is not an open descriptor.
            let entering = unsafe { libc::ioctl(-1, KVM_RUN as _, 0) };
            let entering = (entering as libc::c_long, errno());
            // SAFETY: `lseek` on a closed descriptor touches no memory.
            let seeking = unsafe { libc::lseek(-1, 0, libc::SEEK_SET) };
            (entering, (seeking as libc::c_long, errno()))
        });
        assert_eq!(
            entering,
            (-1, libc::ENOSYS),
            "KVM_RUN was allowed on a device thread"
        );
        assert_eq!(seeking, (-1, libc::EBADF), "lseek did not reach the kernel");
    }
}
