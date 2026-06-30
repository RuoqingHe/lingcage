// SPDX-FileCopyrightText: 2026 LingCage <opensource@lingcage.com>
//
// SPDX-License-Identifier: Apache-2.0

//! Per-thread syscall allowlists of the threads running a guest.
//!
//! Filter is installed from inside a thread and stays until the thread
//! exits. It only bounds syscalls of that thread, descriptors and memory
//! still belong to the process. On a glibc host, the trim path of
//! malloc reads `/proc/sys/vm/overcommit_memory`, and a confined thread
//! is not allowed to `openat`. `Refusal::Trap` ends the process for it.
//! An embedder on glibc should disable trimming
//! (`mallopt(M_TRIM_THRESHOLD, -1)`) or accept `Refusal::Errno`, since
//! under it malloc treats the read as absent.

use std::collections::BTreeMap;

use seccompiler::{
    SeccompAction, SeccompCmpArgLen, SeccompCmpOp, SeccompCondition, SeccompFilter, SeccompRule,
    TargetArch,
};
use thiserror::Error;

mod report;

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
    /// `sigaction` failed to register the `SIGSYS` handler.
    #[error("failed to install the SIGSYS handler")]
    Report(#[source] std::io::Error),
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
/// allocator, `futex` for a hold, `rt_sigreturn` for a kick, `exit`,
/// `exit_group` for the `SIGSYS` handler, and `write`.
///
/// Not listed: process creation, sockets, `ptrace`, `openat`, `mount`
/// and module loading.
const COMMON: &[libc::c_long] = &[
    libc::SYS_brk,
    libc::SYS_exit,
    libc::SYS_exit_group,
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

/// Architecture which the allowlist checks syscall numbers against.
#[cfg(target_arch = "x86_64")]
const ARCH: TargetArch = TargetArch::x86_64;
#[cfg(target_arch = "riscv64")]
const ARCH: TargetArch = TargetArch::riscv64;

/// Syscall behind `poll(2)`. x86_64 has `poll`, riscv64 only has
/// `ppoll`.
#[cfg(target_arch = "x86_64")]
const SYS_POLL: libc::c_long = libc::SYS_poll;
#[cfg(target_arch = "riscv64")]
const SYS_POLL: libc::c_long = libc::SYS_ppoll;

/// Index of `request` in `ioctl(fd, request, ...)`.
const IOCTL_REQUEST: u8 = 1;

/// `KVM_RUN` is `_IO(KVMIO, 0x80)` with `KVMIO` 0xAE, from
/// `include/uapi/linux/kvm.h`.
const KVM_RUN: u64 = 0xae80;

/// `FIONBIO`, the request issued by `set_nonblocking` on a socket, from
/// `include/uapi/asm-generic/ioctls.h`.
const FIONBIO: u64 = 0x5421;

/// `KVM_IRQ_LINE` is `_IOW(KVMIO, 0x61, struct kvm_irq_level)`, eight
/// bytes, from `include/uapi/linux/kvm.h`. A riscv64 thread raises the
/// line of a device through it.
#[cfg(target_arch = "riscv64")]
const KVM_IRQ_LINE: u64 = 0x4008_ae61;

impl Thread {
    /// Returns the name of this thread in a `SIGSYS` report.
    fn tag(self) -> &'static str {
        match self {
            Thread::Vcpu => "vcpu",
            Thread::Device => "device",
        }
    }

    /// Returns the syscalls needed by this thread beyond `COMMON`, with the
    /// conditions on their arguments. Empty rule list allows the syscall
    /// unconditionally.
    fn extras(self) -> Result<BTreeMap<i64, Vec<SeccompRule>>> {
        // `socket` for `AF_UNIX` only. Other family is refused.
        let unix_only = vec![
            SeccompRule::new(vec![
                SeccompCondition::new(
                    0,
                    SeccompCmpArgLen::Dword,
                    SeccompCmpOp::Eq,
                    libc::AF_UNIX as u64,
                )
                .map_err(Error::Assemble)?,
            ])
            .map_err(Error::Assemble)?,
        ];
        // `ioctl` for `request` only. Other request is refused.
        let request = |request: u64| -> Result<SeccompRule> {
            SeccompRule::new(vec![
                SeccompCondition::new(
                    IOCTL_REQUEST,
                    SeccompCmpArgLen::Dword,
                    SeccompCmpOp::Eq,
                    request,
                )
                .map_err(Error::Assemble)?,
            ])
            .map_err(Error::Assemble)
        };
        match self {
            // `ioctl` for `KVM_RUN`, and on riscv64 for `KVM_IRQ_LINE` which
            // raises the line of the console. The thread there also draws the
            // `seed` CSR of the guest from `getrandom`.
            Thread::Vcpu => Ok(BTreeMap::from([
                (
                    libc::SYS_ioctl,
                    vec![
                        request(KVM_RUN)?,
                        #[cfg(target_arch = "riscv64")]
                        request(KVM_IRQ_LINE)?,
                    ],
                ),
                #[cfg(target_arch = "riscv64")]
                (libc::SYS_getrandom, Vec::new()),
            ])),
            // The ioeventfd is polled and read, the disk is sought, read,
            // written and flushed, the channel accepts incoming connections and
            // opens, connects, sends on, receives on, shuts and closes a host
            // socket per connection. `ioctl` is for `FIONBIO`, and on riscv64
            // for `KVM_IRQ_LINE` which raises the line of a device.
            Thread::Device => Ok(BTreeMap::from([
                (libc::SYS_accept4, Vec::new()),
                (libc::SYS_close, Vec::new()),
                (libc::SYS_connect, Vec::new()),
                (libc::SYS_fcntl, Vec::new()),
                (libc::SYS_fdatasync, Vec::new()),
                (libc::SYS_lseek, Vec::new()),
                (SYS_POLL, Vec::new()),
                (libc::SYS_read, Vec::new()),
                (libc::SYS_recvfrom, Vec::new()),
                (libc::SYS_sendto, Vec::new()),
                (libc::SYS_shutdown, Vec::new()),
                (
                    libc::SYS_ioctl,
                    vec![
                        request(FIONBIO)?,
                        #[cfg(target_arch = "riscv64")]
                        request(KVM_IRQ_LINE)?,
                    ],
                ),
                (libc::SYS_socket, unix_only),
            ])),
        }
    }
}

/// Assembled allowlist of a thread kind. Assembling is separated from
/// installing, so that a list which fails to assemble is reported by
/// the caller starting the threads.
#[derive(Clone)]
pub struct Filter {
    program: seccompiler::BpfProgram,
    thread: Thread,
    refusal: Refusal,
}

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
        let filter = SeccompFilter::new(rules, refused, SeccompAction::Allow, ARCH)
            .map_err(Error::Assemble)?;
        let program = seccompiler::BpfProgram::try_from(filter).map_err(Error::Assemble)?;
        Ok(Filter {
            program,
            thread,
            refusal,
        })
    }

    /// Install the allowlist on the calling thread, it stays until the
    /// thread exits. Call it from inside the thread, before the guest runs.
    ///
    /// Under `Refusal::Trap` the `SIGSYS` handler is registered first,
    /// since `rt_sigaction` is on no allowlist.
    pub fn confine(&self) -> Result<()> {
        if self.refusal == Refusal::Trap {
            report::arm(self.thread.tag()).map_err(Error::Report)?;
        }
        seccompiler::apply_filter(&self.program).map_err(Error::Install)
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
    #[test]
    fn test_sigsys_report() {
        // Report names the thread and the syscall number. It is read from
        // a child process, since the handler ends the process which made
        // it.
        use crate::seccomp::report::tests::ended_in_a_child;

        // Allowlist is assembled here instead of in the child. Building one
        // allocates, which the child of a fork cannot do.
        let filter = Filter::new(Thread::Vcpu, Refusal::Trap).expect("assemble allowlist");
        let ended = ended_in_a_child(|| {
            filter.confine().expect("install allowlist");
            // SAFETY: `socket` takes no pointer. Under `Refusal::Trap` the
            // kernel raises `SIGSYS` instead of returning.
            unsafe { libc::socket(libc::AF_INET, libc::SOCK_STREAM, 0) };
        });
        let said = &ended.said;
        let owed = format!("the vcpu thread was refused syscall {}", libc::SYS_socket);
        assert!(said.contains(&owed), "stderr was:\n{said}");
        assert_eq!(
            ended.code,
            Some(128 + libc::SIGSYS),
            "exit status is not 128 + SIGSYS"
        );
    }
}
