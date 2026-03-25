// SPDX-FileCopyrightText: 2026 LingCage <opensource@lingcage.com>
//
// SPDX-License-Identifier: Apache-2.0

//! `KvmVm`, the guest handle, and the parts created from it.

use std::sync::{Arc, Mutex, OnceLock};
use std::thread::JoinHandle;

#[cfg(target_arch = "x86_64")]
use kvm_bindings::{KVM_PIT_SPEAKER_DUMMY, kvm_pit_config};
use kvm_ioctls::{Cap, VmFd};
use vmm_sys_util::eventfd::{EFD_NONBLOCK, EventFd};
use vmm_sys_util::signal::{Killable, SIGRTMIN, register_signal_handler};

use crate::hv::backend::kvm::ioeventfd::KvmIoeventFdRegistry;
use crate::hv::backend::kvm::irq::{KvmIrqSender, KvmMsiSender, Routing};
use crate::hv::backend::kvm::kvm_err;
use crate::hv::backend::kvm::memory::KvmMemory;
use crate::hv::backend::kvm::vcpu::KvmVcpu;
use crate::hv::{Error, Result};

/// Signal handler of the kick. A signal with handler makes `KVM_RUN`
/// return `EINTR`, an ignored one leaves the run going and a defaulted
/// one ends the process.
extern "C" fn take_kick(_: libc::c_int, _: *mut libc::siginfo_t, _: *mut libc::c_void) {}

/// Result of installing `take_kick`, done once per process.
static KICK_HANDLER: OnceLock<std::result::Result<(), i32>> = OnceLock::new();

/// Install `take_kick` on `SIGRTMIN` once per process. `sigaction` is
/// issued without `SA_RESTART`, so that an interrupted `KVM_RUN` returns
/// instead of resuming.
fn register_kick() -> Result<()> {
    let outcome = KICK_HANDLER
        .get_or_init(|| register_signal_handler(SIGRTMIN(), take_kick).map_err(|err| err.errno()));
    match outcome {
        Ok(()) => Ok(()),
        Err(errno) => Err(Error::Os {
            op: "sigaction",
            errno: *errno,
        }),
    }
}

/// Guest handle, the VM fd returned by `KVM_CREATE_VM`. Parts created
/// from it share the fd.
pub struct KvmVm {
    pub(in crate::hv::backend::kvm) fd: Arc<VmFd>,
    pub(in crate::hv::backend::kvm) routing: Arc<Mutex<Routing>>,
}

impl KvmVm {
    /// Wrap `fd`. Routing table starts empty.
    pub(in crate::hv::backend::kvm) fn new(fd: VmFd) -> Self {
        KvmVm {
            fd: Arc::new(fd),
            routing: Arc::new(Mutex::new(Routing::default())),
        }
    }

    /// Create the guest physical address space, no region mapped yet.
    pub fn create_vm_memory(&self) -> Result<KvmMemory> {
        Ok(KvmMemory::new(Arc::clone(&self.fd)))
    }

    /// Create the in-kernel irqchip (PIC, IOAPIC and LAPICs) through
    /// `KVM_CREATE_IRQCHIP`, and the i8254 PIT through `KVM_CREATE_PIT2`.
    #[cfg(target_arch = "x86_64")]
    pub fn enable_irqchip(&self) -> Result<()> {
        self.fd
            .create_irq_chip()
            .map_err(kvm_err("KVM_CREATE_IRQCHIP"))?;
        // `KVM_PIT_SPEAKER_DUMMY` registers a speaker stub at port 0x61 in
        // kernel, so guest write there does not exit to VMM.
        self.fd
            .create_pit2(kvm_pit_config {
                flags: KVM_PIT_SPEAKER_DUMMY,
                ..Default::default()
            })
            .map_err(kvm_err("KVM_CREATE_PIT2"))?;
        Ok(())
    }

    /// Create the vCPU with id `cpu_index` through `KVM_CREATE_VCPU`. A
    /// second vCPU with the same id fails with `EEXIST`.
    pub fn create_vcpu(&self, cpu_index: u16) -> Result<KvmVcpu> {
        let fd = self
            .fd
            .create_vcpu(u64::from(cpu_index))
            .map_err(kvm_err("KVM_CREATE_VCPU"))?;
        Ok(KvmVcpu::new(
            fd,
            #[cfg(target_arch = "x86_64")]
            self.xsave_size(),
        ))
    }

    /// Returns XSAVE area size in bytes, as reported by `KVM_CAP_XSAVE2`, or
    /// `size_of::<kvm_xsave>()` on a kernel without the cap.
    #[cfg(target_arch = "x86_64")]
    fn xsave_size(&self) -> usize {
        let reported = self.fd.check_extension_int(Cap::Xsave2);
        if reported <= 0 {
            size_of::<kvm_bindings::kvm_xsave>()
        } else {
            reported as usize
        }
    }

    /// Bind a new eventfd to irqchip pin `pin` through `KVM_IRQFD` and
    /// return the sender which writes it. Pin is fixed for each sender.
    pub fn create_irq_sender(&self, pin: u8) -> Result<KvmIrqSender> {
        let eventfd = EventFd::new(EFD_NONBLOCK).map_err(kvm_err("eventfd"))?;
        {
            let mut routing = self.routing.lock().unwrap();
            routing.pins.insert(pin);
            routing.apply(&self.fd)?;
        }
        self.fd
            .register_irqfd(&eventfd, u32::from(pin))
            .map_err(kvm_err("KVM_IRQFD"))?;
        Ok(KvmIrqSender::new(eventfd))
    }

    /// Create the MSI sender. Returns `Unsupported` without
    /// `KVM_CAP_SIGNAL_MSI`.
    pub fn create_msi_sender(&self) -> Result<KvmMsiSender> {
        if !self.fd.check_extension(Cap::SignalMsi) {
            return Err(Error::Unsupported("KVM_CAP_SIGNAL_MSI"));
        }
        Ok(KvmMsiSender::new(
            Arc::clone(&self.fd),
            Arc::clone(&self.routing),
        ))
    }

    /// Kick the vCPU thread driven by `handle` with `SIGRTMIN`. A run inside
    /// `KVM_RUN` returns `VmExit::Interrupted`, a kick landing outside the
    /// ioctl has no effect, so caller repeats it until the run reports it.
    pub fn stop_vcpu<T>(&self, _cpu_index: u16, handle: &JoinHandle<T>) -> Result<()> {
        register_kick()?;
        handle.kill(SIGRTMIN()).map_err(kvm_err("pthread_kill"))
    }

    /// Create the ioeventfd registry.
    pub fn create_ioeventfd_registry(&self) -> KvmIoeventFdRegistry {
        KvmIoeventFdRegistry::new(Arc::clone(&self.fd))
    }
}

#[cfg(test)]
mod tests {
    #[cfg(target_arch = "x86_64")]
    use std::alloc::{Layout, alloc_zeroed, dealloc};
    use std::os::fd::AsRawFd;
    #[cfg(target_arch = "x86_64")]
    use std::sync::mpsc;
    #[cfg(target_arch = "x86_64")]
    use std::thread;
    #[cfg(target_arch = "x86_64")]
    use std::time::Duration;

    use crate::hv::backend::kvm::hypervisor::KvmHv;
    #[cfg(target_arch = "x86_64")]
    use crate::hv::memory::{MemMapOption, VmMemory};
    #[cfg(target_arch = "x86_64")]
    use crate::hv::vcpu::{Vcpu, VmEntry, VmExit};

    #[test]
    fn test_create_guests() {
        let hv = KvmHv::new().expect("open /dev/kvm");
        let one = hv.create_vm().expect("first guest");
        let two = hv.create_vm().expect("second guest");
        assert_ne!(one.fd.as_raw_fd(), two.fd.as_raw_fd());
    }

    #[cfg(target_arch = "x86_64")]
    #[test]
    fn test_irqchip_created_once() {
        let hv = KvmHv::new().expect("open /dev/kvm");
        let vm = hv.create_vm().expect("guest");
        vm.enable_irqchip().expect("in-kernel irqchip");
        // Second `KVM_CREATE_IRQCHIP` fails with `EEXIST`.
        vm.enable_irqchip().expect_err("irqchip again");
    }

    #[cfg(target_arch = "x86_64")]
    #[test]
    fn test_kick_blocked_vcpu() {
        // vCPU other than 0 is created stopped and blocks inside `KVM_RUN`
        // until the guest starts it, so a kick is needed to bring it out.
        let hv = KvmHv::new().expect("open /dev/kvm");
        let vm = hv.create_vm().expect("guest");
        // With in-kernel irqchip, `hlt` blocks inside `KVM_RUN` instead of
        // exiting as `Halt`.
        vm.enable_irqchip().expect("in-kernel irqchip");
        let mem = vm.create_vm_memory().expect("address space");

        let layout = Layout::from_size_align(0x1000, 0x1000).expect("page-aligned layout");
        // SAFETY: `layout` has non-zero size.
        let reset = unsafe { alloc_zeroed(layout) };
        assert!(!reset.is_null());
        let code = [0xf4, 0xeb, 0xfd]; // hlt; jmp back to the hlt
        // SAFETY: the allocation is one page and `code` fits at 0xff0.
        unsafe { std::ptr::copy_nonoverlapping(code.as_ptr(), reset.add(0xff0), code.len()) };
        mem.mem_map(0xffff_f000, 0x1000, reset as usize, MemMapOption::default())
            .expect("map the reset vector");

        let mut cpu = vm.create_vcpu(0).expect("vcpu 0");
        let (tell, exits) = mpsc::channel();
        let running = thread::spawn(move || {
            let exit = cpu.run(VmEntry::Run);
            tell.send(exit).expect("report the exit");
        });

        // Kick before the thread is inside the ioctl has no effect, so
        // repeat it until the run reports one.
        let mut exit = None;
        for _ in 0..50 {
            vm.stop_vcpu(0, &running).expect("kick");
            match exits.recv_timeout(Duration::from_millis(100)) {
                Ok(reported) => {
                    exit = Some(reported.expect("run"));
                    break;
                }
                Err(mpsc::RecvTimeoutError::Timeout) => continue,
                Err(err) => panic!("vCPU thread went away: {err}"),
            }
        }
        // Checked before the join, so that a thread still inside `KVM_RUN`
        // fails the test instead of hanging it.
        let exit = exit.expect("run did not return");
        running.join().expect("vCPU thread");
        assert_eq!(
            exit,
            VmExit::Interrupted,
            "guest came out for another reason"
        );

        // SAFETY: `reset` came from `alloc_zeroed` with `layout`, and the
        // guest is not run anymore.
        unsafe { dealloc(reset, layout) };
    }
}
