// SPDX-FileCopyrightText: 2026 LingCage <opensource@lingcage.com>
//
// SPDX-License-Identifier: Apache-2.0

//! `KvmVm`, the guest handle, and the parts created from it.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::thread::JoinHandle;

#[cfg(target_arch = "x86_64")]
use kvm_bindings::{KVM_PIT_SPEAKER_DUMMY, kvm_pit_config};
use kvm_ioctls::{Cap as KvmCap, VmFd};
#[cfg(not(target_arch = "riscv64"))]
use vmm_sys_util::eventfd::{EFD_CLOEXEC, EFD_NONBLOCK, EventFd};
use vmm_sys_util::signal::{Killable, SIGRTMIN, register_signal_handler};

#[cfg(any(target_arch = "x86_64", target_arch = "riscv64"))]
use crate::hv::StateBlob;
#[cfg(target_arch = "riscv64")]
use crate::hv::arch::Aia;
#[cfg(target_arch = "aarch64")]
use crate::hv::arch::Gic;
#[cfg(target_arch = "aarch64")]
use crate::hv::backend::kvm::aarch64::vm::Platform;
use crate::hv::backend::kvm::ioeventfd::KvmIoeventFdRegistry;
#[cfg(any(target_arch = "aarch64", target_arch = "riscv64"))]
use crate::hv::backend::kvm::irq::FIRST_MSI_GSI;
use crate::hv::backend::kvm::irq::{KvmIrqSender, KvmMsiSender, Routing};
use crate::hv::backend::kvm::kvm_err;
use crate::hv::backend::kvm::memory::KvmMemory;
#[cfg(target_arch = "riscv64")]
use crate::hv::backend::kvm::riscv64::clock::ClockState;
#[cfg(target_arch = "riscv64")]
use crate::hv::backend::kvm::riscv64::vm::Platform;
use crate::hv::backend::kvm::vcpu::KvmVcpu;
#[cfg(target_arch = "x86_64")]
use crate::hv::backend::kvm::x86_64::clock::ClockState;
#[cfg(target_arch = "x86_64")]
use crate::hv::backend::kvm::x86_64::irqchip::IrqChipState;
use crate::hv::vm::Vm;
use crate::hv::{Cap, Error, Result};

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
    /// Set once `enable_irqchip` has created the in-kernel irqchip.
    irqchip: AtomicBool,
    /// MSR indices from `KVM_GET_MSR_INDEX_LIST`, passed to each vCPU.
    #[cfg(target_arch = "x86_64")]
    msrs: Arc<[u32]>,
    /// Harts, the AIA and the clock descriptor.
    #[cfg(target_arch = "riscv64")]
    platform: Platform,
    /// Preferred target every vCPU is initialized with.
    #[cfg(target_arch = "aarch64")]
    platform: Platform,
}

impl KvmVm {
    /// Wrap `fd`. Routing table starts empty.
    pub(in crate::hv::backend::kvm) fn new(
        fd: VmFd,
        #[cfg(target_arch = "x86_64")] msrs: Arc<[u32]>,
    ) -> Self {
        KvmVm {
            fd: Arc::new(fd),
            routing: Arc::new(Mutex::new(Routing::default())),
            irqchip: AtomicBool::new(false),
            #[cfg(target_arch = "x86_64")]
            msrs,
            #[cfg(any(target_arch = "aarch64", target_arch = "riscv64"))]
            platform: Platform::default(),
        }
    }

    /// Returns XSAVE area size in bytes, as reported by `KVM_CAP_XSAVE2`, or
    /// `size_of::<kvm_xsave>()` on a kernel without the cap.
    #[cfg(target_arch = "x86_64")]
    fn xsave_size(&self) -> usize {
        let reported = self.fd.check_extension_int(KvmCap::Xsave2);
        if reported <= 0 {
            size_of::<kvm_bindings::kvm_xsave>()
        } else {
            reported as usize
        }
    }
}

impl Vm for KvmVm {
    type Vcpu = KvmVcpu;
    type Memory = KvmMemory;
    type IrqSender = KvmIrqSender;
    type MsiSender = KvmMsiSender;
    type IoeventFdRegistry = KvmIoeventFdRegistry;

    fn create_vcpu(&self, cpu_index: u16) -> Result<KvmVcpu> {
        let fd = self
            .fd
            .create_vcpu(u64::from(cpu_index))
            .map_err(kvm_err("KVM_CREATE_VCPU"))?;
        #[cfg(target_arch = "aarch64")]
        self.platform.adopt(cpu_index, &self.fd, &fd)?;
        #[cfg(target_arch = "riscv64")]
        self.platform.adopt(cpu_index, &fd)?;
        KvmVcpu::new(
            fd,
            #[cfg(target_arch = "x86_64")]
            self.xsave_size(),
            #[cfg(target_arch = "x86_64")]
            Arc::clone(&self.msrs),
        )
    }

    fn create_vm_memory(&self) -> Result<KvmMemory> {
        Ok(KvmMemory::new(Arc::clone(&self.fd)))
    }

    #[cfg(not(target_arch = "riscv64"))]
    fn create_irq_sender(&self, pin: u8) -> Result<KvmIrqSender> {
        let eventfd = EventFd::new(EFD_NONBLOCK | EFD_CLOEXEC).map_err(kvm_err("eventfd"))?;
        // The irqchip routes its pins when created and `Routing::apply`
        // rewrites them, so binding a pin writes no table.
        self.fd
            .register_irqfd(&eventfd, u32::from(pin))
            .map_err(kvm_err("KVM_IRQFD"))?;
        Ok(KvmIrqSender::new(eventfd))
    }

    /// Line is raised through `KVM_IRQ_LINE`, which fails with `ENXIO`
    /// without irqchip. The check is done here, only once.
    #[cfg(target_arch = "riscv64")]
    fn create_irq_sender(&self, pin: u8) -> Result<KvmIrqSender> {
        if !self.irqchip.load(Ordering::Acquire) {
            return Err(Error::Os {
                op: "KVM_IRQ_LINE",
                errno: libc::ENXIO,
            });
        }
        Ok(KvmIrqSender::new(Arc::clone(&self.fd), u32::from(pin)))
    }

    fn create_msi_sender(&self) -> Result<KvmMsiSender> {
        if !self.fd.check_extension(KvmCap::SignalMsi) {
            return Err(Error::Unsupported("KVM_CAP_SIGNAL_MSI"));
        }
        Ok(KvmMsiSender::new(
            Arc::clone(&self.fd),
            Arc::clone(&self.routing),
        ))
    }

    fn create_ioeventfd_registry(&self) -> Result<KvmIoeventFdRegistry> {
        Ok(KvmIoeventFdRegistry::new(Arc::clone(&self.fd)))
    }

    /// Returns whether the guest has `cap`. `IrqFd` and `InKernelIrqChip`
    /// are false until `enable_irqchip` has run.
    fn capability(&self, cap: Cap) -> bool {
        let irqchip = self.irqchip.load(Ordering::Acquire);
        match cap {
            Cap::IoeventFd => self.fd.check_extension(KvmCap::Ioeventfd),
            // irqfd needs a GSI route, and `KVM_SET_GSI_ROUTING` fails with
            // `EINVAL` without in-kernel irqchip.
            Cap::IrqFd => irqchip && self.fd.check_extension(KvmCap::Irqfd),
            Cap::InKernelIrqChip => irqchip,
            // `KVM_MEM_LOG_DIRTY_PAGES` is a slot flag, not an extension.
            Cap::DirtyLog => true,
        }
    }

    #[cfg(target_arch = "x86_64")]
    fn enable_in_kernel_irqchip(&self) -> Result<()> {
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
        self.irqchip.store(true, Ordering::Release);
        Ok(())
    }

    /// Create the AIA for vCPUs created so far. Wired sources take the GSIs
    /// below the first MSI one, since a sender names its pin in a byte.
    #[cfg(target_arch = "aarch64")]
    fn enable_in_kernel_irqchip(&self, gic: &Gic) -> Result<()> {
        if gic.sources >= FIRST_MSI_GSI {
            return Err(Error::Overfull {
                of: "wired interrupt sources",
            });
        }
        self.platform.create_gic(&self.fd, gic)?;
        // The GIC routes GSI `n` to SPI `n`, which is interrupt id 32 plus
        // `n`. Table written from here carries the pins again.
        self.routing.lock().unwrap().pins = gic.sources;
        self.irqchip.store(true, Ordering::Release);
        Ok(())
    }

    #[cfg(target_arch = "riscv64")]
    fn enable_in_kernel_irqchip(&self, aia: &Aia) -> Result<()> {
        if aia.sources >= FIRST_MSI_GSI {
            return Err(Error::Overfull {
                of: "wired interrupt sources",
            });
        }
        self.platform.create_aia(&self.fd, aia)?;
        // The AIA routes GSI `n` to source `n` for each source and the
        // reserved source 0. Table written from here carries them again.
        self.routing.lock().unwrap().pins = aia.sources + 1;
        self.irqchip.store(true, Ordering::Release);
        Ok(())
    }

    #[cfg(target_arch = "riscv64")]
    fn get_irqchip_state(&self) -> Result<StateBlob> {
        self.platform.aia("get_irqchip_state")?.capture()
    }

    #[cfg(target_arch = "riscv64")]
    fn set_irqchip_state(&self, state: &StateBlob) -> Result<()> {
        self.platform.aia("set_irqchip_state")?.restore(state)
    }

    #[cfg(target_arch = "riscv64")]
    fn get_clock(&self) -> Result<StateBlob> {
        ClockState::capture(self.platform.clock("get_clock")?)
    }

    #[cfg(target_arch = "riscv64")]
    fn set_clock(&self, state: &StateBlob) -> Result<()> {
        ClockState::restore(self.platform.clock("set_clock")?, state)
    }

    #[cfg(target_arch = "riscv64")]
    fn set_clock_elapsed(&self, state: &StateBlob) -> Result<()> {
        ClockState::restore_elapsed(self.platform.clock("set_clock_elapsed")?, state)
    }

    #[cfg(target_arch = "x86_64")]
    fn get_irqchip_state(&self) -> Result<StateBlob> {
        if !self.irqchip.load(Ordering::Acquire) {
            return Err(Error::Unsupported("get_irqchip_state"));
        }
        IrqChipState::capture(&self.fd)
    }

    #[cfg(target_arch = "x86_64")]
    fn set_irqchip_state(&self, state: &StateBlob) -> Result<()> {
        if !self.irqchip.load(Ordering::Acquire) {
            return Err(Error::Unsupported("set_irqchip_state"));
        }
        IrqChipState::restore(&self.fd, state)
    }

    #[cfg(target_arch = "x86_64")]
    fn get_clock(&self) -> Result<StateBlob> {
        ClockState::capture(&self.fd)
    }

    #[cfg(target_arch = "x86_64")]
    fn set_clock(&self, state: &StateBlob) -> Result<()> {
        ClockState::restore(&self.fd, state)
    }

    #[cfg(target_arch = "x86_64")]
    fn set_clock_elapsed(&self, state: &StateBlob) -> Result<()> {
        ClockState::restore_elapsed(&self.fd, state)
    }

    fn stop_vcpu<T>(&self, _cpu_index: u16, handle: &JoinHandle<T>) -> Result<()> {
        register_kick()?;
        handle.kill(SIGRTMIN()).map_err(kvm_err("pthread_kill"))
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

    #[cfg(target_arch = "x86_64")]
    use crate::hv::Cap;
    use crate::hv::backend::kvm::hypervisor::KvmHv;
    use crate::hv::hypervisor::Hypervisor;
    #[cfg(target_arch = "x86_64")]
    use crate::hv::memory::{MemMapOption, VmMemory};
    #[cfg(target_arch = "x86_64")]
    use crate::hv::vcpu::{Vcpu, VmEntry, VmExit};
    #[cfg(target_arch = "x86_64")]
    use crate::hv::vm::Vm;

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
        vm.enable_in_kernel_irqchip().expect("in-kernel irqchip");
        // Second `KVM_CREATE_IRQCHIP` fails with `EEXIST`.
        vm.enable_in_kernel_irqchip().expect_err("irqchip again");
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
        vm.enable_in_kernel_irqchip().expect("in-kernel irqchip");
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

    #[cfg(target_arch = "x86_64")]
    #[test]
    fn test_capabilities() {
        let hv = KvmHv::new().expect("open /dev/kvm");
        let vm = hv.create_vm().expect("guest");

        // Ioeventfds and dirty logging do not depend on the irqchip.
        assert!(vm.capability(Cap::IoeventFd));
        assert!(vm.capability(Cap::DirtyLog));

        // Interrupt caps are reported once the irqchip is in the kernel.
        assert!(!vm.capability(Cap::InKernelIrqChip));
        assert!(!vm.capability(Cap::IrqFd));
        vm.enable_in_kernel_irqchip().expect("in-kernel irqchip");
        assert!(vm.capability(Cap::InKernelIrqChip));
        assert!(vm.capability(Cap::IrqFd));
    }
}
