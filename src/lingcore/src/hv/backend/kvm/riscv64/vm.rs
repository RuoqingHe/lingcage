// SPDX-FileCopyrightText: 2026 LingCage <opensource@lingcage.com>
//
// SPDX-License-Identifier: Apache-2.0

//! riscv64 side of `KvmVm`, harts counted for the AIA, and the AIA once
//! created.

use std::sync::OnceLock;
use std::sync::atomic::{AtomicU32, Ordering};

use kvm_bindings::{KVM_MP_STATE_STOPPED, kvm_mp_state};
use kvm_ioctls::{VcpuFd, VmFd};

use crate::hv::arch::Aia;
use crate::hv::backend::kvm::kvm_err;
use crate::hv::backend::kvm::riscv64::aia::KvmAia;
use crate::hv::{Error, Result};

/// Platform of a riscv64 guest, its harts and the AIA.
#[derive(Default)]
pub(in crate::hv::backend::kvm) struct Platform {
    /// The AIA, once created by `enable_in_kernel_irqchip`.
    aia: OnceLock<KvmAia>,
    /// vCPUs created so far. The AIA is sized according to them.
    harts: AtomicU32,
}

impl Platform {
    /// Count the vCPU named by `fd`, numbered `cpu_index`, as a hart. vCPU
    /// other than 0 is stopped, so that the guest starts it through SBI
    /// HSM.
    pub(in crate::hv::backend::kvm) fn adopt(&self, cpu_index: u16, fd: &VcpuFd) -> Result<()> {
        if cpu_index != 0 {
            fd.set_mp_state(kvm_mp_state {
                mp_state: KVM_MP_STATE_STOPPED,
            })
            .map_err(kvm_err("KVM_SET_MP_STATE"))?;
        }
        self.harts.fetch_add(1, Ordering::SeqCst);
        Ok(())
    }

    /// Create the AIA placed by `aia` in `vm`, for the harts counted so far.
    /// KVM initializes one AIA per guest, a second one is refused.
    pub(in crate::hv::backend::kvm) fn create_aia(&self, vm: &VmFd, aia: &Aia) -> Result<()> {
        let made = KvmAia::new(vm, aia, self.harts.load(Ordering::SeqCst))?;
        if self.aia.set(made).is_err() {
            return Err(Error::Os {
                op: "KVM_CREATE_DEVICE",
                errno: libc::EEXIST,
            });
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::sync::mpsc;
    use std::thread;
    use std::time::Duration;

    use crate::hv::Cap;
    use crate::hv::arch::Aia;
    use crate::hv::backend::kvm::hypervisor::KvmHv;
    use crate::hv::hypervisor::Hypervisor;
    use crate::hv::vcpu::{Vcpu, VmEntry, VmExit};
    use crate::hv::vm::Vm;

    /// An AIA laid out the way a machine lays one out.
    const AIA: Aia = Aia {
        aplic: 0x0040_0000,
        imsic: 0x0400_0000,
        sources: 31,
        ids: 63,
    };

    #[test]
    fn test_irqchip_created_once() {
        let hv = KvmHv::new().expect("open /dev/kvm");
        let vm = hv.create_vm().expect("guest");
        let _cpu0 = vm.create_vcpu(0).expect("vcpu 0");
        vm.enable_in_kernel_irqchip(&AIA)
            .expect("in-kernel irqchip");
        // KVM initializes an AIA only once, a second one gets `EBUSY`.
        vm.enable_in_kernel_irqchip(&AIA)
            .expect_err("irqchip again");
    }

    #[test]
    fn test_kick_blocked_vcpu() {
        // vCPU other than 0 is created stopped and blocks inside `KVM_RUN`
        // until the guest starts it, so a kick is needed to bring it out.
        let hv = KvmHv::new().expect("open /dev/kvm");
        let vm = hv.create_vm().expect("guest");
        let _cpu0 = vm.create_vcpu(0).expect("vcpu 0");
        let mut cpu = vm.create_vcpu(1).expect("vcpu 1");
        let (tell, exits) = mpsc::channel();
        let running = thread::spawn(move || {
            let exit = cpu.run(VmEntry::Run);
            tell.send(exit).expect("report the exit");
        });

        // Kick before the thread is inside the ioctl has no effect, so
        // repeat it until the run reports one.
        let mut exit = None;
        for _ in 0..50 {
            vm.stop_vcpu(1, &running).expect("kick");
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
    }

    #[test]
    fn test_capabilities() {
        let hv = KvmHv::new().expect("open /dev/kvm");
        let vm = hv.create_vm().expect("guest");
        let _cpu0 = vm.create_vcpu(0).expect("vcpu 0");

        // Ioeventfds and dirty logging do not depend on the irqchip.
        assert!(vm.capability(Cap::IoeventFd));
        assert!(vm.capability(Cap::DirtyLog));

        // Interrupt caps are reported once the AIA is in the kernel.
        assert!(!vm.capability(Cap::InKernelIrqChip));
        assert!(!vm.capability(Cap::IrqFd));
        vm.enable_in_kernel_irqchip(&AIA)
            .expect("in-kernel irqchip");
        assert!(vm.capability(Cap::InKernelIrqChip));
        assert!(vm.capability(Cap::IrqFd));
    }
}
