// SPDX-FileCopyrightText: 2026 LingCage <opensource@lingcage.com>
//
// SPDX-License-Identifier: Apache-2.0

//! riscv64 side of `KvmVcpu`, core registers read by id.

use kvm_bindings::KVM_REG_RISCV_CORE;
use kvm_ioctls::VcpuFd;

use crate::hv::Result;
use crate::hv::arch::Reg;
use crate::hv::backend::kvm::riscv64::{get_reg, reg_id, set_reg};

/// Read core register `reg` of the vCPU named by `fd`.
pub(in crate::hv::backend::kvm) fn core_reg(fd: &VcpuFd, reg: Reg) -> Result<u64> {
    get_reg(fd, reg_id(KVM_REG_RISCV_CORE, reg as u64))
}

/// Write core registers in `vals`, in order, to the vCPU named by `fd`.
pub(in crate::hv::backend::kvm) fn set_core_regs(fd: &VcpuFd, vals: &[(Reg, u64)]) -> Result<()> {
    for &(reg, val) in vals {
        set_reg(fd, reg_id(KVM_REG_RISCV_CORE, reg as u64), val)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::alloc::{Layout, alloc_zeroed, dealloc};

    use crate::hv::arch::Reg;
    use crate::hv::backend::kvm::hypervisor::KvmHv;
    use crate::hv::hypervisor::Hypervisor;
    use crate::hv::memory::{MemMapOption, VmMemory};
    use crate::hv::vcpu::{Vcpu, VmEntry, VmExit};
    use crate::hv::vm::Vm;

    const PAGE: usize = 4096;

    /// Guest address the tests map their code at.
    const CODE: u64 = 0x8000_0000;

    /// li t0, 0x2000 / li t1, 0x37 / sb t1, 0(t0) / lb t1, 0(t0)
    /// sb t1, 8(t0) / ecall for `sbi_system_reset` shutdown / j .
    ///
    /// Nothing is mapped at 0x2000, so store and load both exit as MMIO.
    const MMIO_PROGRAM: [u8; 38] = [
        0x89, 0x62, 0x13, 0x03, 0x70, 0x03, 0x23, 0x80, 0x62, 0x00, 0x03, 0x83, 0x02, 0x00, 0x23,
        0x84, 0x62, 0x00, 0xb7, 0x58, 0x52, 0x53, 0x9b, 0x88, 0x48, 0x35, 0x01, 0x48, 0x01, 0x45,
        0x81, 0x45, 0x73, 0x00, 0x00, 0x00, 0x01, 0xa0,
    ];

    /// Map one page holding `code` at `CODE` in `vm`. Returns allocation of
    /// the page.
    fn map_code(vm: &impl Vm, code: &[u8]) -> (*mut u8, Layout) {
        let mem = vm.create_vm_memory().expect("address space");
        let layout = Layout::from_size_align(PAGE, PAGE).expect("page-aligned layout");
        // SAFETY: `layout` has non-zero size.
        let host = unsafe { alloc_zeroed(layout) };
        assert!(!host.is_null());
        // SAFETY: the allocation is one page and `code` fits at its start.
        unsafe { std::ptr::copy_nonoverlapping(code.as_ptr(), host, code.len()) };
        mem.mem_map(CODE, PAGE as u64, host as usize, MemMapOption::default())
            .expect("map the code");
        (host, layout)
    }
    #[test]
    fn test_run_and_complete_port_read() {
        let hv = KvmHv::new().expect("open /dev/kvm");
        let vm = hv.create_vm().expect("guest");
        let (host, layout) = map_code(&vm, &MMIO_PROGRAM);

        let mut cpu = vm.create_vcpu(0).expect("vcpu 0");
        cpu.set_regs(&[(Reg::Pc, CODE)]).expect("entry point");
        assert_eq!(
            cpu.run(VmEntry::Run).expect("run"),
            VmExit::Mmio {
                addr: 0x2000,
                write: Some(0x37),
                size: 1
            }
        );
        assert_eq!(
            cpu.run(VmEntry::Run).expect("run"),
            VmExit::Mmio {
                addr: 0x2000,
                write: None,
                size: 1
            }
        );
        // Guest stores the value of the load next, which shows the read was
        // completed.
        assert_eq!(
            cpu.run(VmEntry::Mmio { data: 0x5a })
                .expect("answer the read"),
            VmExit::Mmio {
                addr: 0x2008,
                write: Some(0x5a),
                size: 1
            }
        );
        assert_eq!(cpu.run(VmEntry::Run).expect("run"), VmExit::Shutdown);

        // SAFETY: `host` came from `alloc_zeroed` with `layout`, and the VM
        // which maps it is dropped at the end of the scope.
        unsafe { dealloc(host, layout) };
    }

    #[test]
    fn test_stopper_interrupts_on_entry() {
        // `Stopper` set between two runs makes the next one return
        // `Interrupted` on entry, before the guest executes anything.
        let hv = KvmHv::new().expect("open /dev/kvm");
        let vm = hv.create_vm().expect("guest");
        let (host, layout) = map_code(&vm, &MMIO_PROGRAM);

        let mut cpu = vm.create_vcpu(0).expect("vcpu 0");
        cpu.set_regs(&[(Reg::Pc, CODE)]).expect("entry point");
        let stopper = cpu.stopper();

        // Without a stop the run reaches the first store.
        assert_eq!(
            cpu.run(VmEntry::Run).expect("run"),
            VmExit::Mmio {
                addr: 0x2000,
                write: Some(0x37),
                size: 1
            }
        );

        // With the stop set, the run returns on entry.
        stopper.stop();
        assert_eq!(
            cpu.run(VmEntry::Run).expect("run"),
            VmExit::Interrupted,
            "run did not return on entry"
        );

        // The run clears the stop, next one reaches the load.
        assert_eq!(
            cpu.run(VmEntry::Run).expect("run"),
            VmExit::Mmio {
                addr: 0x2000,
                write: None,
                size: 1
            },
            "stop not cleared by the run"
        );

        // SAFETY: `host` came from `alloc_zeroed` with `layout`, and the VM
        // which maps it is dropped at the end of the scope.
        unsafe { dealloc(host, layout) };
    }
}
