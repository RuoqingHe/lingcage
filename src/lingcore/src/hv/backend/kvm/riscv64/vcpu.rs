// SPDX-FileCopyrightText: 2026 LingCage <opensource@lingcage.com>
//
// SPDX-License-Identifier: Apache-2.0

//! riscv64 side of `KvmVcpu`. Exits left to userspace by KVM and
//! answered in the run page, plus core and configuration registers read
//! by id.

use std::mem::offset_of;

use kvm_bindings::{
    KVM_EXIT_RISCV_SBI, KVM_REG_RISCV_CONFIG, KVM_REG_RISCV_CORE, KVM_REG_RISCV_ISA_EXT,
    KVM_REG_RISCV_ISA_SINGLE, KVM_REG_RISCV_TIMER, kvm_riscv_config, kvm_riscv_timer, kvm_run,
};
use kvm_ioctls::VcpuFd;
use log::debug;

use crate::hv::arch::{ConfigReg, Reg};
use crate::hv::backend::kvm::riscv64::{
    extension_name, get_reg, index, kind, reg_id, reg_list, set_reg,
};
use crate::hv::{Error, Result};

// TODO: The SBI debug console extension is not yet offered.
/// `SBI_ERR_NOT_SUPPORTED`, the reply to a call on an extension which
/// the platform does not have.
const SBI_ERR_NOT_SUPPORTED: i64 = -2;

/// Single-letter extensions in canonical order of the ISA manual. `i`
/// opens the string as the base.
const SINGLE_LETTERS: &str = "iemafdqlcbkjtpvnh";

/// The Zkr `seed` CSR, `CSR_SEED` in `arch/riscv/include/asm/csr.h`. KVM
/// leaves it to userspace. Bits 31:30 carry the status, `ES16` for a
/// valid draw of sixteen bits and `WAIT` for none.
const CSR_SEED: u64 = 0x015;
const SEED_ES16: u64 = 2 << 30;
const SEED_WAIT: u64 = 1 << 30;

/// Answer the exit in `run`, one which KVM leaves to userspace. SBI call
/// is refused, so the guest sees an extension the platform does not
/// have. CSR access is `seed`, answered with entropy.
pub(in crate::hv::backend::kvm) fn answer(run: &mut kvm_run) {
    if run.exit_reason == KVM_EXIT_RISCV_SBI {
        refuse_sbi(run);
    } else {
        answer_csr(run);
    }
}

/// Answer the SBI call in `run` with `SBI_ERR_NOT_SUPPORTED`.
fn refuse_sbi(run: &mut kvm_run) {
    // SAFETY: the exit was `KVM_EXIT_RISCV_SBI`, so `riscv_sbi` is the
    // union arm filled in by KVM.
    let call = unsafe { &mut run.__bindgen_anon_1.riscv_sbi };
    // The guest picks the calls, so this stays at debug.
    debug!(
        "SBI extension {:#x} function {:#x} not offered, refused",
        call.extension_id, call.function_id
    );
    call.ret[0] = SBI_ERR_NOT_SUPPORTED as u64;
    call.ret[1] = 0;
}

/// Answer the CSR access in `run`. `seed` reads sixteen bits from
/// `getrandom(2)`, or reports `WAIT` if the call gives none. Other CSRs
/// read as zero, since KVM forwards no other.
fn answer_csr(run: &mut kvm_run) {
    // SAFETY: the exit was `KVM_EXIT_RISCV_CSR`, so `riscv_csr` is the
    // union arm filled in by KVM.
    let access = unsafe { &mut run.__bindgen_anon_1.riscv_csr };
    access.ret_value = if u64::from(access.csr_num) == CSR_SEED {
        let mut entropy = [0u8; 2];
        // SAFETY: `entropy` is writable for its length during the call.
        let drawn = unsafe { libc::getrandom(entropy.as_mut_ptr().cast(), entropy.len(), 0) };
        if drawn == entropy.len() as isize {
            SEED_ES16 | u64::from(u16::from_le_bytes(entropy))
        } else {
            SEED_WAIT
        }
    } else {
        debug!("CSR {:#x} not emulated, read as zero", access.csr_num);
        0
    };
}

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

/// Read configuration register `reg` of the vCPU named by `fd`. Block
/// size is zero without its extension.
pub(in crate::hv::backend::kvm) fn config(fd: &VcpuFd, reg: ConfigReg) -> Result<u64> {
    let config = |field: usize| reg_id(KVM_REG_RISCV_CONFIG, (field / size_of::<u64>()) as u64);
    let id = match reg {
        ConfigReg::Isa => config(offset_of!(kvm_riscv_config, isa)),
        ConfigReg::SatpMode => config(offset_of!(kvm_riscv_config, satp_mode)),
        ConfigReg::Timebase => reg_id(
            KVM_REG_RISCV_TIMER,
            (offset_of!(kvm_riscv_timer, frequency) / size_of::<u64>()) as u64,
        ),
        ConfigReg::CbomBlockSize => config(offset_of!(kvm_riscv_config, zicbom_block_size)),
        ConfigReg::CbozBlockSize => config(offset_of!(kvm_riscv_config, zicboz_block_size)),
    };
    match get_reg(fd, id) {
        // Block size is `ENOENT` without its extension.
        Err(Error::Os { errno, .. })
            if errno == libc::ENOENT
                && matches!(reg, ConfigReg::CbomBlockSize | ConfigReg::CbozBlockSize) =>
        {
            Ok(0)
        }
        other => other,
    }
}

/// Returns ISA of the vCPU named by `fd`, spelled like `riscv,isa`,
/// namely `rv64`, single-letter extensions, then each multi-letter
/// extension enabled by KVM after an underscore.
pub(in crate::hv::backend::kvm) fn isa(fd: &VcpuFd) -> Result<String> {
    let letters = config(fd, ConfigReg::Isa)?;
    let mut isa = String::from("rv64");
    for letter in SINGLE_LETTERS.chars() {
        if letters & 1 << (letter as u32 - 'a' as u32) != 0 {
            isa.push(letter);
        }
    }
    for id in reg_list(fd)? {
        if kind(id) != KVM_REG_RISCV_ISA_EXT | KVM_REG_RISCV_ISA_SINGLE {
            continue;
        }
        if get_reg(fd, id)? == 0 {
            continue;
        }
        if let Some(name) = extension_name(index(id)) {
            isa.push('_');
            isa.push_str(name);
        }
    }
    Ok(isa)
}

#[cfg(test)]
mod tests {
    use std::alloc::{Layout, alloc_zeroed, dealloc};

    use crate::hv::arch::{ConfigReg, Reg};
    use crate::hv::backend::kvm::hypervisor::KvmHv;
    use crate::hv::backend::kvm::riscv64::vcpu::{SBI_ERR_NOT_SUPPORTED, SEED_ES16};
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

    /// li t0, 0x2000 / lui a7, 0x08000 / li a6, 0 / ecall / sw a0, 0(t0)
    /// / ecall for `sbi_system_reset` shutdown / j .
    ///
    /// Experimental extension range is forwarded to userspace. The store
    /// carries `a0`.
    const SBI_PROGRAM: [u8; 36] = [
        0x89, 0x62, 0xb7, 0x08, 0x00, 0x08, 0x01, 0x48, 0x73, 0x00, 0x00, 0x00, 0x23, 0xa0, 0xa2,
        0x00, 0xb7, 0x58, 0x52, 0x53, 0x9b, 0x88, 0x48, 0x35, 0x01, 0x48, 0x01, 0x45, 0x81, 0x45,
        0x73, 0x00, 0x00, 0x00, 0x01, 0xa0,
    ];

    #[test]
    fn test_refuse_forwarded_sbi_call() {
        let hv = KvmHv::new().expect("open /dev/kvm");
        let vm = hv.create_vm().expect("guest");
        let (host, layout) = map_code(&vm, &SBI_PROGRAM);
        let mut cpu = vm.create_vcpu(0).expect("vcpu 0");
        cpu.set_regs(&[(Reg::Pc, CODE)]).expect("entry point");
        assert_eq!(
            cpu.run(VmEntry::Run).expect("run"),
            VmExit::Mmio {
                addr: 0x2000,
                write: Some(SBI_ERR_NOT_SUPPORTED as u32 as u64),
                size: 4
            }
        );
        assert_eq!(cpu.run(VmEntry::Run).expect("run"), VmExit::Shutdown);

        // SAFETY: `host` came from `alloc_zeroed` with `layout`, and the VM
        // which maps it is dropped at the end of the scope.
        unsafe { dealloc(host, layout) };
    }

    /// li t0, 0x2000 / csrrw t1, seed, zero / sw t1, 0(t0) / ecall for
    /// `sbi_system_reset` shutdown / j .
    const SEED_PROGRAM: [u8; 30] = [
        0x89, 0x62, 0x73, 0x13, 0x50, 0x01, 0x23, 0xa0, 0x62, 0x00, 0xb7, 0x58, 0x52, 0x53, 0x9b,
        0x88, 0x48, 0x35, 0x01, 0x48, 0x01, 0x45, 0x81, 0x45, 0x73, 0x00, 0x00, 0x00, 0x01, 0xa0,
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

    #[test]
    fn test_isa_and_config_registers() {
        let hv = KvmHv::new().expect("open /dev/kvm");
        let vm = hv.create_vm().expect("guest");
        let cpu = vm.create_vcpu(0).expect("vcpu 0");

        let isa = cpu.isa().expect("isa");
        let letters = &isa[..isa.find('_').unwrap_or(isa.len())];
        assert!(letters.starts_with("rv64i"), "{isa}");
        // Letters which KVM does not disable.
        for letter in ['m', 'a', 'c'] {
            assert!(letters.contains(letter), "{isa} lacks {letter}");
        }
        assert!(
            matches!(
                cpu.get_config(ConfigReg::SatpMode).expect("satp"),
                8 | 9 | 10
            ),
            "satp mode is not Sv39, Sv48 or Sv57"
        );
        assert_ne!(cpu.get_config(ConfigReg::Timebase).expect("timebase"), 0);
        // Block size is zero without its extension and a power of two with
        // it.
        for (name, reg) in [
            ("_zicbom", ConfigReg::CbomBlockSize),
            ("_zicboz", ConfigReg::CbozBlockSize),
        ] {
            let size = cpu.get_config(reg).expect("block size");
            assert_eq!(isa.contains(name), size != 0, "{isa}: {name} {size}");
            assert!(size == 0 || size.is_power_of_two());
        }
    }

    #[test]
    fn test_seed_csr_entropy() {
        // KVM leaves the `seed` CSR to userspace. Guest stores the value
        // it read, with the `ES16` status bits inside.
        let hv = KvmHv::new().expect("open /dev/kvm");
        let vm = hv.create_vm().expect("guest");
        let (host, layout) = map_code(&vm, &SEED_PROGRAM);
        let mut cpu = vm.create_vcpu(0).expect("vcpu 0");
        // Without Zkr the access is an illegal instruction in the guest.
        if !cpu.isa().expect("isa").contains("_zkr") {
            // SAFETY: `host` came from `alloc_zeroed` with `layout`, and the
            // VM which maps it is dropped at the end of the scope.
            unsafe { dealloc(host, layout) };
            return;
        }
        cpu.set_regs(&[(Reg::Pc, CODE)]).expect("entry point");
        match cpu.run(VmEntry::Run).expect("run") {
            VmExit::Mmio {
                addr: 0x2000,
                write: Some(seed),
                size: 4,
            } => assert_eq!(seed & 0xc000_0000, SEED_ES16, "seed read {seed:#x}"),
            other => panic!("unexpected exit {other:?}"),
        }
        assert_eq!(cpu.run(VmEntry::Run).expect("run"), VmExit::Shutdown);

        // SAFETY: `host` came from `alloc_zeroed` with `layout`, and the VM
        // which maps it is dropped at the end of the scope.
        unsafe { dealloc(host, layout) };
    }
}
