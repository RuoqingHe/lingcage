// SPDX-FileCopyrightText: 2026 LingCage <opensource@lingcage.com>
//
// SPDX-License-Identifier: Apache-2.0

//! `KvmVcpu`, the `KVM_RUN` loop and register access.

#[cfg(target_arch = "x86_64")]
use std::sync::Arc;

#[cfg(target_arch = "x86_64")]
use kvm_bindings::KVM_EXIT_IO_IN;
use kvm_bindings::{KVM_SYSTEM_EVENT_RESET, KVM_SYSTEM_EVENT_SHUTDOWN};
use kvm_ioctls::{VcpuExit, VcpuFd};

#[cfg(target_arch = "x86_64")]
use crate::hv::Error;
use crate::hv::Result;
#[cfg(target_arch = "x86_64")]
use crate::hv::StateBlob;
#[cfg(target_arch = "x86_64")]
use crate::hv::arch::{CpuidEntry, DtReg, DtRegVal, Reg, SReg, SegReg, SegRegVal};
#[cfg(target_arch = "x86_64")]
use crate::hv::backend::kvm::cpuid::to_kvm;
use crate::hv::backend::kvm::kvm_err;
#[cfg(target_arch = "x86_64")]
use crate::hv::backend::kvm::state::VcpuState;
use crate::hv::vcpu::{Vcpu, VmEntry, VmExit};

/// Exit still being reported or waiting for its value. KVM completes it
/// on the next `KVM_RUN` from the `kvm_run` page.
enum Pending {
    /// Port instruction in progress. Access `next` is reported on the next
    /// `run`, access `next - 1` is the read waiting for its value.
    #[cfg(target_arch = "x86_64")]
    Port { next: u32 },
    /// MMIO read of `len` bytes, value goes to `mmio.data`.
    Mmio { len: usize },
}

/// `KVM_EXIT_IO` as decoded from the `kvm_run` page, `count` accesses of
/// `size` bytes, packed from `offset`. String instruction has `count`
/// above one.
#[cfg(target_arch = "x86_64")]
struct PortAccess {
    port: u16,
    size: u8,
    count: u32,
    offset: usize,
    is_in: bool,
}

/// Decode `data`, little endian and at most eight bytes.
fn le(data: &[u8]) -> u64 {
    let mut bytes = [0u8; 8];
    let len = data.len().min(bytes.len());
    bytes[..len].copy_from_slice(&data[..len]);
    u64::from_le_bytes(bytes)
}

/// vCPU handle, the fd returned by `KVM_CREATE_VCPU`, plus the read exit
/// waiting for its value.
pub struct KvmVcpu {
    fd: VcpuFd,
    pending: Option<Pending>,
    /// Bytes copied by `KVM_GET_XSAVE` and `KVM_SET_XSAVE` on this host.
    #[cfg(target_arch = "x86_64")]
    xsave_size: usize,
    /// MSR indices read by a capture, from `KVM_GET_MSR_INDEX_LIST`.
    #[cfg(target_arch = "x86_64")]
    msrs: Arc<[u32]>,
}

impl KvmVcpu {
    /// Wrap `fd` with no exit pending. `msrs` is the index list read by a
    /// capture.
    pub(in crate::hv::backend::kvm) fn new(
        fd: VcpuFd,
        #[cfg(target_arch = "x86_64")] xsave_size: usize,
        #[cfg(target_arch = "x86_64")] msrs: Arc<[u32]>,
    ) -> Self {
        KvmVcpu {
            fd,
            pending: None,
            #[cfg(target_arch = "x86_64")]
            xsave_size,
            #[cfg(target_arch = "x86_64")]
            msrs,
        }
    }
}

impl Vcpu for KvmVcpu {
    fn run(&mut self, entry: VmEntry) -> Result<VmExit> {
        match self.pending.take() {
            #[cfg(target_arch = "x86_64")]
            Some(Pending::Port { next }) => {
                let access = self.port_access();
                if access.is_in
                    && let VmEntry::Io { data } = entry
                {
                    self.write_slot(&access, next - 1, u64::from(data));
                }
                // String instruction is one exit of `count` accesses, the rest
                // are reported without entering the guest.
                if next < access.count {
                    return Ok(self.report_port(&access, next));
                }
            }
            Some(Pending::Mmio { len }) => {
                let value = match entry {
                    VmEntry::Mmio { data } => data,
                    _ => 0,
                };
                self.complete_mmio(len, value);
            }
            None => {}
        }

        // Stop still enters `KVM_RUN` with `immediate_exit` set. KVM
        // completes the pending operation and returns `EINTR`.
        let stop = match entry {
            VmEntry::Shutdown => Some(VmExit::Shutdown),
            VmEntry::Reboot => Some(VmExit::Reboot),
            _ => None,
        };
        if stop.is_some() {
            self.fd.set_kvm_immediate_exit(1);
        }

        #[cfg(target_arch = "x86_64")]
        let mut port = false;
        let mut mmio = None;
        let exit = match self.fd.run() {
            #[cfg(target_arch = "x86_64")]
            Ok(VcpuExit::IoOut(..) | VcpuExit::IoIn(..)) => {
                port = true;
                None
            }
            Ok(VcpuExit::MmioWrite(addr, data)) => Some(VmExit::Mmio {
                addr,
                write: Some(le(data)),
                size: data.len() as u8,
            }),
            Ok(VcpuExit::MmioRead(addr, data)) => {
                let size = data.len() as u8;
                mmio = Some(Pending::Mmio {
                    len: data.len().min(8),
                });
                Some(VmExit::Mmio {
                    addr,
                    write: None,
                    size,
                })
            }
            Ok(VcpuExit::Hlt) => Some(VmExit::Halt),
            Ok(VcpuExit::Shutdown) => Some(VmExit::Shutdown),
            Ok(VcpuExit::Intr) => Some(VmExit::Interrupted),
            Ok(VcpuExit::Debug(_)) => Some(VmExit::Debug),
            Ok(VcpuExit::Hypercall(call)) => Some(VmExit::Hypercall {
                nr: call.nr,
                args: call.args,
            }),
            Ok(VcpuExit::SystemEvent(kind, _)) => Some(match kind {
                KVM_SYSTEM_EVENT_SHUTDOWN => VmExit::Shutdown,
                KVM_SYSTEM_EVENT_RESET => VmExit::Reboot,
                other => VmExit::Unknown(u64::from(other)),
            }),
            Ok(_) => None,
            Err(err) => {
                self.fd.set_kvm_immediate_exit(0);
                // `EINTR` and `EAGAIN` are not failures, vCPU state is intact
                // and caller re-enters.
                let cut_short = matches!(
                    std::io::Error::from_raw_os_error(err.errno()).kind(),
                    std::io::ErrorKind::Interrupted | std::io::ErrorKind::WouldBlock
                );
                return match (cut_short, stop) {
                    (true, Some(exit)) => Ok(exit),
                    (true, None) => Ok(VmExit::Interrupted),
                    (false, _) => Err(kvm_err("KVM_RUN")(err)),
                };
            }
        };
        self.pending = mmio;
        if stop.is_some() {
            self.fd.set_kvm_immediate_exit(0);
        }
        #[cfg(target_arch = "x86_64")]
        if port {
            let access = self.port_access();
            return Ok(self.report_port(&access, 0));
        }
        match exit {
            Some(exit) => Ok(exit),
            // Exit reason not mapped above, caller logs the raw value.
            None => Ok(VmExit::Unknown(u64::from(
                self.fd.get_kvm_run().exit_reason,
            ))),
        }
    }

    #[cfg(target_arch = "x86_64")]
    fn get_reg(&self, reg: Reg) -> Result<u64> {
        let regs = self.fd.get_regs().map_err(kvm_err("KVM_GET_REGS"))?;
        Ok(match reg {
            Reg::Rax => regs.rax,
            Reg::Rbx => regs.rbx,
            Reg::Rcx => regs.rcx,
            Reg::Rdx => regs.rdx,
            Reg::Rsi => regs.rsi,
            Reg::Rdi => regs.rdi,
            Reg::Rsp => regs.rsp,
            Reg::Rbp => regs.rbp,
            Reg::R8 => regs.r8,
            Reg::R9 => regs.r9,
            Reg::R10 => regs.r10,
            Reg::R11 => regs.r11,
            Reg::R12 => regs.r12,
            Reg::R13 => regs.r13,
            Reg::R14 => regs.r14,
            Reg::R15 => regs.r15,
            Reg::Rip => regs.rip,
            Reg::Rflags => regs.rflags,
        })
    }

    #[cfg(target_arch = "x86_64")]
    fn set_regs(&mut self, vals: &[(Reg, u64)]) -> Result<()> {
        // `KVM_SET_REGS` takes the full `kvm_regs`, registers not in `vals`
        // are read and written back unchanged.
        let mut regs = self.fd.get_regs().map_err(kvm_err("KVM_GET_REGS"))?;
        for &(reg, val) in vals {
            match reg {
                Reg::Rax => regs.rax = val,
                Reg::Rbx => regs.rbx = val,
                Reg::Rcx => regs.rcx = val,
                Reg::Rdx => regs.rdx = val,
                Reg::Rsi => regs.rsi = val,
                Reg::Rdi => regs.rdi = val,
                Reg::Rsp => regs.rsp = val,
                Reg::Rbp => regs.rbp = val,
                Reg::R8 => regs.r8 = val,
                Reg::R9 => regs.r9 = val,
                Reg::R10 => regs.r10 = val,
                Reg::R11 => regs.r11 = val,
                Reg::R12 => regs.r12 = val,
                Reg::R13 => regs.r13 = val,
                Reg::R14 => regs.r14 = val,
                Reg::R15 => regs.r15 = val,
                Reg::Rip => regs.rip = val,
                Reg::Rflags => regs.rflags = val,
            }
        }
        self.fd.set_regs(&regs).map_err(kvm_err("KVM_SET_REGS"))
    }

    #[cfg(target_arch = "x86_64")]
    fn get_seg_reg(&self, reg: SegReg) -> Result<SegRegVal> {
        let sregs = self.fd.get_sregs().map_err(kvm_err("KVM_GET_SREGS"))?;
        let seg = match reg {
            SegReg::Cs => sregs.cs,
            SegReg::Ds => sregs.ds,
            SegReg::Es => sregs.es,
            SegReg::Fs => sregs.fs,
            SegReg::Gs => sregs.gs,
            SegReg::Ss => sregs.ss,
            SegReg::Tr => sregs.tr,
            SegReg::Ldtr => sregs.ldt,
        };
        Ok(SegRegVal {
            base: seg.base,
            limit: seg.limit,
            selector: seg.selector,
            attr: pack_attr(&seg),
        })
    }

    #[cfg(target_arch = "x86_64")]
    fn set_cpuid(&mut self, entries: &[CpuidEntry]) -> Result<()> {
        let entries = entries.iter().map(to_kvm).collect::<Vec<_>>();
        let cpuid = kvm_bindings::CpuId::from_entries(&entries)
            .map_err(|_| Error::Other("too many CPUID entries"))?;
        self.fd
            .set_cpuid2(&cpuid)
            .map_err(kvm_err("KVM_SET_CPUID2"))
    }

    #[cfg(target_arch = "x86_64")]
    fn get_state(&self) -> Result<StateBlob> {
        VcpuState::capture(&self.fd, self.xsave_size, &self.msrs)
    }

    #[cfg(target_arch = "x86_64")]
    fn set_state(&mut self, blob: &StateBlob) -> Result<()> {
        VcpuState::restore(&self.fd, self.xsave_size, blob)
    }

    #[cfg(target_arch = "x86_64")]
    fn get_dt_reg(&self, reg: DtReg) -> Result<DtRegVal> {
        let sregs = self.fd.get_sregs().map_err(kvm_err("KVM_GET_SREGS"))?;
        let table = match reg {
            DtReg::Gdt => sregs.gdt,
            DtReg::Idt => sregs.idt,
        };
        Ok(DtRegVal {
            base: table.base,
            limit: table.limit,
        })
    }

    #[cfg(target_arch = "x86_64")]
    fn get_sreg(&self, reg: SReg) -> Result<u64> {
        let sregs = self.fd.get_sregs().map_err(kvm_err("KVM_GET_SREGS"))?;
        Ok(match reg {
            SReg::Cr0 => sregs.cr0,
            SReg::Cr2 => sregs.cr2,
            SReg::Cr3 => sregs.cr3,
            SReg::Cr4 => sregs.cr4,
            SReg::Cr8 => sregs.cr8,
            SReg::Efer => sregs.efer,
            SReg::ApicBase => sregs.apic_base,
        })
    }

    #[cfg(target_arch = "x86_64")]
    fn set_sregs(
        &mut self,
        sregs: &[(SReg, u64)],
        seg_regs: &[(SegReg, SegRegVal)],
        dt_regs: &[(DtReg, DtRegVal)],
    ) -> Result<()> {
        // `KVM_SET_SREGS` takes the full `kvm_sregs`, so the three groups go
        // in one write and the rest is read and written back unchanged.
        let mut all = self.fd.get_sregs().map_err(kvm_err("KVM_GET_SREGS"))?;
        for &(reg, val) in sregs {
            match reg {
                SReg::Cr0 => all.cr0 = val,
                SReg::Cr2 => all.cr2 = val,
                SReg::Cr3 => all.cr3 = val,
                SReg::Cr4 => all.cr4 = val,
                SReg::Cr8 => all.cr8 = val,
                SReg::Efer => all.efer = val,
                SReg::ApicBase => all.apic_base = val,
            }
        }
        for &(reg, val) in seg_regs {
            let seg = kvm_seg(&val);
            match reg {
                SegReg::Cs => all.cs = seg,
                SegReg::Ds => all.ds = seg,
                SegReg::Es => all.es = seg,
                SegReg::Fs => all.fs = seg,
                SegReg::Gs => all.gs = seg,
                SegReg::Ss => all.ss = seg,
                SegReg::Tr => all.tr = seg,
                SegReg::Ldtr => all.ldt = seg,
            }
        }
        for &(reg, val) in dt_regs {
            let table = kvm_bindings::kvm_dtable {
                base: val.base,
                limit: val.limit,
                ..Default::default()
            };
            match reg {
                DtReg::Gdt => all.gdt = table,
                DtReg::Idt => all.idt = table,
            }
        }
        self.fd.set_sregs(&all).map_err(kvm_err("KVM_SET_SREGS"))
    }
}

/// Convert `val` to a `kvm_segment`, `attr` is unpacked into the access
/// rights fields, one per byte.
#[cfg(target_arch = "x86_64")]
pub(in crate::hv::backend::kvm) fn kvm_seg(val: &SegRegVal) -> kvm_bindings::kvm_segment {
    kvm_bindings::kvm_segment {
        base: val.base,
        limit: val.limit,
        selector: val.selector,
        type_: (val.attr & 0xf) as u8,
        s: (val.attr >> 4) as u8 & 1,
        dpl: (val.attr >> 5) as u8 & 3,
        present: (val.attr >> 7) as u8 & 1,
        avl: (val.attr >> 12) as u8 & 1,
        l: (val.attr >> 13) as u8 & 1,
        db: (val.attr >> 14) as u8 & 1,
        g: (val.attr >> 15) as u8 & 1,
        unusable: 0,
        padding: 0,
    }
}

/// Pack access rights of `seg` into one word in descriptor layout, type
/// in bits 0-3, S, DPL and P through bit 7, AVL, L, D/B and G from bit
/// 12.
#[cfg(target_arch = "x86_64")]
pub(in crate::hv::backend::kvm) fn pack_attr(seg: &kvm_bindings::kvm_segment) -> u16 {
    u16::from(seg.type_)
        | u16::from(seg.s) << 4
        | u16::from(seg.dpl) << 5
        | u16::from(seg.present) << 7
        | u16::from(seg.avl) << 12
        | u16::from(seg.l) << 13
        | u16::from(seg.db) << 14
        | u16::from(seg.g) << 15
}

impl KvmVcpu {
    /// Decode the `KVM_EXIT_IO` in the `kvm_run` page.
    #[cfg(target_arch = "x86_64")]
    fn port_access(&mut self) -> PortAccess {
        let run = self.fd.get_kvm_run();
        // SAFETY: the exit was `KVM_EXIT_IO`, so `io` is the union arm filled
        // in by KVM.
        let io = unsafe { run.__bindgen_anon_1.io };
        PortAccess {
            port: io.port,
            size: io.size,
            count: io.count,
            offset: io.data_offset as usize,
            is_in: io.direction == KVM_EXIT_IO_IN as u8,
        }
    }

    /// Report access `index` of `access` and record `index + 1` as the next
    /// one to report.
    #[cfg(target_arch = "x86_64")]
    fn report_port(&mut self, access: &PortAccess, index: u32) -> VmExit {
        let write = if access.is_in {
            None
        } else {
            Some(self.read_slot(access, index) as u32)
        };
        self.pending = Some(Pending::Port { next: index + 1 });
        VmExit::Io {
            port: access.port,
            write,
            size: access.size,
        }
    }

    /// Returns address of access `index` in the `kvm_run` page.
    #[cfg(target_arch = "x86_64")]
    fn slot(&mut self, access: &PortAccess, index: u32) -> *mut u8 {
        let run = self.fd.get_kvm_run();
        let page = std::ptr::from_mut(run).cast::<u8>();
        let at = access.offset + index as usize * access.size as usize;
        // SAFETY: KVM packs `count * size` bytes at `data_offset` inside the
        // page, and `index` is below `count`.
        unsafe { page.add(at) }
    }

    /// Read the value of OUT access `index`.
    #[cfg(target_arch = "x86_64")]
    fn read_slot(&mut self, access: &PortAccess, index: u32) -> u64 {
        let len = (access.size as usize).min(8);
        let mut bytes = [0u8; 8];
        let slot = self.slot(access, index);
        // SAFETY: `slot` points at `size` bytes written by KVM.
        unsafe { std::ptr::copy_nonoverlapping(slot, bytes.as_mut_ptr(), len) };
        u64::from_le_bytes(bytes)
    }

    /// Write `value` into the slot of IN access `index`.
    #[cfg(target_arch = "x86_64")]
    fn write_slot(&mut self, access: &PortAccess, index: u32, value: u64) {
        let len = (access.size as usize).min(8);
        let bytes = value.to_le_bytes();
        let slot = self.slot(access, index);
        // SAFETY: `slot` points at `size` bytes KVM reads on the next entry.
        unsafe { std::ptr::copy_nonoverlapping(bytes.as_ptr(), slot, len) };
    }

    /// Write `value` into `mmio.data` for the pending MMIO read.
    fn complete_mmio(&mut self, len: usize, value: u64) {
        let bytes = value.to_le_bytes();
        let run = self.fd.get_kvm_run();
        // SAFETY: the pending exit was `KVM_EXIT_MMIO`, so `mmio` is the
        // union arm filled in by KVM.
        let mmio = unsafe { &mut run.__bindgen_anon_1.mmio };
        mmio.data[..len].copy_from_slice(&bytes[..len]);
    }
}

#[cfg(test)]
mod tests {
    #[cfg(target_arch = "x86_64")]
    use std::alloc::{Layout, alloc_zeroed, dealloc};
    use std::os::fd::AsRawFd;

    use crate::hv::backend::kvm::hypervisor::KvmHv;
    #[cfg(target_arch = "x86_64")]
    use crate::hv::backend::kvm::vcpu::*;
    use crate::hv::hypervisor::Hypervisor;
    #[cfg(target_arch = "x86_64")]
    use crate::hv::memory::{MemMapOption, VmMemory};
    use crate::hv::vm::Vm;

    #[cfg(target_arch = "x86_64")]
    const PAGE: usize = 4096;

    #[test]
    fn test_create_vcpus() {
        let hv = KvmHv::new().expect("open /dev/kvm");
        let vm = hv.create_vm().expect("guest");
        let cpu0 = vm.create_vcpu(0).expect("vcpu 0");
        let cpu1 = vm.create_vcpu(1).expect("vcpu 1");
        assert_ne!(cpu0.fd.as_raw_fd(), cpu1.fd.as_raw_fd());
        // Second `KVM_CREATE_VCPU` with the same id fails with `EEXIST`.
        assert!(vm.create_vcpu(0).is_err(), "vCPU 0 created a second time");
    }

    #[cfg(target_arch = "x86_64")]
    #[test]
    fn test_run_and_complete_port_read() {
        let hv = KvmHv::new().expect("open /dev/kvm");
        let vm = hv.create_vm().expect("guest");
        let mem = vm.create_vm_memory().expect("address space");

        // Page of the reset vector. x86 vCPU starts fetching at
        // 0xffff_fff0, so the guest runs without setting any register.
        const GPA: u64 = 0xffff_f000;
        let layout = Layout::from_size_align(PAGE, PAGE).expect("page-aligned layout");
        // SAFETY: `layout` has non-zero size.
        let host = unsafe { alloc_zeroed(layout) };
        assert!(!host.is_null());
        let code = [
            0xb0, 0x42, // mov al, 0x42
            0xe6, 0xf8, // out 0xf8, al
            0xe4, 0xf9, // in al, 0xf9
            0xe6, 0xfa, // out 0xfa, al
            0xf4, // hlt
        ];
        // SAFETY: the allocation is one page and `code` fits at 0xff0.
        unsafe { std::ptr::copy_nonoverlapping(code.as_ptr(), host.add(0xff0), code.len()) };
        mem.mem_map(GPA, PAGE as u64, host as usize, MemMapOption::default())
            .expect("map the reset vector");

        let mut cpu = vm.create_vcpu(0).expect("vcpu 0");
        assert_eq!(
            cpu.run(VmEntry::Run).expect("run"),
            VmExit::Io {
                port: 0xf8,
                write: Some(0x42),
                size: 1
            }
        );
        assert_eq!(
            cpu.run(VmEntry::Run).expect("run"),
            VmExit::Io {
                port: 0xf9,
                write: None,
                size: 1
            }
        );
        // Guest writes the value of the completed IN to port 0xfa next.
        assert_eq!(
            cpu.run(VmEntry::Io { data: 0x99 })
                .expect("answer the read"),
            VmExit::Io {
                port: 0xfa,
                write: Some(0x99),
                size: 1
            }
        );
        // Without in-kernel irqchip, `HLT` exits to userspace.
        assert_eq!(cpu.run(VmEntry::Run).expect("run"), VmExit::Halt);
        assert_eq!(cpu.run(VmEntry::Shutdown).expect("stop"), VmExit::Shutdown);

        // SAFETY: `host` came from `alloc_zeroed` with `layout` and is not
        // mapped into the guest anymore.
        unsafe { dealloc(host, layout) };
    }

    #[cfg(target_arch = "x86_64")]
    #[test]
    fn test_run_from_written_rip() {
        let hv = KvmHv::new().expect("open /dev/kvm");
        let vm = hv.create_vm().expect("guest");
        let mem = vm.create_vm_memory().expect("address space");

        let layout = Layout::from_size_align(PAGE, PAGE).expect("page-aligned layout");
        // SAFETY: `layout` has non-zero size.
        let reset = unsafe { alloc_zeroed(layout) };
        assert!(!reset.is_null());
        // Two instruction streams in one page. Reset vector reaches the
        // first at 0xff0, only a written `rip` reaches the second at 0.
        let at_reset = [0xb0, 0x11, 0xe6, 0xf8, 0xf4]; // mov al,0x11; out 0xf8,al; hlt
        let elsewhere = [0xb0, 0x22, 0xe6, 0xf8, 0xf4]; // mov al,0x22; out 0xf8,al; hlt
        // SAFETY: the allocation is one page and both fit, at 0xff0 and at 0.
        unsafe {
            std::ptr::copy_nonoverlapping(at_reset.as_ptr(), reset.add(0xff0), at_reset.len());
            std::ptr::copy_nonoverlapping(elsewhere.as_ptr(), reset, elsewhere.len());
        }
        mem.mem_map(
            0xffff_f000,
            PAGE as u64,
            reset as usize,
            MemMapOption::default(),
        )
        .expect("map the reset vector");

        // Out of reset `CS` has selector 0xf000 and base 0xffff_0000, so the
        // reset vector is in this page.
        let mut cpu = vm.create_vcpu(0).expect("vcpu 0");
        let cs = cpu.get_seg_reg(SegReg::Cs).expect("cs");
        assert_eq!(cs.selector, 0xf000);
        assert_eq!(cs.base, 0xffff_0000);

        // With `rip` written the second stream runs and writes 0x22 to port
        // 0xf8.
        cpu.set_regs(&[(Reg::Rip, 0xf000)]).expect("set rip");
        assert_eq!(
            cpu.run(VmEntry::Run).expect("run"),
            VmExit::Io {
                port: 0xf8,
                write: Some(0x22),
                size: 1
            }
        );
        assert_eq!(cpu.get_reg(Reg::Rax).expect("rax") & 0xff, 0x22);

        // `CR2` round trips through `set_sregs` and `get_sreg`.
        cpu.set_sregs(&[(SReg::Cr2, 0xdead_beef)], &[], &[])
            .expect("set cr2");
        assert_eq!(cpu.get_sreg(SReg::Cr2).expect("cr2"), 0xdead_beef);

        // SAFETY: `reset` came from `alloc_zeroed` with `layout`, and the
        // guest is not run anymore.
        unsafe { dealloc(reset, layout) };
    }

    #[cfg(target_arch = "x86_64")]
    #[test]
    fn test_enter_protected_mode() {
        let hv = KvmHv::new().expect("open /dev/kvm");
        let vm = hv.create_vm().expect("guest");
        let mem = vm.create_vm_memory().expect("address space");

        let layout = Layout::from_size_align(PAGE, PAGE).expect("page-aligned layout");
        // SAFETY: `layout` has non-zero size.
        let host = unsafe { alloc_zeroed(layout) };
        assert!(!host.is_null());
        // Code at guest address 0x1000. Out of reset `CS` has base
        // 0xffff_0000, so only a flat code segment reaches it.
        let code = [0xb0, 0x55, 0xe6, 0xf8, 0xf4]; // mov al,0x55; out 0xf8,al; hlt
        // SAFETY: the allocation is one page and `code` fits at its start.
        unsafe { std::ptr::copy_nonoverlapping(code.as_ptr(), host, code.len()) };
        mem.mem_map(0x1000, PAGE as u64, host as usize, MemMapOption::default())
            .expect("map the code");

        // Flat 4 GiB descriptors in GDT entry attribute layout, 0xc09b is a
        // 32-bit code segment, 0xc093 is the matching data segment. `limit`
        // is in bytes. Note that on SVM `KVM_GET_SREGS` reports granularity
        // bit as `limit > 0xfffff`, so a limit given in pages reads back
        // with G clear.
        let code_seg = SegRegVal {
            base: 0,
            limit: 0xffff_ffff,
            selector: 0x08,
            attr: 0xc09b,
        };
        let data_seg = SegRegVal {
            selector: 0x10,
            attr: 0xc093,
            ..code_seg
        };
        let gdt = DtRegVal {
            base: 0x500,
            limit: 0x17,
        };

        let mut cpu = vm.create_vcpu(0).expect("vcpu 0");
        let cr0 = cpu.get_sreg(SReg::Cr0).expect("cr0");
        cpu.set_sregs(
            // `CR0.PE`, bit 0, selects protected mode.
            &[(SReg::Cr0, cr0 | 1)],
            &[
                (SegReg::Cs, code_seg),
                (SegReg::Ds, data_seg),
                (SegReg::Es, data_seg),
                (SegReg::Ss, data_seg),
            ],
            &[(DtReg::Gdt, gdt)],
        )
        .expect("enter protected mode");
        cpu.set_regs(&[(Reg::Rip, 0x1000)]).expect("entry point");

        // The code sits at an address only a flat code segment can reach,
        // in protected mode it exits on port 0xf8.
        assert_eq!(
            cpu.run(VmEntry::Run).expect("run"),
            VmExit::Io {
                port: 0xf8,
                write: Some(0x55),
                size: 1
            }
        );
        assert_eq!(cpu.get_seg_reg(SegReg::Cs).expect("cs"), code_seg);
        assert_eq!(cpu.get_dt_reg(DtReg::Gdt).expect("gdt"), gdt);
        assert_eq!(cpu.get_sreg(SReg::Cr0).expect("cr0") & 1, 1);

        // SAFETY: `host` came from `alloc_zeroed` with `layout`, and the
        // guest is not run again.
        unsafe { dealloc(host, layout) };
    }

    #[cfg(target_arch = "x86_64")]
    #[test]
    fn test_string_read_reported_per_access() {
        // rep insb is one KVM exit, each access should be reported alone.
        let hv = KvmHv::new().expect("open /dev/kvm");
        let vm = hv.create_vm().expect("guest");
        let mem = vm.create_vm_memory().expect("address space");

        let layout = Layout::from_size_align(PAGE, PAGE).expect("page-aligned layout");
        // SAFETY: `layout` has non-zero size.
        let low = unsafe { alloc_zeroed(layout) };
        // SAFETY: same as above.
        let reset = unsafe { alloc_zeroed(layout) };
        assert!(!low.is_null() && !reset.is_null());

        // rep insb, three reads of port 0xf9 stored at ES:DI, which is guest
        // address zero out of reset.
        let code = [
            0xba, 0xf9, 0x00, // mov dx, 0x00f9
            0xbf, 0x00, 0x00, // mov di, 0x0000
            0xb9, 0x03, 0x00, // mov cx, 3
            0xf3, 0x6c, // rep insb
            0xf4, // hlt
        ];
        // SAFETY: the allocation is one page and `code` fits at 0xff0.
        unsafe { std::ptr::copy_nonoverlapping(code.as_ptr(), reset.add(0xff0), code.len()) };
        mem.mem_map(0, PAGE as u64, low as usize, MemMapOption::default())
            .expect("map the page guest writes to");
        mem.mem_map(
            0xffff_f000,
            PAGE as u64,
            reset as usize,
            MemMapOption::default(),
        )
        .expect("map the reset vector");

        let mut cpu = vm.create_vcpu(0).expect("vcpu 0");
        let read = VmExit::Io {
            port: 0xf9,
            write: None,
            size: 1,
        };
        // KVM reports the three reads as one exit with `count` 3, each one
        // is reported to the caller as a one-byte access.
        assert_eq!(cpu.run(VmEntry::Run).expect("run"), read);
        assert_eq!(cpu.run(VmEntry::Io { data: 0x11 }).expect("run"), read);
        assert_eq!(cpu.run(VmEntry::Io { data: 0x22 }).expect("run"), read);
        // Third value completes the instruction and the guest runs on.
        assert_eq!(
            cpu.run(VmEntry::Io { data: 0x33 }).expect("run"),
            VmExit::Halt
        );

        // SAFETY: `low` is one page, and the guest wrote its first three bytes.
        let written = unsafe { std::slice::from_raw_parts(low, 3) };
        assert_eq!(written, [0x11, 0x22, 0x33], "reads landed out of order");

        // SAFETY: both came from `alloc_zeroed` with `layout` and are not
        // mapped into the guest anymore.
        unsafe {
            dealloc(low, layout);
            dealloc(reset, layout);
        }
    }

    /// Boot a guest which runs CPUID leaf 0 and writes the low byte of EBX
    /// to port 0xf8. `cpuid` is set on the vCPU first if given.
    #[cfg(target_arch = "x86_64")]
    fn vendor_letter_the_guest_reads(hv: &KvmHv, cpuid: Option<&[CpuidEntry]>) -> u32 {
        const GPA: u64 = 0xffff_f000;
        let vm = hv.create_vm().expect("guest");
        let mem = vm.create_vm_memory().expect("address space");
        let layout = Layout::from_size_align(PAGE, PAGE).expect("page-aligned layout");
        // SAFETY: `layout` has non-zero size.
        let host = unsafe { alloc_zeroed(layout) };
        assert!(!host.is_null());
        let code = [
            0x66, 0xb8, 0x00, 0x00, 0x00, 0x00, // mov eax, 0
            0x0f, 0xa2, // cpuid
            0x88, 0xd8, // mov al, bl
            0xe6, 0xf8, // out 0xf8, al
            0xf4, // hlt
        ];
        // SAFETY: the allocation is one page and `code` fits at 0xff0.
        unsafe { std::ptr::copy_nonoverlapping(code.as_ptr(), host.add(0xff0), code.len()) };
        mem.mem_map(GPA, PAGE as u64, host as usize, MemMapOption::default())
            .expect("map the reset vector");

        let mut cpu = vm.create_vcpu(0).expect("vcpu 0");
        if let Some(entries) = cpuid {
            cpu.set_cpuid(entries).expect("set cpuid");
        }
        let letter = match cpu.run(VmEntry::Run).expect("run") {
            VmExit::Io {
                port: 0xf8,
                write: Some(value),
                ..
            } => value,
            other => panic!("unexpected exit {other:?}"),
        };
        // SAFETY: `host` came from `alloc_zeroed` with `layout`, and the VM
        // which maps it is dropped at the end of the scope.
        unsafe { dealloc(host, layout) };
        letter
    }

    #[cfg(target_arch = "x86_64")]
    #[test]
    fn test_set_cpuid_vendor() {
        let hv = KvmHv::new().expect("open /dev/kvm");
        let supported = hv.supported_cpuid().expect("supported cpuid");
        let leaf0 = supported
            .iter()
            .find(|leaf| leaf.function == 0)
            .expect("leaf 0");
        let vendor = leaf0.ebx & 0xff;
        assert_ne!(vendor, 0, "leaf 0 reports no vendor");

        assert_eq!(
            vendor_letter_the_guest_reads(&hv, None),
            0,
            "vCPU without CPUID set reports a vendor"
        );
        assert_eq!(
            vendor_letter_the_guest_reads(&hv, Some(&supported)),
            vendor,
            "guest reads a vendor other than the one set"
        );
    }
}
