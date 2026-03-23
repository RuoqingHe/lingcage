// SPDX-FileCopyrightText: 2026 LingCage <opensource@lingcage.com>
//
// SPDX-License-Identifier: Apache-2.0

//! KVM backend.

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::os::fd::{AsFd, AsRawFd, BorrowedFd};
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, Mutex};

#[cfg(target_arch = "x86_64")]
use kvm_bindings::KVM_EXIT_IO_IN;
use kvm_bindings::{
    KVM_API_VERSION, KVM_IRQ_ROUTING_IRQCHIP, KVM_IRQ_ROUTING_MSI, KVM_MEM_LOG_DIRTY_PAGES,
    KVM_MEM_READONLY, KVM_SYSTEM_EVENT_RESET, KVM_SYSTEM_EVENT_SHUTDOWN, KvmIrqRouting,
    kvm_irq_routing_entry, kvm_irq_routing_irqchip, kvm_irq_routing_msi, kvm_msi,
    kvm_userspace_memory_region,
};
#[cfg(target_arch = "x86_64")]
use kvm_bindings::{KVM_PIT_SPEAKER_DUMMY, kvm_pit_config};
use kvm_ioctls::{Cap, IoEventAddress, Kvm, NoDatamatch, VcpuExit, VcpuFd, VmFd};
use vmm_sys_util::eventfd::{EFD_NONBLOCK, EventFd};

#[cfg(target_arch = "x86_64")]
use crate::hv::arch::{DtReg, DtRegVal, Reg, SReg, SegReg, SegRegVal};
use crate::hv::irq::{IrqSender, MsiSender};
use crate::hv::memory::{MemMapOption, VmMemory};
use crate::hv::os::linux::ioeventfd::{IoeventFd, IoeventFdRegistry};
use crate::hv::os::linux::irqfd::IrqFd;
use crate::hv::vcpu::{Vcpu, VmEntry, VmExit};
#[cfg(target_arch = "x86_64")]
use crate::hv::{Arch, Backend, StateBlob};
use crate::hv::{Error, Result};

/// Map a `kvm_ioctls::Error`, or the `io::Error` of an eventfd call, to
/// `Error::Os` with operation `op`.
fn kvm_err<E: Into<kvm_ioctls::Error>>(op: &'static str) -> impl Fn(E) -> Error {
    move |err| Error::Os {
        op,
        errno: err.into().errno(),
    }
}

/// Opened `/dev/kvm` handle.
pub struct KvmHv {
    kvm: Kvm,
}

impl KvmHv {
    /// Open `/dev/kvm`, refuse a kernel whose `KVM_GET_API_VERSION` is not
    /// `KVM_API_VERSION`.
    pub fn new() -> Result<Self> {
        let kvm = Kvm::new().map_err(kvm_err("open /dev/kvm"))?;
        // `get_api_version` returns the raw ioctl result, negative value
        // means failure with errno set.
        let version = kvm.get_api_version();
        if version < 0 {
            return Err(Error::Os {
                op: "KVM_GET_API_VERSION",
                errno: kvm_ioctls::Error::last().errno(),
            });
        }
        if version != KVM_API_VERSION as i32 {
            return Err(Error::ApiVersion(version));
        }
        Ok(KvmHv { kvm })
    }

    /// Create a guest through `KVM_CREATE_VM`, without vCPU or memory.
    pub fn create_vm(&self) -> Result<KvmVm> {
        let fd = self.kvm.create_vm().map_err(kvm_err("KVM_CREATE_VM"))?;
        Ok(KvmVm {
            fd: Arc::new(fd),
            routing: Arc::new(Mutex::new(Routing::default())),
        })
    }
}

/// Guest handle, the VM fd returned by `KVM_CREATE_VM`. Parts created
/// from it share the fd.
pub struct KvmVm {
    fd: Arc<VmFd>,
    routing: Arc<Mutex<Routing>>,
}

impl KvmVm {
    /// Create the guest physical address space, no region mapped yet.
    pub fn create_vm_memory(&self) -> Result<KvmMemory> {
        Ok(KvmMemory {
            vm: Arc::clone(&self.fd),
            next_slot: AtomicU32::new(0),
            slots: Mutex::new(HashMap::new()),
        })
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
        Ok(KvmVcpu {
            fd,
            pending: None,
            #[cfg(target_arch = "x86_64")]
            xsave_size: self.xsave_size(),
        })
    }

    /// Returns XSAVE area size in bytes, as reported by `KVM_CAP_XSAVE2`,
    /// or `size_of::<kvm_xsave>()` on a kernel without the cap.
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
        Ok(KvmIrqSender { eventfd })
    }

    /// Create the MSI sender. Returns `Unsupported` without
    /// `KVM_CAP_SIGNAL_MSI`.
    pub fn create_msi_sender(&self) -> Result<KvmMsiSender> {
        if !self.fd.check_extension(Cap::SignalMsi) {
            return Err(Error::Unsupported("KVM_CAP_SIGNAL_MSI"));
        }
        Ok(KvmMsiSender {
            vm: Arc::clone(&self.fd),
            routing: Arc::clone(&self.routing),
        })
    }

    /// Create the ioeventfd registry.
    pub fn create_ioeventfd_registry(&self) -> KvmIoeventFdRegistry {
        KvmIoeventFdRegistry {
            vm: Arc::clone(&self.fd),
        }
    }
}

/// Guest physical address space of one guest, as KVM memory slots.
/// `slots` maps each mapped guest address to the slot number given to
/// it, since `KVM_SET_USER_MEMORY_REGION` addresses a region by slot.
pub struct KvmMemory {
    vm: Arc<VmFd>,
    next_slot: AtomicU32,
    slots: Mutex<HashMap<u64, u32>>,
}

impl VmMemory for KvmMemory {
    fn mem_map(&self, gpa: u64, size: u64, hva: usize, opt: MemMapOption) -> Result<()> {
        let slot = self.next_slot.fetch_add(1, Ordering::SeqCst);
        let mut flags = 0u32;
        if opt.log_dirty {
            flags |= KVM_MEM_LOG_DIRTY_PAGES;
        }
        if !opt.write {
            flags |= KVM_MEM_READONLY;
        }
        let region = kvm_userspace_memory_region {
            slot,
            flags,
            guest_phys_addr: gpa,
            memory_size: size,
            userspace_addr: hva as u64,
        };
        // SAFETY: `hva` points to `size` bytes of host memory which stay
        // mapped as long as the region exists.
        unsafe {
            self.vm
                .set_user_memory_region(region)
                .map_err(kvm_err("KVM_SET_USER_MEMORY_REGION"))?
        };
        self.slots.lock().unwrap().insert(gpa, slot);
        Ok(())
    }

    fn unmap(&self, gpa: u64, _size: u64) -> Result<()> {
        let slot = self
            .slots
            .lock()
            .unwrap()
            .remove(&gpa)
            .ok_or(Error::Other("unmap: no region at given guest address"))?;
        let region = kvm_userspace_memory_region {
            slot,
            flags: 0,
            guest_phys_addr: gpa,
            memory_size: 0,
            userspace_addr: 0,
        };
        // SAFETY: zero `memory_size` deletes the slot, no host address is read.
        unsafe {
            self.vm
                .set_user_memory_region(region)
                .map_err(kvm_err("KVM_SET_USER_MEMORY_REGION"))?
        };
        Ok(())
    }
}

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

/// Layout version of `StateBlob::data`, `set_state` refuses others.
#[cfg(target_arch = "x86_64")]
const STATE_VERSION: u32 = 1;

/// Segment register as serialized in a blob.
#[cfg(target_arch = "x86_64")]
#[derive(Default, serde::Serialize, serde::Deserialize)]
#[serde(default)]
struct SegmentState {
    base: u64,
    limit: u32,
    selector: u16,
    attr: u16,
}

/// Descriptor table register as serialized in a blob.
#[cfg(target_arch = "x86_64")]
#[derive(Default, serde::Serialize, serde::Deserialize)]
#[serde(default)]
struct TableState {
    base: u64,
    limit: u16,
}

/// Pending exception, interrupt, NMI and SMI state, as reported by
/// `KVM_GET_VCPU_EVENTS`.
#[cfg(target_arch = "x86_64")]
#[derive(Default, serde::Serialize, serde::Deserialize)]
#[serde(default)]
struct EventState {
    exception_injected: u8,
    exception_nr: u8,
    exception_has_error_code: u8,
    exception_pending: u8,
    exception_error_code: u32,
    exception_has_payload: u8,
    exception_payload: u64,
    interrupt_injected: u8,
    interrupt_nr: u8,
    interrupt_soft: u8,
    interrupt_shadow: u8,
    nmi_injected: u8,
    nmi_pending: u8,
    nmi_masked: u8,
    smi_smm: u8,
    smi_pending: u8,
    smi_inside_nmi: u8,
    smi_latched_init: u8,
    triple_fault_pending: u8,
    sipi_vector: u32,
    flags: u32,
}

/// vCPU state as captured in a blob, with general, control, segment and
/// descriptor table registers, interrupt bitmap, debug registers, XCRs,
/// XSAVE area, `mp_state`, pending events and the LAPIC. Fields are
/// named, and a field missing from a blob takes its default.
#[cfg(target_arch = "x86_64")]
#[derive(Default, serde::Serialize, serde::Deserialize)]
#[serde(default)]
struct VcpuState {
    rax: u64,
    rbx: u64,
    rcx: u64,
    rdx: u64,
    rsi: u64,
    rdi: u64,
    rsp: u64,
    rbp: u64,
    r8: u64,
    r9: u64,
    r10: u64,
    r11: u64,
    r12: u64,
    r13: u64,
    r14: u64,
    r15: u64,
    rip: u64,
    rflags: u64,
    cr0: u64,
    cr2: u64,
    cr3: u64,
    cr4: u64,
    cr8: u64,
    efer: u64,
    apic_base: u64,
    cs: SegmentState,
    ds: SegmentState,
    es: SegmentState,
    fs: SegmentState,
    gs: SegmentState,
    ss: SegmentState,
    tr: SegmentState,
    ldt: SegmentState,
    gdt: TableState,
    idt: TableState,
    /// Pending interrupt vectors, the four words of `interrupt_bitmap`.
    interrupt_bitmap: Vec<u64>,
    /// Breakpoint address registers `DR0` to `DR3`.
    dr: Vec<u64>,
    dr6: u64,
    dr7: u64,
    /// Extended control registers, keyed by number.
    xcrs: BTreeMap<u32, u64>,
    /// XSAVE area, 4096 bytes as `u32` words.
    xsave: Vec<u32>,
    mp_state: u32,
    events: EventState,
    /// LAPIC registers, `None` without in-kernel irqchip.
    lapic: Option<Vec<u8>>,
}

#[cfg(target_arch = "x86_64")]
impl SegmentState {
    fn from_kvm(seg: &kvm_bindings::kvm_segment) -> Self {
        SegmentState {
            base: seg.base,
            limit: seg.limit,
            selector: seg.selector,
            attr: pack_attr(seg),
        }
    }
}

#[cfg(target_arch = "x86_64")]
impl TableState {
    fn from_kvm(table: &kvm_bindings::kvm_dtable) -> Self {
        TableState {
            base: table.base,
            limit: table.limit,
        }
    }
}

#[cfg(target_arch = "x86_64")]
impl EventState {
    fn from_kvm(events: &kvm_bindings::kvm_vcpu_events) -> Self {
        EventState {
            exception_injected: events.exception.injected,
            exception_nr: events.exception.nr,
            exception_has_error_code: events.exception.has_error_code,
            exception_pending: events.exception.pending,
            exception_error_code: events.exception.error_code,
            exception_has_payload: events.exception_has_payload,
            exception_payload: events.exception_payload,
            interrupt_injected: events.interrupt.injected,
            interrupt_nr: events.interrupt.nr,
            interrupt_soft: events.interrupt.soft,
            interrupt_shadow: events.interrupt.shadow,
            nmi_injected: events.nmi.injected,
            nmi_pending: events.nmi.pending,
            nmi_masked: events.nmi.masked,
            smi_smm: events.smi.smm,
            smi_pending: events.smi.pending,
            smi_inside_nmi: events.smi.smm_inside_nmi,
            smi_latched_init: events.smi.latched_init,
            triple_fault_pending: events.triple_fault.pending,
            sipi_vector: events.sipi_vector,
            flags: events.flags,
        }
    }
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

        // Stop still enters `KVM_RUN`, with `immediate_exit` set. KVM
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
    fn get_state(&self) -> Result<StateBlob> {
        // XSAVE area larger than `kvm_xsave` is not captured.
        if self.xsave_size > size_of::<kvm_bindings::kvm_xsave>() {
            return Err(Error::Unsupported("XSAVE areas past 4096 bytes"));
        }
        // Without in-kernel irqchip there is no LAPIC, `KVM_GET_LAPIC` fails
        // with `EINVAL` and the blob carries `None`.
        let lapic = match self.fd.get_lapic() {
            Ok(lapic) => Some(lapic.regs.iter().map(|&b| b as u8).collect()),
            Err(err)
                if std::io::Error::from_raw_os_error(err.errno()).kind()
                    == std::io::ErrorKind::InvalidInput =>
            {
                None
            }
            Err(err) => return Err(kvm_err("KVM_GET_LAPIC")(err)),
        };
        let regs = self.fd.get_regs().map_err(kvm_err("KVM_GET_REGS"))?;
        let sregs = self.fd.get_sregs().map_err(kvm_err("KVM_GET_SREGS"))?;
        let xcrs = self.fd.get_xcrs().map_err(kvm_err("KVM_GET_XCRS"))?;
        let debug = self
            .fd
            .get_debug_regs()
            .map_err(kvm_err("KVM_GET_DEBUGREGS"))?;
        let xsave = self.fd.get_xsave().map_err(kvm_err("KVM_GET_XSAVE"))?;
        let mp_state = self
            .fd
            .get_mp_state()
            .map_err(kvm_err("KVM_GET_MP_STATE"))?;
        let events = self
            .fd
            .get_vcpu_events()
            .map_err(kvm_err("KVM_GET_VCPU_EVENTS"))?;
        let state = VcpuState {
            rax: regs.rax,
            rbx: regs.rbx,
            rcx: regs.rcx,
            rdx: regs.rdx,
            rsi: regs.rsi,
            rdi: regs.rdi,
            rsp: regs.rsp,
            rbp: regs.rbp,
            r8: regs.r8,
            r9: regs.r9,
            r10: regs.r10,
            r11: regs.r11,
            r12: regs.r12,
            r13: regs.r13,
            r14: regs.r14,
            r15: regs.r15,
            rip: regs.rip,
            rflags: regs.rflags,
            cr0: sregs.cr0,
            cr2: sregs.cr2,
            cr3: sregs.cr3,
            cr4: sregs.cr4,
            cr8: sregs.cr8,
            efer: sregs.efer,
            apic_base: sregs.apic_base,
            cs: SegmentState::from_kvm(&sregs.cs),
            ds: SegmentState::from_kvm(&sregs.ds),
            es: SegmentState::from_kvm(&sregs.es),
            fs: SegmentState::from_kvm(&sregs.fs),
            gs: SegmentState::from_kvm(&sregs.gs),
            ss: SegmentState::from_kvm(&sregs.ss),
            tr: SegmentState::from_kvm(&sregs.tr),
            ldt: SegmentState::from_kvm(&sregs.ldt),
            gdt: TableState::from_kvm(&sregs.gdt),
            idt: TableState::from_kvm(&sregs.idt),
            interrupt_bitmap: sregs.interrupt_bitmap.to_vec(),
            dr: debug.db.to_vec(),
            dr6: debug.dr6,
            dr7: debug.dr7,
            xcrs: xcrs.xcrs[..xcrs.nr_xcrs as usize]
                .iter()
                .map(|xcr| (xcr.xcr, xcr.value))
                .collect(),
            xsave: xsave.region.to_vec(),
            mp_state: mp_state.mp_state,
            events: EventState::from_kvm(&events),
            lapic,
        };
        let data =
            serde_json::to_vec(&state).map_err(|_| Error::Other("failed to encode vCPU state"))?;
        Ok(StateBlob {
            backend: Backend::Kvm,
            arch: Arch::X86_64,
            version: STATE_VERSION,
            data,
        })
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
fn kvm_seg(val: &SegRegVal) -> kvm_bindings::kvm_segment {
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
fn pack_attr(seg: &kvm_bindings::kvm_segment) -> u16 {
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

/// Legacy interrupt line, the eventfd bound to its pin by `KVM_IRQFD`.
/// `send` writes the fd and issues no ioctl on the VM fd. Binding is
/// not undone on drop, it ends together with the VM fd.
pub struct KvmIrqSender {
    eventfd: EventFd,
}

impl IrqSender for KvmIrqSender {
    fn send(&self) -> Result<()> {
        // Without resamplefd, KVM raises the line and lowers it for each write.
        self.eventfd.write(1).map_err(kvm_err("irqfd write"))
    }
}

/// irqchip which a legacy pin routes to. IOAPIC on x86_64, irqchip 0 on
/// other architectures.
#[cfg(target_arch = "x86_64")]
const PIN_IRQCHIP: u32 = kvm_bindings::KVM_IRQCHIP_IOAPIC;
#[cfg(not(target_arch = "x86_64"))]
const PIN_IRQCHIP: u32 = 0;

/// First GSI taken by an irqfd. Legacy pins are `u8` and stay below it.
const FIRST_MSI_GSI: u32 = 256;

/// MSI route of one irqfd.
#[derive(Clone, Copy)]
struct MsiRoute {
    addr: u64,
    data: u32,
    masked: bool,
}

impl Default for MsiRoute {
    /// Masked, so that the route stays out of the table until address and
    /// data are set.
    fn default() -> Self {
        MsiRoute {
            addr: 0,
            data: 0,
            masked: true,
        }
    }
}

/// Routing table of the guest. `KVM_SET_GSI_ROUTING` overwrites the
/// table, so legacy pins which have a sender are kept here and written
/// together with MSI routes.
#[derive(Default)]
struct Routing {
    pins: BTreeSet<u8>,
    msi: BTreeMap<u32, MsiRoute>,
    next_gsi: u32,
}

impl Routing {
    /// Returns GSI of the next irqfd.
    fn take_gsi(&mut self) -> u32 {
        let gsi = FIRST_MSI_GSI + self.next_gsi;
        self.next_gsi += 1;
        gsi
    }

    /// Write the table through `KVM_SET_GSI_ROUTING`. Masked routes are
    /// left out.
    fn apply(&self, vm: &VmFd) -> Result<()> {
        let mut entries = Vec::with_capacity(self.pins.len() + self.msi.len());
        for &pin in &self.pins {
            let mut entry = kvm_irq_routing_entry {
                gsi: u32::from(pin),
                type_: KVM_IRQ_ROUTING_IRQCHIP,
                ..Default::default()
            };
            entry.u.irqchip = kvm_irq_routing_irqchip {
                irqchip: PIN_IRQCHIP,
                pin: u32::from(pin),
            };
            entries.push(entry);
        }
        for (&gsi, route) in &self.msi {
            if route.masked {
                continue;
            }
            let mut entry = kvm_irq_routing_entry {
                gsi,
                type_: KVM_IRQ_ROUTING_MSI,
                ..Default::default()
            };
            entry.u.msi = kvm_irq_routing_msi {
                address_lo: route.addr as u32,
                address_hi: (route.addr >> 32) as u32,
                data: route.data,
                ..Default::default()
            };
            entries.push(entry);
        }
        let table = KvmIrqRouting::from_entries(&entries)
            .map_err(|_| Error::Other("guest holds more routes than KVM accepts"))?;
        vm.set_gsi_routing(&table)
            .map_err(kvm_err("KVM_SET_GSI_ROUTING"))
    }
}

/// Sender for message signalled interrupts. Address and data are passed
/// with each `send`, so all devices of a guest share one sender.
pub struct KvmMsiSender {
    vm: Arc<VmFd>,
    routing: Arc<Mutex<Routing>>,
}

impl MsiSender for KvmMsiSender {
    type IrqFd = KvmIrqFd;

    fn send(&self, addr: u64, data: u32) -> Result<()> {
        let msi = kvm_msi {
            address_lo: addr as u32,
            address_hi: (addr >> 32) as u32,
            data,
            ..Default::default()
        };
        self.vm.signal_msi(msi).map_err(kvm_err("KVM_SIGNAL_MSI"))?;
        Ok(())
    }

    fn create_irqfd(&self) -> Result<KvmIrqFd> {
        let eventfd = EventFd::new(EFD_NONBLOCK).map_err(kvm_err("eventfd"))?;
        let gsi = {
            let mut routing = self.routing.lock().unwrap();
            let gsi = routing.take_gsi();
            // Masked, so the route is out of the table and the fd is off the
            // GSI until the caller sets address and data and unmasks it.
            routing.msi.insert(gsi, MsiRoute::default());
            gsi
        };
        Ok(KvmIrqFd {
            vm: Arc::clone(&self.vm),
            routing: Arc::clone(&self.routing),
            eventfd,
            gsi,
        })
    }
}

/// eventfd bound to a GSI through `KVM_IRQFD`, together with the MSI
/// route of that GSI. Writing the fd injects the MSI in kernel.
pub struct KvmIrqFd {
    vm: Arc<VmFd>,
    routing: Arc<Mutex<Routing>>,
    eventfd: EventFd,
    gsi: u32,
}

impl KvmIrqFd {
    /// Apply `change` to the route and rewrite the table.
    fn update(&self, change: impl FnOnce(&mut MsiRoute)) -> Result<()> {
        let mut routing = self.routing.lock().unwrap();
        let route = routing
            .msi
            .get_mut(&self.gsi)
            .ok_or(Error::Other("irqfd has no route"))?;
        change(route);
        routing.apply(&self.vm)
    }
}

impl AsFd for KvmIrqFd {
    fn as_fd(&self) -> BorrowedFd<'_> {
        // SAFETY: `eventfd` is owned by `self`, so the fd stays open during
        // the lifetime of the borrow.
        unsafe { BorrowedFd::borrow_raw(self.eventfd.as_raw_fd()) }
    }
}

impl IrqFd for KvmIrqFd {
    fn set_addr(&self, addr: u64) -> Result<()> {
        self.update(|route| route.addr = addr)
    }

    fn set_data(&self, data: u32) -> Result<()> {
        self.update(|route| route.data = data)
    }

    /// Masking unregisters the irqfd before the route leaves the table,
    /// unmasking registers it after the route is in. Note that an irqfd on
    /// a GSI without route panicked SVM hosts before kernel commit
    /// a80ced6ea514.
    fn set_masked(&self, masked: bool) -> Result<()> {
        let mut routing = self.routing.lock().unwrap();
        let route = routing
            .msi
            .get_mut(&self.gsi)
            .ok_or(Error::Other("irqfd has no route"))?;
        if route.masked == masked {
            return Ok(());
        }
        route.masked = masked;
        if masked {
            self.vm
                .unregister_irqfd(&self.eventfd, self.gsi)
                .map_err(kvm_err("KVM_IRQFD"))?;
            routing.apply(&self.vm)
        } else {
            routing.apply(&self.vm)?;
            self.vm
                .register_irqfd(&self.eventfd, self.gsi)
                .map_err(kvm_err("KVM_IRQFD"))
        }
    }
}

impl Drop for KvmIrqFd {
    fn drop(&mut self) {
        // KVM detaches the irqfd on eventfd hangup. The route stays in the
        // table held by KVM until next write, with no fd on its GSI.
        self.routing.lock().unwrap().msi.remove(&self.gsi);
    }
}

/// Datamatch of an ioeventfd, at the width KVM compares it in.
/// `kvm-ioctls` takes `len` from the type. `Any` means `len` 0, a write
/// of any width.
enum Datamatch {
    Any,
    Byte(u8),
    Word(u16),
    Long(u32),
    Quad(u64),
}

impl Datamatch {
    /// Build the datamatch for `len` and `data`. `len` is not used without
    /// `data`.
    fn new(len: u8, data: Option<u64>) -> Result<Self> {
        match (data, len) {
            (None, _) => Ok(Datamatch::Any),
            (Some(d), 1) => Ok(Datamatch::Byte(d as u8)),
            (Some(d), 2) => Ok(Datamatch::Word(d as u16)),
            (Some(d), 4) => Ok(Datamatch::Long(d as u32)),
            (Some(d), 8) => Ok(Datamatch::Quad(d)),
            (Some(_), _) => Err(Error::Other("datamatch should be 1, 2, 4 or 8 bytes wide")),
        }
    }
}

/// Ioeventfd, the eventfd signalled by KVM on a guest write, together
/// with its binding. Deassign needs address, width and value of the
/// assign, so `bound` is kept until `deregister`.
pub struct KvmIoeventFd {
    eventfd: EventFd,
    bound: Mutex<Option<(u64, Datamatch)>>,
}

impl IoeventFd for KvmIoeventFd {}

/// Ioeventfd registry, which issues `KVM_IOEVENTFD` on the VM fd.
pub struct KvmIoeventFdRegistry {
    vm: Arc<VmFd>,
}

impl IoeventFdRegistry for KvmIoeventFdRegistry {
    type IoeventFd = KvmIoeventFd;

    fn create(&self) -> Result<KvmIoeventFd> {
        let eventfd = EventFd::new(EFD_NONBLOCK).map_err(kvm_err("eventfd"))?;
        Ok(KvmIoeventFd {
            eventfd,
            bound: Mutex::new(None),
        })
    }

    fn register(&self, fd: &KvmIoeventFd, gpa: u64, len: u8, data: Option<u64>) -> Result<()> {
        let datamatch = Datamatch::new(len, data)?;
        let addr = IoEventAddress::Mmio(gpa);
        match datamatch {
            Datamatch::Any => self.vm.register_ioevent(&fd.eventfd, &addr, NoDatamatch),
            Datamatch::Byte(d) => self.vm.register_ioevent(&fd.eventfd, &addr, d),
            Datamatch::Word(d) => self.vm.register_ioevent(&fd.eventfd, &addr, d),
            Datamatch::Long(d) => self.vm.register_ioevent(&fd.eventfd, &addr, d),
            Datamatch::Quad(d) => self.vm.register_ioevent(&fd.eventfd, &addr, d),
        }
        .map_err(kvm_err("KVM_IOEVENTFD"))?;
        *fd.bound.lock().unwrap() = Some((gpa, datamatch));
        Ok(())
    }

    fn deregister(&self, fd: &KvmIoeventFd) -> Result<()> {
        let (gpa, datamatch) = fd
            .bound
            .lock()
            .unwrap()
            .take()
            .ok_or(Error::Other("ioeventfd is not bound"))?;
        let addr = IoEventAddress::Mmio(gpa);
        match datamatch {
            Datamatch::Any => self.vm.unregister_ioevent(&fd.eventfd, &addr, NoDatamatch),
            Datamatch::Byte(d) => self.vm.unregister_ioevent(&fd.eventfd, &addr, d),
            Datamatch::Word(d) => self.vm.unregister_ioevent(&fd.eventfd, &addr, d),
            Datamatch::Long(d) => self.vm.unregister_ioevent(&fd.eventfd, &addr, d),
            Datamatch::Quad(d) => self.vm.unregister_ioevent(&fd.eventfd, &addr, d),
        }
        .map_err(kvm_err("KVM_IOEVENTFD"))
    }
}

#[cfg(test)]
mod tests {
    use std::alloc::{Layout, alloc_zeroed, dealloc};
    use std::os::fd::AsRawFd;

    use crate::hv::backend::kvm::*;

    const PAGE: usize = 4096;

    #[test]
    fn test_open_kvm() {
        KvmHv::new().expect("/dev/kvm at the expected KVM API version");
    }

    #[test]
    fn test_create_guests() {
        let hv = KvmHv::new().expect("open /dev/kvm");
        let one = hv.create_vm().expect("first guest");
        let two = hv.create_vm().expect("second guest");
        assert_ne!(one.fd.as_raw_fd(), two.fd.as_raw_fd());
    }

    #[test]
    fn test_map_unmap_guest_memory() {
        let hv = KvmHv::new().expect("open /dev/kvm");
        let vm = hv.create_vm().expect("guest");
        let mem = vm.create_vm_memory().expect("address space");

        let size = 2 * PAGE;
        let layout = Layout::from_size_align(size, PAGE).expect("page-aligned layout");
        // SAFETY: `layout` has non-zero size.
        let host = unsafe { alloc_zeroed(layout) };
        assert!(!host.is_null());

        let gpa = 0x1000_0000;
        mem.mem_map(gpa, size as u64, host as usize, MemMapOption::default())
            .expect("map");
        mem.unmap(gpa, size as u64).expect("unmap");
        mem.unmap(gpa, size as u64).expect_err("unmap again");

        // SAFETY: `host` came from `alloc_zeroed` with `layout` and is not
        // mapped into the guest anymore.
        unsafe { dealloc(host, layout) };
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

    #[test]
    fn test_ioeventfd_registry() {
        let hv = KvmHv::new().expect("open /dev/kvm");
        let vm = hv.create_vm().expect("guest");
        let registry = vm.create_ioeventfd_registry();

        let eventfd = registry.create().expect("ioeventfd");
        registry
            .register(&eventfd, 0x1000, 4, None)
            .expect("bind at 0x1000");
        // Second `KVM_IOEVENTFD` at the address of a `len` 0 ioeventfd fails
        // with `EEXIST`.
        let clash = registry.create().expect("ioeventfd");
        assert!(
            registry.register(&clash, 0x1000, 4, None).is_err(),
            "second ioeventfd bound to the same address"
        );

        registry.deregister(&eventfd).expect("unbind");
        assert!(
            registry.deregister(&eventfd).is_err(),
            "same ioeventfd unbound twice"
        );

        // Ioeventfds with different datamatch values can share an address.
        // Each deassign names its own value.
        let seven = registry.create().expect("ioeventfd");
        let nine = registry.create().expect("ioeventfd");
        registry
            .register(&seven, 0x2000, 2, Some(7))
            .expect("bind on 7");
        registry
            .register(&nine, 0x2000, 2, Some(9))
            .expect("bind on 9");
        registry.deregister(&seven).expect("unbind 7");
        registry.deregister(&nine).expect("unbind 9");

        assert!(
            registry.register(&eventfd, 0x3000, 3, Some(1)).is_err(),
            "three-byte datamatch accepted"
        );
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
        // Guest writes the value of the IN to port 0xfa next, which shows
        // the read was completed.
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

        // With `rip` written the second stream runs, byte on port 0xf8
        // shows which one did.
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
        // so the exit on port 0xf8 shows the mode took effect.
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
    fn test_ioeventfd_avoids_mmio_exit() {
        // Guest write should signal the eventfd instead of exiting as MMIO.
        let hv = KvmHv::new().expect("open /dev/kvm");
        let layout = Layout::from_size_align(PAGE, PAGE).expect("page-aligned layout");
        // No memory is mapped at `NOTIFY`. Write to it exits as MMIO unless an
        // ioeventfd is bound there.
        const NOTIFY: u64 = 0x8000;
        let code = [
            0xbb, 0x00, 0x80, // mov bx, 0x8000
            0xb0, 0x42, // mov al, 0x42
            0x88, 0x07, // mov [bx], al
            0xf4, // hlt
        ];

        // Build a guest with only the reset vector page mapped. Caller frees
        // `reset` once the guest is not run anymore.
        let guest = |hv: &KvmHv| {
            let vm = hv.create_vm().expect("guest");
            let mem = vm.create_vm_memory().expect("address space");
            // SAFETY: `layout` has non-zero size.
            let reset = unsafe { alloc_zeroed(layout) };
            assert!(!reset.is_null());
            // SAFETY: the allocation is one page and `code` fits at 0xff0.
            unsafe { std::ptr::copy_nonoverlapping(code.as_ptr(), reset.add(0xff0), code.len()) };
            mem.mem_map(
                0xffff_f000,
                PAGE as u64,
                reset as usize,
                MemMapOption::default(),
            )
            .expect("map the reset vector");
            (vm, mem, reset)
        };

        // Without ioeventfd, the write exits as MMIO.
        let (vm, _mem, reset) = guest(&hv);
        let mut cpu = vm.create_vcpu(0).expect("vcpu 0");
        assert_eq!(
            cpu.run(VmEntry::Run).expect("run"),
            VmExit::Mmio {
                addr: NOTIFY,
                write: Some(0x42),
                size: 1
            }
        );
        // SAFETY: `reset` came from `alloc_zeroed` with `layout`, and the
        // guest is not run anymore.
        unsafe { dealloc(reset, layout) };

        // With an ioeventfd bound at `NOTIFY`, KVM signals it instead of
        // exiting, guest runs on to `hlt`.
        let (vm, _mem, reset) = guest(&hv);
        let registry = vm.create_ioeventfd_registry();
        let eventfd = registry.create().expect("ioeventfd");
        registry
            .register(&eventfd, NOTIFY, 1, None)
            .expect("bind the ioeventfd");
        let mut cpu = vm.create_vcpu(0).expect("vcpu 0");
        assert_eq!(
            cpu.run(VmEntry::Run).expect("run"),
            VmExit::Halt,
            "write exited as MMIO"
        );
        assert_eq!(eventfd.eventfd.read().expect("ioeventfd signalled"), 1);
        // SAFETY: same as above.
        unsafe { dealloc(reset, layout) };
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

        // rep insb: three reads of port 0xf9 stored at ES:DI, which is guest
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

    #[cfg(target_arch = "x86_64")]
    #[test]
    fn test_send_msi() {
        let hv = KvmHv::new().expect("open /dev/kvm");
        let vm = hv.create_vm().expect("guest");
        vm.enable_irqchip().expect("in-kernel irqchip");
        let msi = vm.create_msi_sender().expect("msi sender");

        // Without vCPU there is no LAPIC to deliver to. `KVM_SIGNAL_MSI`
        // returns -1, which shows as `EPERM` at the syscall boundary.
        assert!(
            msi.send(0xfee0_0000, 0x30).is_err(),
            "message delivered with no LAPIC to take it"
        );

        let _cpu0 = vm.create_vcpu(0).expect("vcpu 0");
        // Vector 0x30, fixed delivery, addressed to APIC id 0.
        msi.send(0xfee0_0000, 0x30).expect("deliver to vcpu 0");
    }

    /// Returns whether `fd` is registered on its GSI. A second `KVM_IRQFD`
    /// assign of a registered eventfd fails with `EBUSY`. Probe which
    /// succeeds is undone afterwards.
    #[cfg(target_arch = "x86_64")]
    fn assigned(vm: &KvmVm, fd: &KvmIrqFd) -> bool {
        match vm.fd.register_irqfd(&fd.eventfd, fd.gsi) {
            Ok(()) => {
                vm.fd
                    .unregister_irqfd(&fd.eventfd, fd.gsi)
                    .expect("undo the probe");
                false
            }
            Err(err) => {
                assert_eq!(err.errno(), 16, "expected EBUSY");
                true
            }
        }
    }

    #[cfg(target_arch = "x86_64")]
    #[test]
    fn test_irqfd_routing() {
        // Check GSI assignment, masking and route removal of irqfds.
        let hv = KvmHv::new().expect("open /dev/kvm");
        let vm = hv.create_vm().expect("guest");
        vm.enable_irqchip().expect("in-kernel irqchip");

        // Legacy line. Its pin is in each table written after this.
        let com1 = vm.create_irq_sender(4).expect("sender on IRQ 4");
        assert!(vm.routing.lock().unwrap().pins.contains(&4));

        let msi = vm.create_msi_sender().expect("msi sender");
        let one = msi.create_irqfd().expect("irqfd");
        let two = msi.create_irqfd().expect("second irqfd");
        assert_ne!(one.gsi, two.gsi, "two irqfds got the same GSI");
        assert!(one.gsi >= FIRST_MSI_GSI, "irqfd took a legacy pin number");

        // Both routes are still masked, so neither of them is in the table.
        let fresh = vm.routing.lock().unwrap();
        assert!(
            fresh.msi[&one.gsi].masked,
            "route without message went to KVM"
        );
        assert!(
            fresh.msi[&two.gsi].masked,
            "route without message went to KVM"
        );
        drop(fresh);
        // Masked irqfd is not registered on its GSI.
        assert!(!assigned(&vm, &one), "unprogrammed irqfd holds its GSI");

        // Each call rewrites the table with the legacy pin and both MSI
        // routes. `KVM_SET_GSI_ROUTING` fails on a table it can not route.
        one.set_addr(0xfee0_0000).expect("address");
        one.set_data(0x31).expect("data");
        one.set_masked(false).expect("unmask");
        two.set_addr(0xfee0_0000).expect("address");
        two.set_data(0x32).expect("data");
        two.set_masked(false).expect("unmask");
        assert!(assigned(&vm, &one), "unmasked irqfd is off its GSI");

        // Masking unregisters the fd, repeating it is a no-op, and unmasking
        // registers it again.
        one.set_masked(true).expect("mask");
        assert!(!assigned(&vm, &one), "masked irqfd holds its GSI");
        one.set_masked(true).expect("mask twice");
        one.set_masked(false).expect("unmask again");
        assert!(assigned(&vm, &one), "unmasked irqfd is off its GSI");

        let routing = vm.routing.lock().unwrap();
        assert!(routing.pins.contains(&4), "legacy pin left the table");
        assert_eq!(routing.msi.len(), 2);
        drop(routing);

        one.eventfd.write(1).expect("fire the irqfd");
        com1.send().expect("pulse IRQ 4");

        let gone = two.gsi;
        drop(two);
        assert!(
            !vm.routing.lock().unwrap().msi.contains_key(&gone),
            "dropped irqfd left its route behind"
        );
    }

    #[cfg(target_arch = "x86_64")]
    #[test]
    fn test_legacy_irq_line() {
        let hv = KvmHv::new().expect("open /dev/kvm");
        let vm = hv.create_vm().expect("guest");
        // `KVM_IRQFD` fails with `EINVAL` before `KVM_CREATE_IRQCHIP`.
        assert!(
            vm.create_irq_sender(4).is_err(),
            "pin bound with no controller behind it"
        );

        vm.enable_irqchip().expect("in-kernel irqchip");
        let com1 = vm.create_irq_sender(4).expect("sender on IRQ 4");
        com1.send().expect("pulse");
        com1.send().expect("pulse again");
    }
}
