// SPDX-FileCopyrightText: 2026 LingCage <opensource@lingcage.com>
//
// SPDX-License-Identifier: Apache-2.0

//! vCPU state as a `StateBlob`, named fields through `serde_json`
//! instead of raw bytes of KVM structs.

#![cfg(target_arch = "x86_64")]

use std::collections::BTreeMap;

use kvm_ioctls::VcpuFd;

use crate::hv::arch::SegRegVal;
use crate::hv::backend::kvm::kvm_err;
use crate::hv::backend::kvm::vcpu::{kvm_seg, pack_attr};
use crate::hv::{Arch, Backend, Error, Result, StateBlob};

/// Layout version of `StateBlob::data`, `restore` refuses others.
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
pub(in crate::hv::backend::kvm) struct VcpuState {
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
    /// MSRs keyed by index, so that a blob decodes on a kernel with another
    /// list.
    msrs: BTreeMap<u32, u64>,
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

    fn to_kvm(&self) -> kvm_bindings::kvm_segment {
        kvm_seg(&SegRegVal {
            base: self.base,
            limit: self.limit,
            selector: self.selector,
            attr: self.attr,
        })
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

    fn to_kvm(&self) -> kvm_bindings::kvm_dtable {
        kvm_bindings::kvm_dtable {
            base: self.base,
            limit: self.limit,
            ..Default::default()
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

    fn to_kvm(&self) -> kvm_bindings::kvm_vcpu_events {
        let mut events = kvm_bindings::kvm_vcpu_events {
            sipi_vector: self.sipi_vector,
            flags: self.flags,
            exception_has_payload: self.exception_has_payload,
            exception_payload: self.exception_payload,
            ..Default::default()
        };
        events.exception.injected = self.exception_injected;
        events.exception.nr = self.exception_nr;
        events.exception.has_error_code = self.exception_has_error_code;
        events.exception.pending = self.exception_pending;
        events.exception.error_code = self.exception_error_code;
        events.interrupt.injected = self.interrupt_injected;
        events.interrupt.nr = self.interrupt_nr;
        events.interrupt.soft = self.interrupt_soft;
        events.interrupt.shadow = self.interrupt_shadow;
        events.nmi.injected = self.nmi_injected;
        events.nmi.pending = self.nmi_pending;
        events.nmi.masked = self.nmi_masked;
        events.smi.smm = self.smi_smm;
        events.smi.pending = self.smi_pending;
        events.smi.smm_inside_nmi = self.smi_inside_nmi;
        events.smi.latched_init = self.smi_latched_init;
        events.triple_fault.pending = self.triple_fault_pending;
        events
    }
}

/// Largest batch accepted by `KVM_GET_MSRS` and `KVM_SET_MSRS`, the
/// kernel refuses `nmsrs` of `MAX_IO_MSRS` (256) or more.
#[cfg(target_arch = "x86_64")]
const MSR_BATCH: usize = 255;

/// Read the MSRs in `indices` which this vCPU has. KVM stops a batch at
/// the first register it can not read and returns the count read, so the
/// walk steps over that register and goes on.
#[cfg(target_arch = "x86_64")]
fn capture_msrs(fd: &VcpuFd, indices: &[u32]) -> Result<BTreeMap<u32, u64>> {
    let mut captured = BTreeMap::new();
    let mut rest = indices;
    while !rest.is_empty() {
        let batch = rest.len().min(MSR_BATCH);
        let entries = rest[..batch]
            .iter()
            .map(|&index| kvm_bindings::kvm_msr_entry {
                index,
                ..Default::default()
            })
            .collect::<Vec<_>>();
        let mut msrs = kvm_bindings::Msrs::from_entries(&entries)
            .map_err(|_| Error::Other("MSR batch does not fit"))?;
        let read = fd.get_msrs(&mut msrs).map_err(kvm_err("KVM_GET_MSRS"))?;
        captured.extend(
            msrs.as_slice()[..read]
                .iter()
                .map(|entry| (entry.index, entry.data)),
        );
        rest = &rest[batch.min(read + 1)..];
    }
    Ok(captured)
}

/// Write captured MSRs in ascending index order, which puts `IA32_TSC`
/// (0x10) before `IA32_TSC_DEADLINE` (0x6e0), since KVM reads the TSC
/// while setting the deadline. KVM stops a batch at the first register
/// it refuses. Refused zero is stepped over, since `MSR_KVM_ASYNC_PF_INT`
/// can be read without in-kernel LAPIC but not written, and a new vCPU
/// reads zero there. Refused non-zero value is reported as
/// `Error::Partial`.
#[cfg(target_arch = "x86_64")]
fn restore_msrs(fd: &VcpuFd, msrs: &BTreeMap<u32, u64>) -> Result<()> {
    let entries = msrs
        .iter()
        .map(|(&index, &data)| kvm_bindings::kvm_msr_entry {
            index,
            data,
            ..Default::default()
        })
        .collect::<Vec<_>>();
    let mut rest = &entries[..];
    while !rest.is_empty() {
        let batch = rest.len().min(MSR_BATCH);
        let msrs = kvm_bindings::Msrs::from_entries(&rest[..batch])
            .map_err(|_| Error::Other("MSR batch does not fit"))?;
        let written = fd.set_msrs(&msrs).map_err(kvm_err("KVM_SET_MSRS"))?;
        if written < batch && rest[written].data != 0 {
            return Err(Error::Partial {
                op: "KVM_SET_MSRS",
                index: rest[written].index,
            });
        }
        rest = &rest[batch.min(written + 1)..];
    }
    Ok(())
}

#[cfg(target_arch = "x86_64")]
impl VcpuState {
    /// Capture state of the vCPU behind `fd` as a `StateBlob`.
    pub(in crate::hv::backend::kvm) fn capture(
        fd: &VcpuFd,
        xsave_size: usize,
        msr_indices: &[u32],
    ) -> Result<StateBlob> {
        if xsave_size > size_of::<kvm_bindings::kvm_xsave>() {
            return Err(Error::Unsupported("XSAVE areas past 4096 bytes"));
        }
        // Without in-kernel irqchip there is no LAPIC, `KVM_GET_LAPIC` fails
        // with `EINVAL` and the blob carries `None`.
        let lapic = match fd.get_lapic() {
            Ok(lapic) => Some(lapic.regs.iter().map(|&b| b as u8).collect()),
            Err(err)
                if std::io::Error::from_raw_os_error(err.errno()).kind()
                    == std::io::ErrorKind::InvalidInput =>
            {
                None
            }
            Err(err) => return Err(kvm_err("KVM_GET_LAPIC")(err)),
        };
        let regs = fd.get_regs().map_err(kvm_err("KVM_GET_REGS"))?;
        let sregs = fd.get_sregs().map_err(kvm_err("KVM_GET_SREGS"))?;
        let xcrs = fd.get_xcrs().map_err(kvm_err("KVM_GET_XCRS"))?;
        let debug = fd.get_debug_regs().map_err(kvm_err("KVM_GET_DEBUGREGS"))?;
        let xsave = fd.get_xsave().map_err(kvm_err("KVM_GET_XSAVE"))?;
        let mp_state = fd.get_mp_state().map_err(kvm_err("KVM_GET_MP_STATE"))?;
        let events = fd
            .get_vcpu_events()
            .map_err(kvm_err("KVM_GET_VCPU_EVENTS"))?;
        let msrs = capture_msrs(fd, msr_indices)?;
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
            msrs,
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

    /// Restore `blob` into the vCPU behind `fd`. Blob of another backend,
    /// arch or layout version is refused.
    pub(in crate::hv::backend::kvm) fn restore(
        fd: &VcpuFd,
        xsave_size: usize,
        blob: &StateBlob,
    ) -> Result<()> {
        if blob.backend != Backend::Kvm || blob.arch != Arch::X86_64 {
            return Err(Error::Other("state blob from another backend or arch"));
        }
        if blob.version != STATE_VERSION {
            return Err(Error::Other("state blob version not supported"));
        }
        if xsave_size > size_of::<kvm_bindings::kvm_xsave>() {
            return Err(Error::Unsupported("XSAVE areas past 4096 bytes"));
        }
        let state: VcpuState = serde_json::from_slice(&blob.data)
            .map_err(|_| Error::Other("failed to decode vCPU state"))?;

        let regs = kvm_bindings::kvm_regs {
            rax: state.rax,
            rbx: state.rbx,
            rcx: state.rcx,
            rdx: state.rdx,
            rsi: state.rsi,
            rdi: state.rdi,
            rsp: state.rsp,
            rbp: state.rbp,
            r8: state.r8,
            r9: state.r9,
            r10: state.r10,
            r11: state.r11,
            r12: state.r12,
            r13: state.r13,
            r14: state.r14,
            r15: state.r15,
            rip: state.rip,
            rflags: state.rflags,
        };
        fd.set_regs(&regs).map_err(kvm_err("KVM_SET_REGS"))?;

        let mut sregs = kvm_bindings::kvm_sregs {
            cr0: state.cr0,
            cr2: state.cr2,
            cr3: state.cr3,
            cr4: state.cr4,
            cr8: state.cr8,
            efer: state.efer,
            apic_base: state.apic_base,
            cs: state.cs.to_kvm(),
            ds: state.ds.to_kvm(),
            es: state.es.to_kvm(),
            fs: state.fs.to_kvm(),
            gs: state.gs.to_kvm(),
            ss: state.ss.to_kvm(),
            tr: state.tr.to_kvm(),
            ldt: state.ldt.to_kvm(),
            gdt: state.gdt.to_kvm(),
            idt: state.idt.to_kvm(),
            ..Default::default()
        };
        for (slot, word) in sregs
            .interrupt_bitmap
            .iter_mut()
            .zip(&state.interrupt_bitmap)
        {
            *slot = *word;
        }
        fd.set_sregs(&sregs).map_err(kvm_err("KVM_SET_SREGS"))?;

        let mut xcrs = kvm_bindings::kvm_xcrs::default();
        for (slot, (&nr, &value)) in xcrs.xcrs.iter_mut().zip(&state.xcrs) {
            *slot = kvm_bindings::kvm_xcr {
                xcr: nr,
                value,
                ..Default::default()
            };
        }
        xcrs.nr_xcrs = state.xcrs.len().min(xcrs.xcrs.len()) as u32;
        fd.set_xcrs(&xcrs).map_err(kvm_err("KVM_SET_XCRS"))?;

        let mut debug = kvm_bindings::kvm_debugregs {
            dr6: state.dr6,
            dr7: state.dr7,
            ..Default::default()
        };
        for (slot, word) in debug.db.iter_mut().zip(&state.dr) {
            *slot = *word;
        }
        fd.set_debug_regs(&debug)
            .map_err(kvm_err("KVM_SET_DEBUGREGS"))?;

        let mut xsave = kvm_bindings::kvm_xsave::default();
        for (slot, word) in xsave.region.iter_mut().zip(&state.xsave) {
            *slot = *word;
        }
        // SAFETY: `KVM_SET_XSAVE` copies `xsave_size` bytes, and the check
        // above bounds that by the size of `kvm_xsave`.
        unsafe { fd.set_xsave(&xsave) }.map_err(kvm_err("KVM_SET_XSAVE"))?;

        fd.set_mp_state(kvm_bindings::kvm_mp_state {
            mp_state: state.mp_state,
        })
        .map_err(kvm_err("KVM_SET_MP_STATE"))?;
        fd.set_vcpu_events(&state.events.to_kvm())
            .map_err(kvm_err("KVM_SET_VCPU_EVENTS"))?;

        if let Some(bytes) = &state.lapic {
            let mut lapic = kvm_bindings::kvm_lapic_state::default();
            for (slot, byte) in lapic.regs.iter_mut().zip(bytes) {
                *slot = *byte as i8;
            }
            fd.set_lapic(&lapic).map_err(kvm_err("KVM_SET_LAPIC"))?;
        }
        restore_msrs(fd, &state.msrs)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    #[cfg(target_arch = "x86_64")]
    use crate::hv::Error;
    use crate::hv::arch::{Reg, SReg};
    use crate::hv::backend::kvm::hypervisor::KvmHv;
    use crate::hv::hypervisor::Hypervisor;
    use crate::hv::vcpu::Vcpu;
    use crate::hv::vm::Vm;
    use crate::hv::{Arch, Backend};

    #[cfg(target_arch = "x86_64")]
    #[test]
    fn test_vcpu_capture_restore() {
        let hv = KvmHv::new().expect("open /dev/kvm");
        let vm = hv.create_vm().expect("guest");
        // With in-kernel irqchip the capture carries the LAPIC.
        vm.enable_irqchip().expect("in-kernel irqchip");
        let mut cpu = vm.create_vcpu(0).expect("vcpu 0");

        cpu.set_regs(&[(Reg::Rip, 0x1_2345), (Reg::Rax, 0xdead_beef)])
            .expect("seed the registers");
        cpu.set_sregs(&[(SReg::Cr2, 0x5555)], &[], &[])
            .expect("seed cr2");
        let blob = cpu.get_state().expect("capture");
        assert_eq!(blob.backend, Backend::Kvm);
        assert_eq!(blob.arch, Arch::X86_64);

        // Overwrite the seeded registers, then restore the blob.
        cpu.set_regs(&[(Reg::Rip, 0), (Reg::Rax, 0)])
            .expect("clobber");
        cpu.set_sregs(&[(SReg::Cr2, 0)], &[], &[]).expect("clobber");
        assert_eq!(cpu.get_reg(Reg::Rax).expect("rax"), 0);

        cpu.set_state(&blob).expect("restore");
        assert_eq!(cpu.get_reg(Reg::Rip).expect("rip"), 0x1_2345);
        assert_eq!(cpu.get_reg(Reg::Rax).expect("rax"), 0xdead_beef);
        assert_eq!(cpu.get_sreg(SReg::Cr2).expect("cr2"), 0x5555);

        // Blob of another backend, or a later layout, is refused before
        // decoding.
        let mut alien = blob.clone();
        alien.backend = Backend::Mshv;
        assert!(
            cpu.set_state(&alien).is_err(),
            "state of another backend accepted"
        );
        let mut newer = blob.clone();
        newer.version += 1;
        assert!(cpu.set_state(&newer).is_err(), "unknown layout accepted");

        // Fields are read by name, dropped field takes default and unknown
        // field is ignored.
        let mut text: serde_json::Value =
            serde_json::from_slice(&blob.data).expect("decode the blob as JSON");
        let object = text.as_object_mut().expect("a JSON object");
        object.remove("rbx").expect("field to drop");
        object.insert("something_later".into(), serde_json::Value::from(7));
        let mut edited = blob.clone();
        edited.data = serde_json::to_vec(&text).expect("re-encode");
        cpu.set_state(&edited).expect("restore with other fields");
        assert_eq!(cpu.get_reg(Reg::Rip).expect("rip"), 0x1_2345);
        assert_eq!(cpu.get_reg(Reg::Rbx).expect("rbx"), 0, "dropped field");

        // Without in-kernel irqchip the capture has no LAPIC but still
        // succeeds.
        let bare = hv.create_vm().expect("guest");
        let bare_cpu = bare.create_vcpu(0).expect("vcpu 0");
        bare_cpu.get_state().expect("capture without LAPIC");
    }

    #[cfg(target_arch = "x86_64")]
    #[test]
    fn test_msr_capture_restore() {
        /// `MSR_KERNEL_GS_BASE`, KVM takes any canonical address.
        const KERNEL_GS_BASE: u32 = 0xc000_0102;
        /// A canonical address.
        const SEEDED: u64 = 0x1234_5678_9000;

        let hv = KvmHv::new().expect("open /dev/kvm");
        let vm = hv.create_vm().expect("guest");
        let mut cpu = vm.create_vcpu(0).expect("vcpu 0");

        let blob = cpu.get_state().expect("capture");
        let mut text: serde_json::Value =
            serde_json::from_slice(&blob.data).expect("decode the blob as JSON");
        let msrs = text["msrs"].as_object_mut().expect("MSRs by index");
        let seat = msrs
            .get_mut(&KERNEL_GS_BASE.to_string())
            .expect("KERNEL_GS_BASE in the list");
        *seat = serde_json::Value::from(SEEDED);

        let mut edited = blob.clone();
        edited.data = serde_json::to_vec(&text).expect("re-encode");
        cpu.set_state(&edited).expect("restore");

        let after = cpu.get_state().expect("capture");
        let text: serde_json::Value =
            serde_json::from_slice(&after.data).expect("decode the blob as JSON");
        assert_eq!(
            text["msrs"][KERNEL_GS_BASE.to_string()],
            serde_json::Value::from(SEEDED),
            "MSR did not survive the round trip"
        );
    }

    #[cfg(target_arch = "x86_64")]
    #[test]
    fn test_refused_msr_reported() {
        const KERNEL_GS_BASE: u32 = 0xc000_0102;
        /// Bit 47 set and bits above it clear, which is not canonical, so KVM
        /// refuses the write.
        const CROOKED: u64 = 0xdead_beef_0000;

        let hv = KvmHv::new().expect("open /dev/kvm");
        let vm = hv.create_vm().expect("guest");
        let mut cpu = vm.create_vcpu(0).expect("vcpu 0");

        let blob = cpu.get_state().expect("capture");
        let mut text: serde_json::Value =
            serde_json::from_slice(&blob.data).expect("decode the blob as JSON");
        let msrs = text["msrs"].as_object_mut().expect("MSRs by index");
        msrs.insert(KERNEL_GS_BASE.to_string(), serde_json::Value::from(CROOKED));

        let mut edited = blob.clone();
        edited.data = serde_json::to_vec(&text).expect("re-encode");
        assert!(
            matches!(
                cpu.set_state(&edited),
                Err(Error::Partial {
                    op: "KVM_SET_MSRS",
                    index: KERNEL_GS_BASE
                })
            ),
            "refused non-zero MSR not reported"
        );
    }
}
