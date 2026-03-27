// SPDX-FileCopyrightText: 2026 LingCage <opensource@lingcage.com>
//
// SPDX-License-Identifier: Apache-2.0

//! Interrupt controller state as a `StateBlob`. It covers the two 8259
//! PICs, the I/O APIC and the 8254 PIT.

#![cfg(target_arch = "x86_64")]

use kvm_bindings::{
    KVM_IRQCHIP_IOAPIC, KVM_IRQCHIP_PIC_MASTER, KVM_IRQCHIP_PIC_SLAVE, kvm_irqchip,
};
use kvm_ioctls::VmFd;

use crate::hv::backend::kvm::kvm_err;
use crate::hv::{Arch, Backend, Error, Result, StateBlob};

/// Layout version of `StateBlob::data`, `restore` refuses others.
const STATE_VERSION: u32 = 1;

/// Redirection entry after `kvm_ioapic_reset`, mask bit set and the rest
/// zero. Entries not covered by a blob are set to it on restore.
const LINE_MASKED: u64 = 0x1_0000;

/// One 8259 as serialized in a blob, fields are the ones of
/// `kvm_pic_state`.
#[derive(Default, serde::Serialize, serde::Deserialize)]
#[serde(default)]
struct PicState {
    last_irr: u8,
    irr: u8,
    imr: u8,
    isr: u8,
    priority_add: u8,
    irq_base: u8,
    read_reg_select: u8,
    poll: u8,
    special_mask: u8,
    init_state: u8,
    auto_eoi: u8,
    rotate_on_auto_eoi: u8,
    special_fully_nested_mode: u8,
    init4: u8,
    elcr: u8,
    elcr_mask: u8,
}

/// I/O APIC as serialized in a blob. Each redirection entry is kept as
/// its 64-bit word, the kernel defines the bitfield inside.
#[derive(Default, serde::Serialize, serde::Deserialize)]
#[serde(default)]
struct IoApicState {
    base_address: u64,
    ioregsel: u32,
    id: u32,
    irr: u32,
    redirtbl: Vec<u64>,
}

/// One 8254 counter as serialized in a blob.
#[derive(Default, serde::Serialize, serde::Deserialize)]
#[serde(default)]
struct PitChannelState {
    count: u32,
    latched_count: u16,
    count_latched: u8,
    status_latched: u8,
    status: u8,
    read_state: u8,
    write_state: u8,
    write_latch: u8,
    rw_mode: u8,
    mode: u8,
    bcd: u8,
    gate: u8,
    count_load_time: i64,
}

/// 8254 PIT as serialized in a blob.
#[derive(Default, serde::Serialize, serde::Deserialize)]
#[serde(default)]
struct PitState {
    channels: Vec<PitChannelState>,
    flags: u32,
}

/// Interrupt controller state as captured in a blob. Field missing from
/// a blob takes its default.
#[derive(Default, serde::Serialize, serde::Deserialize)]
#[serde(default)]
pub(in crate::hv::backend::kvm) struct IrqChipState {
    pic_master: PicState,
    pic_slave: PicState,
    ioapic: IoApicState,
    pit: PitState,
}

impl PicState {
    fn from_kvm(pic: &kvm_bindings::kvm_pic_state) -> Self {
        PicState {
            last_irr: pic.last_irr,
            irr: pic.irr,
            imr: pic.imr,
            isr: pic.isr,
            priority_add: pic.priority_add,
            irq_base: pic.irq_base,
            read_reg_select: pic.read_reg_select,
            poll: pic.poll,
            special_mask: pic.special_mask,
            init_state: pic.init_state,
            auto_eoi: pic.auto_eoi,
            rotate_on_auto_eoi: pic.rotate_on_auto_eoi,
            special_fully_nested_mode: pic.special_fully_nested_mode,
            init4: pic.init4,
            elcr: pic.elcr,
            elcr_mask: pic.elcr_mask,
        }
    }

    fn to_kvm(&self) -> kvm_bindings::kvm_pic_state {
        kvm_bindings::kvm_pic_state {
            last_irr: self.last_irr,
            irr: self.irr,
            imr: self.imr,
            isr: self.isr,
            priority_add: self.priority_add,
            irq_base: self.irq_base,
            read_reg_select: self.read_reg_select,
            poll: self.poll,
            special_mask: self.special_mask,
            init_state: self.init_state,
            auto_eoi: self.auto_eoi,
            rotate_on_auto_eoi: self.rotate_on_auto_eoi,
            special_fully_nested_mode: self.special_fully_nested_mode,
            init4: self.init4,
            elcr: self.elcr,
            elcr_mask: self.elcr_mask,
        }
    }
}

impl IoApicState {
    fn from_kvm(ioapic: &kvm_bindings::kvm_ioapic_state) -> Self {
        IoApicState {
            base_address: ioapic.base_address,
            ioregsel: ioapic.ioregsel,
            id: ioapic.id,
            irr: ioapic.irr,
            redirtbl: ioapic
                .redirtbl
                .iter()
                // SAFETY: the entry is a union of `bits` and the bitfields over
                // the same 8 bytes, both written by `KVM_GET_IRQCHIP`.
                .map(|entry| unsafe { entry.bits })
                .collect(),
        }
    }

    fn to_kvm(&self) -> kvm_bindings::kvm_ioapic_state {
        let mut ioapic = kvm_bindings::kvm_ioapic_state {
            base_address: self.base_address,
            ioregsel: self.ioregsel,
            id: self.id,
            irr: self.irr,
            ..Default::default()
        };
        // Zero entry means an unmasked line at vector 0, so the table starts
        // as `LINE_MASKED` and entries of the blob are copied over it up to
        // the shorter length.
        for slot in ioapic.redirtbl.iter_mut() {
            slot.bits = LINE_MASKED;
        }
        for (slot, &bits) in ioapic.redirtbl.iter_mut().zip(&self.redirtbl) {
            slot.bits = bits;
        }
        ioapic
    }
}

impl PitChannelState {
    fn from_kvm(channel: &kvm_bindings::kvm_pit_channel_state) -> Self {
        PitChannelState {
            count: channel.count,
            latched_count: channel.latched_count,
            count_latched: channel.count_latched,
            status_latched: channel.status_latched,
            status: channel.status,
            read_state: channel.read_state,
            write_state: channel.write_state,
            write_latch: channel.write_latch,
            rw_mode: channel.rw_mode,
            mode: channel.mode,
            bcd: channel.bcd,
            gate: channel.gate,
            count_load_time: channel.count_load_time,
        }
    }

    fn to_kvm(&self) -> kvm_bindings::kvm_pit_channel_state {
        kvm_bindings::kvm_pit_channel_state {
            count: self.count,
            latched_count: self.latched_count,
            count_latched: self.count_latched,
            status_latched: self.status_latched,
            status: self.status,
            read_state: self.read_state,
            write_state: self.write_state,
            write_latch: self.write_latch,
            rw_mode: self.rw_mode,
            mode: self.mode,
            bcd: self.bcd,
            gate: self.gate,
            count_load_time: self.count_load_time,
        }
    }
}

/// Read the chip named by `chip_id`, `KVM_GET_IRQCHIP` fills the union
/// arm of that chip.
fn get_chip(fd: &VmFd, chip_id: u32) -> Result<kvm_irqchip> {
    let mut chip = kvm_irqchip {
        chip_id,
        ..Default::default()
    };
    fd.get_irqchip(&mut chip)
        .map_err(kvm_err("KVM_GET_IRQCHIP"))?;
    Ok(chip)
}

impl IrqChipState {
    /// Capture the controller state behind `fd` as a `StateBlob`.
    pub(in crate::hv::backend::kvm) fn capture(fd: &VmFd) -> Result<StateBlob> {
        let master = get_chip(fd, KVM_IRQCHIP_PIC_MASTER)?;
        let slave = get_chip(fd, KVM_IRQCHIP_PIC_SLAVE)?;
        let ioapic = get_chip(fd, KVM_IRQCHIP_IOAPIC)?;
        let pit = fd.get_pit2().map_err(kvm_err("KVM_GET_PIT2"))?;
        let state = IrqChipState {
            // SAFETY: read under `KVM_IRQCHIP_PIC_MASTER`, which fills `pic`.
            pic_master: PicState::from_kvm(unsafe { &master.chip.pic }),
            // SAFETY: read under `KVM_IRQCHIP_PIC_SLAVE`, which fills `pic`.
            pic_slave: PicState::from_kvm(unsafe { &slave.chip.pic }),
            // SAFETY: read under `KVM_IRQCHIP_IOAPIC`, which fills `ioapic`.
            ioapic: IoApicState::from_kvm(unsafe { &ioapic.chip.ioapic }),
            pit: PitState {
                channels: pit.channels.iter().map(PitChannelState::from_kvm).collect(),
                flags: pit.flags,
            },
        };
        let data = serde_json::to_vec(&state)
            .map_err(|_| Error::Other("failed to encode controller state"))?;
        Ok(StateBlob {
            backend: Backend::Kvm,
            arch: Arch::X86_64,
            version: STATE_VERSION,
            data,
        })
    }

    /// Restore `blob` into the controller behind `fd`. Blob of another
    /// backend, arch or layout version is refused.
    pub(in crate::hv::backend::kvm) fn restore(fd: &VmFd, blob: &StateBlob) -> Result<()> {
        if blob.backend != Backend::Kvm || blob.arch != Arch::X86_64 {
            return Err(Error::Other("state blob from another backend or arch"));
        }
        if blob.version != STATE_VERSION {
            return Err(Error::Other("state blob version not supported"));
        }
        let state: IrqChipState = serde_json::from_slice(&blob.data)
            .map_err(|_| Error::Other("failed to decode controller state"))?;

        let mut pit = kvm_bindings::kvm_pit_state2 {
            flags: state.pit.flags,
            ..Default::default()
        };
        for (slot, channel) in pit.channels.iter_mut().zip(&state.pit.channels) {
            *slot = channel.to_kvm();
        }
        fd.set_pit2(&pit).map_err(kvm_err("KVM_SET_PIT2"))?;

        for (chip_id, pic) in [
            (KVM_IRQCHIP_PIC_MASTER, &state.pic_master),
            (KVM_IRQCHIP_PIC_SLAVE, &state.pic_slave),
        ] {
            let mut chip = kvm_irqchip {
                chip_id,
                ..Default::default()
            };
            chip.chip.pic = pic.to_kvm();
            fd.set_irqchip(&chip).map_err(kvm_err("KVM_SET_IRQCHIP"))?;
        }

        let mut chip = kvm_irqchip {
            chip_id: KVM_IRQCHIP_IOAPIC,
            ..Default::default()
        };
        chip.chip.ioapic = state.ioapic.to_kvm();
        fd.set_irqchip(&chip).map_err(kvm_err("KVM_SET_IRQCHIP"))?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use crate::hv::backend::kvm::hypervisor::KvmHv;
    use crate::hv::backend::kvm::irqchip::*;
    use crate::hv::hypervisor::Hypervisor;
    use crate::hv::vm::Vm;
    use crate::hv::{Arch, Backend, Error};

    #[test]
    fn test_irqchip_capture_restore() {
        let hv = KvmHv::new().expect("open /dev/kvm");

        // Without in-kernel irqchip there is no state to read.
        let bare = hv.create_vm().expect("guest");
        assert!(
            matches!(bare.get_irqchip_state(), Err(Error::Unsupported(_))),
            "state reported without in-kernel irqchip"
        );

        let vm = hv.create_vm().expect("guest");
        vm.enable_irqchip().expect("in-kernel irqchip");
        let blob = vm.get_irqchip_state().expect("capture");
        assert_eq!(blob.backend, Backend::Kvm);
        assert_eq!(blob.arch, Arch::X86_64);

        let mut text: serde_json::Value =
            serde_json::from_slice(&blob.data).expect("decode the blob as JSON");
        let lines = text["ioapic"]["redirtbl"]
            .as_array()
            .expect("redirection entries");
        // After `kvm_ioapic_reset` the 24 entries read as `LINE_MASKED`, not
        // zero.
        assert_eq!(lines.len(), 24);
        assert!(
            lines.iter().all(|line| *line == LINE_MASKED),
            "line unmasked after reset"
        );
        assert_eq!(
            text["pit"]["channels"].as_array().expect("counters").len(),
            3
        );

        text["pic_master"]["imr"] = serde_json::Value::from(0xab);
        text["ioapic"]["redirtbl"][3] = serde_json::Value::from(LINE_MASKED | 0x35);
        let mut edited = blob.clone();
        edited.data = serde_json::to_vec(&text).expect("re-encode");
        vm.set_irqchip_state(&edited).expect("restore");

        let after = vm.get_irqchip_state().expect("capture");
        let text: serde_json::Value =
            serde_json::from_slice(&after.data).expect("decode the blob as JSON");
        assert_eq!(text["pic_master"]["imr"], serde_json::Value::from(0xab));
        assert_eq!(
            text["ioapic"]["redirtbl"][3],
            serde_json::Value::from(LINE_MASKED | 0x35)
        );

        // Blob of another backend, or another layout version, is refused.
        let mut alien = blob.clone();
        alien.backend = Backend::Mshv;
        assert!(
            vm.set_irqchip_state(&alien).is_err(),
            "blob of another backend accepted"
        );
        let mut newer = blob.clone();
        newer.version += 1;
        assert!(
            vm.set_irqchip_state(&newer).is_err(),
            "unknown layout version accepted"
        );
    }

    #[test]
    fn test_uncovered_lines_restored_masked() {
        let hv = KvmHv::new().expect("open /dev/kvm");
        let vm = hv.create_vm().expect("guest");
        vm.enable_irqchip().expect("in-kernel irqchip");

        let blob = vm.get_irqchip_state().expect("capture");
        let mut text: serde_json::Value =
            serde_json::from_slice(&blob.data).expect("decode the blob as JSON");
        // Empty table stands for a blob without the field, lines it does
        // not cover must be restored as masked.
        text["ioapic"]["redirtbl"] = serde_json::Value::from(Vec::<u64>::new());
        let mut edited = blob.clone();
        edited.data = serde_json::to_vec(&text).expect("re-encode");
        vm.set_irqchip_state(&edited).expect("restore");

        let after = vm.get_irqchip_state().expect("capture");
        let text: serde_json::Value =
            serde_json::from_slice(&after.data).expect("decode the blob as JSON");
        let lines = text["ioapic"]["redirtbl"]
            .as_array()
            .expect("redirection entries");
        assert!(
            lines
                .iter()
                .all(|line| line.as_u64().expect("word") & LINE_MASKED != 0),
            "line not covered by the blob is unmasked: {lines:?}"
        );
    }
}
