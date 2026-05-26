// SPDX-FileCopyrightText: 2026 LingCage <opensource@lingcage.com>
//
// SPDX-License-Identifier: Apache-2.0

//! The AIA as a `KVM_DEV_TYPE_RISCV_AIA` device. Its `StateBlob` holds
//! APLIC registers and IMSIC file of each hart.

use kvm_bindings::{
    KVM_DEV_RISCV_AIA_ADDR_APLIC, KVM_DEV_RISCV_AIA_CONFIG_HART_BITS, KVM_DEV_RISCV_AIA_CONFIG_IDS,
    KVM_DEV_RISCV_AIA_CONFIG_SRCS, KVM_DEV_RISCV_AIA_CTRL_INIT, KVM_DEV_RISCV_AIA_GRP_ADDR,
    KVM_DEV_RISCV_AIA_GRP_APLIC, KVM_DEV_RISCV_AIA_GRP_CONFIG, KVM_DEV_RISCV_AIA_GRP_CTRL,
    KVM_DEV_RISCV_AIA_GRP_IMSIC, KVM_DEV_RISCV_AIA_IMSIC_ISEL_BITS, kvm_create_device,
    kvm_device_attr, kvm_device_type_KVM_DEV_TYPE_RISCV_AIA,
};
use kvm_ioctls::{DeviceFd, VmFd};

use crate::hv::arch::{Aia, IMSIC_SIZE, hart_index_bits};
use crate::hv::backend::kvm::kvm_err;
use crate::hv::{Arch, Backend, Error, Result, StateBlob};

/// Layout version of `StateBlob::data`, `restore` refuses others.
const STATE_VERSION: u32 = 1;

/// APLIC register offsets, from `include/linux/irqchip/riscv-aplic.h`.
/// `SOURCECFG_BASE` and `TARGET_BASE` are of source 1. Bitmaps hold one
/// bit per source starting from source 0.
const DOMAINCFG: u64 = 0x0000;
const SOURCECFG_BASE: u64 = 0x0004;
const SETIP_BASE: u64 = 0x1c00;
const IN_CLRIP_BASE: u64 = 0x1d00;
const SETIE_BASE: u64 = 0x1e00;
const CLRIE_BASE: u64 = 0x1f00;
const TARGET_BASE: u64 = 0x3004;

/// IMSIC register selectors, from `include/linux/irqchip/riscv-imsic.h`.
/// On rv64 `eip` and `eie` are 64 bits wide, and only every other
/// selector from the first one is valid.
const EIDELIVERY: u64 = 0x70;
const EITHRESHOLD: u64 = 0x72;
const EIP0: u64 = 0x80;
const EIE0: u64 = 0xc0;

/// APLIC state as serialized in a blob. `sourcecfg` and `target` start
/// from source 1. `enabled` and `pending` are the bitmaps, one bit per
/// source starting from source 0.
#[derive(Default, serde::Serialize, serde::Deserialize)]
#[serde(default)]
struct AplicState {
    domaincfg: u32,
    sourcecfg: Vec<u32>,
    target: Vec<u32>,
    enabled: Vec<u32>,
    pending: Vec<u32>,
}

/// One IMSIC file as serialized in a blob. `pending` and `enabled` are
/// `eip0`, `eip2` and so on, 64 identities each.
#[derive(Default, serde::Serialize, serde::Deserialize)]
#[serde(default)]
struct ImsicState {
    eidelivery: u64,
    eithreshold: u64,
    pending: Vec<u64>,
    enabled: Vec<u64>,
}

/// Interrupt controller state as captured in a blob, the APLIC and the
/// IMSIC file of each hart. Field missing from a blob takes its default.
#[derive(Default, serde::Serialize, serde::Deserialize)]
#[serde(default)]
struct IrqChipState {
    aplic: AplicState,
    imsics: Vec<ImsicState>,
}

/// AIA of one guest, its device fd and the shape it was created with.
pub(in crate::hv::backend::kvm) struct KvmAia {
    device: DeviceFd,
    harts: u32,
    sources: u32,
    ids: u32,
}

impl KvmAia {
    /// Create and initialize the AIA of `vm` placed at `aia` for `harts`
    /// vCPUs, which should exist already, since the init refuses one still
    /// being created.
    pub(in crate::hv::backend::kvm) fn new(vm: &VmFd, aia: &Aia, harts: u32) -> Result<Self> {
        let mut request = kvm_create_device {
            type_: kvm_device_type_KVM_DEV_TYPE_RISCV_AIA,
            fd: 0,
            flags: 0,
        };
        let device = vm
            .create_device(&mut request)
            .map_err(kvm_err("KVM_CREATE_DEVICE"))?;
        let made = KvmAia {
            device,
            harts,
            sources: aia.sources,
            ids: aia.ids,
        };
        made.set(
            KVM_DEV_RISCV_AIA_GRP_CONFIG,
            u64::from(KVM_DEV_RISCV_AIA_CONFIG_SRCS),
            &aia.sources,
        )?;
        made.set(
            KVM_DEV_RISCV_AIA_GRP_CONFIG,
            u64::from(KVM_DEV_RISCV_AIA_CONFIG_IDS),
            &aia.ids,
        )?;
        made.set(
            KVM_DEV_RISCV_AIA_GRP_CONFIG,
            u64::from(KVM_DEV_RISCV_AIA_CONFIG_HART_BITS),
            &hart_index_bits(harts),
        )?;
        made.set(
            KVM_DEV_RISCV_AIA_GRP_ADDR,
            u64::from(KVM_DEV_RISCV_AIA_ADDR_APLIC),
            &aia.aplic,
        )?;
        // `KVM_DEV_RISCV_AIA_ADDR_IMSIC(n)` is `1 + n`.
        for hart in 0..harts {
            made.set(
                KVM_DEV_RISCV_AIA_GRP_ADDR,
                u64::from(1 + hart),
                &(aia.imsic + u64::from(hart) * IMSIC_SIZE),
            )?;
        }
        made.set(
            KVM_DEV_RISCV_AIA_GRP_CTRL,
            u64::from(KVM_DEV_RISCV_AIA_CTRL_INIT),
            &0u32,
        )?;
        Ok(made)
    }

    /// Write `value` to attribute `attr` of `group`. KVM reads the value at
    /// the width taken by the attribute, `u32` for config, `u64` for
    /// address, `unsigned long` for IMSIC register.
    fn set<T>(&self, group: u32, attr: u64, value: &T) -> Result<()> {
        let request = kvm_device_attr {
            group,
            attr,
            addr: std::ptr::from_ref(value) as u64,
            flags: 0,
        };
        self.device
            .set_device_attr(&request)
            .map_err(kvm_err("KVM_SET_DEVICE_ATTR"))
    }

    /// Read attribute `attr` of `group` into `value`.
    fn get<T>(&self, group: u32, attr: u64, value: &mut T) -> Result<()> {
        let mut request = kvm_device_attr {
            group,
            attr,
            addr: std::ptr::from_mut(value) as u64,
            flags: 0,
        };
        // SAFETY: `addr` points at `value`, which is as wide as the
        // attribute and outlives the call.
        unsafe { self.device.get_device_attr(&mut request) }.map_err(kvm_err("KVM_GET_DEVICE_ATTR"))
    }

    /// Read the APLIC register at `offset`.
    fn aplic_read(&self, offset: u64) -> Result<u32> {
        let mut value = 0u32;
        self.get(KVM_DEV_RISCV_AIA_GRP_APLIC, offset, &mut value)?;
        Ok(value)
    }

    /// Write `value` to the APLIC register at `offset`.
    fn aplic_write(&self, offset: u64, value: u32) -> Result<()> {
        self.set(KVM_DEV_RISCV_AIA_GRP_APLIC, offset, &value)
    }

    /// Returns the attribute of register `isel` in the file of hart `hart`.
    fn imsic_attr(hart: u32, isel: u64) -> u64 {
        u64::from(hart) << KVM_DEV_RISCV_AIA_IMSIC_ISEL_BITS | isel
    }

    /// Read register `isel` of the IMSIC file of hart `hart`.
    fn imsic_read(&self, hart: u32, isel: u64) -> Result<u64> {
        let mut value = 0u64;
        self.get(
            KVM_DEV_RISCV_AIA_GRP_IMSIC,
            KvmAia::imsic_attr(hart, isel),
            &mut value,
        )?;
        Ok(value)
    }

    /// Write `value` to register `isel` of the IMSIC file of hart `hart`.
    fn imsic_write(&self, hart: u32, isel: u64, value: u64) -> Result<()> {
        self.set(
            KVM_DEV_RISCV_AIA_GRP_IMSIC,
            KvmAia::imsic_attr(hart, isel),
            &value,
        )
    }

    /// Returns the number of 32-bit words a source bitmap takes, source 0
    /// included.
    fn words(&self) -> u64 {
        u64::from((self.sources + 1).div_ceil(32))
    }

    /// Returns the number of 64-bit `eip` or `eie` registers a file takes,
    /// identity 0 included.
    fn files(&self) -> u64 {
        u64::from((self.ids + 1).div_ceil(64))
    }

    /// Capture the controller state as a `StateBlob`.
    pub(in crate::hv::backend::kvm) fn capture(&self) -> Result<StateBlob> {
        let mut aplic = AplicState {
            domaincfg: self.aplic_read(DOMAINCFG)?,
            ..Default::default()
        };
        for source in 0..u64::from(self.sources) {
            aplic
                .sourcecfg
                .push(self.aplic_read(SOURCECFG_BASE + source * 4)?);
            aplic
                .target
                .push(self.aplic_read(TARGET_BASE + source * 4)?);
        }
        for word in 0..self.words() {
            aplic.enabled.push(self.aplic_read(SETIE_BASE + word * 4)?);
            aplic.pending.push(self.aplic_read(SETIP_BASE + word * 4)?);
        }
        let mut imsics = Vec::with_capacity(self.harts as usize);
        for hart in 0..self.harts {
            let mut file = ImsicState {
                eidelivery: self.imsic_read(hart, EIDELIVERY)?,
                eithreshold: self.imsic_read(hart, EITHRESHOLD)?,
                ..Default::default()
            };
            for index in 0..self.files() {
                file.pending.push(self.imsic_read(hart, EIP0 + index * 2)?);
                file.enabled.push(self.imsic_read(hart, EIE0 + index * 2)?);
            }
            imsics.push(file);
        }
        let state = IrqChipState { aplic, imsics };
        let data = serde_json::to_vec(&state).map_err(|_| Error::Capture { part: "controller" })?;
        Ok(StateBlob {
            backend: Backend::Kvm,
            arch: Arch::Riscv64,
            version: STATE_VERSION,
            data,
        })
    }

    /// Restore `blob` into the controller. Blob of another backend, arch or
    /// layout version is refused. `domaincfg` is written last, so that a
    /// source restored as pending and enabled is only delivered once.
    pub(in crate::hv::backend::kvm) fn restore(&self, blob: &StateBlob) -> Result<()> {
        if blob.backend != Backend::Kvm || blob.arch != Arch::Riscv64 {
            return Err(Error::Restore { part: "controller" });
        }
        if blob.version != STATE_VERSION {
            return Err(Error::Restore { part: "controller" });
        }
        let state: IrqChipState = serde_json::from_slice(&blob.data)
            .map_err(|_| Error::Restore { part: "controller" })?;

        self.aplic_write(DOMAINCFG, 0)?;
        let sources = self.sources as usize;
        for (source, &cfg) in state.aplic.sourcecfg.iter().take(sources).enumerate() {
            self.aplic_write(SOURCECFG_BASE + source as u64 * 4, cfg)?;
        }
        for (source, &target) in state.aplic.target.iter().take(sources).enumerate() {
            self.aplic_write(TARGET_BASE + source as u64 * 4, target)?;
        }
        // Bit written to the clear registers clears it, and the set
        // registers set it. Bitmaps are cleared entirely first, so a word
        // missing from the blob is restored as empty.
        for word in 0..self.words() {
            self.aplic_write(IN_CLRIP_BASE + word * 4, u32::MAX)?;
            self.aplic_write(CLRIE_BASE + word * 4, u32::MAX)?;
        }
        let words = self.words() as usize;
        for (word, &bits) in state.aplic.enabled.iter().take(words).enumerate() {
            self.aplic_write(SETIE_BASE + word as u64 * 4, bits)?;
        }
        for (word, &bits) in state.aplic.pending.iter().take(words).enumerate() {
            self.aplic_write(SETIP_BASE + word as u64 * 4, bits)?;
        }

        let files = self.files() as usize;
        for (hart, file) in (0..self.harts).zip(&state.imsics) {
            self.imsic_write(hart, EIDELIVERY, file.eidelivery)?;
            self.imsic_write(hart, EITHRESHOLD, file.eithreshold)?;
            for (index, &bits) in file.enabled.iter().take(files).enumerate() {
                self.imsic_write(hart, EIE0 + index as u64 * 2, bits)?;
            }
            for (index, &bits) in file.pending.iter().take(files).enumerate() {
                self.imsic_write(hart, EIP0 + index as u64 * 2, bits)?;
            }
        }
        self.aplic_write(DOMAINCFG, state.aplic.domaincfg)
    }
}

#[cfg(test)]
mod tests {
    use crate::hv::arch::Aia;
    use crate::hv::backend::kvm::hypervisor::KvmHv;
    use crate::hv::hypervisor::Hypervisor;
    use crate::hv::vm::Vm;
    use crate::hv::{Arch, Backend, Error};

    /// An AIA placed the same way the machine places it.
    const AIA: Aia = Aia {
        aplic: 0x0040_0000,
        imsic: 0x0400_0000,
        sources: 31,
        ids: 63,
    };

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
        let _cpu0 = vm.create_vcpu(0).expect("vcpu 0");
        let _cpu1 = vm.create_vcpu(1).expect("vcpu 1");
        vm.enable_in_kernel_irqchip(&AIA)
            .expect("in-kernel irqchip");
        let blob = vm.get_irqchip_state().expect("capture");
        assert_eq!(blob.backend, Backend::Kvm);
        assert_eq!(blob.arch, Arch::Riscv64);

        let mut text: serde_json::Value =
            serde_json::from_slice(&blob.data).expect("decode the blob as JSON");
        assert_eq!(
            text["aplic"]["sourcecfg"]
                .as_array()
                .expect("sources")
                .len(),
            31
        );
        assert_eq!(text["imsics"].as_array().expect("files").len(), 2);

        // Source 3 is level triggered and aimed at hart 1, identity 5.
        // Delivery on, and the identity enabled in file of hart 1.
        text["aplic"]["sourcecfg"][2] = serde_json::Value::from(6);
        text["aplic"]["target"][2] = serde_json::Value::from((1u32 << 18) | 5);
        text["aplic"]["enabled"][0] = serde_json::Value::from(1u32 << 3);
        text["aplic"]["domaincfg"] = serde_json::Value::from(1u32 << 8);
        text["imsics"][1]["eidelivery"] = serde_json::Value::from(1);
        text["imsics"][1]["enabled"][0] = serde_json::Value::from(1u64 << 5);
        let mut edited = blob.clone();
        edited.data = serde_json::to_vec(&text).expect("re-encode");
        vm.set_irqchip_state(&edited).expect("restore");

        let after = vm.get_irqchip_state().expect("capture");
        let text: serde_json::Value =
            serde_json::from_slice(&after.data).expect("decode the blob as JSON");
        assert_eq!(text["aplic"]["sourcecfg"][2], serde_json::Value::from(6));
        assert_eq!(
            text["aplic"]["target"][2],
            serde_json::Value::from((1u32 << 18) | 5)
        );
        assert_eq!(
            text["aplic"]["enabled"][0].as_u64().expect("word") & (1 << 3),
            1 << 3,
            "source 3 is not enabled"
        );
        assert_eq!(
            text["aplic"]["domaincfg"].as_u64().expect("domaincfg") & (1 << 8),
            1 << 8,
            "delivery is off"
        );
        assert_eq!(text["imsics"][1]["eidelivery"], serde_json::Value::from(1));
        assert_eq!(
            text["imsics"][1]["enabled"][0],
            serde_json::Value::from(1u64 << 5)
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
}
