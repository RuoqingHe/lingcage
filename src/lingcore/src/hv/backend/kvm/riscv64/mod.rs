// SPDX-FileCopyrightText: 2026 LingCage <opensource@lingcage.com>
//
// SPDX-License-Identifier: Apache-2.0

//! KVM backend parts of a riscv64 guest. The `cfg` is on the
//! declaration in `kvm/mod.rs`. Registers are read and written through
//! `onereg`, which every architecture with one-register ioctls shares.

/// The AIA as a KVM device, and its state blob.
pub(in crate::hv::backend::kvm) mod aia;
/// Serialized guest clock state.
pub(in crate::hv::backend::kvm) mod clock;
/// Legacy line, pulsed through `KVM_IRQ_LINE`.
pub(in crate::hv::backend::kvm) mod irq;
/// Serialized vCPU state.
pub(in crate::hv::backend::kvm) mod state;
/// Exits answered in userspace, and registers read by id.
pub(in crate::hv::backend::kvm) mod vcpu;
/// Harts, the AIA and the clock descriptor of a guest.
pub(in crate::hv::backend::kvm) mod vm;

use kvm_bindings::{
    KVM_REG_RISCV, KVM_REG_RISCV_SUBTYPE_MASK, KVM_REG_RISCV_TYPE_MASK, KVM_REG_SIZE_MASK,
    KVM_REG_SIZE_U64,
};

/// Returns the id of 64-bit register `index` of `kind`, a
/// `KVM_REG_RISCV_*` type with its subtype.
pub(in crate::hv::backend::kvm) const fn reg_id(kind: u32, index: u64) -> u64 {
    KVM_REG_RISCV as u64 | KVM_REG_SIZE_U64 | kind as u64 | index
}

/// Returns type and subtype bits of `id`.
pub(in crate::hv::backend::kvm) fn kind(id: u64) -> u32 {
    (id & u64::from(KVM_REG_RISCV_TYPE_MASK | KVM_REG_RISCV_SUBTYPE_MASK)) as u32
}

/// Returns index of `id` within its kind.
pub(in crate::hv::backend::kvm) fn index(id: u64) -> u64 {
    id & !(KVM_REG_RISCV as u64 | KVM_REG_SIZE_MASK)
        & !u64::from(KVM_REG_RISCV_TYPE_MASK | KVM_REG_RISCV_SUBTYPE_MASK)
}

/// Names of multi-letter extensions, by `KVM_RISCV_ISA_EXT_ID`, spelled
/// the way `riscv,isa` does. Single-letter extension, which is carried
/// by the config register, has no entry here.
const EXTENSIONS: &[(u32, &str)] = &[
    (
        kvm_bindings::KVM_RISCV_ISA_EXT_ID_KVM_RISCV_ISA_EXT_SVPBMT,
        "svpbmt",
    ),
    (
        kvm_bindings::KVM_RISCV_ISA_EXT_ID_KVM_RISCV_ISA_EXT_SSTC,
        "sstc",
    ),
    (
        kvm_bindings::KVM_RISCV_ISA_EXT_ID_KVM_RISCV_ISA_EXT_SVINVAL,
        "svinval",
    ),
    (
        kvm_bindings::KVM_RISCV_ISA_EXT_ID_KVM_RISCV_ISA_EXT_ZIHINTPAUSE,
        "zihintpause",
    ),
    (
        kvm_bindings::KVM_RISCV_ISA_EXT_ID_KVM_RISCV_ISA_EXT_ZICBOM,
        "zicbom",
    ),
    (
        kvm_bindings::KVM_RISCV_ISA_EXT_ID_KVM_RISCV_ISA_EXT_ZICBOZ,
        "zicboz",
    ),
    (
        kvm_bindings::KVM_RISCV_ISA_EXT_ID_KVM_RISCV_ISA_EXT_ZBB,
        "zbb",
    ),
    (
        kvm_bindings::KVM_RISCV_ISA_EXT_ID_KVM_RISCV_ISA_EXT_SSAIA,
        "ssaia",
    ),
    (
        kvm_bindings::KVM_RISCV_ISA_EXT_ID_KVM_RISCV_ISA_EXT_SVNAPOT,
        "svnapot",
    ),
    (
        kvm_bindings::KVM_RISCV_ISA_EXT_ID_KVM_RISCV_ISA_EXT_ZBA,
        "zba",
    ),
    (
        kvm_bindings::KVM_RISCV_ISA_EXT_ID_KVM_RISCV_ISA_EXT_ZBS,
        "zbs",
    ),
    (
        kvm_bindings::KVM_RISCV_ISA_EXT_ID_KVM_RISCV_ISA_EXT_ZICNTR,
        "zicntr",
    ),
    (
        kvm_bindings::KVM_RISCV_ISA_EXT_ID_KVM_RISCV_ISA_EXT_ZICSR,
        "zicsr",
    ),
    (
        kvm_bindings::KVM_RISCV_ISA_EXT_ID_KVM_RISCV_ISA_EXT_ZIFENCEI,
        "zifencei",
    ),
    (
        kvm_bindings::KVM_RISCV_ISA_EXT_ID_KVM_RISCV_ISA_EXT_ZIHPM,
        "zihpm",
    ),
    (
        kvm_bindings::KVM_RISCV_ISA_EXT_ID_KVM_RISCV_ISA_EXT_SMSTATEEN,
        "smstateen",
    ),
    (
        kvm_bindings::KVM_RISCV_ISA_EXT_ID_KVM_RISCV_ISA_EXT_ZICOND,
        "zicond",
    ),
    (
        kvm_bindings::KVM_RISCV_ISA_EXT_ID_KVM_RISCV_ISA_EXT_ZBC,
        "zbc",
    ),
    (
        kvm_bindings::KVM_RISCV_ISA_EXT_ID_KVM_RISCV_ISA_EXT_ZBKB,
        "zbkb",
    ),
    (
        kvm_bindings::KVM_RISCV_ISA_EXT_ID_KVM_RISCV_ISA_EXT_ZBKC,
        "zbkc",
    ),
    (
        kvm_bindings::KVM_RISCV_ISA_EXT_ID_KVM_RISCV_ISA_EXT_ZBKX,
        "zbkx",
    ),
    (
        kvm_bindings::KVM_RISCV_ISA_EXT_ID_KVM_RISCV_ISA_EXT_ZKND,
        "zknd",
    ),
    (
        kvm_bindings::KVM_RISCV_ISA_EXT_ID_KVM_RISCV_ISA_EXT_ZKNE,
        "zkne",
    ),
    (
        kvm_bindings::KVM_RISCV_ISA_EXT_ID_KVM_RISCV_ISA_EXT_ZKNH,
        "zknh",
    ),
    (
        kvm_bindings::KVM_RISCV_ISA_EXT_ID_KVM_RISCV_ISA_EXT_ZKR,
        "zkr",
    ),
    (
        kvm_bindings::KVM_RISCV_ISA_EXT_ID_KVM_RISCV_ISA_EXT_ZKSED,
        "zksed",
    ),
    (
        kvm_bindings::KVM_RISCV_ISA_EXT_ID_KVM_RISCV_ISA_EXT_ZKSH,
        "zksh",
    ),
    (
        kvm_bindings::KVM_RISCV_ISA_EXT_ID_KVM_RISCV_ISA_EXT_ZKT,
        "zkt",
    ),
    (
        kvm_bindings::KVM_RISCV_ISA_EXT_ID_KVM_RISCV_ISA_EXT_ZVBB,
        "zvbb",
    ),
    (
        kvm_bindings::KVM_RISCV_ISA_EXT_ID_KVM_RISCV_ISA_EXT_ZVBC,
        "zvbc",
    ),
    (
        kvm_bindings::KVM_RISCV_ISA_EXT_ID_KVM_RISCV_ISA_EXT_ZVKB,
        "zvkb",
    ),
    (
        kvm_bindings::KVM_RISCV_ISA_EXT_ID_KVM_RISCV_ISA_EXT_ZVKG,
        "zvkg",
    ),
    (
        kvm_bindings::KVM_RISCV_ISA_EXT_ID_KVM_RISCV_ISA_EXT_ZVKNED,
        "zvkned",
    ),
    (
        kvm_bindings::KVM_RISCV_ISA_EXT_ID_KVM_RISCV_ISA_EXT_ZVKNHA,
        "zvknha",
    ),
    (
        kvm_bindings::KVM_RISCV_ISA_EXT_ID_KVM_RISCV_ISA_EXT_ZVKNHB,
        "zvknhb",
    ),
    (
        kvm_bindings::KVM_RISCV_ISA_EXT_ID_KVM_RISCV_ISA_EXT_ZVKSED,
        "zvksed",
    ),
    (
        kvm_bindings::KVM_RISCV_ISA_EXT_ID_KVM_RISCV_ISA_EXT_ZVKSH,
        "zvksh",
    ),
    (
        kvm_bindings::KVM_RISCV_ISA_EXT_ID_KVM_RISCV_ISA_EXT_ZVKT,
        "zvkt",
    ),
    (
        kvm_bindings::KVM_RISCV_ISA_EXT_ID_KVM_RISCV_ISA_EXT_ZFH,
        "zfh",
    ),
    (
        kvm_bindings::KVM_RISCV_ISA_EXT_ID_KVM_RISCV_ISA_EXT_ZFHMIN,
        "zfhmin",
    ),
    (
        kvm_bindings::KVM_RISCV_ISA_EXT_ID_KVM_RISCV_ISA_EXT_ZIHINTNTL,
        "zihintntl",
    ),
    (
        kvm_bindings::KVM_RISCV_ISA_EXT_ID_KVM_RISCV_ISA_EXT_ZVFH,
        "zvfh",
    ),
    (
        kvm_bindings::KVM_RISCV_ISA_EXT_ID_KVM_RISCV_ISA_EXT_ZVFHMIN,
        "zvfhmin",
    ),
    (
        kvm_bindings::KVM_RISCV_ISA_EXT_ID_KVM_RISCV_ISA_EXT_ZFA,
        "zfa",
    ),
    (
        kvm_bindings::KVM_RISCV_ISA_EXT_ID_KVM_RISCV_ISA_EXT_ZTSO,
        "ztso",
    ),
    (
        kvm_bindings::KVM_RISCV_ISA_EXT_ID_KVM_RISCV_ISA_EXT_ZACAS,
        "zacas",
    ),
    (
        kvm_bindings::KVM_RISCV_ISA_EXT_ID_KVM_RISCV_ISA_EXT_SSCOFPMF,
        "sscofpmf",
    ),
    (
        kvm_bindings::KVM_RISCV_ISA_EXT_ID_KVM_RISCV_ISA_EXT_ZIMOP,
        "zimop",
    ),
    (
        kvm_bindings::KVM_RISCV_ISA_EXT_ID_KVM_RISCV_ISA_EXT_ZCA,
        "zca",
    ),
    (
        kvm_bindings::KVM_RISCV_ISA_EXT_ID_KVM_RISCV_ISA_EXT_ZCB,
        "zcb",
    ),
    (
        kvm_bindings::KVM_RISCV_ISA_EXT_ID_KVM_RISCV_ISA_EXT_ZCD,
        "zcd",
    ),
    (
        kvm_bindings::KVM_RISCV_ISA_EXT_ID_KVM_RISCV_ISA_EXT_ZCF,
        "zcf",
    ),
    (
        kvm_bindings::KVM_RISCV_ISA_EXT_ID_KVM_RISCV_ISA_EXT_ZCMOP,
        "zcmop",
    ),
    (
        kvm_bindings::KVM_RISCV_ISA_EXT_ID_KVM_RISCV_ISA_EXT_ZAWRS,
        "zawrs",
    ),
    (
        kvm_bindings::KVM_RISCV_ISA_EXT_ID_KVM_RISCV_ISA_EXT_SMNPM,
        "smnpm",
    ),
    (
        kvm_bindings::KVM_RISCV_ISA_EXT_ID_KVM_RISCV_ISA_EXT_SSNPM,
        "ssnpm",
    ),
    (
        kvm_bindings::KVM_RISCV_ISA_EXT_ID_KVM_RISCV_ISA_EXT_SVADE,
        "svade",
    ),
    (
        kvm_bindings::KVM_RISCV_ISA_EXT_ID_KVM_RISCV_ISA_EXT_SVADU,
        "svadu",
    ),
    (
        kvm_bindings::KVM_RISCV_ISA_EXT_ID_KVM_RISCV_ISA_EXT_SVVPTC,
        "svvptc",
    ),
    (
        kvm_bindings::KVM_RISCV_ISA_EXT_ID_KVM_RISCV_ISA_EXT_ZABHA,
        "zabha",
    ),
    (
        kvm_bindings::KVM_RISCV_ISA_EXT_ID_KVM_RISCV_ISA_EXT_ZICCRSE,
        "ziccrse",
    ),
    (
        kvm_bindings::KVM_RISCV_ISA_EXT_ID_KVM_RISCV_ISA_EXT_ZAAMO,
        "zaamo",
    ),
    (
        kvm_bindings::KVM_RISCV_ISA_EXT_ID_KVM_RISCV_ISA_EXT_ZALRSC,
        "zalrsc",
    ),
];

/// Returns name of the multi-letter extension numbered `id` by KVM, or
/// `None` for a single-letter one and for an id not named by this build.
pub(in crate::hv::backend::kvm) fn extension_name(id: u64) -> Option<&'static str> {
    EXTENSIONS
        .iter()
        .find(|(number, _)| u64::from(*number) == id)
        .map(|(_, name)| *name)
}

#[cfg(test)]
mod tests {
    use kvm_bindings::{KVM_REG_RISCV_CORE, KVM_REG_RISCV_CSR, KVM_REG_RISCV_CSR_AIA};

    use crate::hv::backend::kvm::onereg::width;
    use crate::hv::backend::kvm::riscv64::*;

    #[test]
    fn test_reg_id_round_trip() {
        let id = reg_id(KVM_REG_RISCV_CORE, 10);
        assert_eq!(kind(id), KVM_REG_RISCV_CORE);
        assert_eq!(index(id), 10);
        assert_eq!(width(id), 8);

        // Subtype goes together with the type.
        let id = reg_id(KVM_REG_RISCV_CSR | KVM_REG_RISCV_CSR_AIA, 2);
        assert_eq!(kind(id), KVM_REG_RISCV_CSR | KVM_REG_RISCV_CSR_AIA);
        assert_eq!(index(id), 2);
    }

    #[test]
    fn test_extension_name() {
        assert_eq!(extension_name(14), Some("ssaia"));
        // `d` is a single-letter extension.
        assert_eq!(extension_name(2), None);
        assert_eq!(extension_name(1 << 20), None);
    }
}
