// SPDX-FileCopyrightText: 2026 LingCage <opensource@lingcage.com>
//
// SPDX-License-Identifier: Apache-2.0

//! CPUID leaves of one vCPU.
//!
//! Leaves returned by `Hypervisor::supported_cpuid` are the ones of the
//! host, APIC ID fields included. Guest kernel compares the ID in CPUID
//! with the one reported by its local APIC and logs `APIC ID mismatch`
//! as a firmware bug, so the fields are set to the vCPU index.

use crate::hv::arch::CpuidEntry;

/// Leaf 1, EBX bits 31:24 hold the initial APIC ID.
const FEATURES: u32 = 0x1;

/// Leaf 0xB, extended topology, EDX holds the x2APIC ID.
const TOPOLOGY: u32 = 0xb;

/// Leaf 0x1F, V2 extended topology, read before leaf 0xB when present,
/// EDX holds the x2APIC ID.
const TOPOLOGY_V2: u32 = 0x1f;

/// Leaf 0x8000001E, AMD extended APIC ID in EAX.
const AMD_IDENTITY: u32 = 0x8000_001e;

/// Bit offset of the 8-bit initial APIC ID in leaf 1 EBX.
const INITIAL_APIC_ID: u32 = 24;

/// Leaf 1 ECX bit 31, the hypervisor present bit. `supported_cpuid`
/// leaves it clear since KVM counts it as emulated, and guest kernel
/// only probes the hypervisor leaves at 0x4000_0000 with it set.
const HYPERVISOR_PRESENT: u32 = 1 << 31;

/// Returns leaves of `host` with the APIC ID fields set to `index`, the
/// low byte in leaf 1 and the full value in leaves 0xB, 0x1F and
/// 0x8000001E, and with `HYPERVISOR_PRESENT` set in leaf 1 ECX. Other
/// fields and leaves are unchanged.
pub fn for_vcpu(host: &[CpuidEntry], index: u16) -> Vec<CpuidEntry> {
    let id = u32::from(index);
    host.iter()
        .copied()
        .map(|mut leaf| {
            match leaf.function {
                FEATURES => {
                    leaf.ebx = (leaf.ebx & 0x00ff_ffff) | ((id & 0xff) << INITIAL_APIC_ID);
                    leaf.ecx |= HYPERVISOR_PRESENT;
                }
                TOPOLOGY | TOPOLOGY_V2 => leaf.edx = id,
                AMD_IDENTITY => leaf.eax = id,
                _ => {}
            }
            leaf
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use crate::machine::x86_64::cpuid::*;

    /// Host leaves carrying APIC ID 3, fixed so that the test does not
    /// depend on the machine it runs on.
    fn host() -> Vec<CpuidEntry> {
        vec![
            CpuidEntry {
                function: FEATURES,
                ebx: 0x0308_0800,
                ecx: 0x76f8_3203,
                edx: 0x078b_fbff,
                ..Default::default()
            },
            CpuidEntry {
                function: TOPOLOGY,
                index: Some(0),
                edx: 3,
                ..Default::default()
            },
            CpuidEntry {
                function: AMD_IDENTITY,
                eax: 3,
                ..Default::default()
            },
            CpuidEntry {
                function: 0x8000_0008,
                eax: 0x0000_3030,
                ..Default::default()
            },
        ]
    }

    #[test]
    fn test_apic_id_set_per_vcpu() {
        let leaves = for_vcpu(&host(), 1);

        let features = leaves
            .iter()
            .find(|l| l.function == FEATURES)
            .expect("leaf");
        assert_eq!(
            features.ebx >> INITIAL_APIC_ID,
            1,
            "leaf 1 EBX still carries APIC ID of the host"
        );
        // Bits 23:0 of EBX stay as the host.
        assert_eq!(features.ebx & 0x00ff_ffff, 0x0008_0800);
        assert_eq!(
            features.ecx,
            0x76f8_3203 | HYPERVISOR_PRESENT,
            "feature bit moved or hypervisor bit is clear"
        );
        assert_eq!({ features.edx }, 0x078b_fbff, "feature bit moved");

        let topology = leaves
            .iter()
            .find(|l| l.function == TOPOLOGY)
            .expect("leaf");
        assert_eq!({ topology.edx }, 1, "leaf 0xB EDX carries ID of the host");

        let amd = leaves
            .iter()
            .find(|l| l.function == AMD_IDENTITY)
            .expect("leaf");
        assert_eq!({ amd.eax }, 1);

        assert_eq!(leaves.len(), 4);
        let other = leaves
            .iter()
            .find(|l| l.function == 0x8000_0008)
            .expect("leaf");
        assert_eq!({ other.eax }, 0x0000_3030, "unrelated leaf changed");
    }

    #[test]
    fn test_hypervisor_present_bit() {
        let leaves = for_vcpu(&host(), 0);
        let features = leaves
            .iter()
            .find(|l| l.function == FEATURES)
            .expect("leaf");

        assert_eq!(
            features.ecx & HYPERVISOR_PRESENT,
            HYPERVISOR_PRESENT,
            "hypervisor bit is clear"
        );
        // Other ECX bits stay as the host.
        assert_eq!(
            features.ecx & !HYPERVISOR_PRESENT,
            0x76f8_3203,
            "host feature bit cleared"
        );
    }

    #[test]
    fn test_no_leaf_added() {
        // Leaf 0x8000001E is from AMD, a host without it must not gain
        // one.
        let short: Vec<CpuidEntry> = host()
            .into_iter()
            .filter(|leaf| leaf.function != AMD_IDENTITY)
            .collect();

        let leaves = for_vcpu(&short, 2);
        assert_eq!(leaves.len(), short.len(), "leaf count changed");
        assert!(
            !leaves.iter().any(|leaf| leaf.function == AMD_IDENTITY),
            "leaf 0x8000001E was added"
        );
        for leaf in &leaves {
            match leaf.function {
                FEATURES => assert_eq!(leaf.ebx >> INITIAL_APIC_ID, 2),
                TOPOLOGY | TOPOLOGY_V2 => assert_eq!({ leaf.edx }, 2),
                _ => {}
            }
        }
    }

    #[test]
    fn test_vcpu_zero_reads_zero() {
        let leaves = for_vcpu(&host(), 0);
        for leaf in &leaves {
            match leaf.function {
                FEATURES => assert_eq!(leaf.ebx >> INITIAL_APIC_ID, 0),
                TOPOLOGY => assert_eq!({ leaf.edx }, 0),
                AMD_IDENTITY => assert_eq!({ leaf.eax }, 0),
                _ => {}
            }
        }
    }
}
