// SPDX-FileCopyrightText: 2026 LingCage <opensource@lingcage.com>
//
// SPDX-License-Identifier: Apache-2.0

//! Intel MP table. The processors, the I/O APIC and its lines, for a
//! kernel booted without firmware to describe them.
//!
//! Without it the kernel runs one CPU in virtual wire mode and leaves
//! the I/O APIC unused. Floating pointer is written at 0x9fc00, the top
//! kilobyte of base RAM, one of the ranges scanned by
//! `mpparse_find_mptable`.

use crate::machine::{Error, Result};
use crate::mem::GuestRam;

/// Address of the floating pointer, top kilobyte of base RAM.
const TABLE: u64 = 0x9_fc00;

/// Size of the scanned kilobyte, pointer and table fit inside it.
const ROOM: u64 = 0x400;

/// Floating pointer signature.
const POINTER_SIGNATURE: [u8; 4] = *b"_MP_";

/// Configuration table signature.
const CONFIG_SIGNATURE: [u8; 4] = *b"PCMP";

/// MP specification revision 1.4.
const REVISION: u8 = 4;

/// Floating pointer length in 16-byte paragraphs.
const POINTER_PARAGRAPHS: u8 = 1;

/// Floating pointer length in bytes.
const POINTER_BYTES: u64 = 16;

/// Local APIC base address.
const LOCAL_APIC: u32 = 0xfee0_0000;

/// I/O APIC base address.
const IO_APIC: u32 = 0xfec0_0000;

/// APIC version 0x14, reported for both local and I/O APIC.
const APIC_VERSION: u8 = 0x14;

/// Entry types, in the order listed by the specification.
const PROCESSOR: u8 = 0;
const BUS: u8 = 1;
const IO_APIC_ENTRY: u8 = 2;
const INTERRUPT: u8 = 3;
const LOCAL_INTERRUPT: u8 = 4;

/// Processor flag, enabled.
const CPU_ENABLED: u8 = 1;
/// Processor flag, the bootstrap processor.
const CPU_BOOTSTRAP: u8 = 2;

/// Interrupt type INT, vectored through the APIC.
const DELIVERY_VECTORED: u8 = 0;
/// Interrupt type NMI.
const DELIVERY_NMI: u8 = 1;
/// Interrupt type ExtINT, delivered by the 8259.
const DELIVERY_EXTERNAL: u8 = 3;

/// I/O APIC input pins.
const LINES: u8 = 24;

/// Bus type, padded to six bytes.
const BUS_KIND: [u8; 6] = *b"ISA   ";

/// Bus id of the only ISA bus.
const BUS_ID: u8 = 0;

/// Local APIC inputs, LINT0 for ExtINT and LINT1 for NMI.
const LINT_EXTERNAL: u8 = 0;
const LINT_NMI: u8 = 1;

/// Destination APIC id which addresses all processors.
const ANY_PROCESSOR: u8 = 0xff;

/// Returns the byte which makes `bytes` sum to zero modulo 256.
fn checksum(bytes: &[u8]) -> u8 {
    let sum = bytes.iter().fold(0u8, |sum, byte| sum.wrapping_add(*byte));
    (!sum).wrapping_add(1)
}

/// Returns entries for `vcpus` processors in specification order,
/// together with their count.
fn entries(vcpus: u16, io_apic_id: u8) -> (Vec<u8>, u16) {
    let mut bytes = Vec::new();
    let mut count = 0u16;

    for cpu in 0..vcpus {
        let flags = if cpu == 0 {
            CPU_ENABLED | CPU_BOOTSTRAP
        } else {
            CPU_ENABLED
        };
        bytes.extend_from_slice(&[PROCESSOR, cpu as u8, APIC_VERSION, flags]);
        // CPU signature and feature flags, left zero.
        bytes.extend_from_slice(&0u32.to_le_bytes());
        bytes.extend_from_slice(&0u32.to_le_bytes());
        bytes.extend_from_slice(&[0; 8]);
        count += 1;
    }

    bytes.extend_from_slice(&[BUS, BUS_ID]);
    bytes.extend_from_slice(&BUS_KIND);
    count += 1;

    bytes.extend_from_slice(&[IO_APIC_ENTRY, io_apic_id, APIC_VERSION, CPU_ENABLED]);
    bytes.extend_from_slice(&IO_APIC.to_le_bytes());
    count += 1;

    // ISA IRQ n is routed to I/O APIC pin n.
    for line in 0..LINES {
        bytes.extend_from_slice(&[INTERRUPT, DELIVERY_VECTORED]);
        bytes.extend_from_slice(&0u16.to_le_bytes());
        bytes.extend_from_slice(&[BUS_ID, line, io_apic_id, line]);
        count += 1;
    }

    // LINT0 takes ExtINT and LINT1 takes NMI, on all processors.
    for (delivery, lint) in [(DELIVERY_EXTERNAL, LINT_EXTERNAL), (DELIVERY_NMI, LINT_NMI)] {
        bytes.extend_from_slice(&[LOCAL_INTERRUPT, delivery]);
        bytes.extend_from_slice(&0u16.to_le_bytes());
        bytes.extend_from_slice(&[BUS_ID, 0, ANY_PROCESSOR, lint]);
        count += 1;
    }

    (bytes, count)
}

/// Write the MP table for `vcpus` processors to `ram`.
pub fn write(ram: &GuestRam, vcpus: u16) -> Result<()> {
    // APIC ids are one range, so the I/O APIC takes the id after the
    // last processor.
    let io_apic_id = vcpus as u8;
    let (entries, count) = entries(vcpus, io_apic_id);

    let config = TABLE + POINTER_BYTES;
    let mut pointer = Vec::with_capacity(POINTER_BYTES as usize);
    pointer.extend_from_slice(&POINTER_SIGNATURE);
    pointer.extend_from_slice(&(config as u32).to_le_bytes());
    pointer.extend_from_slice(&[POINTER_PARAGRAPHS, REVISION, 0]);
    pointer.extend_from_slice(&[0; 5]);
    let sum = checksum(&pointer);
    pointer[10] = sum;

    let length = 44 + entries.len();
    let mut header = Vec::with_capacity(length);
    header.extend_from_slice(&CONFIG_SIGNATURE);
    header.extend_from_slice(&(length as u16).to_le_bytes());
    header.extend_from_slice(&[REVISION, 0]);
    header.extend_from_slice(b"LINGCAGE");
    header.extend_from_slice(b"LINGCORE\0\0\0\0");
    header.extend_from_slice(&0u32.to_le_bytes());
    header.extend_from_slice(&0u16.to_le_bytes());
    header.extend_from_slice(&count.to_le_bytes());
    header.extend_from_slice(&LOCAL_APIC.to_le_bytes());
    header.extend_from_slice(&0u32.to_le_bytes());
    header.extend_from_slice(&entries);
    let sum = checksum(&header);
    header[7] = sum;

    if POINTER_BYTES + header.len() as u64 > ROOM {
        return Err(Error::NoRoomForMpTable);
    }
    ram.write(TABLE, &pointer)?;
    ram.write(config, &header)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use crate::machine::mptable::*;

    /// Read back the floating pointer and the configuration table.
    fn read(vcpus: u16) -> (Vec<u8>, Vec<u8>) {
        let ram = GuestRam::new(&[(0, 1 << 20)]).expect("host pages");
        write(&ram, vcpus).expect("write the table");

        let mut pointer = vec![0u8; POINTER_BYTES as usize];
        ram.read(TABLE, &mut pointer).expect("read pointer");

        let at = u32::from_le_bytes(pointer[4..8].try_into().expect("four bytes"));
        let mut length = [0u8; 2];
        ram.read(u64::from(at) + 4, &mut length).expect("read");
        let mut config = vec![0u8; u16::from_le_bytes(length) as usize];
        ram.read(u64::from(at), &mut config).expect("read table");
        (pointer, config)
    }

    /// The check applied by `mpf_checksum`, bytes sum to zero.
    fn sums_to_zero(bytes: &[u8]) -> bool {
        bytes.iter().fold(0u8, |sum, byte| sum.wrapping_add(*byte)) == 0
    }

    #[test]
    fn test_checksums() {
        let (pointer, config) = read(1);

        // The scan skips a pointer with bad checksum, a table with one is
        // dropped with `MPTABLE: checksum error!`.
        assert_eq!(&pointer[..4], &POINTER_SIGNATURE, "bad pointer signature");
        assert!(sums_to_zero(&pointer), "bad pointer checksum");
        assert_eq!(&config[..4], &CONFIG_SIGNATURE, "table signature is bad");
        assert!(sums_to_zero(&config), "bad table checksum");
    }

    #[test]
    fn test_processor_and_ioapic_entries() {
        let (_, config) = read(2);

        let count = u16::from_le_bytes(config[34..36].try_into().expect("two bytes"));
        let mut kinds = Vec::new();
        let mut at = 44;
        for _ in 0..count {
            let kind = config[at];
            kinds.push(kind);
            // Processor entry is 20 bytes, other kinds are 8.
            at += if kind == PROCESSOR { 20 } else { 8 };
        }
        assert_eq!(at, config.len(), "count and entries disagree");

        assert_eq!(
            kinds.iter().filter(|k| **k == PROCESSOR).count(),
            2,
            "processor count is wrong"
        );
        assert_eq!(kinds.iter().filter(|k| **k == IO_APIC_ENTRY).count(), 1);
        assert_eq!(
            kinds.iter().filter(|k| **k == INTERRUPT).count(),
            usize::from(LINES),
            "ISA IRQ has no interrupt entry"
        );
        assert_eq!(kinds.iter().filter(|k| **k == LOCAL_INTERRUPT).count(), 2);

        // Processor 0 is the bootstrap processor.
        assert_eq!(config[44 + 3], CPU_ENABLED | CPU_BOOTSTRAP);
        assert_eq!(config[44 + 20 + 3], CPU_ENABLED);
    }

    #[test]
    fn test_table_within_kilobyte() {
        let ram = GuestRam::new(&[(0, 1 << 20)]).expect("host pages");
        for vcpus in 1..=64 {
            match write(&ram, vcpus) {
                Ok(()) => {
                    let (pointer, config) = read(vcpus);
                    assert!(
                        pointer.len() as u64 + config.len() as u64 <= ROOM,
                        "{vcpus} processors wrote past the kilobyte"
                    );
                }
                Err(Error::NoRoomForMpTable) => {}
                Err(other) => panic!("{other}"),
            }
        }
    }
}
