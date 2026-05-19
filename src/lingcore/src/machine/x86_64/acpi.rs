// SPDX-FileCopyrightText: 2026 LingCage <opensource@lingcage.com>
//
// SPDX-License-Identifier: Apache-2.0

//! ACPI tables of a kernel booted without firmware. The RSDP, an XSDT
//! listing the FADT and MADT, and a DSDT naming the VM generation ID,
//! the GED, the console and virtio register blocks with their lines.

use acpi_tables::fadt::{FADTBuilder, Flags};
use acpi_tables::madt::{
    EnabledStatus, IoApic, LocalInterruptController, MADT, ProcessorLocalApic,
};
use acpi_tables::rsdp::Rsdp;
use acpi_tables::sdt::Sdt;
use acpi_tables::xsdt::XSDT;
use acpi_tables::{Aml, aml};

use crate::machine::{Error, Result};
use crate::mem::GuestRam;

/// Address of the RSDP, start of the window scanned by
/// `acpi_find_root_pointer` (`ACPI_HI_RSDP_WINDOW_BASE` in
/// `include/acpi/acconfig.h`).
const POINTER_AT: u64 = 0x000e_0000;

/// Start of the tables, above the kilobyte of MP table at 0x9fc00.
const TABLES_AT: u64 = 0x000a_0000;

/// Alignment of address of each table.
const ALIGN: u64 = 8;

/// Address of the VM generation ID, `vmgenid::ROOM` bytes below the RSDP.
/// Table area ends here.
pub const GENID_AT: u64 = POINTER_AT - crate::machine::vmgenid::ROOM;

/// Length of `DESCRIPTION_HEADER` in bytes (ACPI 6.5, section 5.2.6).
const HEADER: u32 = 36;

/// `OEMID` field of each table header.
const OEM_ID: [u8; 6] = *b"LINGCG";

/// `OEM Revision` field of each table header.
const OEM_REVISION: u32 = 1;

/// `Local Interrupt Controller Address` field of the MADT.
const LOCAL_APIC: u32 = 0xfee0_0000;

/// `I/O APIC Address` field of I/O APIC structure of the MADT.
const IO_APIC: u32 = 0xfec0_0000;

/// `I/O APIC ID` field of I/O APIC structure of the MADT.
const IO_APIC_ID: u8 = 0;

/// `_HID` of the VM generation ID device, the first id listed by
/// `vmgenid_acpi_ids` (`drivers/virt/vmgenid.c`).
const GENID_HARDWARE: aml::AmlStr = "VMGENCTR";

/// `_CID` of the same device, `vmgenid_acpi_ids` has it as
/// `VM_GEN_COUNTER`.
const GENID_COMPATIBLE: aml::AmlStr = "VM_Gen_Counter";

/// `_HID` of the Generic Event Device, the id matched by
/// `drivers/acpi/evged.c`.
const EVENTS_HARDWARE: aml::AmlStr = "ACPI0013";

/// `Notify` value 0x80, the first device specific one. Handler of the
/// driver is installed for `ACPI_DEVICE_NOTIFY`, the range from 0x80 up.
const CHANGED: aml::Usize = 0x80;

/// Namespace path of the VM generation ID device.
const GENID_PATH: &str = "\\_SB_.VGEN";

/// `_HID` of a virtio-mmio device, the id listed by
/// `virtio_mmio_acpi_match`.
const VIRTIO_HARDWARE: aml::AmlStr = "LNRO0005";

/// `_HID` of a 16550 compatible serial port, the id listed by `8250_pnp`.
const CONSOLE_HARDWARE: &str = "PNP0501";

/// One device named by the DSDT, with resources carried by its `_CRS`.
///
/// The i8042 is not among them, since a `PNP0303` entry would make the
/// kernel probe keyboard through the data port not placed on the bus.
pub struct Named {
    /// Port base or MMIO address.
    pub at: u64,
    /// Length in ports or bytes.
    pub room: u64,
    /// Interrupt line, `None` for a device without one.
    pub line: Option<u8>,
}

/// Processors listed by the MADT and devices named by the DSDT.
pub struct Parts {
    /// Number of vCPUs, one `Processor Local APIC` structure for each.
    pub vcpus: u16,
    /// Address of the VM generation ID, `\_SB_.VGEN`.
    pub genid: u64,
    /// Interrupt line of the GED, `\_SB_.GED_`.
    pub events: u8,
    /// Serial console, `\_SB_.COM1`.
    pub console: Named,
    /// Virtio register blocks, `\_SB_.V000` onward in slot order.
    pub virtio: Vec<Named>,
}

/// Write cursor over the table area, from `TABLES_AT` up to `GENID_AT`.
struct Laying<'a> {
    ram: &'a GuestRam,
    next: u64,
}

impl Laying<'_> {
    /// Write `table` at the cursor and return its address. Table reaching
    /// `GENID_AT` is reported as `Error::NoRoomForTables`.
    fn lay(&mut self, table: &[u8]) -> Result<u64> {
        let at = self.next;
        let past = at + table.len() as u64;
        if past > GENID_AT {
            return Err(Error::NoRoomForTables);
        }
        self.ram.write(at, table)?;
        self.next = past.next_multiple_of(ALIGN);
        Ok(at)
    }
}

/// Write the tables for `parts` into `ram`, the DSDT, the FADT naming
/// it, the MADT, the XSDT listing both, and the RSDP at `POINTER_AT`.
/// Each table is written before the one carrying its address.
pub fn lay(ram: &GuestRam, parts: &Parts) -> Result<()> {
    let mut laying = Laying {
        ram,
        next: TABLES_AT,
    };
    let namespace = lay_namespace(&mut laying, parts)?;
    let machine = lay_machine(&mut laying, namespace)?;
    let processors = lay_processors(&mut laying, parts.vcpus)?;

    let mut list = XSDT::new(OEM_ID, *b"LINGXSDT", OEM_REVISION);
    list.add_entry(machine);
    list.add_entry(processors);
    let mut bytes = Vec::new();
    list.to_aml_bytes(&mut bytes);
    let list_at = laying.lay(&bytes)?;

    let mut pointer = Vec::new();
    Rsdp::new(OEM_ID, list_at).to_aml_bytes(&mut pointer);
    ram.write(POINTER_AT, &pointer)?;
    Ok(())
}

/// Write the DSDT, a `Device` for the VM generation ID, the GED, the
/// console and one per virtio block.
fn lay_namespace(laying: &mut Laying, parts: &Parts) -> Result<u64> {
    let (genid, line) = (parts.genid, parts.events);
    let low = genid as u32;
    let high = (genid >> 32) as u32;
    let hardware = aml::Name::new(aml::Path::new("_HID"), &GENID_HARDWARE);
    let compatible = aml::Name::new(aml::Path::new("_CID"), &GENID_COMPATIBLE);
    let address = aml::Name::new(
        aml::Path::new("ADDR"),
        &aml::Package::new(vec![&low, &high]),
    );
    let identifier = aml::Device::new(
        aml::Path::new(GENID_PATH),
        vec![&hardware, &compatible, &address],
    );

    // Kernel runs `_EVT` with the GSI as argument on each interrupt
    // (`acpi_ged_irq_handler` in `drivers/acpi/evged.c`). On a match the
    // method notifies `\_SB_.VGEN`.
    let kind = aml::Name::new(aml::Path::new("_HID"), &EVENTS_HARDWARE);
    let raised = aml::Interrupt::new(true, true, false, false, u32::from(line));
    let resources = aml::Name::new(
        aml::Path::new("_CRS"),
        &aml::ResourceTemplate::new(vec![&raised]),
    );
    let asked = aml::Equal::new(&aml::Arg(0), &line);
    let named = aml::Path::new(GENID_PATH);
    let told = aml::Notify::new(&named, &CHANGED);
    let when = aml::If::new(&asked, vec![&told]);
    let handler = aml::Method::new(aml::Path::new("_EVT"), 1, true, vec![&when]);
    let events = aml::Device::new(
        aml::Path::new("\\_SB_.GED_"),
        vec![&kind, &resources, &handler],
    );

    let mut namespace = Vec::new();
    identifier.to_aml_bytes(&mut namespace);
    events.to_aml_bytes(&mut namespace);
    name_console(&mut namespace, &parts.console);
    for (slot, block) in parts.virtio.iter().enumerate() {
        name_virtio(&mut namespace, slot, block);
    }
    let mut table = Sdt::new(*b"DSDT", HEADER, 6, OEM_ID, *b"LINGDSDT", OEM_REVISION);
    table.append_slice(&namespace);
    laying.lay(table.as_slice())
}

/// Write the FADT with `X_DSDT` set to `namespace` and `HW_REDUCED_ACPI`
/// set, so that no fixed hardware register block is looked for (ACPI
/// 6.5, section 4.1).
fn lay_machine(laying: &mut Laying, namespace: u64) -> Result<u64> {
    let table = FADTBuilder::new(OEM_ID, *b"LINGFADT", OEM_REVISION)
        .dsdt_64(namespace)
        .flag(Flags::HwReducedAcpi)
        .finalize();
    let mut bytes = Vec::new();
    table.to_aml_bytes(&mut bytes);
    laying.lay(&bytes)
}

/// Write the MADT, a `Processor Local APIC` structure per vCPU plus the
/// I/O APIC. With it present the kernel takes its SMP configuration
/// from ACPI and skips the MP table (`arch/x86/kernel/mpparse.c`).
fn lay_processors(laying: &mut Laying, vcpus: u16) -> Result<u64> {
    let mut table = MADT::new(
        OEM_ID,
        *b"LINGAPIC",
        OEM_REVISION,
        LocalInterruptController::Address(LOCAL_APIC),
    );
    for index in 0..vcpus {
        let id = u8::try_from(index).map_err(|_| Error::NoRoomForMpTable)?;
        table.add_structure(ProcessorLocalApic::new(id, id, EnabledStatus::Enabled));
    }
    table.add_structure(IoApic::new(IO_APIC_ID, IO_APIC, 0));
    let mut bytes = Vec::new();
    table.to_aml_bytes(&mut bytes);
    laying.lay(&bytes)
}

/// Name the console `\_SB_.COM1`, `PNP0501`, with its ports and line in
/// `_CRS`.
fn name_console(namespace: &mut Vec<u8>, console: &Named) {
    let hardware = aml::Name::new(
        aml::Path::new("_HID"),
        &aml::EISAName::new(CONSOLE_HARDWARE),
    );
    let unique = aml::Name::new(aml::Path::new("_UID"), &0u8);
    let ports = ports(console);
    let raised = line(console);
    let mut held: Vec<&dyn Aml> = vec![&ports];
    if let Some(raised) = raised.as_ref() {
        held.push(raised);
    }
    let resources = aml::Name::new(aml::Path::new("_CRS"), &aml::ResourceTemplate::new(held));
    aml::Device::new(
        aml::Path::new("\\_SB_.COM1"),
        vec![&hardware, &unique, &resources],
    )
    .to_aml_bytes(namespace);
}

/// Name virtio block `slot` as `\_SB_.V<slot>`, `LNRO0005`, with its
/// window and line in `_CRS`.
fn name_virtio(namespace: &mut Vec<u8>, slot: usize, block: &Named) {
    let hardware = aml::Name::new(aml::Path::new("_HID"), &VIRTIO_HARDWARE);
    let unique = aml::Name::new(aml::Path::new("_UID"), &(slot as u32));
    let window = aml::Memory32Fixed::new(true, block.at as u32, block.room as u32);
    let raised = line(block);
    let mut held: Vec<&dyn Aml> = vec![&window];
    if let Some(raised) = raised.as_ref() {
        held.push(raised);
    }
    let resources = aml::Name::new(aml::Path::new("_CRS"), &aml::ResourceTemplate::new(held));
    // Name segment is four characters, `V` plus three digits of `slot`.
    let path = format!("V{slot:03}");
    aml::Device::new(
        aml::Path::new(&format!("\\_SB_.{path}")),
        vec![&hardware, &unique, &resources],
    )
    .to_aml_bytes(namespace);
}

/// Returns the `IO` port descriptor for `part`.
fn ports(part: &Named) -> aml::IO {
    let first = part.at as u16;
    let room = part.room as u8;
    aml::IO::new(first, first, 1, room)
}

/// Returns the `Interrupt` descriptor for the line of `part`, edge
/// triggered, active high and exclusive. `None` for a part without
/// line.
fn line(part: &Named) -> Option<aml::Interrupt> {
    part.line
        .map(|raised| aml::Interrupt::new(true, true, false, false, u32::from(raised)))
}

#[cfg(test)]
mod tests {
    use crate::machine::x86_64::acpi::*;

    /// Two vCPUs, the VM generation ID, console at `COM1` and two virtio
    /// blocks, the shape assembled by `machine::Machine`.
    fn parts() -> Parts {
        Parts {
            vcpus: 2,
            genid: GENID_AT,
            events: 9,
            console: Named {
                at: 0x3f8,
                room: 8,
                line: Some(4),
            },
            virtio: vec![
                Named {
                    at: 0xd000_0000,
                    room: 0x200,
                    line: Some(5),
                },
                Named {
                    at: 0xd000_0200,
                    room: 0x200,
                    line: Some(6),
                },
            ],
        }
    }

    /// Guest RAM covering the first MiB, table area and RSDP included.
    fn ram() -> GuestRam {
        GuestRam::new(&[(0, 0x10_0000)]).expect("host pages")
    }

    /// Returns `len` bytes of `ram` at `gpa`.
    fn read(ram: &GuestRam, gpa: u64, len: usize) -> Vec<u8> {
        let mut bytes = vec![0u8; len];
        ram.read(gpa, &mut bytes).expect("read tables back");
        bytes
    }

    #[test]
    fn test_rsdp_in_scan_window() {
        let ram = ram();
        lay(&ram, &parts()).expect("lay tables");

        // Kernel scans `ACPI_HI_RSDP_WINDOW_BASE` for the signature, so the
        // address is checked together with the bytes.
        let pointer = read(&ram, POINTER_AT, 36);
        assert_eq!(&pointer[..8], b"RSD PTR ", "no RSDP signature");
        assert_eq!(pointer[15], 2, "RSDP revision is not 2");

        // The XSDT lies in the table area below the RSDP.
        let list = u64::from_le_bytes(pointer[24..32].try_into().expect("eight bytes"));
        assert!(
            (TABLES_AT..POINTER_AT).contains(&list),
            "XSDT at {list:#x}, outside of table area"
        );
        assert_eq!(&read(&ram, list, 4), b"XSDT", "no XSDT at RSDP address");
    }

    #[test]
    fn test_dsdt_names_devices_with_lines() {
        let ram = ram();
        lay(&ram, &parts()).expect("lay tables");

        // The DSDT is reached from the RSDP through the XSDT and the FADT,
        // same path as the kernel takes, so a table naming wrong address
        // fails here.
        let pointer = read(&ram, POINTER_AT, 36);
        let list = u64::from_le_bytes(pointer[24..32].try_into().expect("eight bytes"));
        let machine = u64::from_le_bytes(read(&ram, list + 36, 8).try_into().expect("entry"));
        assert_eq!(&read(&ram, machine, 4), b"FACP", "no FADT at XSDT entry");
        // `X_DSDT` is at offset 140 of the FADT (`struct acpi_table_fadt`).
        let namespace =
            u64::from_le_bytes(read(&ram, machine + 140, 8).try_into().expect("address"));
        assert_eq!(
            &read(&ram, namespace, 4),
            b"DSDT",
            "no DSDT at X_DSDT of FADT"
        );

        let length = u32::from_le_bytes(read(&ram, namespace + 4, 4).try_into().expect("length"));
        let written = read(&ram, namespace, length as usize);
        // Both `LNRO0005` blocks and `COM1` are in the DSDT.
        let names = |wanted: &[u8]| written.windows(wanted.len()).any(|run| run == wanted);
        assert!(
            names(VIRTIO_HARDWARE.as_bytes()),
            "no LNRO0005 device in the DSDT"
        );
        assert!(
            written
                .windows(VIRTIO_HARDWARE.len())
                .filter(|run| *run == VIRTIO_HARDWARE.as_bytes())
                .count()
                == 2,
            "not two LNRO0005 devices in the DSDT"
        );
        assert!(names(b"COM1"), "no COM1 device in the DSDT");
    }
}
