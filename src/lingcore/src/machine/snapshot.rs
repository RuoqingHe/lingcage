// SPDX-FileCopyrightText: 2026 LingCage <opensource@lingcage.com>
//
// SPDX-License-Identifier: Apache-2.0

//! Guest state other than RAM, serialized as JSON for capture and
//! restore.
//!
//! `read_from` checks the format version and `fits` checks the guest
//! shape before a restore starts. Each blob is decoded by the backend or
//! device which applies it. Field missing from the JSON takes its
//! default.

use std::io::{Read, Write};

use crate::devices::Blob;
use crate::hv::StateBlob;
use crate::machine::{Error, Result};

/// Format version written into a snapshot, `read_from` refuses others.
const FORMAT_VERSION: u32 = 1;

/// Guest state other than RAM, namely shape, irqchip, clock, vCPUs and
/// devices. RAM moves separately, through `Machine::write_memory` and
/// `read_memory`.
#[derive(serde::Serialize, serde::Deserialize)]
#[serde(default)]
pub struct Snapshot {
    format: u32,
    /// Guest shape, RAM size and vCPU count, checked by `fits`.
    memory: u64,
    vcpus: u16,
    /// Interrupt controller state, if reported by the backend.
    irqchip: Option<StateBlob>,
    /// Clock state, if reported by the backend.
    clock: Option<StateBlob>,
    /// One per vCPU, in creation order.
    processors: Vec<StateBlob>,
    /// One entry per device in bus order, `None` for a stateless device.
    devices: Vec<Option<Blob>>,
}

impl Default for Snapshot {
    fn default() -> Self {
        Snapshot {
            format: FORMAT_VERSION,
            memory: 0,
            vcpus: 0,
            irqchip: None,
            clock: None,
            processors: Vec::new(),
            devices: Vec::new(),
        }
    }
}

impl Snapshot {
    /// Build a snapshot at `FORMAT_VERSION`.
    pub(in crate::machine) fn new(
        memory: u64,
        vcpus: u16,
        irqchip: Option<StateBlob>,
        clock: Option<StateBlob>,
        processors: Vec<StateBlob>,
        devices: Vec<Option<Blob>>,
    ) -> Self {
        Snapshot {
            format: FORMAT_VERSION,
            memory,
            vcpus,
            irqchip,
            clock,
            processors,
            devices,
        }
    }

    /// Write the snapshot as JSON.
    pub fn write_to(&self, out: &mut impl Write) -> Result<()> {
        serde_json::to_writer(out, self).map_err(|_| Error::Snapshot)
    }

    /// Read a snapshot from JSON and check its format version. Guest shape
    /// is checked by `fits`.
    pub fn read_from(from: &mut impl Read) -> Result<Self> {
        let snapshot: Snapshot = serde_json::from_reader(from).map_err(|_| Error::Snapshot)?;
        if snapshot.format != FORMAT_VERSION {
            return Err(Error::SnapshotFormat {
                version: snapshot.format,
            });
        }
        Ok(snapshot)
    }

    /// Returns `SnapshotShape` unless the snapshot was taken from a guest of
    /// `memory` bytes, `vcpus` vCPUs and `devices` devices, and carries one
    /// state per vCPU.
    pub(in crate::machine) fn fits(&self, memory: u64, vcpus: u16, devices: usize) -> Result<()> {
        if self.memory != memory || self.vcpus != vcpus || self.devices.len() != devices {
            return Err(Error::SnapshotShape);
        }
        if self.processors.len() != usize::from(vcpus) {
            return Err(Error::SnapshotShape);
        }
        Ok(())
    }

    /// Interrupt controller state, if any.
    pub(in crate::machine) fn irqchip(&self) -> Option<&StateBlob> {
        self.irqchip.as_ref()
    }

    /// Clock state, if any.
    pub(in crate::machine) fn clock(&self) -> Option<&StateBlob> {
        self.clock.as_ref()
    }

    /// vCPU states in creation order.
    pub(in crate::machine) fn processors(&self) -> &[StateBlob] {
        &self.processors
    }

    /// Device states in bus order.
    pub(in crate::machine) fn devices(&self) -> &[Option<Blob>] {
        &self.devices
    }
}

#[cfg(test)]
mod tests {
    use crate::machine::snapshot::*;

    fn taken(memory: u64, vcpus: u16, devices: usize) -> Snapshot {
        Snapshot::new(
            memory,
            vcpus,
            None,
            None,
            (0..vcpus)
                .map(|_| StateBlob {
                    backend: crate::hv::Backend::Kvm,
                    arch: crate::hv::Arch::X86_64,
                    version: 1,
                    data: Vec::new(),
                })
                .collect(),
            vec![None; devices],
        )
    }

    #[test]
    fn test_reject_other_shape() {
        let snapshot = taken(16 << 20, 2, 3);
        snapshot.fits(16 << 20, 2, 3).expect("fit its own shape");

        // Another RAM size, vCPU count or device count is refused.
        for (memory, vcpus, devices) in [(32 << 20, 2, 3), (16 << 20, 4, 3), (16 << 20, 2, 4)] {
            assert!(
                matches!(
                    snapshot.fits(memory, vcpus, devices),
                    Err(Error::SnapshotShape)
                ),
                "snapshot fits {memory} bytes, {vcpus} vCPUs and {devices} devices"
            );
        }
    }

    #[test]
    fn test_reject_processor_count_mismatch() {
        // `vcpus` and `processors` are separate fields. Two named but one
        // carried is refused.
        let mut snapshot = taken(16 << 20, 2, 0);
        snapshot.processors.pop();
        assert!(matches!(
            snapshot.fits(16 << 20, 2, 0),
            Err(Error::SnapshotShape)
        ));
    }

    #[test]
    fn test_reject_other_format_version() {
        let mut written = Vec::new();
        taken(16 << 20, 1, 0)
            .write_to(&mut written)
            .expect("write the snapshot");
        Snapshot::read_from(&mut written.as_slice()).expect("read the snapshot back");

        // Later format version is refused.
        let ahead = String::from_utf8(written).expect("json is text").replace(
            r#""format":1"#,
            &format!(r#""format":{}"#, FORMAT_VERSION + 1),
        );
        assert!(matches!(
            Snapshot::read_from(&mut ahead.as_bytes()),
            Err(Error::SnapshotFormat { .. })
        ));
    }

    #[test]
    fn test_reject_non_json() {
        assert!(matches!(
            Snapshot::read_from(&mut b"not a snapshot".as_slice()),
            Err(Error::Snapshot)
        ));
    }
}
