// SPDX-FileCopyrightText: 2026 LingCage <opensource@lingcage.com>
//
// SPDX-License-Identifier: Apache-2.0

//! ACPI PM1 fixed hardware. `PM1a_STS` and `PM1a_EN` are the event
//! grouping named by FADT in `PM1a_EVT_BLK`, then comes `PM1a_CNT`, the
//! register a kernel writes power-off request to (ACPI 6.5, section
//! 4.8.3).

use std::io;

use crate::devices::{Blob, Device, Error, Result};
use crate::hv::vcpu::VmExit;

/// `Blob::kind` of PM1 block.
const KIND: &str = "pm1";

/// Layout version of `Pm1State`. Blob of another version is reported as
/// `WrongVersion`.
const STATE_VERSION: u32 = 1;

/// Ports taken by the event grouping, `PM1a_STS` then `PM1a_EN`. FADT
/// carries the count as `PM1_EVT_LEN`.
pub const EVENT_PORTS: u8 = 4;

/// Ports taken by the control register. FADT carries the count as
/// `PM1_CNT_LEN`.
pub const CONTROL_PORTS: u8 = 2;

/// Ports taken by the whole block.
pub const SIZE: u16 = EVENT_PORTS as u16 + CONTROL_PORTS as u16;

/// Offset of `PM1a_STS`, written to clear the events it names.
const STATUS: u64 = 0;

/// Offset of `PM1a_EN`. FADT gives it as the second half of
/// `PM1a_EVT_BLK` instead of a separate address.
const ENABLE: u64 = 2;

/// Offset of `PM1a_CNT`, after the event grouping.
const CONTROL: u64 = EVENT_PORTS as u64;

/// `SCI_EN` in `PM1a_CNT`. Machine whose FADT carries no `SMI_CMD` is in
/// ACPI mode since reset, so this bit reads as set.
const SCI_ENABLED: u16 = 1 << 0;

/// `SLP_TYP` in `PM1a_CNT`, three bits naming the state to enter.
const SLEEP_TYPE: u16 = 0x7 << SLEEP_TYPE_SHIFT;

/// Offset of `SLP_TYP` in `PM1a_CNT`.
const SLEEP_TYPE_SHIFT: u32 = 10;

// TODO: Sleep states besides soft off are not yet entered.
/// `SLP_EN` in `PM1a_CNT`, the bit which enters the state named by
/// `SLP_TYP`.
const SLEEP_ENABLE: u16 = 1 << 13;

/// `SLP_TYP` of soft off, the value carried by `\_S5` in the namespace.
pub const SOFT_OFF: u8 = 5;

/// PM1 registers of one guest.
#[derive(Default)]
pub struct Pm1 {
    /// `PM1a_EN` as last written by the guest.
    enable: u16,
}

/// Enable bits of PM1 block, encoded as `Blob::data` through serde_json.
/// Status register has no state to carry.
#[derive(Default, serde::Serialize, serde::Deserialize)]
#[serde(default)]
struct Pm1State {
    enable: u16,
}

impl Device for Pm1 {
    /// Status register reads as clear, enable register holds what was
    /// written to it, and control register reports ACPI mode.
    fn read(&mut self, offset: u64, _size: u8) -> u64 {
        match offset {
            STATUS => 0,
            ENABLE => u64::from(self.enable),
            CONTROL => u64::from(SCI_ENABLED),
            _ => 0,
        }
    }

    /// Write of `SLP_EN` with `SLP_TYP` of `\_S5` stops the guest. Write to
    /// status register clears the events it names, which we have none, and
    /// the rest of the block takes the enable bits.
    fn write(&mut self, offset: u64, _size: u8, value: u64) -> io::Result<Option<VmExit>> {
        let value = value as u16;
        match offset {
            ENABLE => self.enable = value,
            CONTROL
                if value & SLEEP_ENABLE != 0
                    && (value & SLEEP_TYPE) >> SLEEP_TYPE_SHIFT == u16::from(SOFT_OFF) =>
            {
                return Ok(Some(VmExit::Shutdown));
            }
            _ => {}
        }
        Ok(None)
    }

    fn capture(&self) -> Result<Option<Blob>> {
        let state = Pm1State {
            enable: self.enable,
        };
        let data = serde_json::to_vec(&state).map_err(|_| Error::State)?;
        Ok(Some(Blob {
            kind: KIND.to_string(),
            version: STATE_VERSION,
            data,
        }))
    }

    fn restore(&mut self, blob: &Blob) -> Result<()> {
        if blob.kind != KIND {
            return Err(Error::WrongState {
                found: blob.kind.clone(),
                wanted: KIND,
            });
        }
        if blob.version != STATE_VERSION {
            return Err(Error::WrongVersion {
                kind: KIND,
                version: blob.version,
            });
        }
        let state: Pm1State = serde_json::from_slice(&blob.data).map_err(|_| Error::State)?;
        self.enable = state.enable;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use crate::devices::pm1::*;

    /// Control value ACPICA writes for a sleep state, `SLP_TYP` and `SLP_EN`
    /// on top of the bits it read back.
    fn sleep(state: u8) -> u64 {
        u64::from(SCI_ENABLED | (u16::from(state) << SLEEP_TYPE_SHIFT) | SLEEP_ENABLE)
    }

    #[test]
    fn test_soft_off_exits_shutdown() {
        let mut block = Pm1::default();
        assert_eq!(
            block
                .write(CONTROL, 2, sleep(SOFT_OFF))
                .expect("control register"),
            Some(VmExit::Shutdown)
        );
    }

    #[test]
    fn test_other_sleep_states_ignored() {
        let mut block = Pm1::default();
        for state in [0, 1, 2, 3, 4] {
            assert_eq!(
                block
                    .write(CONTROL, 2, sleep(state))
                    .expect("control register"),
                None,
                "sleep state {state} is taken as soft off"
            );
        }
    }

    #[test]
    fn test_control_write_without_slp_en() {
        let mut block = Pm1::default();
        let asked = u64::from(u16::from(SOFT_OFF) << SLEEP_TYPE_SHIFT);
        assert_eq!(
            block.write(CONTROL, 2, asked).expect("control register"),
            None
        );
    }

    #[test]
    fn test_register_defaults() {
        let mut block = Pm1::default();
        // No fixed event is raised on this bus, so status is clear.
        assert_eq!(block.read(STATUS, 2), 0);
        // ACPI mode is on since reset, as FADT carries no `SMI_CMD`.
        assert_eq!(block.read(CONTROL, 2) & u64::from(SCI_ENABLED), 1);
        // Enable register holds what was written to it.
        block.write(ENABLE, 2, 0x0320).expect("enable register");
        assert_eq!(block.read(ENABLE, 2), 0x0320);
    }

    #[test]
    fn test_capture_restore_enable_bits() {
        let mut block = Pm1::default();
        block.write(ENABLE, 2, 0x0120).expect("enable register");
        let blob = block.capture().expect("capture").expect("blob");

        let mut taken_up = Pm1::default();
        taken_up.restore(&blob).expect("restore");
        assert_eq!(taken_up.read(ENABLE, 2), 0x0120);
    }

    #[test]
    fn test_reject_foreign_state() {
        let mut block = Pm1::default();
        let blob = Blob {
            kind: "serial".to_string(),
            version: STATE_VERSION,
            data: Vec::new(),
        };
        assert!(matches!(
            block.restore(&blob),
            Err(Error::WrongState { .. })
        ));
    }
}
