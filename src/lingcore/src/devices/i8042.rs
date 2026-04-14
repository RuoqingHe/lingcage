// SPDX-FileCopyrightText: 2026 LingCage <opensource@lingcage.com>
//
// SPDX-License-Identifier: Apache-2.0

//! i8042 keyboard controller, only the reset command is supported.

use std::io;

use crate::devices::Device;
use crate::hv::vcpu::VmExit;

/// Command which pulses the reset line.
const CMD_RESET: u64 = 0xfe;

/// Command register of the keyboard controller. Reset command ends the
/// run with `Reboot`. Data port is not placed on the bus, so a driver
/// probing for keyboard finds nothing.
pub struct I8042;

impl Device for I8042 {
    /// Status register. Command is handled within the write, so the input
    /// buffer full bit always reads clear.
    fn read(&mut self, _offset: u64, _size: u8) -> u64 {
        0
    }

    /// Register is one byte wide, a wider write only carries its lowest byte.
    fn write(&mut self, _offset: u64, _size: u8, value: u64) -> io::Result<Option<VmExit>> {
        match value & 0xff {
            CMD_RESET => Ok(Some(VmExit::Reboot)),
            _ => Ok(None),
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::devices::i8042::*;

    #[test]
    fn test_reset_command_exits_reboot() {
        let mut controller = I8042;
        assert_eq!(
            controller.write(0, 1, CMD_RESET).expect("command"),
            Some(VmExit::Reboot)
        );
    }

    #[test]
    fn test_other_commands_ignored() {
        let mut controller = I8042;
        // Read and write control register and output port, disable and enable
        // keyboard. None of them is a reset.
        for command in [0x20, 0x60, 0xd0, 0xd1, 0xad, 0xae, 0x00, 0xff] {
            assert_eq!(
                controller.write(0, 1, command).expect("command"),
                None,
                "{command:#x} is taken as reset"
            );
        }
    }

    #[test]
    fn test_status_input_buffer_clear() {
        /// Status bit for full input buffer. Driver polls it to be clear before
        /// sending a command.
        const STATUS_INPUT_FULL: u64 = 0x02;

        let mut controller = I8042;
        assert_eq!(controller.read(0, 1) & STATUS_INPUT_FULL, 0);
    }
}
