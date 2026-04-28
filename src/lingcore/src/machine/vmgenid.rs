// SPDX-FileCopyrightText: 2026 LingCage <opensource@lingcage.com>
//
// SPDX-License-Identifier: Apache-2.0

//! VM generation ID, sixteen bytes of guest RAM named by the DSDT. It
//! is redrawn on restore and announced on the GED line. Kernel mixes
//! the new value into its random pool and reseeds at once
//! (`add_vmfork_randomness` in `drivers/char/random.c`).

use std::fs::File;
use std::io::Read;

use crate::hv::irq::IrqSender;
use crate::machine::{Error, Result};
use crate::mem::GuestRam;

/// Length of the identifier in bytes (`VMGENID_SIZE` in `vmgenid.c`).
pub const ROOM: u64 = 16;

/// The VM generation ID, its line and the file it is drawn from.
pub struct VmGenId {
    /// Guest address of the identifier, `ADDR` in the DSDT.
    at: u64,
    line: Box<dyn IrqSender>,
    /// Entropy source, opened once at assembly time.
    source: File,
}

impl VmGenId {
    /// Create the identifier at `at`, which raises `line` on change and is
    /// drawn from `source`.
    pub fn new(at: u64, line: Box<dyn IrqSender>, source: File) -> Self {
        VmGenId { at, line, source }
    }

    /// Returns guest address of the identifier.
    pub fn at(&self) -> u64 {
        self.at
    }

    /// Draw a fresh identifier into RAM. Line stays low, since a first boot
    /// has no old value to compare against.
    pub fn lay(&mut self, ram: &GuestRam) -> Result<()> {
        let mut drawn = [0u8; ROOM as usize];
        self.source.read_exact(&mut drawn).map_err(Error::Entropy)?;
        ram.write(self.at, &drawn)?;
        Ok(())
    }

    /// Draw a fresh identifier into RAM, then raise the line. The write
    /// goes first, since the driver reads the bytes on notification and
    /// compares them with the last read (`vmgenid_notify`).
    pub fn renew(&mut self, ram: &GuestRam) -> Result<()> {
        self.lay(ram)?;
        self.line.send()?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use crate::machine::vmgenid::*;

    /// `IrqSender` which counts its `send` calls.
    #[derive(Clone, Default)]
    struct Counter(std::sync::Arc<std::sync::atomic::AtomicUsize>);

    impl IrqSender for Counter {
        fn send(&self) -> crate::hv::Result<()> {
            self.0.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            Ok(())
        }
    }

    impl Counter {
        fn pulses(&self) -> usize {
            self.0.load(std::sync::atomic::Ordering::SeqCst)
        }
    }

    fn source() -> File {
        File::open("/dev/urandom").expect("open /dev/urandom")
    }

    /// Read the identifier at `at` back from `ram`.
    fn identifier(ram: &GuestRam, at: u64) -> [u8; ROOM as usize] {
        let mut read = [0u8; ROOM as usize];
        ram.read(at, &mut read).expect("read the identifier");
        read
    }

    #[test]
    fn test_lay_without_notification() {
        let ram = GuestRam::new(&[(0, 0x10000)]).expect("host pages");
        let line = Counter::default();
        let mut genid = VmGenId::new(0x1000, Box::new(line.clone()), source());

        genid.lay(&ram).expect("lay the identifier");
        assert_ne!(
            identifier(&ram, 0x1000),
            [0u8; ROOM as usize],
            "identifier is still zero"
        );
        assert_eq!(line.pulses(), 0, "line raised on the first draw");
    }

    #[test]
    fn test_renew_draws_new_value() {
        let ram = GuestRam::new(&[(0, 0x10000)]).expect("host pages");
        let line = Counter::default();
        let mut genid = VmGenId::new(0x1000, Box::new(line.clone()), source());

        genid.lay(&ram).expect("lay the identifier");
        let first = identifier(&ram, 0x1000);
        genid.renew(&ram).expect("renew the identifier");
        let second = identifier(&ram, 0x1000);

        // Driver skips a notification whose bytes match the last it read
        // (`vmgenid_notify`), so a repeated value would go unreported.
        assert_ne!(first, second, "renewed identifier repeats the old one");
        assert_eq!(line.pulses(), 1, "line not raised just once");
    }

    #[test]
    fn test_write_within_room() {
        let ram = GuestRam::new(&[(0, 0x10000)]).expect("host pages");
        let mut genid = VmGenId::new(0x1000, Box::new(Counter::default()), source());

        genid.lay(&ram).expect("lay the identifier");
        let mut after = [0u8; 8];
        ram.read(0x1000 + ROOM, &mut after).expect("read past ROOM");
        assert_eq!(after, [0u8; 8], "identifier wrote past ROOM");
    }
}
