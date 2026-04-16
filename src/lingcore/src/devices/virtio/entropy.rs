// SPDX-FileCopyrightText: 2026 LingCage <opensource@lingcage.com>
//
// SPDX-License-Identifier: Apache-2.0

//! Virtio entropy device, section 5.4 of virtio 1.2.
//!
//! Device reads from the `Read` source it is created with, so a cloned
//! guest can be given its own source.

use std::io::Read;

use crate::devices::virtio::queue::Queue;
use crate::devices::virtio::{Device, Error, Result};
use crate::mem::GuestRam;

/// Device ID of entropy device, section 5.4.
const DEVICE_ID: u32 = 4;

/// Entropy device backed by a `Read` source.
pub struct Entropy<R> {
    source: R,
}

impl<R: Read> Entropy<R> {
    /// Create an entropy device reading from `source`.
    pub fn new(source: R) -> Self {
        Entropy { source }
    }
}

impl<R: Read + Send> Device for Entropy<R> {
    fn device_id(&self) -> u32 {
        DEVICE_ID
    }

    /// Fill writable buffers of each chain from the source and report bytes
    /// written. Short read ends the chain at that length.
    fn notify(&mut self, _index: u16, queue: &mut Queue, ram: &GuestRam) -> Result<()> {
        while let Some(chain) = queue.pop(ram)? {
            let mut written = 0u32;
            for descriptor in chain.descriptors.iter().filter(|d| d.writable()) {
                let mut bytes = vec![0u8; descriptor.len as usize];
                let taken = self.source.read(&mut bytes).map_err(|_| Error::Source)?;
                ram.write(descriptor.addr, &bytes[..taken])
                    .map_err(|_| Error::Ring {
                        gpa: descriptor.addr,
                    })?;
                written += taken as u32;
                if taken < bytes.len() {
                    break;
                }
            }
            queue.add_used(ram, chain.head, written)?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::io::Cursor;

    use crate::devices::virtio::entropy::*;

    const RAM_SIZE: u64 = 0x10000;
    const DESC_TABLE: u64 = 0x1000;
    const AVAIL_RING: u64 = 0x2000;
    const USED_RING: u64 = 0x3000;
    const BUFFER: u64 = 0x4000;
    /// `VIRTQ_DESC_F_WRITE`, the device-writable flag.
    const WRITABLE: u16 = 0x2;

    /// Post one writable buffer of `len` bytes. Available index moves to
    /// `slot + 1`.
    fn ask_for(ram: &GuestRam, len: u32, slot: u16) {
        let mut descriptor = [0u8; 16];
        descriptor[0..8].copy_from_slice(&BUFFER.to_le_bytes());
        descriptor[8..12].copy_from_slice(&len.to_le_bytes());
        descriptor[12..14].copy_from_slice(&WRITABLE.to_le_bytes());
        ram.write(DESC_TABLE, &descriptor).expect("descriptor");
        ram.write(AVAIL_RING + 4, &0u16.to_le_bytes())
            .expect("head");
        ram.write(AVAIL_RING + 2, &(slot + 1).to_le_bytes())
            .expect("index");
    }

    /// Returns `len` field of used ring element `slot`.
    fn reported(ram: &GuestRam, slot: u64) -> u32 {
        let mut bytes = [0u8; 4];
        ram.read(USED_RING + 8 + slot * 8, &mut bytes)
            .expect("used ring");
        u32::from_le_bytes(bytes)
    }

    #[test]
    fn test_serve_from_source() {
        let ram = GuestRam::new(&[(0, RAM_SIZE)]).expect("host pages");
        let mut queue = Queue::new(8, DESC_TABLE, AVAIL_RING, USED_RING).expect("ring");
        let seed: Vec<u8> = (0..16u8).collect();
        let mut device = Entropy::new(Cursor::new(seed.clone()));

        ask_for(&ram, 16, 0);
        device.notify(0, &mut queue, &ram).expect("notify");

        let mut served = [0u8; 16];
        ram.read(BUFFER, &mut served).expect("read the buffer back");
        assert_eq!(served.to_vec(), seed, "buffer differs from the seed");
        assert_eq!(reported(&ram, 0), 16);
    }

    #[test]
    fn test_short_read_reported() {
        let ram = GuestRam::new(&[(0, RAM_SIZE)]).expect("host pages");
        let mut queue = Queue::new(8, DESC_TABLE, AVAIL_RING, USED_RING).expect("ring");
        let mut device = Entropy::new(Cursor::new(vec![0xa5u8; 4]));

        // 16-byte buffer over a 4-byte source is reported used with 4.
        ask_for(&ram, 16, 0);
        device.notify(0, &mut queue, &ram).expect("notify");
        assert_eq!(reported(&ram, 0), 4);

        // Source is drained, second chain is used with zero bytes.
        ask_for(&ram, 16, 1);
        device.notify(0, &mut queue, &ram).expect("notify");
        assert_eq!(reported(&ram, 1), 0);
    }

    #[test]
    fn test_readonly_buffer_untouched() {
        let ram = GuestRam::new(&[(0, RAM_SIZE)]).expect("host pages");
        let mut queue = Queue::new(8, DESC_TABLE, AVAIL_RING, USED_RING).expect("ring");
        let mut device = Entropy::new(Cursor::new(vec![0xa5u8; 16]));

        // Descriptor without `VIRTQ_DESC_F_WRITE` is not filled.
        let mut descriptor = [0u8; 16];
        descriptor[0..8].copy_from_slice(&BUFFER.to_le_bytes());
        descriptor[8..12].copy_from_slice(&16u32.to_le_bytes());
        ram.write(DESC_TABLE, &descriptor).expect("descriptor");
        ram.write(AVAIL_RING + 4, &0u16.to_le_bytes())
            .expect("head");
        ram.write(AVAIL_RING + 2, &1u16.to_le_bytes())
            .expect("index");
        ram.write(BUFFER, &[0u8; 16]).expect("clear the buffer");

        device.notify(0, &mut queue, &ram).expect("notify");

        let mut untouched = [0u8; 16];
        ram.read(BUFFER, &mut untouched).expect("read it back");
        assert_eq!(untouched, [0u8; 16], "read-only buffer was written");
        assert_eq!(reported(&ram, 0), 0);
    }
}
