// SPDX-FileCopyrightText: 2026 LingCage <opensource@lingcage.com>
//
// SPDX-License-Identifier: Apache-2.0

//! Virtio balloon device, section 5.5 of virtio 1.2.
//!
//! Guest reports free pages to the balloon, and the host drops them.
//! Configuration space reads zero, so the guest is asked for no page.
//! Inflate and deflate queues stay idle.

use log::debug;

use crate::devices::virtio::queue::{Chain, Queue};
use crate::devices::virtio::{Device, Result};
use crate::mem::GuestRam;

/// Device ID of balloon device, section 5.5.
const DEVICE_ID: u32 = 5;
/// `VIRTIO_BALLOON_F_REPORTING`, free pages are reported on a queue.
const FEATURE_REPORTING: u64 = 1 << 5;
/// Reporting queue, carrying pages the guest holds free. Stats and hint
/// queues are not offered, so the driver sets this one up third, after
/// inflate and deflate queues.
const REPORTING: u16 = 2;
/// Balloon counts pages of 4 KiB, `VIRTIO_BALLOON_PFN_SHIFT`.
const PFN_SHIFT: u64 = 12;

/// Balloon device used to drop pages reported free by the guest.
#[derive(Default)]
pub struct Balloon {
    /// Pages reported free and dropped.
    reported: u64,
    /// Reported ranges skipped, since they are not whole host pages. Range
    /// in a device-readable buffer and chain on inflate or deflate queue
    /// are counted as well.
    refused: u64,
}

impl Balloon {
    /// Create a balloon asking the guest for no page.
    pub fn new() -> Self {
        Balloon::default()
    }

    /// Drop each range of `chain` reported free by the guest. Returns pages
    /// dropped. Driver puts ranges in device-writable buffers. A range in a
    /// readable buffer, or not whole host pages, is counted in `refused`.
    fn ranges(&mut self, chain: &Chain, ram: &GuestRam) -> u64 {
        let mut pages = 0u64;
        for descriptor in &chain.descriptors {
            let (addr, len) = (descriptor.addr, u64::from(descriptor.len));
            // `discard` refuses a range not covering whole host pages.
            if !descriptor.writable() || len == 0 || ram.discard(addr, len).is_err() {
                debug!("reported range of {len:#x} bytes at {addr:#x} skipped");
                self.refused += 1;
                continue;
            }
            pages += len >> PFN_SHIFT;
        }
        pages
    }
}

impl Device for Balloon {
    fn device_id(&self) -> u32 {
        DEVICE_ID
    }

    fn features(&self) -> u64 {
        FEATURE_REPORTING
    }

    fn queue_count(&self) -> u16 {
        // Driver sets up inflate and deflate queues as well.
        3
    }

    /// Returns pages reported, then ranges and chains refused.
    fn counts(&self) -> Vec<(&'static str, u64)> {
        vec![("reported", self.reported), ("refused", self.refused)]
    }

    /// Serve each chain of queue `index`. Pages reported free are dropped.
    /// A chain on inflate or deflate queue is skipped, since the guest is
    /// asked for no page. Each chain is marked used with no byte written.
    fn notify(&mut self, index: u16, queue: &mut Queue, ram: &GuestRam) -> Result<()> {
        while let Some(chain) = queue.pop(ram)? {
            if index == REPORTING {
                self.reported += self.ranges(&chain, ram);
            } else {
                debug!("chain on queue {index} skipped");
                self.refused += 1;
            }
            queue.add_used(ram, chain.head, 0)?;
        }
        Ok(())
    }

    /// Serve chains waiting at capture time, as a notify does.
    fn restored(&mut self, index: u16, queue: &mut Queue, ram: &GuestRam) -> Result<()> {
        self.notify(index, queue, ram)
    }
}

#[cfg(test)]
mod tests {
    use crate::devices::virtio::balloon::*;

    const RAM_SIZE: u64 = 0x40000;
    const DESC_TABLE: u64 = 0x1000;
    const AVAIL_RING: u64 = 0x2000;
    const USED_RING: u64 = 0x3000;
    /// Buffer holding a frame number.
    const LIST: u64 = 0x4000;
    /// Two pages reported free by the guest.
    const PAGES: u64 = 0x10000;
    /// `VIRTQ_DESC_F_WRITE`, the buffer is device-writable.
    const WRITE: u16 = 0x2;
    /// Inflate queue.
    const INFLATE: u16 = 0;

    /// Post one buffer of `len` bytes at `addr` with descriptor `flags`.
    /// Available index moves to `slot + 1`.
    fn post(ram: &GuestRam, addr: u64, len: u32, flags: u16, slot: u16) {
        let mut descriptor = [0u8; 16];
        descriptor[0..8].copy_from_slice(&addr.to_le_bytes());
        descriptor[8..12].copy_from_slice(&len.to_le_bytes());
        descriptor[12..14].copy_from_slice(&flags.to_le_bytes());
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

    /// Returns index of used ring, chains marked used so far.
    fn used(ram: &GuestRam) -> u16 {
        let mut index = [0u8; 2];
        ram.read(USED_RING + 2, &mut index).expect("used index");
        u16::from_le_bytes(index)
    }

    fn filled(ram: &GuestRam) {
        ram.write(PAGES, &[0xa5u8; 8192]).expect("fill two pages");
    }

    fn sum(ram: &GuestRam) -> u64 {
        let mut bytes = vec![0u8; 8192];
        ram.read(PAGES, &mut bytes).expect("read two pages");
        bytes.iter().map(|b| u64::from(*b)).sum()
    }

    #[test]
    fn test_reported_range_dropped() {
        let ram = GuestRam::new(&[(0, RAM_SIZE)]).expect("host pages");
        let mut queue = Queue::new(8, DESC_TABLE, AVAIL_RING, USED_RING).expect("ring");
        let mut device = Balloon::new();
        filled(&ram);
        post(&ram, PAGES, 8192, WRITE, 0);
        device.notify(REPORTING, &mut queue, &ram).expect("notify");
        assert_eq!(sum(&ram), 0, "reported pages still hold data");
        assert_eq!(reported(&ram, 0), 0);
        assert_eq!(device.counts()[0], ("reported", 2));
    }

    #[test]
    fn test_malformed_ranges_skipped() {
        // Part of a page, an unaligned range and a readable buffer are each
        // skipped, and no page is dropped.
        let ram = GuestRam::new(&[(0, RAM_SIZE)]).expect("host pages");
        let mut queue = Queue::new(8, DESC_TABLE, AVAIL_RING, USED_RING).expect("ring");
        let mut device = Balloon::new();
        filled(&ram);
        let ranges = [
            (PAGES, 100, WRITE),
            (PAGES + 8, 4096, WRITE),
            (PAGES, 8192, 0),
        ];
        for (slot, (addr, len, flags)) in ranges.into_iter().enumerate() {
            post(&ram, addr, len, flags, slot as u16);
            device.notify(REPORTING, &mut queue, &ram).expect("notify");
        }
        assert_eq!(sum(&ram), 0xa5 * 8192, "a page was dropped");
        assert_eq!(device.counts()[0], ("reported", 0));
        assert_eq!(device.counts()[1], ("refused", 3));
        // Each chain is used, so the driver does not wait on it.
        assert_eq!(used(&ram), 3);
    }

    #[test]
    fn test_inflate_drops_no_page() {
        // Guest is asked for no page, so a frame named on inflate queue is
        // kept, and its chain is marked used.
        let ram = GuestRam::new(&[(0, RAM_SIZE)]).expect("host pages");
        let mut queue = Queue::new(8, DESC_TABLE, AVAIL_RING, USED_RING).expect("ring");
        let mut device = Balloon::new();
        assert_eq!(device.read_config(0, 8), 0, "guest is asked for pages");
        filled(&ram);
        ram.write(LIST, &((PAGES >> PFN_SHIFT) as u32).to_le_bytes())
            .expect("frame list");
        post(&ram, LIST, 4, 0, 0);
        device.notify(INFLATE, &mut queue, &ram).expect("notify");
        assert_eq!(sum(&ram), 0xa5 * 8192, "frame was dropped");
        assert_eq!(device.counts()[1], ("refused", 1));
        assert_eq!(used(&ram), 1);
    }
}
