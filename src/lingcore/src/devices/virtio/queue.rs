// SPDX-FileCopyrightText: 2026 LingCage <opensource@lingcage.com>
//
// SPDX-License-Identifier: Apache-2.0

//! Split virtqueue, laid out as described in section 2.7 of virtio 1.2.
//!
//! Indices and addresses in the rings are written by the guest.
//! [`Queue::pop`] walks a chain and checks each link and buffer before
//! returning it.

use std::num::Wrapping;

use crate::devices::virtio::{Error, Result};
use crate::mem::GuestRam;

/// Bytes per descriptor in the table.
const DESCRIPTOR_SIZE: u64 = 16;
/// Largest queue size allowed by section 2.7.
const MAX_SIZE: u16 = 1 << 15;

/// With `VIRTQ_DESC_F_NEXT` set the chain continues at `next`.
const NEXT: u16 = 0x1;
/// With `VIRTQ_DESC_F_WRITE` set the buffer is device-writable.
const WRITE: u16 = 0x2;
/// With `VIRTQ_DESC_F_INDIRECT` set the buffer holds a descriptor table.
const INDIRECT: u16 = 0x4;

/// One descriptor, as held in the table.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Descriptor {
    /// Guest address of the buffer, checked to be backed for `len` bytes.
    pub addr: u64,
    /// Length of the buffer in bytes.
    pub len: u32,
    flags: u16,
    next: u16,
}

impl Descriptor {
    /// Decode a descriptor from its sixteen bytes in the table.
    fn from_bytes(bytes: &[u8; 16]) -> Self {
        Descriptor {
            addr: u64::from_le_bytes(bytes[0..8].try_into().expect("eight bytes")),
            len: u32::from_le_bytes(bytes[8..12].try_into().expect("four bytes")),
            flags: u16::from_le_bytes(bytes[12..14].try_into().expect("two bytes")),
            next: u16::from_le_bytes(bytes[14..16].try_into().expect("two bytes")),
        }
    }

    pub fn writable(&self) -> bool {
        self.flags & WRITE != 0
    }
}

/// Descriptor chain read from the table and checked.
#[derive(Debug, PartialEq, Eq)]
pub struct Chain {
    /// Index of the first descriptor. `add_used` reports the chain by it.
    pub head: u16,
    /// Descriptors in chain order.
    pub descriptors: Vec<Descriptor>,
}

/// Split virtqueue, the three rings and position of the device in the
/// available and used ones.
#[derive(Debug)]
pub struct Queue {
    size: u16,
    desc_table: u64,
    avail_ring: u64,
    used_ring: u64,
    next_avail: Wrapping<u16>,
    next_used: Wrapping<u16>,
}

impl Queue {
    /// Create a queue over the rings at given guest addresses. `size` is
    /// checked against section 2.7: nonzero, power of two and at most
    /// `MAX_SIZE`.
    pub fn new(size: u16, desc_table: u64, avail_ring: u64, used_ring: u64) -> Result<Self> {
        if size == 0 || size > MAX_SIZE || !size.is_power_of_two() {
            return Err(Error::BadSize { size });
        }
        Ok(Queue {
            size,
            desc_table,
            avail_ring,
            used_ring,
            next_avail: Wrapping(0),
            next_used: Wrapping(0),
        })
    }

    /// Returns the next chain made available by the driver, or `None` once
    /// the available index is reached.
    ///
    /// Cursor advances before the walk, so a malformed chain is only
    /// reported once and not read again on the next call.
    pub fn pop(&mut self, ram: &GuestRam) -> Result<Option<Chain>> {
        // avail: le16 flags, le16 idx, le16 ring[size].
        let published = Wrapping(read_u16(ram, offset(self.avail_ring, 2)?)?);
        if self.next_avail == published {
            return Ok(None);
        }
        let slot = u64::from(self.next_avail.0 % self.size);
        let head = read_u16(ram, offset(self.avail_ring, 4 + slot * 2)?)?;
        self.next_avail += Wrapping(1);
        self.walk(ram, head).map(Some)
    }

    /// Report the chain at `head` as used, with `len` bytes written into it.
    pub fn add_used(&mut self, ram: &GuestRam, head: u16, len: u32) -> Result<()> {
        // used: le16 flags, le16 idx, { le32 id, le32 len } ring[size].
        let slot = u64::from(self.next_used.0 % self.size);
        let element = offset(self.used_ring, 4 + slot * 8)?;
        write_u32(ram, element, u32::from(head))?;
        write_u32(ram, offset(element, 4)?, len)?;
        // Index is written last, after the element it counts.
        self.next_used += Wrapping(1);
        write_u16(ram, offset(self.used_ring, 2)?, self.next_used.0)
    }

    /// Returns the next available index and the next used index. Rings
    /// themselves stay in guest RAM.
    pub fn cursors(&self) -> (u16, u16) {
        (self.next_avail.0, self.next_used.0)
    }

    /// Set the indices returned by `cursors`.
    pub fn set_cursors(&mut self, next_avail: u16, next_used: u16) {
        self.next_avail = Wrapping(next_avail);
        self.next_used = Wrapping(next_used);
    }

    /// Walk the chain from `head`, check each link and buffer.
    fn walk(&self, ram: &GuestRam, head: u16) -> Result<Chain> {
        let mut descriptors = Vec::new();
        let mut index = head;
        loop {
            if index >= self.size {
                return Err(Error::BadIndex {
                    index,
                    size: self.size,
                });
            }
            // Chain longer than the table revisits a descriptor, which
            // is a loop.
            if descriptors.len() >= usize::from(self.size) {
                return Err(Error::ChainTooLong { size: self.size });
            }
            let at = offset(self.desc_table, u64::from(index) * DESCRIPTOR_SIZE)?;
            let mut bytes = [0u8; 16];
            ram.read(at, &mut bytes)
                .map_err(|_| Error::Ring { gpa: at })?;
            let descriptor = Descriptor::from_bytes(&bytes);

            if descriptor.flags & INDIRECT != 0 {
                return Err(Error::Indirect);
            }
            if !ram.holds(descriptor.addr, u64::from(descriptor.len)) {
                return Err(Error::Unbacked {
                    addr: descriptor.addr,
                    len: descriptor.len,
                });
            }
            descriptors.push(descriptor);

            if descriptor.flags & NEXT == 0 {
                return Ok(Chain { head, descriptors });
            }
            index = descriptor.next;
        }
    }
}

/// Returns `base + delta`, or `Error::Ring` if fields of the ring
/// overflow the address space.
fn offset(base: u64, delta: u64) -> Result<u64> {
    base.checked_add(delta).ok_or(Error::Ring { gpa: base })
}

fn read_u16(ram: &GuestRam, gpa: u64) -> Result<u16> {
    let mut bytes = [0u8; 2];
    ram.read(gpa, &mut bytes).map_err(|_| Error::Ring { gpa })?;
    Ok(u16::from_le_bytes(bytes))
}

fn write_u16(ram: &GuestRam, gpa: u64, value: u16) -> Result<()> {
    ram.write(gpa, &value.to_le_bytes())
        .map_err(|_| Error::Ring { gpa })
}

fn write_u32(ram: &GuestRam, gpa: u64, value: u32) -> Result<()> {
    ram.write(gpa, &value.to_le_bytes())
        .map_err(|_| Error::Ring { gpa })
}

#[cfg(test)]
mod tests {
    use crate::devices::virtio::queue::*;

    const SIZE: u16 = 8;
    const DESC_TABLE: u64 = 0x1000;
    const AVAIL_RING: u64 = 0x2000;
    const USED_RING: u64 = 0x3000;
    const BUFFER: u64 = 0x4000;
    const RAM_SIZE: u64 = 0x10000;

    fn ram() -> GuestRam {
        GuestRam::new(&[(0, RAM_SIZE)]).expect("host pages")
    }

    fn queue() -> Queue {
        Queue::new(SIZE, DESC_TABLE, AVAIL_RING, USED_RING).expect("queue of eight")
    }

    /// Write descriptor `index` to the table the way a driver does.
    fn describe(ram: &GuestRam, index: u16, addr: u64, len: u32, flags: u16, next: u16) {
        let mut bytes = [0u8; 16];
        bytes[0..8].copy_from_slice(&addr.to_le_bytes());
        bytes[8..12].copy_from_slice(&len.to_le_bytes());
        bytes[12..14].copy_from_slice(&flags.to_le_bytes());
        bytes[14..16].copy_from_slice(&next.to_le_bytes());
        ram.write(DESC_TABLE + u64::from(index) * 16, &bytes)
            .expect("write a descriptor");
    }

    /// Put `head` in the available ring at `slot` and set the index to
    /// `count`.
    fn publish(ram: &GuestRam, slot: u16, head: u16, count: u16) {
        ram.write(AVAIL_RING + 4 + u64::from(slot) * 2, &head.to_le_bytes())
            .expect("publish a head");
        ram.write(AVAIL_RING + 2, &count.to_le_bytes())
            .expect("bump the index");
    }

    #[test]
    fn test_pop_chain_in_link_order() {
        let ram = ram();
        describe(&ram, 0, BUFFER, 16, NEXT | WRITE, 3);
        describe(&ram, 3, BUFFER + 16, 8, WRITE, 0);
        publish(&ram, 0, 0, 1);

        let mut queue = queue();
        let chain = queue.pop(&ram).expect("walk").expect("one chain");
        assert_eq!(chain.head, 0);
        assert_eq!(chain.descriptors.len(), 2);
        assert_eq!(chain.descriptors[0].len, 16);
        assert_eq!(chain.descriptors[1].addr, BUFFER + 16);
        assert!(chain.descriptors[1].writable());
        assert_eq!(queue.pop(&ram).expect("walk"), None, "a second chain");
    }

    #[test]
    fn test_add_used() {
        let ram = ram();
        let mut queue = queue();
        queue.add_used(&ram, 3, 16).expect("report a chain");

        let mut element = [0u8; 8];
        ram.read(USED_RING + 4, &mut element).expect("read it back");
        assert_eq!(u32::from_le_bytes(element[0..4].try_into().unwrap()), 3);
        assert_eq!(u32::from_le_bytes(element[4..8].try_into().unwrap()), 16);

        let mut index = [0u8; 2];
        ram.read(USED_RING + 2, &mut index).expect("read the index");
        assert_eq!(u16::from_le_bytes(index), 1, "used index not updated");
    }

    #[test]
    fn test_reject_bad_size() {
        // Zero, one over `MAX_SIZE`, and two which are not power of two.
        for size in [0, MAX_SIZE + 1, 3, 6] {
            assert_eq!(
                Queue::new(size, DESC_TABLE, AVAIL_RING, USED_RING).unwrap_err(),
                Error::BadSize { size },
                "queue size {size} accepted"
            );
        }
    }

    #[test]
    fn test_reject_index_past_table() {
        let ram = ram();
        publish(&ram, 0, SIZE, 1);
        assert_eq!(
            queue().pop(&ram).unwrap_err(),
            Error::BadIndex {
                index: SIZE,
                size: SIZE
            }
        );
    }

    #[test]
    fn test_reject_looped_chain() {
        let ram = ram();
        describe(&ram, 0, BUFFER, 4, NEXT, 1);
        describe(&ram, 1, BUFFER, 4, NEXT, 0);
        publish(&ram, 0, 0, 1);
        assert_eq!(
            queue().pop(&ram).unwrap_err(),
            Error::ChainTooLong { size: SIZE }
        );
    }

    #[test]
    fn test_reject_indirect() {
        let ram = ram();
        describe(&ram, 0, BUFFER, 4, INDIRECT, 0);
        publish(&ram, 0, 0, 1);
        assert_eq!(queue().pop(&ram).unwrap_err(), Error::Indirect);
    }

    #[test]
    fn test_reject_buffer_past_ram() {
        let ram = ram();
        describe(&ram, 0, RAM_SIZE - 0x1000, 0x2000, WRITE, 0);
        publish(&ram, 0, 0, 1);
        assert_eq!(
            queue().pop(&ram).unwrap_err(),
            Error::Unbacked {
                addr: RAM_SIZE - 0x1000,
                len: 0x2000
            }
        );
    }

    #[test]
    fn test_reject_buffer_across_hole() {
        // RAM has a hole below its second region, so a buffer is checked
        // against the regions instead of the last address. This one starts
        // in the first region and ends in the hole.
        let ram = GuestRam::new(&[(0, 0x8000), (0x10000, 0x8000)]).expect("host pages");
        describe(&ram, 0, 0x7000, 0x2000, WRITE, 0);
        ram.write(AVAIL_RING + 4, &0u16.to_le_bytes())
            .expect("head");
        ram.write(AVAIL_RING + 2, &1u16.to_le_bytes())
            .expect("index");
        assert_eq!(
            queue().pop(&ram).unwrap_err(),
            Error::Unbacked {
                addr: 0x7000,
                len: 0x2000
            },
            "buffer into the hole is accepted"
        );
    }

    #[test]
    fn test_random_rings_no_panic() {
        // With random rings a walk ends in a checked chain or an error,
        // never a panic. Fixed xorshift seed keeps a failure reproducible.
        let mut state = 0x9e37_79b9_7f4a_7c15u64;
        let mut next = || {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            state
        };
        let ram = ram();
        for _ in 0..2000 {
            let mut bytes = vec![0u8; 0x2000];
            for chunk in bytes.chunks_mut(8) {
                let word = next().to_le_bytes();
                chunk.copy_from_slice(&word[..chunk.len()]);
            }
            ram.write(DESC_TABLE, &bytes).expect("write the table");

            let size = 1u16 << (next() % 9);
            let mut queue =
                Queue::new(size, DESC_TABLE, AVAIL_RING, USED_RING).expect("power of two");
            for _ in 0..size {
                match queue.pop(&ram) {
                    Ok(Some(chain)) => {
                        assert!(!chain.descriptors.is_empty());
                        assert!(chain.descriptors.len() <= usize::from(size));
                        for descriptor in &chain.descriptors {
                            assert!(
                                ram.holds(descriptor.addr, u64::from(descriptor.len)),
                                "chain holds an unbacked buffer"
                            );
                        }
                    }
                    Ok(None) => break,
                    Err(_) => continue,
                }
            }
        }
    }
}
