// SPDX-FileCopyrightText: 2026 LingCage <opensource@lingcage.com>
//
// SPDX-License-Identifier: Apache-2.0

//! Virtio block device, section 5.2 of virtio 1.2.
//!
//! A request chain is made of a 16-byte header, data buffers and one
//! writable status byte. Data may span several buffers.

use std::io::{self, Read, Seek, SeekFrom, Write};

use crate::devices::virtio::queue::{Chain, Descriptor, Queue};
use crate::devices::virtio::{Device, Error, Result};
use crate::mem::GuestRam;

/// Device ID of block device, section 5.2.
const DEVICE_ID: u32 = 2;
/// Sector size in bytes. Offsets and lengths are counted in sectors.
const SECTOR: u64 = 512;
/// Size of request header in bytes.
const HEADER_SIZE: u32 = 16;

/// `VIRTIO_BLK_F_FLUSH`, feature bit 9, flush requests are accepted.
const FEATURE_FLUSH: u64 = 1 << 9;

/// `VIRTIO_BLK_T_IN`, read sectors.
const REQUEST_IN: u32 = 0;
/// `VIRTIO_BLK_T_OUT`, write sectors.
const REQUEST_OUT: u32 = 1;
/// `VIRTIO_BLK_T_FLUSH`, flush written data to the disk.
const REQUEST_FLUSH: u32 = 4;

/// `VIRTIO_BLK_S_OK`.
const OK: u8 = 0;
/// `VIRTIO_BLK_S_IOERR`, disk failed the request.
const IOERR: u8 = 1;
/// `VIRTIO_BLK_S_UNSUPP`, request type or shape is not supported.
const UNSUPPORTED: u8 = 2;

/// Block device backed by a seekable `disk`.
pub struct Block<D> {
    disk: D,
    sectors: u64,
}

impl<D: Seek> Block<D> {
    /// Create a block device over `disk`. Its length is only read once here,
    /// a file which grows later is not read beyond the capacity reported.
    pub fn new(mut disk: D) -> io::Result<Self> {
        let bytes = disk.seek(SeekFrom::End(0))?;
        Ok(Block {
            disk,
            sectors: bytes / SECTOR,
        })
    }
}

/// Request header, `type` and `sector` fields of `virtio_blk_req`.
struct Header {
    kind: u32,
    sector: u64,
}

impl<D: Read + Write + Seek + Send> Device for Block<D> {
    fn device_id(&self) -> u32 {
        DEVICE_ID
    }

    fn features(&self) -> u64 {
        FEATURE_FLUSH
    }

    /// Returns bytes of the capacity field, which is the only field in the
    /// configuration space. Read past it returns zero.
    fn read_config(&mut self, offset: u64, size: u8) -> u64 {
        let capacity = self.sectors.to_le_bytes();
        let mut answer = [0u8; 8];
        for (index, byte) in answer.iter_mut().enumerate().take(usize::from(size).min(8)) {
            let at = usize::try_from(offset.saturating_add(index as u64));
            *byte = at
                .ok()
                .and_then(|at| capacity.get(at))
                .copied()
                .unwrap_or(0);
        }
        u64::from_le_bytes(answer)
    }

    /// Serve each request in `queue`. Chain without status byte is reported
    /// as `Error::Request`, any other fault is reported in the status byte.
    fn notify(&mut self, _index: u16, queue: &mut Queue, ram: &GuestRam) -> Result<()> {
        while let Some(chain) = queue.pop(ram)? {
            let answer = answer_in(&chain).ok_or(Error::Request)?;
            let (status, written) = self.serve(&chain, ram);
            ram.write(answer, &[status])
                .map_err(|_| Error::Ring { gpa: answer })?;
            queue.add_used(ram, chain.head, written + 1)?;
        }
        Ok(())
    }
}

impl<D: Read + Write + Seek> Block<D> {
    /// Serve one request. Returns the status byte and bytes written into
    /// guest RAM.
    fn serve(&mut self, chain: &Chain, ram: &GuestRam) -> (u8, u32) {
        let Some(header) = read_header(chain, ram) else {
            return (UNSUPPORTED, 0);
        };
        let data = &chain.descriptors[1..chain.descriptors.len() - 1];
        match header.kind {
            REQUEST_IN => self.transfer(header.sector, data, ram, true),
            REQUEST_OUT => self.transfer(header.sector, data, ram, false),
            REQUEST_FLUSH => match self.disk.flush() {
                Ok(()) => (OK, 0),
                Err(_) => (IOERR, 0),
            },
            // TODO: `VIRTIO_BLK_T_GET_ID` is not yet served.
            _ => (UNSUPPORTED, 0),
        }
    }

    /// Move `data` between disk and guest RAM starting from `sector`.
    fn transfer(
        &mut self,
        sector: u64,
        data: &[Descriptor],
        ram: &GuestRam,
        into_guest: bool,
    ) -> (u8, u32) {
        // Buffer direction must match the request, and total length must be
        // multiple of `SECTOR`.
        if data.iter().any(|d| d.writable() != into_guest) {
            return (UNSUPPORTED, 0);
        }
        let length: u64 = data.iter().map(|d| u64::from(d.len)).sum();
        if !length.is_multiple_of(SECTOR) {
            return (UNSUPPORTED, 0);
        }
        let Some(end) = sector.checked_add(length / SECTOR) else {
            return (IOERR, 0);
        };
        if end > self.sectors {
            return (IOERR, 0);
        }
        if self.disk.seek(SeekFrom::Start(sector * SECTOR)).is_err() {
            return (IOERR, 0);
        }

        let mut moved = 0u32;
        for descriptor in data {
            let mut bytes = vec![0u8; descriptor.len as usize];
            if into_guest {
                if self.disk.read_exact(&mut bytes).is_err()
                    || ram.write(descriptor.addr, &bytes).is_err()
                {
                    return (IOERR, moved);
                }
                moved += descriptor.len;
            } else if ram.read(descriptor.addr, &mut bytes).is_err()
                || self.disk.write_all(&bytes).is_err()
            {
                return (IOERR, moved);
            }
        }
        (OK, moved)
    }
}

/// Returns address of the status byte, which is the writable and
/// non-empty last descriptor of a chain with at least two descriptors.
fn answer_in(chain: &Chain) -> Option<u64> {
    let last = chain.descriptors.last()?;
    if chain.descriptors.len() < 2 || !last.writable() || last.len == 0 {
        return None;
    }
    Some(last.addr)
}

/// Read request header from the first descriptor, if it is readable and
/// at least `HEADER_SIZE` long.
fn read_header(chain: &Chain, ram: &GuestRam) -> Option<Header> {
    let first = chain.descriptors.first()?;
    if first.writable() || first.len < HEADER_SIZE {
        return None;
    }
    let mut bytes = [0u8; 16];
    ram.read(first.addr, &mut bytes).ok()?;
    Some(Header {
        kind: u32::from_le_bytes(bytes[0..4].try_into().expect("four bytes")),
        sector: u64::from_le_bytes(bytes[8..16].try_into().expect("eight bytes")),
    })
}

#[cfg(test)]
mod tests {
    use std::io::Cursor;

    use crate::devices::virtio::block::*;

    const RAM_SIZE: u64 = 0x10000;
    const DESC_TABLE: u64 = 0x1000;
    const AVAIL_RING: u64 = 0x2000;
    const USED_RING: u64 = 0x3000;
    const HEADER_AT: u64 = 0x4000;
    const DATA_AT: u64 = 0x5000;
    const STATUS_AT: u64 = 0x6000;
    /// `VIRTQ_DESC_F_NEXT` and `VIRTQ_DESC_F_WRITE`.
    const NEXT: u16 = 0x1;
    const WRITE: u16 = 0x2;
    /// Capacity of test disk in sectors.
    const SECTORS: u64 = 8;

    fn ram() -> GuestRam {
        GuestRam::new(&[(0, RAM_SIZE)]).expect("host pages")
    }

    fn disk() -> Block<Cursor<Vec<u8>>> {
        // Sector `n` is filled with byte `n`.
        let mut bytes = Vec::new();
        for sector in 0..SECTORS {
            bytes.extend(std::iter::repeat_n(sector as u8, SECTOR as usize));
        }
        Block::new(Cursor::new(bytes)).expect("measure the disk")
    }

    fn describe(ram: &GuestRam, index: u16, addr: u64, len: u32, flags: u16, next: u16) {
        let mut bytes = [0u8; 16];
        bytes[0..8].copy_from_slice(&addr.to_le_bytes());
        bytes[8..12].copy_from_slice(&len.to_le_bytes());
        bytes[12..14].copy_from_slice(&flags.to_le_bytes());
        bytes[14..16].copy_from_slice(&next.to_le_bytes());
        ram.write(DESC_TABLE + u64::from(index) * 16, &bytes)
            .expect("descriptor");
    }

    /// Post a `kind` request at `sector` with one buffer per `(len,
    /// writable)` in `data`, as available entry `slot`.
    fn request(ram: &GuestRam, kind: u32, sector: u64, data: &[(u32, bool)], slot: u16) {
        let mut header = [0u8; 16];
        header[0..4].copy_from_slice(&kind.to_le_bytes());
        header[8..16].copy_from_slice(&sector.to_le_bytes());
        ram.write(HEADER_AT, &header).expect("header");

        let last = data.len() as u16 + 1;
        describe(ram, 0, HEADER_AT, 16, NEXT, 1);
        let mut at = DATA_AT;
        for (index, &(len, writable)) in data.iter().enumerate() {
            let flags = NEXT | if writable { WRITE } else { 0 };
            describe(ram, index as u16 + 1, at, len, flags, index as u16 + 2);
            at += u64::from(len);
        }
        describe(ram, last, STATUS_AT, 1, WRITE, 0);

        ram.write(AVAIL_RING + 4 + u64::from(slot) * 2, &0u16.to_le_bytes())
            .expect("head");
        ram.write(AVAIL_RING + 2, &(slot + 1).to_le_bytes())
            .expect("index");
    }

    fn status(ram: &GuestRam) -> u8 {
        let mut byte = [0u8; 1];
        ram.read(STATUS_AT, &mut byte).expect("status byte");
        byte[0]
    }

    /// Returns `len` field of used ring element `slot`.
    fn reported(ram: &GuestRam, slot: u64) -> u32 {
        let mut bytes = [0u8; 4];
        ram.read(USED_RING + 8 + slot * 8, &mut bytes)
            .expect("used ring");
        u32::from_le_bytes(bytes)
    }

    fn queue() -> Queue {
        Queue::new(8, DESC_TABLE, AVAIL_RING, USED_RING).expect("ring")
    }

    #[test]
    fn test_capacity_config() {
        let mut block = disk();
        assert_eq!(block.read_config(0, 8), SECTORS);
        // Two 4-byte reads give the same capacity.
        assert_eq!(block.read_config(0, 4), SECTORS);
        assert_eq!(block.read_config(4, 4), 0);
        // Read past the field returns zero.
        assert_eq!(block.read_config(64, 4), 0);
    }

    #[test]
    fn test_read_sector() {
        let ram = ram();
        let mut queue = queue();
        let mut block = disk();

        request(&ram, REQUEST_IN, 3, &[(SECTOR as u32, true)], 0);
        block.notify(0, &mut queue, &ram).expect("notify");

        let mut read = vec![0u8; SECTOR as usize];
        ram.read(DATA_AT, &mut read).expect("buffer");
        assert_eq!(read, vec![3u8; SECTOR as usize], "wrong sector read");
        assert_eq!(status(&ram), OK);
        assert_eq!(
            reported(&ram, 0),
            SECTOR as u32 + 1,
            "status byte not counted"
        );
    }

    #[test]
    fn test_read_across_buffers() {
        let ram = ram();
        let mut queue = queue();
        let mut block = disk();

        // Three sectors in three buffers.
        request(
            &ram,
            REQUEST_IN,
            1,
            &[
                (SECTOR as u32, true),
                (SECTOR as u32, true),
                (SECTOR as u32, true),
            ],
            0,
        );
        block.notify(0, &mut queue, &ram).expect("notify");

        let mut read = vec![0u8; 3 * SECTOR as usize];
        ram.read(DATA_AT, &mut read).expect("buffers");
        assert_eq!(&read[..512], &[1u8; 512]);
        assert_eq!(&read[512..1024], &[2u8; 512]);
        assert_eq!(&read[1024..], &[3u8; 512]);
        assert_eq!(status(&ram), OK);
        assert_eq!(reported(&ram, 0), 3 * SECTOR as u32 + 1);
    }

    #[test]
    fn test_write_sector() {
        let ram = ram();
        let mut queue = queue();
        let mut block = disk();

        ram.write(DATA_AT, &[0xa5u8; SECTOR as usize])
            .expect("fill the buffer");
        request(&ram, REQUEST_OUT, 5, &[(SECTOR as u32, false)], 0);
        block.notify(0, &mut queue, &ram).expect("notify");

        assert_eq!(status(&ram), OK);
        // Write leaves guest RAM untouched, used length is the status byte.
        assert_eq!(reported(&ram, 0), 1);
        let written = &block.disk.get_ref()[5 * SECTOR as usize..6 * SECTOR as usize];
        assert_eq!(written, [0xa5u8; SECTOR as usize]);
    }

    #[test]
    fn test_reject_read_past_end() {
        let ram = ram();
        let mut queue = queue();
        let mut block = disk();

        // Two sectors from `SECTORS - 1` end one past the disk.
        request(
            &ram,
            REQUEST_IN,
            SECTORS - 1,
            &[(2 * SECTOR as u32, true)],
            0,
        );
        block.notify(0, &mut queue, &ram).expect("notify");
        assert_eq!(status(&ram), IOERR);

        // Start of `u64::MAX` overflows the end computation.
        request(&ram, REQUEST_IN, u64::MAX, &[(SECTOR as u32, true)], 1);
        block.notify(0, &mut queue, &ram).expect("notify");
        assert_eq!(status(&ram), IOERR, "sector past the end was read");
    }

    #[test]
    fn test_reject_write_past_end() {
        // A refused write does not grow the backing file.
        let ram = ram();
        let mut queue = queue();
        let mut block = disk();
        let before = block.disk.get_ref().len();

        // Write past the end would grow the backing file, so range check
        // refuses it before the seek.
        request(&ram, REQUEST_OUT, SECTORS, &[(SECTOR as u32, false)], 0);
        block.notify(0, &mut queue, &ram).expect("notify");
        assert_eq!(status(&ram), IOERR);
        assert_eq!(
            block.disk.get_ref().len(),
            before,
            "write past the end grew the backing file"
        );

        // Write starting inside the disk but ending past it is refused too.
        request(
            &ram,
            REQUEST_OUT,
            SECTORS - 1,
            &[(2 * SECTOR as u32, false)],
            1,
        );
        block.notify(0, &mut queue, &ram).expect("notify");
        assert_eq!(status(&ram), IOERR);
        assert_eq!(block.disk.get_ref().len(), before);
    }

    #[test]
    fn test_reject_partial_sector() {
        let ram = ram();
        let mut queue = queue();
        let mut block = disk();

        request(&ram, REQUEST_IN, 0, &[(100, true)], 0);
        block.notify(0, &mut queue, &ram).expect("notify");
        assert_eq!(status(&ram), UNSUPPORTED);
    }

    #[test]
    fn test_reject_wrong_direction() {
        let ram = ram();
        let mut queue = queue();
        let mut block = disk();

        // Read into a device-readable buffer is refused.
        request(&ram, REQUEST_IN, 0, &[(SECTOR as u32, false)], 0);
        block.notify(0, &mut queue, &ram).expect("notify");
        assert_eq!(status(&ram), UNSUPPORTED);

        // Write out of a device-writable buffer is refused.
        request(&ram, REQUEST_OUT, 0, &[(SECTOR as u32, true)], 1);
        block.notify(0, &mut queue, &ram).expect("notify");
        assert_eq!(status(&ram), UNSUPPORTED);
    }

    #[test]
    fn test_unsupported_request_type() {
        let ram = ram();
        let mut queue = queue();
        let mut block = disk();

        request(&ram, 0xdead, 0, &[(SECTOR as u32, true)], 0);
        block.notify(0, &mut queue, &ram).expect("notify");
        assert_eq!(status(&ram), UNSUPPORTED);
        assert_eq!(reported(&ram, 0), 1, "unsupported request moved bytes");
    }

    #[test]
    fn test_flush_without_data() {
        let ram = ram();
        let mut queue = queue();
        let mut block = disk();

        request(&ram, REQUEST_FLUSH, 0, &[], 0);
        block.notify(0, &mut queue, &ram).expect("notify");
        assert_eq!(status(&ram), OK);
    }

    #[test]
    fn test_chain_without_status_byte() {
        let ram = ram();
        let mut queue = queue();
        let mut block = disk();

        // Single read-only descriptor leaves no status byte to write.
        describe(&ram, 0, HEADER_AT, 16, 0, 0);
        ram.write(AVAIL_RING + 4, &0u16.to_le_bytes())
            .expect("head");
        ram.write(AVAIL_RING + 2, &1u16.to_le_bytes())
            .expect("index");

        assert_eq!(
            block.notify(0, &mut queue, &ram).unwrap_err(),
            Error::Request
        );
    }
}
