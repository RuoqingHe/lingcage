// SPDX-FileCopyrightText: 2026 LingCage <opensource@lingcage.com>
//
// SPDX-License-Identifier: Apache-2.0

//! Virtio-net device, with receive and transmit rings and the carrier
//! between them. Frame from transmit ring is given to the carrier with
//! its header removed, frame from the carrier is written into a receive
//! buffer after a header.

use std::os::fd::RawFd;

use log::warn;

use crate::devices::virtio::net::carrier::Carrier;
use crate::devices::virtio::net::frame::{Header, MAX_FRAME, ROOM};
use crate::devices::virtio::queue::{Chain, Queue};
use crate::devices::virtio::{Device, Error, Result};
use crate::hv::Interest;
use crate::mem::GuestRam;

/// Device ID of network device, `VIRTIO_ID_NET` in
/// `include/uapi/linux/virtio_ids.h`.
const NET: u32 = 1;

/// Queue indices, receiveq1 and transmitq1 in section 5.1.2 of virtio 1.2.
const RX: u16 = 0;
const TX: u16 = 1;
const QUEUES: u16 = 2;

// TODO: `VIRTIO_NET_F_CTRL_VQ` is not yet offered.
/// `VIRTIO_NET_F_MAC`, configuration space carries a MAC address. This is
/// the only feature offered, a frame requesting offload is refused.
const F_MAC: u64 = 1 << 5;

/// Length of MAC address, `ETH_ALEN`.
const MAC: usize = 6;

/// Virtio-net device, with the MAC address offered, the carrier, and the
/// frame in transfer in each direction.
pub struct Net {
    /// MAC address in configuration space. `None` means no `F_MAC` offered.
    mac: Option<[u8; MAC]>,
    carrier: Box<dyn Carrier>,
    /// Frame from transmit ring, header first.
    sending: Vec<u8>,
    /// Frame from the carrier. `waiting` is its length while it waits for a
    /// receive buffer.
    receiving: Vec<u8>,
    waiting: Option<usize>,
}

impl Net {
    /// Create the device with `mac` in its configuration space and `carrier`
    /// as the host end.
    pub fn new(mac: Option<[u8; MAC]>, carrier: Box<dyn Carrier>) -> Self {
        Net {
            mac,
            carrier,
            sending: vec![0u8; ROOM + MAX_FRAME],
            receiving: vec![0u8; MAX_FRAME],
            waiting: None,
        }
    }

    /// Give each frame of transmit ring to the carrier, with header removed.
    /// Ring is left alone while a frame is still going out.
    fn send(&mut self, queue: &mut Queue, ram: &GuestRam) -> Result<()> {
        // Rest of the last frame goes out first.
        if !self.carrier.resume().map_err(|_| Error::Request)? {
            return Ok(());
        }
        while let Some(chain) = queue.pop(ram)? {
            let Some(whole) = frame_from(&chain, ram, &mut self.sending)? else {
                // Chain too short for a header is reported used and ignored.
                queue.add_used(ram, chain.head, 0)?;
                continue;
            };
            if !self
                .carrier
                .give(&self.sending[ROOM..whole])
                .map_err(|refused| {
                    warn!("give failed: {refused}");
                    Error::Request
                })?
            {
                queue.undo_pop();
                return Ok(());
            }
            queue.add_used(ram, chain.head, 0)?;
        }
        Ok(())
    }

    /// Write each frame from the carrier into a receive buffer, header
    /// first. Frame without a buffer yet is held in `receiving`, and the
    /// carrier is not read again until it is written or dropped.
    fn receive(&mut self, queue: &mut Queue, ram: &GuestRam) -> Result<()> {
        loop {
            if self.waiting.is_none() {
                self.waiting = self.carrier.take(&mut self.receiving).map_err(|refused| {
                    warn!("take failed: {refused}");
                    Error::Request
                })?;
            }
            let Some(len) = self.waiting else {
                return Ok(());
            };
            let Some(chain) = queue.pop(ram)? else {
                return Ok(());
            };
            match frame_into(&chain, ram, &self.receiving[..len])? {
                Some(written) => queue.add_used(ram, chain.head, written)?,
                None => {
                    // Frame longer than the offered buffer is dropped, same
                    // as the driver would do. Buffer is put back for the
                    // next frame.
                    warn!("frame of {len} bytes dropped, longer than receive buffer");
                    queue.undo_pop();
                }
            }
            self.waiting = None;
        }
    }
}

impl Device for Net {
    fn device_id(&self) -> u32 {
        NET
    }

    fn features(&self) -> u64 {
        if self.mac.is_some() { F_MAC } else { 0 }
    }

    fn queue_count(&self) -> u16 {
        QUEUES
    }

    /// Returns bytes of `mac`, the first field of `struct virtio_net_config`.
    /// Read past it, or without an address, returns zero.
    fn read_config(&mut self, offset: u64, size: u8) -> u64 {
        let mac = self.mac.unwrap_or_default();
        let mut read = 0u64;
        for step in 0..u64::from(size) {
            let at = offset + step;
            let byte = mac.get(at as usize).copied().unwrap_or(0);
            read |= u64::from(byte) << (step * 8);
        }
        read
    }

    /// Returns descriptor of the carrier. `Read` is left out while a frame
    /// waits for a receive buffer, otherwise the descriptor would be
    /// reported ready on each wait with no frame taken.
    fn outside(&self) -> Vec<(RawFd, Interest)> {
        self.carrier
            .outside()
            .into_iter()
            .filter_map(|(fd, interest)| match (self.waiting.is_some(), interest) {
                (false, held) => Some((fd, held)),
                (true, Interest::Read) => None,
                (true, Interest::Write | Interest::Both) => Some((fd, Interest::Write)),
            })
            .collect()
    }

    fn notify(&mut self, index: u16, queue: &mut Queue, ram: &GuestRam) -> Result<()> {
        match index {
            TX => self.send(queue, ram),
            RX => self.receive(queue, ram),
            _ => Ok(()),
        }
    }

    /// Returns deadline of the carrier.
    fn wake_after(&self) -> Option<std::time::Duration> {
        self.carrier.wake_after()
    }
}

/// Read readable buffers of `chain` into `into`, header and frame in one
/// run. Returns bytes read, or `None` for a chain shorter than a header.
/// Header requesting offload is refused since none is offered.
fn frame_from(chain: &Chain, ram: &GuestRam, into: &mut [u8]) -> Result<Option<usize>> {
    let mut whole = 0usize;
    for descriptor in &chain.descriptors {
        if descriptor.writable() {
            continue;
        }
        let len = descriptor.len as usize;
        // `len` comes from the driver, the read is bounded by `into`.
        if whole + len > into.len() {
            return Err(Error::Request);
        }
        ram.read(descriptor.addr, &mut into[whole..whole + len])
            .map_err(|_| Error::Ring {
                gpa: descriptor.addr,
            })?;
        whole += len;
    }
    let Some(header) = Header::read(&into[..whole.min(ROOM)]) else {
        return Ok(None);
    };
    if header.asks_for_an_offload() {
        warn!("frame with offload header refused, no offload is offered");
        return Err(Error::Request);
    }
    Ok(Some(whole))
}

/// Write `frame` after a header into writable buffers of `chain`.
/// Returns bytes written, or `None` for a chain shorter than header plus
/// frame.
fn frame_into(chain: &Chain, ram: &GuestRam, frame: &[u8]) -> Result<Option<u32>> {
    let room: usize = chain
        .descriptors
        .iter()
        .filter(|descriptor| descriptor.writable())
        .map(|descriptor| descriptor.len as usize)
        .sum();
    if room < ROOM + frame.len() {
        return Ok(None);
    }

    // `num_buffers` is 1, a frame fills one chain and none is merged.
    let header = Header {
        num_buffers: 1,
        ..Header::default()
    };
    let mut whole = vec![0u8; ROOM + frame.len()];
    header.write(&mut whole);
    whole[ROOM..].copy_from_slice(frame);

    let mut written = 0usize;
    for descriptor in &chain.descriptors {
        if !descriptor.writable() || written == whole.len() {
            continue;
        }
        let room = (descriptor.len as usize).min(whole.len() - written);
        ram.write(descriptor.addr, &whole[written..written + room])
            .map_err(|_| Error::Ring {
                gpa: descriptor.addr,
            })?;
        written += room;
    }
    Ok(Some(written as u32))
}

#[cfg(test)]
mod tests {
    use std::io;
    use std::os::fd::AsRawFd;
    use std::os::unix::net::UnixStream;
    use std::sync::{Arc, Mutex};

    use crate::devices::virtio::net::device::*;

    const SIZE: u16 = 8;
    /// Descriptor table of each ring. `queue` puts available and used rings
    /// at `0x1000` and `0x2000` past it.
    const RX_RING: u64 = 0x1000;
    const TX_RING: u64 = 0x5000;
    const BUFFER: u64 = 0x9000;
    const RAM_SIZE: u64 = 0x20000;
    /// `VIRTQ_DESC_F_WRITE`, buffer is device-writable.
    const WRITE: u16 = 0x2;

    const ADDRESS: [u8; MAC] = [0x02, 0x11, 0x22, 0x33, 0x44, 0x55];

    /// Carrier in memory. Records frames given, returns frames queued in
    /// `bringing`, and takes `takes` frames before refusing.
    #[derive(Clone)]
    struct Wired {
        carried: Arc<Mutex<Vec<Vec<u8>>>>,
        bringing: Arc<Mutex<Vec<Vec<u8>>>>,
        /// Frames `give` still takes before returning `false`.
        takes: Arc<Mutex<usize>>,
        /// Returned by `resume`.
        clear: Arc<Mutex<bool>>,
        held: Arc<UnixStream>,
    }

    impl Wired {
        fn new(takes: usize) -> Self {
            Wired {
                carried: Arc::new(Mutex::new(Vec::new())),
                bringing: Arc::new(Mutex::new(Vec::new())),
                takes: Arc::new(Mutex::new(takes)),
                clear: Arc::new(Mutex::new(true)),
                held: Arc::new(UnixStream::pair().expect("socket pair").0),
            }
        }

        fn carried(&self) -> Vec<Vec<u8>> {
            self.carried.lock().unwrap().clone()
        }
    }

    impl Carrier for Wired {
        fn take(&mut self, into: &mut [u8]) -> io::Result<Option<usize>> {
            let mut bringing = self.bringing.lock().unwrap();
            if bringing.is_empty() {
                return Ok(None);
            }
            let frame = bringing.remove(0);
            into[..frame.len()].copy_from_slice(&frame);
            Ok(Some(frame.len()))
        }

        fn give(&mut self, frame: &[u8]) -> io::Result<bool> {
            let mut takes = self.takes.lock().unwrap();
            if *takes == 0 {
                return Ok(false);
            }
            *takes -= 1;
            self.carried.lock().unwrap().push(frame.to_vec());
            Ok(true)
        }

        fn resume(&mut self) -> io::Result<bool> {
            Ok(*self.clear.lock().unwrap())
        }

        fn outside(&self) -> Vec<(RawFd, Interest)> {
            vec![(self.held.as_raw_fd(), Interest::Read)]
        }
    }

    fn ram() -> GuestRam {
        GuestRam::new(&[(0, RAM_SIZE)]).expect("host pages")
    }

    fn queue(base: u64) -> Queue {
        Queue::new(SIZE, base, base + 0x1000, base + 0x2000).expect("ring")
    }

    fn describe(ram: &GuestRam, base: u64, index: u16, addr: u64, len: u32, flags: u16) {
        let mut bytes = [0u8; 16];
        bytes[0..8].copy_from_slice(&addr.to_le_bytes());
        bytes[8..12].copy_from_slice(&len.to_le_bytes());
        bytes[12..14].copy_from_slice(&flags.to_le_bytes());
        ram.write(base + u64::from(index) * 16, &bytes)
            .expect("write a descriptor");
    }

    fn publish(ram: &GuestRam, base: u64, slot: u16, head: u16, count: u16) {
        ram.write(base + 0x1000 + 4 + u64::from(slot) * 2, &head.to_le_bytes())
            .expect("publish a head");
        ram.write(base + 0x1000 + 2, &count.to_le_bytes())
            .expect("bump the index");
    }

    /// Post `frame` after `header` as available entry `slot` of transmit
    /// ring.
    fn guest_sends(ram: &GuestRam, slot: u16, header: &Header, frame: &[u8]) {
        let mut whole = vec![0u8; ROOM + frame.len()];
        header.write(&mut whole);
        whole[ROOM..].copy_from_slice(frame);
        let at = BUFFER + u64::from(slot) * 0x400;
        ram.write(at, &whole).expect("write the frame");
        describe(ram, TX_RING, slot, at, whole.len() as u32, 0);
        publish(ram, TX_RING, slot, slot, slot + 1);
    }

    /// Post one writable buffer of `0x400` bytes as available entry `slot`
    /// of receive ring.
    fn guest_offers(ram: &GuestRam, slot: u16) {
        let at = BUFFER + 0x8000 + u64::from(slot) * 0x400;
        describe(ram, RX_RING, slot, at, 0x400, WRITE);
        publish(ram, RX_RING, slot, slot, slot + 1);
    }

    /// Returns `len` bytes of the buffer of receive entry `slot`.
    fn guest_given(ram: &GuestRam, slot: u16, len: usize) -> Vec<u8> {
        let at = BUFFER + 0x8000 + u64::from(slot) * 0x400;
        let mut bytes = vec![0u8; len];
        ram.read(at, &mut bytes).expect("read the buffer");
        bytes
    }

    fn device(wired: &Wired) -> Net {
        Net::new(Some(ADDRESS), Box::new(wired.clone()))
    }

    #[test]
    fn test_mac_in_config_space() {
        let mut net = device(&Wired::new(0));
        assert_eq!(net.features(), F_MAC);
        let read = net.read_config(0, 6);
        for (step, byte) in ADDRESS.iter().enumerate() {
            assert_eq!((read >> (step * 8)) as u8, *byte, "byte {step}");
        }
    }

    #[test]
    fn test_no_mac_no_f_mac() {
        let net = Net::new(None, Box::new(Wired::new(0)));
        assert_eq!(net.features(), 0, "F_MAC offered without an address");
    }

    #[test]
    fn test_transmit_strips_header() {
        let wired = Wired::new(1);
        let mut net = device(&wired);
        let ram = ram();
        let mut tx = queue(TX_RING);

        guest_sends(&ram, 0, &Header::default(), b"a frame from the guest");
        net.notify(TX, &mut tx, &ram).expect("notify tx");
        assert_eq!(wired.carried(), vec![b"a frame from the guest".to_vec()]);
    }

    #[test]
    fn test_receive_into_offered_buffer() {
        let wired = Wired::new(0);
        let mut net = device(&wired);
        let ram = ram();
        let mut rx = queue(RX_RING);
        wired
            .bringing
            .lock()
            .unwrap()
            .push(b"a frame from the far end".to_vec());

        guest_offers(&ram, 0);
        net.notify(RX, &mut rx, &ram).expect("notify rx");
        let given = guest_given(&ram, 0, ROOM + 24);
        assert_eq!(
            Header::read(&given).expect("header"),
            Header {
                num_buffers: 1,
                ..Header::default()
            }
        );
        assert_eq!(&given[ROOM..], b"a frame from the far end");
    }

    #[test]
    fn test_frame_left_in_ring_while_sending() {
        let wired = Wired::new(1);
        let mut net = device(&wired);
        let ram = ram();
        let mut tx = queue(TX_RING);

        guest_sends(&ram, 0, &Header::default(), b"first");
        guest_sends(&ram, 1, &Header::default(), b"second");
        net.notify(TX, &mut tx, &ram).expect("notify tx");
        assert_eq!(wired.carried(), vec![b"first".to_vec()]);
        assert_eq!(
            tx.cursors().0,
            1,
            "refused frame was taken off the ring anyway"
        );

        // With room at the carrier, frame left in the ring is given next.
        *wired.takes.lock().unwrap() = 1;
        net.notify(TX, &mut tx, &ram).expect("notify tx again");
        assert_eq!(wired.carried(), vec![b"first".to_vec(), b"second".to_vec()]);
    }

    #[test]
    fn test_ring_untouched_while_part_written() {
        let wired = Wired::new(8);
        let mut net = device(&wired);
        let ram = ram();
        let mut tx = queue(TX_RING);
        *wired.clear.lock().unwrap() = false;

        guest_sends(&ram, 0, &Header::default(), b"a frame");
        net.notify(TX, &mut tx, &ram).expect("notify tx");
        assert!(
            wired.carried().is_empty(),
            "frame given behind a part-written one"
        );
        assert_eq!(tx.cursors().0, 0, "ring popped with a frame part-written");
    }

    #[test]
    fn test_hold_frame_until_buffer_offered() {
        // Read interest is dropped while a frame waits for a buffer.
        let wired = Wired::new(0);
        let mut net = device(&wired);
        let ram = ram();
        let mut rx = queue(RX_RING);
        wired.bringing.lock().unwrap().push(b"held".to_vec());

        net.notify(RX, &mut rx, &ram).expect("notify rx");
        assert_eq!(net.waiting, Some(4), "frame dropped with no buffer offered");
        assert!(
            net.outside().is_empty(),
            "Read kept with a frame waiting for buffer"
        );

        guest_offers(&ram, 0);
        net.notify(RX, &mut rx, &ram).expect("notify rx again");
        assert_eq!(net.waiting, None);
        assert_eq!(&guest_given(&ram, 0, ROOM + 4)[ROOM..], b"held");
        assert_eq!(
            net.outside().len(),
            1,
            "Read left out with no frame waiting"
        );
    }

    #[test]
    fn test_drop_frame_larger_than_buffer() {
        let wired = Wired::new(0);
        let mut net = device(&wired);
        let ram = ram();
        let mut rx = queue(RX_RING);
        // Longer than the `0x400` buffer posted by `guest_offers`.
        wired.bringing.lock().unwrap().push(vec![0xa5u8; 0x800]);
        wired
            .bringing
            .lock()
            .unwrap()
            .push(b"the one behind it".to_vec());

        guest_offers(&ram, 0);
        net.notify(RX, &mut rx, &ram)
            .expect("notify rx with outsized frame");
        assert_eq!(rx.cursors().1, 1, "buffer used up by the dropped frame");
        assert_eq!(
            &guest_given(&ram, 0, ROOM + 17)[ROOM..],
            b"the one behind it",
            "buffer went to the frame which fits"
        );
    }

    #[test]
    fn test_refuse_offload_header() {
        let wired = Wired::new(1);
        let mut net = device(&wired);
        let ram = ram();
        let mut tx = queue(TX_RING);

        let asking = Header {
            gso_type: 1,
            ..Header::default()
        };
        guest_sends(&ram, 0, &asking, b"a segmented frame");
        net.notify(TX, &mut tx, &ram)
            .expect_err("frame built for offload was carried");
        assert!(wired.carried().is_empty());
    }
}
