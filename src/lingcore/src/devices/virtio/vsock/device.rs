// SPDX-FileCopyrightText: 2026 LingCage <opensource@lingcage.com>
//
// SPDX-License-Identifier: Apache-2.0

//! Vsock device, with open connections and the two rings they are
//! served over. Packet from transmit ring goes to the connection it
//! addresses, bytes read from a host end fill buffers of receive ring.

use std::collections::HashMap;
use std::io::{self, Read};
use std::os::fd::RawFd;
use std::time::{Duration, Instant};

use log::warn;

use crate::devices::virtio::queue::{Chain, Queue};
use crate::devices::virtio::vsock::connection::{Answer, Connection};
use crate::devices::virtio::vsock::host::{self, Endpoint, Stream};
use crate::devices::virtio::vsock::packet::{HOST_CID, Header, Op, ROOM, STREAM};
use crate::devices::virtio::{Device, Error, Result};
use crate::hv::Interest;
use crate::mem::GuestRam;

// TODO: `VIRTIO_VSOCK_F_SEQPACKET` is not yet offered.
/// Device ID of socket device, `VIRTIO_ID_VSOCK` in
/// `include/uapi/linux/virtio_ids.h`.
const VSOCK: u32 = 19;

/// Queue indices, the `VSOCK_VQ_*` enum in
/// `drivers/net/vmw_vsock/virtio_transport.c`.
const RX: u16 = 0;
const TX: u16 = 1;
const EVT: u16 = 2;
const QUEUES: u16 = 3;

/// `VIRTIO_VSOCK_EVENT_TRANSPORT_RESET` in
/// `include/uapi/linux/virtio_vsock.h`. On this event the guest closes
/// open connections and keeps listening ones, under the new CID.
const TRANSPORT_RESET: u32 = 0;

/// Largest payload of one packet, `VIRTIO_VSOCK_MAX_PKT_BUF_SIZE`.
const PACKET: usize = 64 * 1024;

/// Bit set in each host port assigned to an incoming connection, to keep
/// it out of the range a guest connects to.
const HOST_SIDE: u32 = 1 << 30;

/// Longest time a connection waits for a packet from the guest before
/// it is reset.
const PATIENCE: Duration = Duration::from_secs(2);

/// Maximum connections open at once. Guest request beyond it is reset,
/// incoming connections wait at the endpoint.
const CONNECTIONS: usize = 1024;

/// Open connection with its host stream.
struct Held {
    connection: Connection,
    stream: Box<dyn Stream>,
    /// Moment the connection was first found waiting on the guest. `None`
    /// while it is not waiting.
    since: Option<Instant>,
}

/// Vsock device, with context id of the guest, the endpoint its
/// connections are opened on, and the open connections.
pub struct Vsock {
    guest_cid: u64,
    endpoint: Box<dyn Endpoint>,
    /// Open connections keyed by guest port and host port.
    open: HashMap<(u32, u32), Held>,
    /// Packets for receive ring, held until the guest offers a buffer. Their
    /// bytes are already read from the host end.
    waiting: Vec<(Header, Vec<u8>)>,
    /// Host port assigned to the last incoming connection.
    last_port: u32,
    /// Transport reset pending for the guest. Each restore sets it, posting
    /// the event to event queue clears it.
    reset_owed: bool,
}

impl Vsock {
    /// Create the device for the guest at `guest_cid`, connections are
    /// opened on `endpoint`.
    pub fn new(guest_cid: u64, endpoint: Box<dyn Endpoint>) -> Self {
        Vsock {
            guest_cid,
            endpoint,
            open: HashMap::new(),
            waiting: Vec::new(),
            last_port: 0,
            reset_owed: false,
        }
    }

    /// Returns a host port without connection to `guest_port`. Up to
    /// `CONNECTIONS` ports are tried, which is more than can be open at
    /// once.
    fn free_port(&mut self, guest_port: u32) -> u32 {
        for _ in 0..CONNECTIONS {
            self.last_port = (self.last_port.wrapping_add(1) & !(1 << 31)) | HOST_SIDE;
            if !self.open.contains_key(&(guest_port, self.last_port)) {
                break;
            }
        }
        self.last_port
    }

    /// Open a connection for each incoming connection at the endpoint and
    /// queue its request to the guest. At `CONNECTIONS` open, incoming
    /// connections are left at the endpoint.
    fn take_incoming(&mut self) {
        while self.open.len() < CONNECTIONS {
            let Some((guest_port, stream)) = self.endpoint.incoming() else {
                return;
            };
            let host_port = self.free_port(guest_port);
            let connection = Connection::asking(self.guest_cid, guest_port, host_port);
            let asks = connection.asks();
            self.open.insert(
                (guest_port, host_port),
                Held {
                    connection,
                    stream,
                    since: None,
                },
            );
            self.owe(asks, Vec::new());
        }
    }

    /// Reset each connection which has waited on the guest for `PATIENCE`,
    /// counted from the first call which found it waiting. `now` is the
    /// clock of the caller.
    fn expire(&mut self, now: Instant) {
        let mut over = Vec::new();
        for (ports, held) in &mut self.open {
            if !held.connection.waiting_on_guest() {
                held.since = None;
                continue;
            }
            let since = *held.since.get_or_insert(now);
            if now.saturating_duration_since(since) >= PATIENCE {
                over.push(*ports);
            }
        }
        let mut owed = Vec::new();
        for ports in over {
            if let Some(mut held) = self.open.remove(&ports) {
                warn!(
                    "connection on port {} reset, guest did not answer in time",
                    ports.1
                );
                owed.push(held.connection.host_done());
            }
        }
        for header in owed {
            self.owe(header, Vec::new());
        }
    }

    /// Queue a packet for the receive ring.
    fn owe(&mut self, header: Header, payload: Vec<u8>) {
        self.waiting.push((header, payload));
    }

    /// Handle one packet from the transmit ring.
    fn took(&mut self, header: &Header, payload: &[u8]) {
        // Packet for another CID or of another kind is reset, not dropped.
        if header.dst_cid != HOST_CID || header.kind != STREAM {
            self.owe(header.answer(Op::Reset), Vec::new());
            return;
        }
        let ports = (header.src_port, header.dst_port);
        if let Some(Held {
            connection, stream, ..
        }) = self.open.get_mut(&ports)
        {
            let answer = connection.guest_sent(header, payload);
            let mut done = connection.done();
            let mut reply = None;
            match answer {
                Answer::Reply(header) => reply = Some(header),
                // `OK <port>` is written before bytes of the guest are carried,
                // host end refusing it is closed.
                Answer::Opened => {
                    let host_port = connection.ports().1;
                    if let Err(refused) = host::acknowledge(stream.as_mut(), host_port) {
                        warn!(
                            "acknowledging an incoming connection failed, connection closed: \
                             {refused}"
                        );
                        reply = Some(connection.host_done());
                        done = true;
                    }
                }
                // Bytes stay in the connection until `carry` writes them.
                Answer::Took => {}
                Answer::Drop => {}
                Answer::Nothing => {}
            }
            if let Some(reply) = reply {
                self.owe(reply, Vec::new());
            }
            if done {
                self.open.remove(&ports);
            }
            return;
        }
        // No connection on these ports. Request opens one, any other packet
        // is reset, so that a stale connection in the guest gets closed.
        if header.op != Op::Request {
            self.owe(header.answer(Op::Reset), Vec::new());
            return;
        }
        // The limit counts connections of both ends.
        if self.open.len() >= CONNECTIONS {
            warn!(
                "guest request for port {} reset, connection limit reached",
                header.dst_port
            );
            self.owe(header.answer(Op::Reset), Vec::new());
            return;
        }
        match self.endpoint.connect(header.dst_port) {
            Some(stream) => {
                let connection = Connection::new(self.guest_cid, header);
                let opened = connection.opened();
                self.open.insert(
                    ports,
                    Held {
                        connection,
                        stream,
                        since: None,
                    },
                );
                self.owe(opened, Vec::new());
            }
            None => self.owe(header.answer(Op::Reset), Vec::new()),
        }
    }

    /// Write waiting bytes of each connection to its host end as far as it
    /// takes them, and queue `CreditUpdate` for bytes written. Host end
    /// taking zero bytes keeps its connection, failed host end is closed
    /// with a reset.
    fn carry(&mut self) {
        let mut gone = Vec::new();
        let mut owed = Vec::new();
        for (ports, held) in &mut self.open {
            let (connection, stream) = (&mut held.connection, &mut held.stream);
            let waiting = connection.waiting();
            if waiting.is_empty() {
                continue;
            }
            match host::write(stream.as_mut(), waiting) {
                Ok(0) => {}
                Ok(count) => owed.push(connection.forwarded(count)),
                Err(_) => gone.push(*ports),
            }
        }
        for ports in gone {
            if let Some(mut held) = self.open.remove(&ports) {
                owed.push(held.connection.host_done());
            }
        }
        for header in owed {
            self.owe(header, Vec::new());
        }
    }

    /// Read each host stream up to the credit of its connection and queue
    /// the bytes for receive ring. Stream at end of stream or failed is
    /// closed with a reset.
    pub fn pump(&mut self) {
        let mut gone = Vec::new();
        let mut owed = Vec::new();
        for (ports, held) in &mut self.open {
            let (connection, stream) = (&mut held.connection, &mut held.stream);
            let room = connection.room().min(PACKET as u32);
            if room == 0 {
                continue;
            }
            let mut taken = vec![0u8; room as usize];
            match stream.read(&mut taken) {
                // Zero means end of stream, host end has closed.
                Ok(0) => gone.push(*ports),
                Ok(count) => {
                    taken.truncate(count);
                    owed.push((connection.host_sent(count as u32), taken));
                }
                // No bytes ready, stream stays open.
                Err(err) if err.kind() == io::ErrorKind::WouldBlock => {}
                Err(_) => gone.push(*ports),
            }
        }
        for ports in gone {
            if let Some(mut held) = self.open.remove(&ports) {
                owed.push((held.connection.host_done(), Vec::new()));
            }
        }
        for (header, payload) in owed {
            self.owe(header, payload);
        }
    }

    /// Write held packets into receive ring, one per chain, until packets
    /// or chains run out.
    fn give(&mut self, queue: &mut Queue, ram: &GuestRam) -> Result<()> {
        while !self.waiting.is_empty() {
            let Some(chain) = queue.pop(ram)? else {
                // No buffer offered, the rest stays in `waiting`.
                return Ok(());
            };
            let (header, payload) = self.waiting.remove(0);
            let written = write_packet(&chain, ram, &header, &payload)?;
            queue.add_used(ram, chain.head, written)?;
        }
        Ok(())
    }

    /// Read each chain of transmit ring and handle its packet.
    fn take(&mut self, queue: &mut Queue, ram: &GuestRam) -> Result<()> {
        while let Some(chain) = queue.pop(ram)? {
            // Chain too short for a header is reported used and ignored.
            if let Some((header, payload)) = read_packet(&chain, ram)? {
                self.took(&header, &payload);
            }
            queue.add_used(ram, chain.head, 0)?;
        }
        Ok(())
    }

    /// Post the owed transport reset event to event queue. Event stays owed
    /// while the guest has posted no buffer.
    fn post_reset(&mut self, queue: &mut Queue, ram: &GuestRam) -> Result<()> {
        if !self.reset_owed {
            return Ok(());
        }
        let Some(chain) = queue.pop(ram)? else {
            return Ok(());
        };
        let written = write_event(&chain, ram, TRANSPORT_RESET)?;
        queue.add_used(ram, chain.head, written)?;
        self.reset_owed = false;
        Ok(())
    }
}

impl Device for Vsock {
    fn device_id(&self) -> u32 {
        VSOCK
    }

    fn queue_count(&self) -> u16 {
        QUEUES
    }

    /// Returns bytes of `guest_cid`, the only field of configuration space
    /// (`struct virtio_vsock_config`). Read past it returns zero.
    fn read_config(&mut self, offset: u64, size: u8) -> u64 {
        let bytes = self.guest_cid.to_le_bytes();
        let mut read = 0u64;
        for step in 0..u64::from(size) {
            let at = offset + step;
            let byte = bytes.get(at as usize).copied().unwrap_or(0);
            read |= u64::from(byte) << (step * 8);
        }
        read
    }

    /// Returns descriptors of the endpoint while below `CONNECTIONS` open,
    /// plus host end of each open connection, with `Read` while the guest
    /// has room, `Write` while bytes wait for the host end, and `Both` for
    /// both. One with neither is left out until credit of the guest arrives
    /// on the ring.
    fn outside(&self) -> Vec<(RawFd, Interest)> {
        // At `CONNECTIONS` open, endpoint is not waited on.
        let mut waited = if self.open.len() < CONNECTIONS {
            self.endpoint.outside()
        } else {
            Vec::new()
        };
        for held in self.open.values() {
            let Some(fd) = held.stream.descriptor() else {
                continue;
            };
            let interest = match (
                held.connection.room() > 0,
                !held.connection.waiting().is_empty(),
            ) {
                (true, true) => Interest::Both,
                (true, false) => Interest::Read,
                (false, true) => Interest::Write,
                (false, false) => continue,
            };
            waited.push((fd, interest));
        }
        waited
    }

    fn notify(&mut self, index: u16, queue: &mut Queue, ram: &GuestRam) -> Result<()> {
        match index {
            TX => {
                self.take(queue, ram)?;
                self.take_incoming();
                self.carry();
                self.pump();
                self.expire(Instant::now());
            }
            RX => {
                self.take_incoming();
                // Host end full at the last `carry` may take bytes now.
                self.carry();
                self.pump();
                self.expire(Instant::now());
                self.give(queue, ram)?;
            }
            EVT => self.post_reset(queue, ram)?,
            _ => {}
        }
        Ok(())
    }

    fn restored(&mut self, index: u16, queue: &mut Queue, ram: &GuestRam) -> Result<()> {
        // Connections open at the host end and packets held for the guest
        // are from before the restore. Both are dropped, and host ends are
        // closed with them.
        self.open.clear();
        self.waiting.clear();
        // One reset per restore, only posted on the event queue. Call of
        // each queue sets the flag, call of this queue reads it.
        self.reset_owed = true;
        if index == EVT {
            self.post_reset(queue, ram)?;
        }
        Ok(())
    }
}

/// Read header and payload from readable descriptors of `chain`. Returns
/// `None` when `Header::read` refuses the bytes.
fn read_packet(chain: &Chain, ram: &GuestRam) -> Result<Option<(Header, Vec<u8>)>> {
    let mut whole = Vec::new();
    for descriptor in &chain.descriptors {
        if descriptor.writable() {
            continue;
        }
        // `descriptor.len` decides a host allocation, so total is capped at a
        // header plus the largest payload.
        if whole.len() + descriptor.len as usize > ROOM + PACKET {
            return Err(Error::Request);
        }
        let mut part = vec![0u8; descriptor.len as usize];
        ram.read(descriptor.addr, &mut part)
            .map_err(|_| Error::Ring {
                gpa: descriptor.addr,
            })?;
        whole.extend_from_slice(&part);
    }
    let Some(header) = Header::read(&whole) else {
        return Ok(None);
    };
    let payload = whole.get(ROOM..).unwrap_or(&[]).to_vec();
    Ok(Some((header, payload)))
}

/// Write the packet into writable descriptors of `chain`. Returns bytes
/// written.
fn write_packet(chain: &Chain, ram: &GuestRam, header: &Header, payload: &[u8]) -> Result<u32> {
    let mut whole = vec![0u8; ROOM + payload.len()];
    header.write(&mut whole);
    whole[ROOM..].copy_from_slice(payload);
    write_fully(chain, ram, &whole)
}

/// Write the event into writable descriptors of `chain`, laid out as
/// `struct virtio_vsock_event` in `include/uapi/linux/virtio_vsock.h`,
/// only the id in little endian. Returns bytes written.
fn write_event(chain: &Chain, ram: &GuestRam, id: u32) -> Result<u32> {
    write_fully(chain, ram, &id.to_le_bytes())
}

/// Write `whole` into writable descriptors of `chain`. Returns bytes
/// written, or `Error::Request` if the chain is too short for them.
fn write_fully(chain: &Chain, ram: &GuestRam, whole: &[u8]) -> Result<u32> {
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
    // Partial write would read as a shorter message than the one sent.
    if written != whole.len() {
        return Err(Error::Request);
    }
    Ok(written as u32)
}

#[cfg(test)]
mod tests {
    use std::io;
    use std::os::fd::AsRawFd;
    use std::sync::{Arc, Mutex};

    use crate::devices::virtio::vsock::connection::WINDOW;
    use crate::devices::virtio::vsock::device::*;

    const GUEST_CID: u64 = 3;
    const GUEST_PORT: u32 = 1024;
    const OPEN_PORT: u32 = 5555;
    const SHUT_PORT: u32 = 5556;

    /// `VIRTQ_DESC_F_WRITE`, buffer is device-writable.
    const WRITE: u16 = 0x2;

    const SIZE: u16 = 8;
    /// Descriptor table of each ring. `queue` puts available and used rings
    /// at `0x1000` and `0x2000` past it.
    const TX_RING: u64 = 0x1000;
    const RX_RING: u64 = 0x5000;
    const EVT_RING: u64 = 0x1_5000;
    const BUFFER: u64 = 0x9000;
    const EVENT_BUFFER: u64 = 0x1_9000;
    const RAM_SIZE: u64 = 0x20000;

    /// Host stream with separate buffer per direction.
    #[derive(Clone, Default)]
    struct Landed {
        /// Bytes written by the guest.
        taken: Arc<Mutex<Vec<u8>>>,
        /// Bytes for the guest to read.
        ready: Arc<Mutex<Vec<u8>>>,
        /// Set once the far end has closed.
        gone: Arc<Mutex<bool>>,
    }

    impl io::Write for Landed {
        fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
            self.taken.lock().unwrap().extend_from_slice(bytes);
            Ok(bytes.len())
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    impl Stream for Landed {
        /// In memory, no descriptor to wait on.
        fn descriptor(&self) -> Option<RawFd> {
            None
        }
    }

    impl Stream for Backed {
        fn descriptor(&self) -> Option<RawFd> {
            None
        }
    }

    impl io::Read for Landed {
        fn read(&mut self, into: &mut [u8]) -> io::Result<usize> {
            let mut held = self.ready.lock().unwrap();
            if held.is_empty() {
                // Read like a socket does, `WouldBlock` with no bytes ready
                // and zero once the other end has closed.
                return if *self.gone.lock().unwrap() {
                    Ok(0)
                } else {
                    Err(io::Error::from(io::ErrorKind::WouldBlock))
                };
            }
            let taken = held.len().min(into.len());
            into[..taken].copy_from_slice(&held[..taken]);
            held.drain(..taken);
            Ok(taken)
        }
    }

    /// Host end refusing each write with `WouldBlock` while `full` is set.
    #[derive(Clone, Default)]
    struct Backed {
        taken: Arc<Mutex<Vec<u8>>>,
        full: Arc<Mutex<bool>>,
    }

    impl io::Write for Backed {
        fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
            if *self.full.lock().unwrap() {
                return Err(io::Error::from(io::ErrorKind::WouldBlock));
            }
            self.taken.lock().unwrap().extend_from_slice(bytes);
            Ok(bytes.len())
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    impl io::Read for Backed {
        fn read(&mut self, _into: &mut [u8]) -> io::Result<usize> {
            Err(io::Error::from(io::ErrorKind::WouldBlock))
        }
    }

    /// Endpoint serving `OPEN_PORT` with a `Backed`.
    struct Backs(Backed);

    impl Endpoint for Backs {
        fn connect(&self, port: u32) -> Option<Box<dyn Stream>> {
            (port == OPEN_PORT).then(|| Box::new(self.0.clone()) as Box<dyn Stream>)
        }

        fn incoming(&mut self) -> Option<(u32, Box<dyn Stream>)> {
            None
        }

        fn outside(&self) -> Vec<(RawFd, Interest)> {
            Vec::new()
        }
    }

    /// Endpoint with incoming connections waiting, counts the calls to
    /// `incoming`.
    struct Incoming {
        waiting: Vec<(u32, Landed)>,
        asked: Arc<Mutex<usize>>,
        /// Stands in for the socket incoming connections arrive on.
        arrives_on: Arc<std::os::unix::net::UnixStream>,
    }

    impl Endpoint for Incoming {
        fn connect(&self, _port: u32) -> Option<Box<dyn Stream>> {
            None
        }

        fn incoming(&mut self) -> Option<(u32, Box<dyn Stream>)> {
            *self.asked.lock().unwrap() += 1;
            let (port, landed) = self.waiting.pop()?;
            Some((port, Box::new(landed)))
        }

        fn outside(&self) -> Vec<(RawFd, Interest)> {
            vec![(self.arrives_on.as_raw_fd(), Interest::Read)]
        }
    }

    /// Endpoint serving `OPEN_PORT` only.
    struct OnePort(Landed);

    impl Endpoint for OnePort {
        fn connect(&self, port: u32) -> Option<Box<dyn Stream>> {
            (port == OPEN_PORT).then(|| Box::new(self.0.clone()) as Box<dyn Stream>)
        }

        fn incoming(&mut self) -> Option<(u32, Box<dyn Stream>)> {
            None
        }

        fn outside(&self) -> Vec<(RawFd, Interest)> {
            Vec::new()
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

    /// Post a packet for `port` as available entry `slot` of transmit ring.
    fn guest_sends(ram: &GuestRam, slot: u16, op: Op, port: u32, payload: &[u8]) {
        let header = Header {
            src_cid: GUEST_CID,
            dst_cid: HOST_CID,
            src_port: GUEST_PORT,
            dst_port: port,
            len: payload.len() as u32,
            kind: STREAM,
            op,
            flags: 0,
            buf_alloc: WINDOW,
            fwd_cnt: 0,
        };
        let mut whole = vec![0u8; ROOM + payload.len()];
        header.write(&mut whole);
        whole[ROOM..].copy_from_slice(payload);
        let at = BUFFER + u64::from(slot) * 0x400;
        ram.write(at, &whole).expect("write the packet");
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

    /// Returns the header written into buffer of receive entry `slot`.
    fn guest_given(ram: &GuestRam, slot: u16) -> Header {
        let at = BUFFER + 0x8000 + u64::from(slot) * 0x400;
        let mut bytes = [0u8; ROOM];
        ram.read(at, &mut bytes).expect("read the buffer");
        Header::read(&bytes).expect("header")
    }

    /// Post one writable buffer as available entry `slot` of event ring.
    /// Size is one `event_list` entry of the driver, one event.
    fn guest_offers_event(ram: &GuestRam, slot: u16) {
        let at = EVENT_BUFFER + u64::from(slot) * 0x400;
        describe(ram, EVT_RING, slot, at, 4, WRITE);
        publish(ram, EVT_RING, slot, slot, slot + 1);
    }

    /// Returns id of the event in the buffer of entry `slot`.
    fn event_given(ram: &GuestRam, slot: u16) -> u32 {
        let at = EVENT_BUFFER + u64::from(slot) * 0x400;
        let mut bytes = [0u8; 4];
        ram.read(at, &mut bytes).expect("read the event");
        u32::from_le_bytes(bytes)
    }

    fn device(landed: &Landed) -> Vsock {
        Vsock::new(GUEST_CID, Box::new(OnePort(landed.clone())))
    }

    #[test]
    fn test_device_id_and_config() {
        let mut vsock = device(&Landed::default());
        assert_eq!(vsock.device_id(), VSOCK);
        // Three queues, event queue included.
        assert_eq!(vsock.queue_count(), QUEUES);
        assert_eq!(vsock.read_config(0, 8), GUEST_CID);
    }

    #[test]
    fn test_connect_and_send_to_host() {
        let landed = Landed::default();
        let mut vsock = device(&landed);
        let ram = ram();
        let mut tx = queue(TX_RING);
        let mut rx = queue(RX_RING);

        guest_sends(&ram, 0, Op::Request, OPEN_PORT, &[]);
        vsock.notify(TX, &mut tx, &ram).expect("notify tx");
        guest_offers(&ram, 0);
        vsock.notify(RX, &mut rx, &ram).expect("notify rx");
        assert_eq!(
            guest_given(&ram, 0).op,
            Op::Response,
            "no response to request"
        );

        guest_sends(&ram, 1, Op::Data, OPEN_PORT, b"hello");
        vsock.notify(TX, &mut tx, &ram).expect("notify tx");
        assert_eq!(&*landed.taken.lock().unwrap(), b"hello");
    }

    #[test]
    fn test_reject_closed_port() {
        let mut vsock = device(&Landed::default());
        let ram = ram();
        let mut tx = queue(TX_RING);
        let mut rx = queue(RX_RING);

        guest_sends(&ram, 0, Op::Request, SHUT_PORT, &[]);
        vsock.notify(TX, &mut tx, &ram).expect("notify tx");
        guest_offers(&ram, 0);
        vsock.notify(RX, &mut rx, &ram).expect("notify rx");
        assert_eq!(guest_given(&ram, 0).op, Op::Reset, "closed port accepted");
    }

    #[test]
    fn test_incoming_request_sent_to_guest() {
        let landed = Landed::default();
        let mut vsock = Vsock::new(
            GUEST_CID,
            Box::new(Incoming {
                waiting: vec![(GUEST_PORT, landed.clone())],
                asked: Arc::new(Mutex::new(0)),
                arrives_on: Arc::new(paired()),
            }),
        );
        let ram = ram();
        let mut rx = queue(RX_RING);

        guest_offers(&ram, 0);
        vsock.notify(RX, &mut rx, &ram).expect("notify rx");
        let asked = guest_given(&ram, 0);
        assert_eq!(asked.op, Op::Request, "no request queued for guest");
        assert_eq!(asked.dst_cid, GUEST_CID);
        assert_eq!(asked.dst_port, GUEST_PORT, "guest port connected is lost");
        assert_eq!(
            asked.src_port & HOST_SIDE,
            HOST_SIDE,
            "host port lacks HOST_SIDE"
        );
    }

    #[test]
    fn test_incoming_gets_unique_host_port() {
        let mut vsock = Vsock::new(
            GUEST_CID,
            Box::new(Incoming {
                waiting: vec![
                    (GUEST_PORT, Landed::default()),
                    (GUEST_PORT, Landed::default()),
                ],
                asked: Arc::new(Mutex::new(0)),
                arrives_on: Arc::new(paired()),
            }),
        );
        let ram = ram();
        let mut rx = queue(RX_RING);

        guest_offers(&ram, 0);
        guest_offers(&ram, 1);
        vsock.notify(RX, &mut rx, &ram).expect("notify rx");
        let (first, second) = (guest_given(&ram, 0), guest_given(&ram, 1));
        assert_ne!(
            first.src_port, second.src_port,
            "two incoming connections got the same host port"
        );
        assert_eq!(vsock.open.len(), 2);
    }

    #[test]
    fn test_incoming_left_at_connection_limit() {
        let asked = Arc::new(Mutex::new(0));
        let arrives_on = Arc::new(paired());
        let mut vsock = Vsock::new(
            GUEST_CID,
            Box::new(Incoming {
                waiting: vec![(GUEST_PORT, Landed::default())],
                asked: Arc::clone(&asked),
                arrives_on: Arc::clone(&arrives_on),
            }),
        );
        // At `CONNECTIONS` open, incoming connection stays at the endpoint.
        for port in 0..CONNECTIONS as u32 {
            vsock.open.insert(
                (port, OPEN_PORT),
                Held {
                    connection: Connection::asking(GUEST_CID, port, OPEN_PORT),
                    stream: Box::new(Landed::default()),
                    since: None,
                },
            );
        }
        let ram = ram();
        let mut rx = queue(RX_RING);
        guest_offers(&ram, 0);
        vsock.notify(RX, &mut rx, &ram).expect("notify rx");
        assert_eq!(
            *asked.lock().unwrap(),
            0,
            "incoming connection taken past the limit"
        );
        assert!(
            !vsock
                .outside()
                .iter()
                .any(|(fd, _)| *fd == arrives_on.as_raw_fd()),
            "endpoint waited on at connection limit"
        );
    }

    /// Returns one end of a socket pair, a descriptor for test double.
    fn paired() -> std::os::unix::net::UnixStream {
        std::os::unix::net::UnixStream::pair()
            .expect("socket pair")
            .0
    }

    /// Returns header of a packet from `GUEST_PORT` to `OPEN_PORT`.
    fn from_guest(op: Op, len: u32, payload_window: u32) -> Header {
        Header {
            src_cid: GUEST_CID,
            dst_cid: HOST_CID,
            src_port: GUEST_PORT,
            dst_port: OPEN_PORT,
            len,
            kind: STREAM,
            op,
            flags: 0,
            buf_alloc: payload_window,
            fwd_cnt: 0,
        }
    }

    #[test]
    fn test_wait_only_on_movable_host_ends() {
        // outside() drops host ends the guest has no room for.
        let mut vsock = device(&Landed::default());
        let (ours, _theirs) = std::os::unix::net::UnixStream::pair().expect("socket pair");
        let fd = ours.as_raw_fd();
        let waited = |vsock: &Vsock| {
            vsock
                .outside()
                .into_iter()
                .find(|(each, _)| *each == fd)
                .map(|(_, interest)| interest)
        };

        // No `Response` yet, so the guest has no room, fd is not waited on.
        vsock.open.insert(
            (GUEST_PORT, OPEN_PORT),
            Held {
                connection: Connection::asking(GUEST_CID, GUEST_PORT, OPEN_PORT),
                stream: Box::new(ours),
                since: None,
            },
        );
        assert_eq!(
            waited(&vsock),
            None,
            "host end waited on while guest has no room"
        );

        // `Response` carries `buf_alloc` of the guest.
        vsock.took(&from_guest(Op::Response, 0, WINDOW), &[]);
        assert_eq!(waited(&vsock), Some(Interest::Read));

        // Bytes waiting for the host end.
        vsock.took(&from_guest(Op::Data, 2, WINDOW), b"hi");
        assert_eq!(waited(&vsock), Some(Interest::Both));

        // Room is zero and bytes forwarded. No interest, so not waited on.
        vsock.took(&from_guest(Op::CreditUpdate, 0, 0), &[]);
        vsock
            .open
            .get_mut(&(GUEST_PORT, OPEN_PORT))
            .expect("connection")
            .connection
            .forwarded(2);
        assert_eq!(
            waited(&vsock),
            None,
            "host end with no room and no bytes waited on"
        );
    }

    /// Insert an incoming connection not answered by the guest yet.
    fn incoming_and_waiting(vsock: &mut Vsock) {
        vsock.open.insert(
            (GUEST_PORT, OPEN_PORT),
            Held {
                connection: Connection::asking(GUEST_CID, GUEST_PORT, OPEN_PORT),
                stream: Box::new(Landed::default()),
                since: None,
            },
        );
    }

    #[test]
    fn test_expire_unanswered_incoming() {
        let mut vsock = device(&Landed::default());
        let start = std::time::Instant::now();
        incoming_and_waiting(&mut vsock);

        // First call starts the wait, later ones do not restart it.
        vsock.expire(start);
        vsock.expire(start + PATIENCE / 2);
        assert_eq!(
            vsock.open.len(),
            1,
            "incoming connection reset before `PATIENCE`"
        );

        vsock.expire(start + PATIENCE);
        assert!(
            vsock.open.is_empty(),
            "unanswered connect kept past `PATIENCE`"
        );
        assert_eq!(
            vsock.waiting.first().map(|(header, _)| header.op),
            Some(Op::Reset),
            "no reset queued for expired connect"
        );
    }

    #[test]
    fn test_keep_answered_incoming() {
        let mut vsock = device(&Landed::default());
        let start = std::time::Instant::now();
        incoming_and_waiting(&mut vsock);
        vsock.expire(start);

        vsock.took(&from_guest(Op::Response, 0, WINDOW), &[]);
        vsock.expire(start + PATIENCE * 10);
        assert_eq!(
            vsock.open.len(),
            1,
            "answered connect reset together with unanswered ones"
        );
    }

    #[test]
    fn test_host_close_resets_connection() {
        let landed = Landed::default();
        let mut vsock = device(&landed);
        let ram = ram();
        let mut tx = queue(TX_RING);
        let mut rx = queue(RX_RING);

        guest_sends(&ram, 0, Op::Request, OPEN_PORT, &[]);
        vsock.notify(TX, &mut tx, &ram).expect("take the request");
        guest_offers(&ram, 0);
        vsock.notify(RX, &mut rx, &ram).expect("answer it");
        assert_eq!(guest_given(&ram, 0).op, Op::Response);
        assert_eq!(vsock.open.len(), 1);

        // Far end closes without any write from the guest, so the read in
        // `pump` is the only place it shows up.
        *landed.gone.lock().unwrap() = true;
        guest_offers(&ram, 1);
        vsock
            .notify(RX, &mut rx, &ram)
            .expect("read from the host end");
        assert_eq!(
            guest_given(&ram, 1).op,
            Op::Reset,
            "no reset after host end closed"
        );
        assert!(vsock.open.is_empty(), "connection still open");
    }

    #[test]
    fn test_reject_request_at_connection_limit() {
        let mut vsock = device(&Landed::default());
        for port in 0..CONNECTIONS as u32 {
            vsock.open.insert(
                (port, OPEN_PORT),
                Held {
                    connection: Connection::asking(GUEST_CID, port, OPEN_PORT),
                    stream: Box::new(Landed::default()),
                    since: None,
                },
            );
        }
        let ram = ram();
        let mut tx = queue(TX_RING);
        let mut rx = queue(RX_RING);

        guest_sends(&ram, 0, Op::Request, OPEN_PORT, &[]);
        vsock.notify(TX, &mut tx, &ram).expect("notify tx");
        guest_offers(&ram, 0);
        vsock.notify(RX, &mut rx, &ram).expect("notify rx");
        assert_eq!(
            guest_given(&ram, 0).op,
            Op::Reset,
            "request past the limit not reset"
        );
    }

    #[test]
    fn test_incoming_acknowledged_with_port() {
        let landed = Landed::default();
        let mut vsock = device(&landed);
        let ram = ram();
        let mut tx = queue(TX_RING);

        // Inserted directly, since the test endpoint serves `incoming`
        // with `None`.
        vsock.open.insert(
            (GUEST_PORT, OPEN_PORT),
            Held {
                connection: Connection::asking(GUEST_CID, GUEST_PORT, OPEN_PORT),
                stream: Box::new(landed.clone()),
                since: None,
            },
        );

        guest_sends(&ram, 0, Op::Response, OPEN_PORT, &[]);
        vsock.notify(TX, &mut tx, &ram).expect("take the response");
        assert_eq!(
            landed.taken.lock().unwrap().as_slice(),
            format!("OK {OPEN_PORT}\n").as_bytes(),
            "no acknowledgement on host end"
        );
    }

    #[test]
    fn test_reject_packet_without_connection() {
        let mut vsock = device(&Landed::default());
        let ram = ram();
        let mut tx = queue(TX_RING);
        let mut rx = queue(RX_RING);

        // Data without a request before it.
        guest_sends(&ram, 0, Op::Data, OPEN_PORT, b"hi");
        vsock.notify(TX, &mut tx, &ram).expect("notify tx");
        guest_offers(&ram, 0);
        vsock.notify(RX, &mut rx, &ram).expect("notify rx");
        assert_eq!(guest_given(&ram, 0).op, Op::Reset);
    }

    #[test]
    fn test_receive_from_host() {
        let landed = Landed::default();
        let mut vsock = device(&landed);
        let ram = ram();
        let mut tx = queue(TX_RING);
        let mut rx = queue(RX_RING);

        guest_sends(&ram, 0, Op::Request, OPEN_PORT, &[]);
        vsock.notify(TX, &mut tx, &ram).expect("notify tx");
        guest_offers(&ram, 0);
        vsock.notify(RX, &mut rx, &ram).expect("notify rx");

        // Bytes ready on the host stream.
        landed.ready.lock().unwrap().extend_from_slice(b"world");
        vsock.pump();
        guest_offers(&ram, 1);
        vsock
            .notify(RX, &mut rx, &ram)
            .expect("notify rx with a buffer");

        let given = guest_given(&ram, 1);
        assert_eq!(given.op, Op::Data);
        assert_eq!(given.len, 5);
        let mut payload = [0u8; 5];
        ram.read(BUFFER + 0x8000 + 0x400 + ROOM as u64, &mut payload)
            .expect("read the payload");
        assert_eq!(&payload, b"world");
    }

    #[test]
    fn test_hold_bytes_for_full_host_end() {
        // Host end returning `WouldBlock` keeps its connection. Bytes wait
        // and are written once it takes them.
        let backed = Backed::default();
        *backed.full.lock().unwrap() = true;
        let mut vsock = Vsock::new(GUEST_CID, Box::new(Backs(backed.clone())));
        let ram = ram();
        let mut tx = queue(TX_RING);
        let mut rx = queue(RX_RING);

        guest_sends(&ram, 0, Op::Request, OPEN_PORT, &[]);
        vsock.notify(TX, &mut tx, &ram).expect("take the request");
        guest_offers(&ram, 0);
        vsock.notify(RX, &mut rx, &ram).expect("answer the request");
        assert_eq!(guest_given(&ram, 0).op, Op::Response);

        // Host end takes no bytes, connection stays open.
        guest_sends(&ram, 1, Op::Data, OPEN_PORT, b"hello");
        vsock.notify(TX, &mut tx, &ram).expect("take the data");
        assert!(
            backed.taken.lock().unwrap().is_empty(),
            "full host end took bytes"
        );
        guest_offers(&ram, 1);
        vsock.notify(RX, &mut rx, &ram).expect("answer");
        // No byte moved, so neither `CreditUpdate` nor reset is queued.
        assert!(
            vsock.waiting.is_empty(),
            "full host end queued packet for guest"
        );
        assert!(
            vsock.open.contains_key(&(GUEST_PORT, OPEN_PORT)),
            "full host end closed the connection"
        );

        // Host end takes the bytes, `CreditUpdate` lands in the buffer
        // offered above.
        *backed.full.lock().unwrap() = false;
        vsock.notify(RX, &mut rx, &ram).expect("carry and answer");
        assert_eq!(
            &*backed.taken.lock().unwrap(),
            b"hello",
            "bytes did not reach host end"
        );
        let note = guest_given(&ram, 1);
        assert_eq!(note.op, Op::CreditUpdate);
        assert_eq!(note.fwd_cnt, 5, "guest got wrong count");
    }

    #[test]
    fn test_hold_packet_until_buffer_offered() {
        let landed = Landed::default();
        let mut vsock = device(&landed);
        let ram = ram();
        let mut tx = queue(TX_RING);
        let mut rx = queue(RX_RING);

        guest_sends(&ram, 0, Op::Request, OPEN_PORT, &[]);
        vsock.notify(TX, &mut tx, &ram).expect("notify tx");
        // No buffer offered yet.
        vsock
            .notify(RX, &mut rx, &ram)
            .expect("notify rx with no buffer");
        assert_eq!(vsock.waiting.len(), 1, "reply dropped");

        guest_offers(&ram, 0);
        vsock.notify(RX, &mut rx, &ram).expect("notify rx");
        assert_eq!(guest_given(&ram, 0).op, Op::Response);
        assert!(vsock.waiting.is_empty(), "reply still held");
    }

    #[test]
    fn test_transport_reset_after_restore() {
        let landed = Landed::default();
        let mut vsock = device(&landed);
        let ram = ram();
        let mut rx = queue(RX_RING);
        let mut evt = queue(EVT_RING);

        // Transport calls `restored` once per queue, reset is posted on
        // the call of event queue.
        vsock.restored(RX, &mut rx, &ram).expect("restored rx");
        guest_offers_event(&ram, 0);
        vsock.restored(EVT, &mut evt, &ram).expect("restored evt");
        assert_eq!(event_given(&ram, 0), TRANSPORT_RESET);
        assert!(!vsock.reset_owed, "reset still owed");

        // No second event without another restore.
        guest_offers_event(&ram, 1);
        vsock.notify(EVT, &mut evt, &ram).expect("notify evt");
        assert_eq!(evt.cursors().1, 1, "restore posted more than one event");
    }

    #[test]
    fn test_reset_held_until_event_buffer() {
        let landed = Landed::default();
        let mut vsock = device(&landed);
        let ram = ram();
        let mut evt = queue(EVT_RING);

        // No buffer posted at the restore.
        vsock.restored(EVT, &mut evt, &ram).expect("restored evt");
        assert!(vsock.reset_owed, "reset dropped with the buffer");
        assert_eq!(evt.cursors(), (0, 0), "event posted with no buffer");

        // Next event queue notification with a buffer delivers it.
        guest_offers_event(&ram, 0);
        vsock.notify(EVT, &mut evt, &ram).expect("notify evt");
        assert_eq!(event_given(&ram, 0), TRANSPORT_RESET);
        assert!(!vsock.reset_owed, "reset still owed");
    }

    #[test]
    fn test_one_reset_per_restore() {
        let landed = Landed::default();
        let mut vsock = device(&landed);
        let ram = ram();
        let mut evt = queue(EVT_RING);

        guest_offers_event(&ram, 0);
        vsock.restored(EVT, &mut evt, &ram).expect("first restore");
        guest_offers_event(&ram, 1);
        vsock.restored(EVT, &mut evt, &ram).expect("second restore");

        assert_eq!(evt.cursors().1, 2, "not one event per restore");
        assert_eq!(event_given(&ram, 0), TRANSPORT_RESET);
        assert_eq!(event_given(&ram, 1), TRANSPORT_RESET);
        vsock.notify(EVT, &mut evt, &ram).expect("notify evt");
        assert_eq!(evt.cursors().1, 2, "extra event appeared");
    }
}
