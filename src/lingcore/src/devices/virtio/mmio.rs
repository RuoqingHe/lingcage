// SPDX-FileCopyrightText: 2026 LingCage <opensource@lingcage.com>
//
// SPDX-License-Identifier: Apache-2.0

//! Virtio MMIO transport, the register block of section 4.2 in virtio
//! 1.2.
//!
//! Transport runs the handshake and holds the queues. The [`Device`]
//! behind it does the actual work when a queue is notified.

use std::io;
use std::time::Duration;

use log::warn;

use crate::devices::virtio::Device;
use crate::devices::virtio::queue::Queue;
use crate::devices::{Blob, Device as BusDevice, Error as BusError, Result as BusResult};
use crate::hv::irq::IrqSender;
use crate::hv::vcpu::VmExit;
use crate::mem::GuestRam;

/// Size of the register block in bytes, configuration space included.
pub const SIZE: u64 = 0x200;

/// Magic value, `virt` in little endian.
const MAGIC: u32 = 0x7472_6976;
/// Transport version. Version 1 is the legacy layout.
const VERSION: u32 = 2;
/// Vendor ID, `LNGC`.
const VENDOR: u32 = 0x4c4e_4743;

const MAGIC_VALUE: u64 = 0x000;
const VERSION_AT: u64 = 0x004;
const DEVICE_ID: u64 = 0x008;
const VENDOR_ID: u64 = 0x00c;
const DEVICE_FEATURES: u64 = 0x010;
const DEVICE_FEATURES_SEL: u64 = 0x014;
const DRIVER_FEATURES: u64 = 0x020;
const DRIVER_FEATURES_SEL: u64 = 0x024;
const QUEUE_SEL: u64 = 0x030;
const QUEUE_NUM_MAX: u64 = 0x034;
const QUEUE_NUM: u64 = 0x038;
const QUEUE_READY: u64 = 0x044;
/// Register which a driver writes queue index to on a kick. Machine binds
/// an ioeventfd on it.
pub const QUEUE_NOTIFY: u64 = 0x050;
const INTERRUPT_STATUS: u64 = 0x060;
const INTERRUPT_ACK: u64 = 0x064;
const STATUS: u64 = 0x070;
const QUEUE_DESC_LOW: u64 = 0x080;
const QUEUE_DESC_HIGH: u64 = 0x084;
const QUEUE_AVAIL_LOW: u64 = 0x090;
const QUEUE_AVAIL_HIGH: u64 = 0x094;
const QUEUE_USED_LOW: u64 = 0x0a0;
const QUEUE_USED_HIGH: u64 = 0x0a4;
const CONFIG_GENERATION: u64 = 0x0fc;
/// Start of device configuration space.
const CONFIG: u64 = 0x100;

// TODO: `VIRTQ_AVAIL_F_NO_INTERRUPT` of the available ring is not yet read.
/// `INTERRUPT_STATUS` bit, a used ring was updated.
const INTERRUPT_VRING: u32 = 0x1;

/// `STATUS` bit `FEATURES_OK`, driver accepted the features.
const STATUS_FEATURES_OK: u32 = 0x08;
/// `STATUS` bit `DEVICE_NEEDS_RESET`, device hit an error which it can
/// not recover from.
const STATUS_NEEDS_RESET: u32 = 0x40;
/// `STATUS` bit `FAILED`, driver gave up on the device.
const STATUS_FAILED: u32 = 0x80;

/// `VIRTIO_F_VERSION_1`, feature bit 32. Driver which does not accept it
/// is a legacy driver, which is not supported by this transport.
const VERSION_1: u64 = 1 << 32;

/// `Blob::kind` of transport.
const KIND: &str = "virtio-mmio";
/// Layout version of `TransportState`. Blob of any other version is
/// reported as `WrongVersion`.
const STATE_VERSION: u32 = 1;

/// Ring addresses, size and readiness of one queue, plus its cursors.
#[derive(Default, serde::Serialize, serde::Deserialize)]
#[serde(default)]
struct SlotState {
    size: u16,
    desc: u64,
    avail: u64,
    used: u64,
    ready: bool,
    next_avail: u16,
    next_used: u16,
}

/// Registers and queues of a transport, encoded as `Blob::data` through
/// serde_json. Rings stay in guest RAM, and the device behind the
/// transport captures its own state.
#[derive(Default, serde::Serialize, serde::Deserialize)]
#[serde(default)]
struct TransportState {
    status: u32,
    device_features_sel: u32,
    driver_features: u64,
    driver_features_sel: u32,
    queue_sel: u32,
    interrupt_status: u32,
    queues: Vec<SlotState>,
}

/// Ring addresses of one queue, written one register at a time.
#[derive(Default)]
struct Slot {
    size: u16,
    desc: u64,
    avail: u64,
    used: u64,
    /// Queue built when driver sets `QUEUE_READY`.
    queue: Option<Queue>,
}

/// MMIO transport which places a virtio [`Device`] on the bus.
pub struct Transport {
    device: Box<dyn Device>,
    ram: GuestRam,
    line: Box<dyn IrqSender>,
    status: u32,
    device_features_sel: u32,
    driver_features: u64,
    driver_features_sel: u32,
    queue_sel: u32,
    interrupt_status: u32,
    queues: Vec<Slot>,
}

impl Transport {
    /// Create a transport for `device` over `ram`, `line` is raised for used
    /// buffers.
    pub fn new(device: Box<dyn Device>, ram: GuestRam, line: Box<dyn IrqSender>) -> Self {
        let queues = (0..device.queue_count()).map(|_| Slot::default()).collect();
        Transport {
            device,
            ram,
            line,
            status: 0,
            device_features_sel: 0,
            driver_features: 0,
            driver_features_sel: 0,
            queue_sel: 0,
            interrupt_status: 0,
            queues,
        }
    }

    /// Returns the slot selected by `QUEUE_SEL`, if the device has that queue.
    fn selected(&mut self) -> Option<&mut Slot> {
        self.queues.get_mut(self.queue_sel as usize)
    }

    /// Returns device features with `VIRTIO_F_VERSION_1` added.
    fn offered(&self) -> u64 {
        self.device.features() | VERSION_1
    }

    fn read_register(&mut self, offset: u64) -> u32 {
        match offset {
            MAGIC_VALUE => MAGIC,
            VERSION_AT => VERSION,
            DEVICE_ID => self.device.device_id(),
            VENDOR_ID => VENDOR,
            DEVICE_FEATURES => {
                let half = if self.device_features_sel == 0 { 0 } else { 32 };
                (self.offered() >> half) as u32
            }
            QUEUE_NUM_MAX => u32::from(self.device.queue_size_max()),
            QUEUE_READY => u32::from(self.selected().is_some_and(|s| s.queue.is_some())),
            INTERRUPT_STATUS => self.interrupt_status,
            STATUS => self.status,
            // Configuration space never changes, so generation stays zero.
            CONFIG_GENERATION => 0,
            _ => 0,
        }
    }

    fn write_register(&mut self, offset: u64, value: u32) -> io::Result<()> {
        match offset {
            DEVICE_FEATURES_SEL => self.device_features_sel = value,
            DRIVER_FEATURES_SEL => self.driver_features_sel = value,
            DRIVER_FEATURES => {
                let half = if self.driver_features_sel == 0 { 0 } else { 32 };
                self.driver_features &= !(0xffff_ffffu64 << half);
                self.driver_features |= u64::from(value) << half;
            }
            QUEUE_SEL => self.queue_sel = value,
            STATUS => self.set_status(value),
            INTERRUPT_ACK => self.interrupt_status &= !value,
            QUEUE_NOTIFY => return self.notify(value as u16),
            _ => self.write_queue_register(offset, value),
        }
        Ok(())
    }

    /// Handle a `STATUS` write. Writing zero resets the device.
    fn set_status(&mut self, value: u32) {
        if value == 0 {
            self.reset();
            return;
        }
        // `FEATURES_OK` without `VIRTIO_F_VERSION_1` means legacy driver. Fail
        // the handshake here, before it lays out legacy rings.
        if value & STATUS_FEATURES_OK != 0 && self.driver_features & VERSION_1 == 0 {
            warn!("FEATURES_OK without VIRTIO_F_VERSION_1, status set to FAILED");
            self.status = value | STATUS_FAILED;
            return;
        }
        self.status = value;
    }

    /// Clear registers and drop the queues.
    fn reset(&mut self) {
        self.status = 0;
        self.driver_features = 0;
        self.device_features_sel = 0;
        self.driver_features_sel = 0;
        self.queue_sel = 0;
        self.interrupt_status = 0;
        for slot in &mut self.queues {
            *slot = Slot::default();
        }
    }

    fn write_queue_register(&mut self, offset: u64, value: u32) {
        let max = self.device.queue_size_max();
        let Some(slot) = self.selected() else {
            return;
        };
        match offset {
            QUEUE_NUM => slot.size = (value as u16).min(max),
            QUEUE_DESC_LOW => slot.desc = high(slot.desc) | u64::from(value),
            QUEUE_DESC_HIGH => slot.desc = low(slot.desc) | (u64::from(value) << 32),
            QUEUE_AVAIL_LOW => slot.avail = high(slot.avail) | u64::from(value),
            QUEUE_AVAIL_HIGH => slot.avail = low(slot.avail) | (u64::from(value) << 32),
            QUEUE_USED_LOW => slot.used = high(slot.used) | u64::from(value),
            QUEUE_USED_HIGH => slot.used = low(slot.used) | (u64::from(value) << 32),
            QUEUE_READY => {
                if value & 0x1 == 0 {
                    slot.queue = None;
                    return;
                }
                match Queue::new(slot.size, slot.desc, slot.avail, slot.used) {
                    Ok(queue) => slot.queue = Some(queue),
                    // Ring can not be indexed at that size, so it is not read
                    // and `DEVICE_NEEDS_RESET` is set.
                    Err(refused) => {
                        warn!("failed to build queue, DEVICE_NEEDS_RESET set: {refused}");
                        self.status |= STATUS_NEEDS_RESET;
                    }
                }
            }
            _ => {}
        }
    }

    /// Handle a `QUEUE_NOTIFY` write for queue `index` and raise the line if
    /// the device reported a chain used. Signal on the ioeventfd reaches
    /// here from the device thread.
    pub fn notify(&mut self, index: u16) -> io::Result<()> {
        let Some(slot) = self.queues.get_mut(usize::from(index)) else {
            return Ok(());
        };
        let Some(queue) = slot.queue.as_mut() else {
            return Ok(());
        };
        let (_, answered) = queue.cursors();
        // Malformed chain sets `DEVICE_NEEDS_RESET`, it does not end the
        // run.
        if let Err(refused) = self.device.notify(index, queue, &self.ram) {
            warn!("queue {index} not served, DEVICE_NEEDS_RESET set: {refused}");
            self.status |= STATUS_NEEDS_RESET;
            return Ok(());
        }
        // Used index did not move, no chain for the guest to read, so the line
        // stays down. Device served on a timer meets empty rings.
        if queue.cursors().1 == answered {
            return Ok(());
        }
        self.interrupt_status |= INTERRUPT_VRING;
        self.line.send().map_err(io::Error::other)
    }
}

impl Transport {
    /// Returns host descriptors of the device, see `Device::outside`.
    pub fn outside(&self) -> Vec<(std::os::fd::RawFd, crate::hv::Interest)> {
        self.device.outside()
    }

    /// Returns the longest time the device can wait, see `Device::wake_after`.
    pub fn wake_after(&self) -> Option<Duration> {
        self.device.wake_after()
    }

    fn state(&self) -> TransportState {
        TransportState {
            status: self.status,
            device_features_sel: self.device_features_sel,
            driver_features: self.driver_features,
            driver_features_sel: self.driver_features_sel,
            queue_sel: self.queue_sel,
            interrupt_status: self.interrupt_status,
            queues: self
                .queues
                .iter()
                .map(|slot| {
                    let (next_avail, next_used) =
                        slot.queue.as_ref().map_or((0, 0), Queue::cursors);
                    SlotState {
                        size: slot.size,
                        desc: slot.desc,
                        avail: slot.avail,
                        used: slot.used,
                        ready: slot.queue.is_some(),
                        next_avail,
                        next_used,
                    }
                })
                .collect(),
        }
    }

    /// Restore `state`. Queue count different from the device is reported
    /// as `WrongQueues`, which means the blob came from another type of
    /// device. Ring marked ready is rebuilt with its cursors.
    fn take_up(&mut self, state: TransportState) -> BusResult<()> {
        if state.queues.len() != self.queues.len() {
            return Err(BusError::WrongQueues {
                found: state.queues.len(),
                wanted: self.queues.len(),
            });
        }
        self.status = state.status;
        self.device_features_sel = state.device_features_sel;
        self.driver_features = state.driver_features;
        self.driver_features_sel = state.driver_features_sel;
        self.queue_sel = state.queue_sel;
        self.interrupt_status = state.interrupt_status;
        for (slot, taken) in self.queues.iter_mut().zip(state.queues) {
            slot.size = taken.size;
            slot.desc = taken.desc;
            slot.avail = taken.avail;
            slot.used = taken.used;
            slot.queue = None;
            if !taken.ready {
                continue;
            }
            let mut queue = Queue::new(taken.size, taken.desc, taken.avail, taken.used)
                .map_err(|_| BusError::State)?;
            queue.set_cursors(taken.next_avail, taken.next_used);
            slot.queue = Some(queue);
        }
        Ok(())
    }
}

impl BusDevice for Transport {
    fn read(&mut self, offset: u64, size: u8) -> u64 {
        match offset.checked_sub(CONFIG) {
            Some(offset) => self.device.read_config(offset, size),
            None => u64::from(self.read_register(offset)),
        }
    }

    fn write(&mut self, offset: u64, size: u8, value: u64) -> io::Result<Option<VmExit>> {
        match offset.checked_sub(CONFIG) {
            Some(offset) => self.device.write_config(offset, size, value),
            // Registers are 32 bits wide, wider write carries its low word.
            None => self.write_register(offset, value as u32)?,
        }
        Ok(None)
    }

    fn capture(&self) -> BusResult<Option<Blob>> {
        let data = serde_json::to_vec(&self.state()).map_err(|_| BusError::State)?;
        Ok(Some(Blob {
            kind: KIND.to_string(),
            version: STATE_VERSION,
            data,
        }))
    }

    fn restore(&mut self, blob: &Blob) -> BusResult<()> {
        if blob.kind != KIND {
            return Err(BusError::WrongState {
                found: blob.kind.clone(),
                wanted: KIND,
            });
        }
        if blob.version != STATE_VERSION {
            return Err(BusError::WrongVersion {
                kind: KIND,
                version: blob.version,
            });
        }
        let state: TransportState =
            serde_json::from_slice(&blob.data).map_err(|_| BusError::State)?;
        self.take_up(state)
    }

    fn restored(&mut self) {
        let mut raised = false;
        for index in 0..self.queues.len() as u16 {
            let Some(queue) = self.queues[usize::from(index)].queue.as_mut() else {
                continue;
            };
            let (_, answered) = queue.cursors();
            // Malformed chain sets `DEVICE_NEEDS_RESET` like `notify` does,
            // it does not fail the restore.
            if let Err(refused) = self.device.restored(index, queue, &self.ram) {
                warn!(
                    "queue {index} not served after a restore, DEVICE_NEEDS_RESET set: {refused}"
                );
                self.status |= STATUS_NEEDS_RESET;
                continue;
            }
            raised |= queue.cursors().1 != answered;
        }
        if !raised {
            return;
        }
        self.interrupt_status |= INTERRUPT_VRING;
        // Failed raise leaves the work in the used ring, which will be
        // seen at the next raise.
        if let Err(err) = self.line.send() {
            warn!("the line for a restore was not raised: {err}");
        }
    }
}

/// Upper 32 bits of `value`.
fn high(value: u64) -> u64 {
    value & 0xffff_ffff_0000_0000
}

/// Lower 32 bits of `value`.
fn low(value: u64) -> u64 {
    value & 0x0000_0000_ffff_ffff
}

#[cfg(test)]
mod tests {
    use std::cell::RefCell;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::{Arc, Once};
    use std::time::Duration;

    use log::{Level, LevelFilter, Log, Metadata, Record};

    use crate::devices::virtio::mmio::*;
    use crate::devices::virtio::{Error, Result};

    const RAM_SIZE: u64 = 0x10000;
    const DESC_TABLE: u64 = 0x1000;
    const AVAIL_RING: u64 = 0x2000;
    const USED_RING: u64 = 0x3000;
    const BUFFER: u64 = 0x4000;
    /// Device ID of entropy device, section 5.4.
    const ENTROPY: u32 = 4;

    /// Line which counts its raises.
    #[derive(Clone)]
    struct Counter(Arc<AtomicUsize>);

    impl Counter {
        fn raises(&self) -> usize {
            self.0.load(Ordering::SeqCst)
        }
    }

    impl IrqSender for Counter {
        fn send(&self) -> crate::hv::Result<()> {
            self.0.fetch_add(1, Ordering::SeqCst);
            Ok(())
        }
    }

    /// Backend which fills each writable buffer with `0xa5` and counts the
    /// chains served.
    #[derive(Default)]
    struct Filler {
        refuse: bool,
        served: Arc<AtomicUsize>,
        /// Wait reported through `wake_after`.
        wake: Option<Duration>,
    }

    impl Device for Filler {
        fn device_id(&self) -> u32 {
            ENTROPY
        }

        fn queue_size_max(&self) -> u16 {
            8
        }

        fn read_config(&mut self, offset: u64, _size: u8) -> u64 {
            0xc0 + offset
        }

        fn notify(&mut self, _index: u16, queue: &mut Queue, ram: &GuestRam) -> Result<()> {
            if self.refuse {
                return Err(Error::Indirect);
            }
            while let Some(chain) = queue.pop(ram)? {
                self.served.fetch_add(1, Ordering::SeqCst);
                let mut written = 0;
                for descriptor in &chain.descriptors {
                    if descriptor.writable() {
                        let filling = vec![0xa5u8; descriptor.len as usize];
                        ram.write(descriptor.addr, &filling)
                            .map_err(|_| Error::Ring {
                                gpa: descriptor.addr,
                            })?;
                        written += descriptor.len;
                    }
                }
                queue.add_used(ram, chain.head, written)?;
            }
            Ok(())
        }

        fn restored(&mut self, index: u16, queue: &mut Queue, ram: &GuestRam) -> Result<()> {
            self.notify(index, queue, ram)
        }

        fn wake_after(&self) -> Option<std::time::Duration> {
            self.wake
        }
    }

    fn transport(line: &Counter) -> Transport {
        let ram = GuestRam::new(&[(0, RAM_SIZE)]).expect("host pages");
        Transport::new(Box::new(Filler::default()), ram, Box::new(line.clone()))
    }

    /// Read `idx` of the used ring.
    fn used_index(ram: &GuestRam) -> u16 {
        let mut bytes = [0u8; 2];
        ram.read(USED_RING + 2, &mut bytes).expect("used index");
        u16::from_le_bytes(bytes)
    }

    /// Read a register the way a driver does, four bytes wide.
    fn reg(mmio: &mut Transport, offset: u64) -> u32 {
        BusDevice::read(mmio, offset, 4) as u32
    }

    fn set(mmio: &mut Transport, offset: u64, value: u32) {
        BusDevice::write(mmio, offset, 4, u64::from(value)).expect("register write");
    }

    #[test]
    fn test_probe_registers() {
        let line = Counter(Arc::new(AtomicUsize::new(0)));
        let mut mmio = transport(&line);

        // Registers a driver probes before claiming the device.
        assert_eq!(reg(&mut mmio, MAGIC_VALUE), MAGIC);
        assert_eq!(reg(&mut mmio, VERSION_AT), VERSION);
        assert_eq!(reg(&mut mmio, DEVICE_ID), ENTROPY);
        assert_eq!(reg(&mut mmio, VENDOR_ID), VENDOR);
        assert_eq!(reg(&mut mmio, QUEUE_NUM_MAX), 8);

        // Configuration space starts at `CONFIG`, backend reads it from
        // offset zero.
        assert_eq!(BusDevice::read(&mut mmio, CONFIG + 3, 1), 0xc3);
    }

    #[test]
    fn test_offer_version_1() {
        let line = Counter(Arc::new(AtomicUsize::new(0)));
        let mut mmio = transport(&line);

        set(&mut mmio, DEVICE_FEATURES_SEL, 1);
        assert_eq!(
            reg(&mut mmio, DEVICE_FEATURES),
            (VERSION_1 >> 32) as u32,
            "VERSION_1 missing from the upper half"
        );
        set(&mut mmio, DEVICE_FEATURES_SEL, 0);
        assert_eq!(reg(&mut mmio, DEVICE_FEATURES), 0);
    }

    #[test]
    fn test_reject_legacy_driver() {
        let line = Counter(Arc::new(AtomicUsize::new(0)));
        let mut mmio = transport(&line);

        // Lower half alone leaves out feature bit 32.
        set(&mut mmio, DRIVER_FEATURES_SEL, 0);
        set(&mut mmio, DRIVER_FEATURES, 0);
        set(&mut mmio, STATUS, STATUS_FEATURES_OK);
        assert_ne!(
            reg(&mut mmio, STATUS) & STATUS_FAILED,
            0,
            "FEATURES_OK accepted without VERSION_1"
        );

        // Handshake passes once bit 32 is accepted.
        set(&mut mmio, STATUS, 0);
        set(&mut mmio, DRIVER_FEATURES_SEL, 1);
        set(&mut mmio, DRIVER_FEATURES, (VERSION_1 >> 32) as u32);
        set(&mut mmio, STATUS, STATUS_FEATURES_OK);
        assert_eq!(reg(&mut mmio, STATUS), STATUS_FEATURES_OK);
    }

    #[test]
    fn test_serve_kicked_queue() {
        let line = Counter(Arc::new(AtomicUsize::new(0)));
        let mut mmio = transport(&line);
        let ram = mmio.ram.clone();

        // One writable buffer, published in the available ring.
        let mut descriptor = [0u8; 16];
        descriptor[0..8].copy_from_slice(&BUFFER.to_le_bytes());
        descriptor[8..12].copy_from_slice(&16u32.to_le_bytes());
        descriptor[12..14].copy_from_slice(&2u16.to_le_bytes());
        ram.write(DESC_TABLE, &descriptor).expect("descriptor");
        ram.write(AVAIL_RING + 4, &0u16.to_le_bytes())
            .expect("head");
        ram.write(AVAIL_RING + 2, &1u16.to_le_bytes())
            .expect("index");

        // Ring addresses, then `QUEUE_READY`, then the notification.
        set(&mut mmio, QUEUE_SEL, 0);
        set(&mut mmio, QUEUE_NUM, 8);
        set(&mut mmio, QUEUE_DESC_LOW, DESC_TABLE as u32);
        set(&mut mmio, QUEUE_AVAIL_LOW, AVAIL_RING as u32);
        set(&mut mmio, QUEUE_USED_LOW, USED_RING as u32);
        assert_eq!(reg(&mut mmio, QUEUE_READY), 0, "QUEUE_READY set early");
        set(&mut mmio, QUEUE_READY, 1);
        assert_eq!(reg(&mut mmio, QUEUE_READY), 1);
        set(&mut mmio, QUEUE_NOTIFY, 0);

        // Backend filled the buffer, reported it used and raised the line.
        let mut filled = [0u8; 16];
        ram.read(BUFFER, &mut filled).expect("read the buffer back");
        assert_eq!(filled, [0xa5u8; 16], "buffer not filled");
        let mut used = [0u8; 2];
        ram.read(USED_RING + 2, &mut used).expect("used index");
        assert_eq!(u16::from_le_bytes(used), 1);
        assert_eq!(line.raises(), 1, "line not raised");
        assert_eq!(reg(&mut mmio, INTERRUPT_STATUS), INTERRUPT_VRING);

        // `INTERRUPT_ACK` clears the bit.
        set(&mut mmio, INTERRUPT_ACK, INTERRUPT_VRING);
        assert_eq!(reg(&mut mmio, INTERRUPT_STATUS), 0);
    }

    #[test]
    fn test_capture_restore_queue() {
        // Ring cursors survive so a served chain is not served twice.
        let line = Counter(Arc::new(AtomicUsize::new(0)));
        let mut mmio = transport(&line);
        let ram = mmio.ram.clone();

        // Two buffers, published one at a time, one chain before capture
        // and one after.
        for index in 0..2u16 {
            let mut descriptor = [0u8; 16];
            let at = BUFFER + u64::from(index) * 16;
            descriptor[0..8].copy_from_slice(&at.to_le_bytes());
            descriptor[8..12].copy_from_slice(&16u32.to_le_bytes());
            descriptor[12..14].copy_from_slice(&2u16.to_le_bytes());
            ram.write(DESC_TABLE + u64::from(index) * 16, &descriptor)
                .expect("descriptor");
            ram.write(AVAIL_RING + 4 + u64::from(index) * 2, &index.to_le_bytes())
                .expect("head");
        }

        set(&mut mmio, QUEUE_NUM, 8);
        set(&mut mmio, QUEUE_DESC_LOW, DESC_TABLE as u32);
        set(&mut mmio, QUEUE_AVAIL_LOW, AVAIL_RING as u32);
        set(&mut mmio, QUEUE_USED_LOW, USED_RING as u32);
        set(&mut mmio, QUEUE_READY, 1);
        // Handshake, with feature bit 32 accepted.
        set(&mut mmio, DRIVER_FEATURES_SEL, 1);
        set(&mut mmio, DRIVER_FEATURES, (VERSION_1 >> 32) as u32);
        set(&mut mmio, STATUS, 0x0f);

        // First chain is published and notified.
        ram.write(AVAIL_RING + 2, &1u16.to_le_bytes())
            .expect("index");
        set(&mut mmio, QUEUE_NOTIFY, 0);
        assert_eq!(used_index(&ram), 1);

        let blob = BusDevice::capture(&mmio)
            .expect("capture")
            .expect("transport has state");
        assert_eq!(blob.kind, KIND);

        // Fresh transport over the same guest RAM and line.
        let served = Arc::new(AtomicUsize::new(0));
        let mut taken_up = Transport::new(
            Box::new(Filler {
                refuse: false,
                served: Arc::clone(&served),
                ..Default::default()
            }),
            ram.clone(),
            Box::new(line.clone()),
        );
        BusDevice::restore(&mut taken_up, &blob).expect("restore");

        // Ready ring, status and pending interrupt are restored.
        assert_eq!(reg(&mut taken_up, QUEUE_READY), 1);
        assert_eq!(reg(&mut taken_up, STATUS), 0x0f);
        assert_eq!(reg(&mut taken_up, INTERRUPT_STATUS), INTERRUPT_VRING);

        // Second chain, notified on the restored transport. Cursor reset
        // to zero would serve the first chain again.
        ram.write(AVAIL_RING + 2, &2u16.to_le_bytes())
            .expect("index");
        set(&mut taken_up, QUEUE_NOTIFY, 0);
        assert_eq!(used_index(&ram), 2);
        assert_eq!(
            served.load(Ordering::SeqCst),
            1,
            "chain served before capture is served again"
        );
    }

    #[test]
    fn test_bad_queue_size_not_built() {
        let line = Counter(Arc::new(AtomicUsize::new(0)));
        let mut mmio = transport(&line);

        // Six is not a power of two.
        set(&mut mmio, QUEUE_NUM, 6);
        set(&mut mmio, QUEUE_DESC_LOW, DESC_TABLE as u32);
        set(&mut mmio, QUEUE_AVAIL_LOW, AVAIL_RING as u32);
        set(&mut mmio, QUEUE_USED_LOW, USED_RING as u32);
        set(&mut mmio, QUEUE_READY, 1);

        assert_eq!(reg(&mut mmio, QUEUE_READY), 0);
        assert_ne!(reg(&mut mmio, STATUS) & STATUS_NEEDS_RESET, 0);

        // Notification finds no queue built.
        set(&mut mmio, QUEUE_NOTIFY, 0);
        assert_eq!(line.raises(), 0, "line raised for an unbuilt ring");
    }

    #[test]
    fn test_refused_chain_needs_reset() {
        let line = Counter(Arc::new(AtomicUsize::new(0)));
        let ram = GuestRam::new(&[(0, RAM_SIZE)]).expect("host pages");
        let mut mmio = Transport::new(
            Box::new(Filler {
                refuse: true,
                served: Arc::new(AtomicUsize::new(0)),
                ..Default::default()
            }),
            ram,
            Box::new(line.clone()),
        );

        set(&mut mmio, QUEUE_NUM, 8);
        set(&mut mmio, QUEUE_DESC_LOW, DESC_TABLE as u32);
        set(&mut mmio, QUEUE_AVAIL_LOW, AVAIL_RING as u32);
        set(&mut mmio, QUEUE_USED_LOW, USED_RING as u32);
        set(&mut mmio, QUEUE_READY, 1);
        set(&mut mmio, QUEUE_NOTIFY, 0);

        assert_ne!(
            reg(&mut mmio, STATUS) & STATUS_NEEDS_RESET,
            0,
            "DEVICE_NEEDS_RESET not set after refused chain"
        );
        assert_eq!(line.raises(), 0, "line raised for refused chain");
    }

    thread_local! {
        /// Records made on the calling thread. Parallel tests do not share them.
        static RECORDED: RefCell<Vec<(Level, String)>> = const { RefCell::new(Vec::new()) };
    }

    /// Logger which pushes each record onto `RECORDED`.
    struct Recorder;

    impl Log for Recorder {
        fn enabled(&self, _asked: &Metadata) -> bool {
            true
        }

        fn log(&self, record: &Record) {
            RECORDED.with_borrow_mut(|kept| kept.push((record.level(), record.args().to_string())));
        }

        fn flush(&self) {}
    }

    /// Install `Recorder` once per process and clear records of this thread.
    fn recording() {
        static RECORDER: Recorder = Recorder;
        static ONCE: Once = Once::new();
        ONCE.call_once(|| {
            log::set_logger(&RECORDER).expect("install the logger");
            log::set_max_level(LevelFilter::Trace);
        });
        RECORDED.with_borrow_mut(Vec::clear);
    }

    #[test]
    fn test_refusals_logged() {
        // Each refusal is logged at `Warn` with its reason: `FEATURES_OK`
        // without `VIRTIO_F_VERSION_1`, queue size not supported by the
        // device, and a chain rejected by the backend.
        recording();
        let line = Counter(Arc::new(AtomicUsize::new(0)));
        let ram = GuestRam::new(&[(0, RAM_SIZE)]).expect("host pages");
        let mut mmio = Transport::new(
            Box::new(Filler {
                refuse: true,
                served: Arc::new(AtomicUsize::new(0)),
                ..Default::default()
            }),
            ram,
            Box::new(line.clone()),
        );

        // `FEATURES_OK` without `VIRTIO_F_VERSION_1`.
        set(&mut mmio, STATUS, STATUS_FEATURES_OK);

        // Queue of 6, which is not a power of two.
        set(&mut mmio, STATUS, 0);
        set(&mut mmio, QUEUE_NUM, 6);
        set(&mut mmio, QUEUE_DESC_LOW, DESC_TABLE as u32);
        set(&mut mmio, QUEUE_AVAIL_LOW, AVAIL_RING as u32);
        set(&mut mmio, QUEUE_USED_LOW, USED_RING as u32);
        set(&mut mmio, QUEUE_READY, 1);

        // Queue of 8, kicked into a `Filler` set to refuse.
        set(&mut mmio, STATUS, 0);
        set(&mut mmio, QUEUE_NUM, 8);
        set(&mut mmio, QUEUE_DESC_LOW, DESC_TABLE as u32);
        set(&mut mmio, QUEUE_AVAIL_LOW, AVAIL_RING as u32);
        set(&mut mmio, QUEUE_USED_LOW, USED_RING as u32);
        set(&mut mmio, QUEUE_READY, 1);
        set(&mut mmio, QUEUE_NOTIFY, 0);

        let kept = RECORDED.with_borrow(Clone::clone);
        let said: Vec<&str> = kept.iter().map(|(_, line)| line.as_str()).collect();
        assert_eq!(kept.len(), 3, "records are {said:?}");
        assert!(
            kept.iter().all(|(level, _)| *level == Level::Warn),
            "record not at Warn level: {kept:?}"
        );
        assert!(said[0].contains("VERSION_1"), "record was {:?}", said[0]);
        // Size written to `QUEUE_NUM` should be in the record.
        assert!(
            said[1].contains("queue size 6 is not supported"),
            "record was {:?}",
            said[1]
        );
        assert!(
            said[2].contains("indirect descriptors are not supported"),
            "record was {:?}",
            said[2]
        );
    }

    #[test]
    fn test_empty_queue_no_interrupt() {
        let line = Counter(Arc::new(AtomicUsize::new(0)));
        let mut mmio = transport(&line);

        set(&mut mmio, QUEUE_NUM, 8);
        set(&mut mmio, QUEUE_DESC_LOW, DESC_TABLE as u32);
        set(&mut mmio, QUEUE_AVAIL_LOW, AVAIL_RING as u32);
        set(&mut mmio, QUEUE_USED_LOW, USED_RING as u32);
        set(&mut mmio, QUEUE_READY, 1);

        set(&mut mmio, QUEUE_NOTIFY, 0);
        assert_eq!(line.raises(), 0, "empty queue woke the guest");
        assert_eq!(
            reg(&mut mmio, STATUS) & STATUS_NEEDS_RESET,
            0,
            "an empty queue set DEVICE_NEEDS_RESET"
        );
    }

    #[test]
    fn test_status_zero_resets() {
        let line = Counter(Arc::new(AtomicUsize::new(0)));
        let mut mmio = transport(&line);

        set(&mut mmio, QUEUE_NUM, 8);
        set(&mut mmio, QUEUE_DESC_LOW, DESC_TABLE as u32);
        set(&mut mmio, QUEUE_AVAIL_LOW, AVAIL_RING as u32);
        set(&mut mmio, QUEUE_USED_LOW, USED_RING as u32);
        set(&mut mmio, QUEUE_READY, 1);
        assert_eq!(reg(&mut mmio, QUEUE_READY), 1);

        set(&mut mmio, STATUS, 0);
        assert_eq!(reg(&mut mmio, STATUS), 0);
        assert_eq!(
            reg(&mut mmio, QUEUE_READY),
            0,
            "QUEUE_READY survived the reset"
        );
    }

    #[test]
    fn test_restored_serves_pending_work() {
        let line = Counter(Arc::new(AtomicUsize::new(0)));
        let mut mmio = transport(&line);
        let ram = mmio.ram.clone();

        // One writable buffer, published in the available ring.
        let mut descriptor = [0u8; 16];
        descriptor[0..8].copy_from_slice(&BUFFER.to_le_bytes());
        descriptor[8..12].copy_from_slice(&16u32.to_le_bytes());
        descriptor[12..14].copy_from_slice(&2u16.to_le_bytes());
        ram.write(DESC_TABLE, &descriptor).expect("descriptor");
        ram.write(AVAIL_RING + 4, &0u16.to_le_bytes())
            .expect("head");
        ram.write(AVAIL_RING + 2, &1u16.to_le_bytes())
            .expect("index");

        set(&mut mmio, QUEUE_NUM, 8);
        set(&mut mmio, QUEUE_DESC_LOW, DESC_TABLE as u32);
        set(&mut mmio, QUEUE_AVAIL_LOW, AVAIL_RING as u32);
        set(&mut mmio, QUEUE_USED_LOW, USED_RING as u32);
        set(&mut mmio, QUEUE_READY, 1);

        BusDevice::restored(&mut mmio);

        // Backend filled the buffer, reported it used and raised the line.
        let mut filled = [0u8; 16];
        ram.read(BUFFER, &mut filled).expect("read the buffer back");
        assert_eq!(filled, [0xa5u8; 16], "buffer not filled");
        assert_eq!(used_index(&ram), 1);
        assert_eq!(line.raises(), 1, "line not raised after the restore");
        assert_eq!(reg(&mut mmio, INTERRUPT_STATUS), INTERRUPT_VRING);

        // No new chain offered, second run raises no line.
        BusDevice::restored(&mut mmio);
        assert_eq!(line.raises(), 1, "an untouched queue woke the guest");
    }

    #[test]
    fn test_reject_blob_queue_count() {
        let line = Counter(Arc::new(AtomicUsize::new(0)));
        let mut mmio = transport(&line);

        let blob = BusDevice::capture(&mmio)
            .expect("capture")
            .expect("transport has state");
        // Blob written by a transport with one more queue, as another kind
        // of device behind the same `virtio-mmio` kind would write.
        let mut state: TransportState = serde_json::from_slice(&blob.data).expect("decode");
        state.queues.push(SlotState::default());
        let blob = Blob {
            kind: blob.kind,
            version: blob.version,
            data: serde_json::to_vec(&state).expect("encode"),
        };

        assert!(matches!(
            BusDevice::restore(&mut mmio, &blob),
            Err(BusError::WrongQueues {
                found: 2,
                wanted: 1
            })
        ));
    }

    #[test]
    fn test_wake_after_passthrough() {
        let line = Counter(Arc::new(AtomicUsize::new(0)));
        let ram = GuestRam::new(&[(0, RAM_SIZE)]).expect("host pages");
        let mmio = Transport::new(
            Box::new(Filler {
                wake: Some(Duration::from_millis(40)),
                ..Default::default()
            }),
            ram,
            Box::new(line.clone()),
        );

        assert_eq!(mmio.wake_after(), Some(Duration::from_millis(40)));
    }
}
