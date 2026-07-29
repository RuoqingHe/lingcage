// SPDX-FileCopyrightText: 2026 LingCage <opensource@lingcage.com>
//
// SPDX-License-Identifier: Apache-2.0

//! Virtio console device, section 5.3 of virtio 1.2.
//!
//! A guest agent is reached over a named port, not the serial line,
//! since a name is how it finds the port: it reads
//! `/sys/class/virtio-ports/*/name` and opens the device behind the one
//! it wants. `VIRTIO_CONSOLE_F_MULTIPORT` carries those names.
//!
//! Queues come in pairs, a receive and a transmit per port, with the
//! control pair between port zero and port one. Each port is carried to a
//! stream socket of the host, and the far side of it reaches the guest.

use std::io::{self, Read, Write};
use std::os::fd::{AsRawFd, RawFd};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::PathBuf;

use log::{debug, warn};

use crate::devices::virtio::queue::Queue;
use crate::devices::virtio::{Device, Result};
use crate::hv::Interest;
use crate::mem::GuestRam;

/// Device ID of the console device, section 5.3.
const DEVICE_ID: u32 = 3;

/// `VIRTIO_CONSOLE_F_MULTIPORT`, feature bit 1. Ports are named and the
/// control queue carries the names.
const FEATURE_MULTIPORT: u64 = 1 << 1;

/// Queue of the receive half of port zero.
const PORT0_RECEIVE: u16 = 0;

/// Queue of the transmit half of port zero.
const PORT0_TRANSMIT: u16 = 1;

/// Queue carrying control messages to the guest.
const CONTROL_RECEIVE: u16 = 2;

/// Queue carrying control messages from the guest.
const CONTROL_TRANSMIT: u16 = 3;

/// Queue of the receive half of port `index`, counting port zero as zero.
fn receive_of(port: u16) -> u16 {
    if port == 0 {
        PORT0_RECEIVE
    } else {
        2 + port * 2
    }
}

/// Queue of the transmit half of port `index`. The receive half is one
/// below it, so `notify` finds the port by halving the index.
#[cfg(test)]
fn transmit_of(port: u16) -> u16 {
    if port == 0 {
        PORT0_TRANSMIT
    } else {
        3 + port * 2
    }
}

/// Control events, `VIRTIO_CONSOLE_*` of section 5.3.6.1.
mod event {
    /// Events of section 5.3.6.1, each about one port.
    pub const DEVICE_READY: u16 = 0;
    pub const DEVICE_ADD: u16 = 1;
    pub const PORT_READY: u16 = 3;
    pub const CONSOLE_PORT: u16 = 4;
    pub const PORT_OPEN: u16 = 6;
    pub const PORT_NAME: u16 = 7;
}

/// Bytes of `virtio_console_control`.
const CONTROL_SIZE: usize = 8;

/// Largest message moved between the guest and a port in one go.
const CHUNK: usize = 4096;

/// Bytes of a port held for a host end nobody has connected to yet. A
/// guest which writes before its reader arrives keeps this much, past it
/// the oldest bytes go.
const HELD: usize = 64 * 1024;

/// One named port and the host end behind it.
struct Port {
    name: String,
    /// Socket the host end is accepted on, `None` once accepted.
    listening: Option<UnixListener>,
    /// Host end, once it has been connected to.
    host: Option<UnixStream>,
    /// Bytes read from the host end and not yet given to the guest.
    to_guest: Vec<u8>,
    /// Bytes of the guest waiting for a host end to write them to.
    to_host: Vec<u8>,
    /// Set once the name and the open state have been told to the guest.
    announced: bool,
}

/// Console device with named ports.
pub struct Console {
    ports: Vec<Port>,
    /// Control messages waiting for the receive queue of the control pair.
    pending: Vec<Vec<u8>>,
    /// Set once the guest is ready for the port list.
    ready: bool,
    /// Bytes carried each way, for the log at teardown.
    sent: u64,
    taken: u64,
}

impl Console {
    /// Create a console whose ports are `named`, each with the path its
    /// host end is accepted on.
    pub fn new(named: &[(String, PathBuf)]) -> io::Result<Self> {
        if named.is_empty() {
            return Err(io::ErrorKind::InvalidInput.into());
        }
        let mut ports = Vec::with_capacity(named.len());
        for (name, at) in named {
            let _ = std::fs::remove_file(at);
            let listening = UnixListener::bind(at)?;
            listening.set_nonblocking(true)?;
            ports.push(Port {
                name: name.clone(),
                listening: Some(listening),
                host: None,
                to_guest: Vec::new(),
                to_host: Vec::new(),
                announced: false,
            });
        }
        Ok(Console {
            ports,
            pending: Vec::new(),
            ready: false,
            sent: 0,
            taken: 0,
        })
    }

    /// Lay `virtio_console_control` out for the guest.
    fn control(id: u32, event: u16, value: u16, name: Option<&str>) -> Vec<u8> {
        let mut out = Vec::with_capacity(CONTROL_SIZE + name.map_or(0, str::len));
        out.extend_from_slice(&id.to_le_bytes());
        out.extend_from_slice(&event.to_le_bytes());
        out.extend_from_slice(&value.to_le_bytes());
        if let Some(name) = name {
            out.extend_from_slice(name.as_bytes());
        }
        out
    }

    /// Queue the messages which tell the guest about every port.
    fn announce(&mut self) {
        for index in 0..self.ports.len() {
            if self.ports[index].announced {
                continue;
            }
            let id = index as u32;
            let name = self.ports[index].name.clone();
            self.pending
                .push(Console::control(id, event::DEVICE_ADD, 0, None));
            self.pending
                .push(Console::control(id, event::PORT_NAME, 1, Some(&name)));
            self.ports[index].announced = true;
        }
    }

    /// Accept the host end of any port nobody has connected to yet.
    fn accept(&mut self) {
        let mut joined = Vec::new();
        for (index, port) in self.ports.iter_mut().enumerate() {
            if port.host.is_some() {
                continue;
            }
            let Some(listening) = &port.listening else {
                continue;
            };
            match listening.accept() {
                Ok((stream, _)) => {
                    if stream.set_nonblocking(true).is_err() {
                        continue;
                    }
                    debug!("console port {} was connected to", port.name);
                    port.host = Some(stream);
                    joined.push(index);
                }
                Err(err) if err.kind() == io::ErrorKind::WouldBlock => {}
                Err(err) => warn!("console port {} refused a dial: {err}", port.name),
            }
        }
        for port in joined {
            // What the guest said before is given to the new arrival.
            self.push(port);
        }
    }

    /// Move bytes of the transmit queue of `port` to its host end.
    fn take_from_guest(&mut self, port: usize, queue: &mut Queue, ram: &GuestRam) -> Result<()> {
        while let Some(chain) = queue.pop(ram)? {
            let mut bytes = Vec::new();
            for descriptor in chain.descriptors.iter().filter(|one| !one.writable()) {
                let mut part = vec![0u8; descriptor.len as usize];
                if ram.read(descriptor.addr, &mut part).is_ok() {
                    bytes.extend_from_slice(&part);
                }
            }
            self.ports[port].to_host.extend_from_slice(&bytes);
            self.push(port);
            queue.add_used(ram, chain.head, 0)?;
        }
        Ok(())
    }

    /// Write what waits for the host end of `port`. Bytes written before
    /// anyone connected are kept, so a guest which speaks first is heard.
    fn push(&mut self, port: usize) {
        let held = self.ports[port].to_host.len();
        if held > HELD {
            // Oldest bytes go, so the port does not grow without bound.
            self.ports[port].to_host.drain(..held - HELD);
        }
        if self.ports[port].host.is_none() {
            return;
        }
        let waiting = std::mem::take(&mut self.ports[port].to_host);
        let host = self.ports[port].host.as_mut().expect("a host end");
        let mut written = 0;
        while written < waiting.len() {
            match host.write(&waiting[written..]) {
                Ok(0) => break,
                Ok(put) => written += put,
                Err(err) if err.kind() == io::ErrorKind::WouldBlock => break,
                Err(err) if err.kind() == io::ErrorKind::Interrupted => {}
                Err(err) => {
                    debug!("console port could not be written: {err}");
                    break;
                }
            }
        }
        self.taken += written as u64;
        self.ports[port].to_host = waiting[written..].to_vec();
    }

    /// Move bytes waiting for `port` into its receive queue.
    fn give_to_guest(&mut self, port: usize, queue: &mut Queue, ram: &GuestRam) -> Result<()> {
        if let Some(host) = self.ports[port].host.as_mut() {
            let mut chunk = vec![0u8; CHUNK];
            match host.read(&mut chunk) {
                Ok(0) => {}
                Ok(len) => {
                    chunk.truncate(len);
                    self.ports[port].to_guest.extend_from_slice(&chunk);
                }
                Err(err) if err.kind() == io::ErrorKind::WouldBlock => {}
                Err(err) => debug!("console port could not be read: {err}"),
            }
        }
        while !self.ports[port].to_guest.is_empty() {
            let Some(chain) = queue.pop(ram)? else { break };
            let mut written = 0;
            for descriptor in chain.descriptors.iter().filter(|one| one.writable()) {
                let waiting = &self.ports[port].to_guest;
                if written >= waiting.len() {
                    break;
                }
                let room = (descriptor.len as usize).min(waiting.len() - written);
                if ram
                    .write(descriptor.addr, &waiting[written..written + room])
                    .is_err()
                {
                    break;
                }
                written += room;
            }
            self.ports[port].to_guest.drain(..written);
            self.sent += written as u64;
            queue.add_used(ram, chain.head, written as u32)?;
        }
        Ok(())
    }

    /// Answer a control message the guest sent.
    fn control_from_guest(&mut self, queue: &mut Queue, ram: &GuestRam) -> Result<()> {
        while let Some(chain) = queue.pop(ram)? {
            let mut bytes = Vec::new();
            for descriptor in chain.descriptors.iter().filter(|one| !one.writable()) {
                let mut part = vec![0u8; descriptor.len as usize];
                if ram.read(descriptor.addr, &mut part).is_ok() {
                    bytes.extend_from_slice(&part);
                }
            }
            if bytes.len() >= CONTROL_SIZE {
                let id = u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
                let what = u16::from_le_bytes([bytes[4], bytes[5]]);
                self.heard(id, what);
            }
            queue.add_used(ram, chain.head, 0)?;
        }
        Ok(())
    }

    /// Act on one control message of the guest.
    fn heard(&mut self, id: u32, what: u16) {
        match what {
            event::DEVICE_READY => {
                self.ready = true;
                self.announce();
            }
            event::PORT_READY => {
                // Port is up, so it is told it is open and that it is not
                // a console, which keeps the guest from binding a tty to it.
                self.pending
                    .push(Console::control(id, event::CONSOLE_PORT, 0, None));
                self.pending
                    .push(Console::control(id, event::PORT_OPEN, 1, None));
            }
            event::PORT_OPEN => {}
            other => debug!("console heard control event {other} about port {id}"),
        }
    }

    /// Hand the control messages waiting to the guest.
    fn control_to_guest(&mut self, queue: &mut Queue, ram: &GuestRam) -> Result<()> {
        while !self.pending.is_empty() {
            let Some(chain) = queue.pop(ram)? else { break };
            let message = self.pending.remove(0);
            let mut written = 0;
            for descriptor in chain.descriptors.iter().filter(|one| one.writable()) {
                if written >= message.len() {
                    break;
                }
                let room = (descriptor.len as usize).min(message.len() - written);
                if ram
                    .write(descriptor.addr, &message[written..written + room])
                    .is_err()
                {
                    break;
                }
                written += room;
            }
            queue.add_used(ram, chain.head, written as u32)?;
        }
        Ok(())
    }
}

impl Device for Console {
    fn device_id(&self) -> u32 {
        DEVICE_ID
    }

    fn features(&self) -> u64 {
        FEATURE_MULTIPORT
    }

    fn queue_count(&self) -> u16 {
        // A receive and a transmit for each port, and the control pair
        // between port zero and the rest.
        2 + 2 * self.ports.len() as u16
    }

    fn read_config(&mut self, offset: u64, size: u8) -> u64 {
        // `cols`, `rows`, `max_nr_ports` and `emerg_wr`.
        let mut space = [0u8; 16];
        space[4..8].copy_from_slice(&(self.ports.len() as u32).to_le_bytes());
        let mut value = 0u64;
        for index in 0..size as usize {
            let byte = space.get(offset as usize + index).copied().unwrap_or(0);
            value |= u64::from(byte) << (index * 8);
        }
        value
    }

    fn outside(&self) -> Vec<(RawFd, Interest)> {
        let mut watched = Vec::new();
        for port in &self.ports {
            match (&port.host, &port.listening) {
                (Some(host), _) => watched.push((host.as_raw_fd(), Interest::Read)),
                (None, Some(listening)) => watched.push((listening.as_raw_fd(), Interest::Read)),
                (None, None) => {}
            }
        }
        watched
    }

    fn counts(&self) -> Vec<(&'static str, u64)> {
        vec![("sent", self.sent), ("taken", self.taken)]
    }

    fn notify(&mut self, index: u16, queue: &mut Queue, ram: &GuestRam) -> Result<()> {
        self.accept();
        match index {
            CONTROL_TRANSMIT => self.control_from_guest(queue, ram),
            CONTROL_RECEIVE => {
                self.announce();
                self.control_to_guest(queue, ram)
            }
            other => {
                let port = if other == PORT0_RECEIVE || other == PORT0_TRANSMIT {
                    0
                } else {
                    ((other - 2) / 2) as usize
                };
                if port >= self.ports.len() {
                    return Ok(());
                }
                if other == receive_of(port as u16) {
                    self.give_to_guest(port, queue, ram)
                } else {
                    self.take_from_guest(port, queue, ram)
                }
            }
        }
    }

    fn restored(&mut self, _index: u16, _queue: &mut Queue, _ram: &GuestRam) -> Result<()> {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use crate::devices::virtio::console::*;

    fn console() -> (Console, PathBuf) {
        let at = std::env::temp_dir().join(format!(
            "lingcore-console-{}-{:?}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let console =
            Console::new(&[("agent".to_string(), at.clone())]).expect("a console with one port");
        (console, at)
    }

    #[test]
    fn test_queue_count_per_port() {
        let (console, at) = console();
        // One port and the control pair.
        assert_eq!(console.queue_count(), 4);
        let _ = std::fs::remove_file(at);
    }

    #[test]
    fn test_queue_of_each_half() {
        assert_eq!(receive_of(0), PORT0_RECEIVE);
        assert_eq!(transmit_of(0), PORT0_TRANSMIT);
        // Port one sits behind the control pair.
        assert_eq!(receive_of(1), 4);
        assert_eq!(transmit_of(1), 5);
    }

    #[test]
    fn test_ready_announces_every_port() {
        let (mut console, at) = console();
        assert!(console.pending.is_empty());
        console.heard(0, event::DEVICE_READY);
        assert_eq!(console.pending.len(), 2, "add and name were not both sent");
        let name = &console.pending[1];
        assert_eq!(&name[CONTROL_SIZE..], b"agent");
        let _ = std::fs::remove_file(at);
    }

    #[test]
    fn test_port_ready_opens_it() {
        let (mut console, at) = console();
        console.heard(0, event::PORT_READY);
        let events: Vec<u16> = console
            .pending
            .iter()
            .map(|one| u16::from_le_bytes([one[4], one[5]]))
            .collect();
        assert!(events.contains(&event::PORT_OPEN), "port was not opened");
        assert!(
            events.contains(&event::CONSOLE_PORT),
            "port was not told it is no console"
        );
        let _ = std::fs::remove_file(at);
    }

    #[test]
    fn test_config_reports_port_count() {
        let (mut console, at) = console();
        assert_eq!(console.read_config(4, 4), 1);
        let _ = std::fs::remove_file(at);
    }
}
