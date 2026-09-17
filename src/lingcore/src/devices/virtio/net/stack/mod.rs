// SPDX-FileCopyrightText: 2026 LingCage <opensource@lingcage.com>
//
// SPDX-License-Identifier: Apache-2.0

//! Network stack behind virtio-net, a `Carrier` which translates frames
//! of the guest into host sockets in this process, no TAP and no
//! privilege needed.
//!
//! Guest side is a smoltcp interface owning the gateway and DNS
//! addresses, with `any_ip` on so that it accepts packets for any
//! destination. A TCP SYN from the guest opens a listening socket for its
//! destination and a host connection towards it, and bytes are pumped
//! between the two. UDP is mapped flow by flow onto host sockets. DHCP is
//! answered by `dhcp` before smoltcp sees it. Connections do not survive a
//! restore, same as the socket carrier.

use std::collections::{BTreeMap, HashMap, VecDeque};
use std::io::{self, Read, Write};
use std::net::{Ipv4Addr, SocketAddrV4, TcpStream, UdpSocket};
use std::os::fd::{AsRawFd, RawFd};
use std::time::{Duration, Instant};

use log::{debug, warn};
use smoltcp::iface::{Config, Interface, SocketHandle, SocketSet};
use smoltcp::socket::{tcp, udp};
use smoltcp::time::Instant as Tick;
use smoltcp::wire::{
    EthernetAddress, EthernetFrame, EthernetProtocol, HardwareAddress, IpAddress, IpCidr,
    IpEndpoint, IpListenEndpoint, IpProtocol, Ipv4Cidr, Ipv4Packet, TcpPacket, UdpPacket,
};

use crate::devices::virtio::net::carrier::Carrier;
use crate::devices::virtio::net::frame::MAX_FRAME;
use crate::devices::virtio::net::pipe::Pipe;
use crate::hv::Interest;

/// DHCP server, replies before smoltcp gets the message.
mod dhcp;
/// Host side sockets.
mod host;

/// Bytes of receive and send buffer of one TCP connection.
const TCP_BUFFER: usize = 64 * 1024;

/// Bytes moved between a host socket and a TCP connection in one go.
const CHUNK: usize = 16 * 1024;

/// Datagrams one UDP flow holds in each direction.
const UDP_PACKETS: usize = 16;

/// Bytes of datagram buffer of one UDP flow, each direction.
const UDP_BUFFER: usize = UDP_PACKETS * 2048;

/// Most TCP connections open at the same time. A SYN past it is reset.
const CONNECTIONS: usize = 1024;

/// Frames from the guest held for smoltcp. Past it a frame is dropped.
const QUEUE: usize = 64;

/// Time a TCP connection is kept while bytes wait for the guest and it
/// stays quiet.
const TCP_IDLE: Duration = Duration::from_secs(60);

/// Time a UDP flow without traffic is kept.
const UDP_IDLE: Duration = Duration::from_secs(60);

/// Addresses and MTU of the stack.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StackConfig {
    /// Address handed to the guest by DHCP.
    pub ip: Ipv4Addr,
    /// Prefix length of the subnet.
    pub prefix: u8,
    /// Gateway address of the stack. Guest connecting to it is carried to
    /// loopback of the host.
    pub gateway: Ipv4Addr,
    /// DNS server named in the lease, queries to it go to resolvers of
    /// the host.
    pub dns: Ipv4Addr,
    /// MTU told to smoltcp.
    pub mtu: usize,
}

impl Default for StackConfig {
    /// Addresses QEMU user networking uses, 10.0.2.15 behind gateway
    /// 10.0.2.2 with DNS at 10.0.2.3.
    fn default() -> Self {
        StackConfig {
            ip: Ipv4Addr::new(10, 0, 2, 15),
            prefix: 24,
            gateway: Ipv4Addr::new(10, 0, 2, 2),
            dns: Ipv4Addr::new(10, 0, 2, 3),
            mtu: 1500,
        }
    }
}

impl StackConfig {
    /// Returns subnet mask of `prefix`.
    fn mask(&self) -> Ipv4Addr {
        let bits = if self.prefix == 0 {
            0
        } else {
            u32::MAX << (32 - u32::from(self.prefix.min(32)))
        };
        Ipv4Addr::from(bits)
    }

    /// Source MAC address of the stack, derived from the gateway.
    fn server_mac(&self) -> EthernetAddress {
        let [a, b, c, d] = self.gateway.octets();
        EthernetAddress([0x52, 0x55, a, b, c, d])
    }
}

/// One TCP connection of the guest and its host end.
struct Proxy {
    host: TcpStream,
    /// Set once the host connect is done.
    connected: bool,
    /// Bytes from the guest not yet written to the host.
    to_host: Vec<u8>,
    /// Bytes of `to_host` written so far.
    sent: usize,
    /// Bytes read from the host end not yet queued for the guest.
    to_guest: Vec<u8>,
    /// Bytes of `to_guest` queued so far.
    fed: usize,
    /// Set once the host end has closed, FIN is then sent to the guest.
    host_closed: bool,
    /// Set once the guest has closed its side and the host end was shut
    /// for writing.
    guest_closed: bool,
}

/// Counts of the stack, read for a log line at teardown. Conditions the
/// guest brings about are counted here and logged at debug, since it can
/// repeat any of them as fast as it likes.
#[derive(Default)]
struct Counted {
    /// Host connections opened.
    connections: u64,
    /// Connections which failed, at the connect or later.
    failed: u64,
    /// SYNs refused past `CONNECTIONS`.
    refused: u64,
    /// UDP flows opened.
    flows: u64,
    /// Frames dropped, from the guest or to it.
    dropped: u64,
}

/// One UDP destination of the guest, with a host socket per guest port
/// talking to it.
struct Flow {
    to: SocketAddrV4,
    senders: BTreeMap<u16, (UdpSocket, Instant)>,
}

/// Stack, a `Carrier` translating guest frames to host sockets.
pub struct Stack {
    config: StackConfig,
    lease: dhcp::Lease,
    iface: Interface,
    sockets: SocketSet<'static>,
    pipe: Pipe,
    /// Resolvers of the host, DNS queries of the guest go to the first.
    resolvers: Vec<Ipv4Addr>,
    /// TCP connections by handle of their smoltcp socket.
    proxies: HashMap<SocketHandle, Proxy>,
    /// Listening sockets by their endpoint, taken out once a SYN moved
    /// them on.
    listening: HashMap<(Ipv4Addr, u16), SocketHandle>,
    /// UDP flows by handle of their smoltcp socket.
    flows: HashMap<SocketHandle, Flow>,
    /// Sockets bound for UDP by their endpoint.
    bound: HashMap<(Ipv4Addr, u16), SocketHandle>,
    started: Instant,
    /// Next moment smoltcp wants a poll, computed by `poll`.
    due: Option<Tick>,
    counted: Counted,
}

impl Stack {
    /// Create the stack for `config`.
    pub fn new(config: StackConfig) -> io::Result<Self> {
        let mut pipe = Pipe {
            from_guest: VecDeque::new(),
            to_guest: VecDeque::new(),
            mtu: config.mtu,
        };
        let mut setup = Config::new(HardwareAddress::Ethernet(config.server_mac()));
        setup.random_seed = seed();
        let started = Instant::now();
        let mut iface = Interface::new(setup, &mut pipe, Tick::from_micros(0));
        iface.update_ip_addrs(|addrs| {
            for ip in [config.gateway, config.dns] {
                if addrs
                    .push(IpCidr::Ipv4(Ipv4Cidr::new(ip, config.prefix)))
                    .is_err()
                {
                    warn!("stack has no room for address {ip}");
                }
            }
        });
        iface.set_any_ip(true);
        let lease = dhcp::Lease {
            ip: config.ip,
            mask: config.mask(),
            gateway: config.gateway,
            dns: config.dns,
            server_mac: config.server_mac(),
        };
        Ok(Stack {
            config,
            lease,
            iface,
            sockets: SocketSet::new(Vec::new()),
            pipe,
            resolvers: host::resolvers(),
            proxies: HashMap::new(),
            listening: HashMap::new(),
            flows: HashMap::new(),
            bound: HashMap::new(),
            started,
            due: None,
            counted: Counted::default(),
        })
    }

    /// Returns smoltcp time of now.
    fn now(&self) -> Tick {
        Tick::from_micros(self.started.elapsed().as_micros() as i64)
    }

    /// Returns host address a guest destination is reached at. Gateway is
    /// loopback of the host and DNS address is its first resolver, the rest
    /// is taken as it is.
    fn host_address(&self, ip: Ipv4Addr, port: u16) -> SocketAddrV4 {
        if ip == self.config.gateway {
            SocketAddrV4::new(Ipv4Addr::LOCALHOST, port)
        } else if ip == self.config.dns {
            match self.resolvers.first() {
                Some(resolver) => SocketAddrV4::new(*resolver, port),
                None => SocketAddrV4::new(ip, port),
            }
        } else {
            SocketAddrV4::new(ip, port)
        }
    }

    /// Look at a frame from the guest before smoltcp gets it. DHCP is
    /// answered here, a TCP SYN opens the listener and host connection it
    /// needs, and a UDP datagram opens its flow. Returns `false` for a
    /// frame smoltcp should not see.
    fn inspect(&mut self, frame: &[u8]) -> bool {
        let Ok(layer2) = EthernetFrame::new_checked(frame) else {
            return true;
        };
        if layer2.ethertype() != EthernetProtocol::Ipv4 {
            return true;
        }
        let Ok(layer3) = Ipv4Packet::new_checked(layer2.payload()) else {
            return true;
        };
        let dst = layer3.dst_addr();
        match layer3.next_header() {
            IpProtocol::Udp => {
                let Ok(layer4) = UdpPacket::new_checked(layer3.payload()) else {
                    return true;
                };
                if layer4.dst_port() == dhcp::SERVER_PORT {
                    if let Some(reply) = dhcp::reply(&self.lease, layer4.payload()) {
                        self.pipe.to_guest.push_back(reply);
                    }
                    return false;
                }
                self.flow_for(dst, layer4.dst_port());
                true
            }
            IpProtocol::Tcp => {
                let Ok(layer4) = TcpPacket::new_checked(layer3.payload()) else {
                    return true;
                };
                if layer4.syn() && !layer4.ack() {
                    self.listen_for(dst, layer4.dst_port());
                }
                true
            }
            _ => true,
        }
    }

    /// Make sure a socket listens on `ip:port` for the SYN just seen, with
    /// host connection started. Past `CONNECTIONS` none is opened and
    /// smoltcp resets the SYN.
    fn listen_for(&mut self, ip: Ipv4Addr, port: u16) {
        if let Some(handle) = self.listening.get(&(ip, port)) {
            if self.sockets.get::<tcp::Socket>(*handle).state() == tcp::State::Listen {
                return;
            }
            self.listening.remove(&(ip, port));
        }
        if self.proxies.len() >= CONNECTIONS {
            debug!("stack refuses a connection to {ip}:{port}, {CONNECTIONS} are open");
            self.counted.refused += 1;
            return;
        }
        let host = match host::connect(self.host_address(ip, port)) {
            Ok(host) => host,
            Err(err) => {
                debug!("stack could not connect to {ip}:{port}: {err}");
                self.counted.failed += 1;
                return;
            }
        };
        let mut socket = tcp::Socket::new(
            tcp::SocketBuffer::new(vec![0; TCP_BUFFER]),
            tcp::SocketBuffer::new(vec![0; TCP_BUFFER]),
        );
        // Guest which stops answering while bytes wait for it would hold
        // the connection and the host socket for ever, smoltcp resets such
        // connection instead.
        socket.set_timeout(Some(TCP_IDLE.into()));
        if socket
            .listen(IpListenEndpoint {
                addr: Some(IpAddress::Ipv4(ip)),
                port,
            })
            .is_err()
        {
            return;
        }
        let handle = self.sockets.add(socket);
        self.listening.insert((ip, port), handle);
        self.counted.connections += 1;
        self.proxies.insert(
            handle,
            Proxy {
                host,
                connected: false,
                to_host: Vec::new(),
                sent: 0,
                to_guest: Vec::new(),
                fed: 0,
                host_closed: false,
                guest_closed: false,
            },
        );
    }

    /// Make sure a UDP socket is bound on `ip:port`, destination of the
    /// datagram just seen.
    fn flow_for(&mut self, ip: Ipv4Addr, port: u16) {
        if self.bound.contains_key(&(ip, port)) {
            return;
        }
        let mut socket = udp::Socket::new(
            udp::PacketBuffer::new(
                vec![udp::PacketMetadata::EMPTY; UDP_PACKETS],
                vec![0; UDP_BUFFER],
            ),
            udp::PacketBuffer::new(
                vec![udp::PacketMetadata::EMPTY; UDP_PACKETS],
                vec![0; UDP_BUFFER],
            ),
        );
        if socket
            .bind(IpListenEndpoint {
                addr: Some(IpAddress::Ipv4(ip)),
                port,
            })
            .is_err()
        {
            return;
        }
        let handle = self.sockets.add(socket);
        self.bound.insert((ip, port), handle);
        self.counted.flows += 1;
        self.flows.insert(
            handle,
            Flow {
                to: self.host_address(ip, port),
                senders: BTreeMap::new(),
            },
        );
    }

    /// Run smoltcp and move bytes between its sockets and host sockets
    /// until no byte moves any more, then note the next deadline.
    fn poll(&mut self) {
        let now = self.now();
        for _ in 0..8 {
            self.iface.poll(now, &mut self.pipe, &mut self.sockets);
            let moved = self.pump_tcp() | self.pump_udp();
            if !moved {
                break;
            }
        }
        self.iface.poll(now, &mut self.pipe, &mut self.sockets);
        self.due = self.iface.poll_at(now, &self.sockets);
    }

    /// Move bytes of each TCP connection. Returns `true` if any moved.
    fn pump_tcp(&mut self) -> bool {
        let mut moved = false;
        let mut gone = Vec::new();
        for (handle, proxy) in &mut self.proxies {
            let socket = self.sockets.get_mut::<tcp::Socket>(*handle);
            let mut failed = false;
            match pump(proxy, socket) {
                Ok(busy) => moved |= busy,
                // A connect refused by the peer is reported here too.
                Err(err) => {
                    debug!("stack drops a connection: {err}");
                    failed = true;
                    socket.abort();
                }
            }
            // An aborted socket is closed as well, one push for both.
            if socket.state() == tcp::State::Closed {
                // Neither end finished, so the guest reset it or `TCP_IDLE`
                // did.
                if !failed && !proxy.host_closed && !proxy.guest_closed {
                    debug!("stack drops a connection closed by neither end");
                    failed = true;
                }
                gone.push(*handle);
            }
            if failed {
                self.counted.failed += 1;
            }
        }
        for handle in gone {
            self.proxies.remove(&handle);
            self.sockets.remove(handle);
            self.listening.retain(|_, held| *held != handle);
            moved = true;
        }
        moved
    }

    /// Move datagrams of each UDP flow. Returns `true` if any moved.
    fn pump_udp(&mut self) -> bool {
        let mut moved = false;
        let mut gone = Vec::new();
        let ip = self.config.ip;
        let counted = &mut self.counted;
        for (handle, flow) in &mut self.flows {
            let socket = self.sockets.get_mut::<udp::Socket>(*handle);
            // Guest to host, one host socket per guest port.
            while socket.can_recv() {
                let Ok((data, meta)) = socket.recv() else {
                    break;
                };
                let data = data.to_vec();
                let port = meta.endpoint.port;
                let sender = match flow.senders.get_mut(&port) {
                    Some(sender) => sender,
                    None => {
                        let bound = match UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 0)) {
                            Ok(bound) => bound,
                            // Guest picks the ports, so a host out of
                            // descriptors would be met once per datagram.
                            Err(err) => {
                                debug!("stack could not bind a UDP socket: {err}");
                                counted.failed += 1;
                                continue;
                            }
                        };
                        if let Err(err) = bound.set_nonblocking(true) {
                            debug!("stack could not make a UDP socket non-blocking: {err}");
                            counted.failed += 1;
                            continue;
                        }
                        flow.senders.entry(port).or_insert((bound, Instant::now()))
                    }
                };
                sender.1 = Instant::now();
                if let Err(err) = sender.0.send_to(&data, flow.to)
                    && err.kind() != io::ErrorKind::WouldBlock
                {
                    debug!("stack could not send a datagram to {}: {err}", flow.to);
                }
                moved = true;
            }
            // Host to guest, replies go back to the guest port they belong
            // to, from address the guest sent to.
            let local = socket.endpoint().addr;
            let mut buf = [0u8; 2048];
            let mut idle = Vec::new();
            for (port, (sender, last)) in &mut flow.senders {
                while socket.can_send() {
                    match sender.recv_from(&mut buf) {
                        Ok((len, _)) => {
                            *last = Instant::now();
                            let meta = udp::UdpMetadata {
                                endpoint: IpEndpoint::new(IpAddress::Ipv4(ip), *port),
                                local_address: local,
                                meta: Default::default(),
                            };
                            if socket.send_slice(&buf[..len], meta).is_err() {
                                break;
                            }
                            moved = true;
                        }
                        Err(err) if err.kind() == io::ErrorKind::WouldBlock => break,
                        Err(err) => {
                            debug!("stack drops a UDP flow to {}: {err}", flow.to);
                            idle.push(*port);
                            break;
                        }
                    }
                }
                if last.elapsed() > UDP_IDLE {
                    idle.push(*port);
                }
            }
            for port in idle {
                flow.senders.remove(&port);
            }
            if flow.senders.is_empty() && socket.recv_queue() == 0 && socket.send_queue() == 0 {
                gone.push(*handle);
            }
        }
        for handle in gone {
            // A flow without senders is only dropped once idle, a datagram
            // still to be sent keeps it.
            if let Some(flow) = self.flows.get(&handle)
                && flow.senders.is_empty()
            {
                self.flows.remove(&handle);
                self.sockets.remove(handle);
                self.bound.retain(|_, held| *held != handle);
            }
        }
        moved
    }
}

/// Move bytes between the host end and the smoltcp socket of one
/// connection. Returns `true` if any moved. Error means the host end is
/// gone, caller resets the connection.
fn pump(proxy: &mut Proxy, socket: &mut tcp::Socket) -> io::Result<bool> {
    let mut moved = false;
    if !proxy.connected {
        if !host::connected(&proxy.host)? {
            return Ok(false);
        }
        proxy.connected = true;
    }
    // Guest to host.
    if proxy.to_host.is_empty() && socket.can_recv() {
        let mut chunk = vec![0u8; CHUNK];
        if let Ok(len) = socket.recv_slice(&mut chunk) {
            chunk.truncate(len);
            proxy.to_host = chunk;
            proxy.sent = 0;
        }
    }
    while proxy.sent < proxy.to_host.len() {
        match proxy.host.write(&proxy.to_host[proxy.sent..]) {
            Ok(0) => return Err(io::ErrorKind::WriteZero.into()),
            Ok(written) => {
                proxy.sent += written;
                moved = true;
            }
            Err(err) if err.kind() == io::ErrorKind::WouldBlock => break,
            Err(err) if err.kind() == io::ErrorKind::Interrupted => {}
            Err(err) => return Err(err),
        }
    }
    if proxy.sent == proxy.to_host.len() {
        proxy.to_host.clear();
        proxy.sent = 0;
    }
    // Guest sent FIN, the socket is past established. Once all its bytes
    // are out, the host end sees EOF.
    let guest_finished = matches!(
        socket.state(),
        tcp::State::CloseWait | tcp::State::LastAck | tcp::State::Closing | tcp::State::TimeWait
    );
    if guest_finished && proxy.to_host.is_empty() && !socket.can_recv() && !proxy.guest_closed {
        proxy.guest_closed = true;
        if let Err(err) = proxy.host.shutdown(std::net::Shutdown::Write)
            && err.kind() != io::ErrorKind::NotConnected
        {
            return Err(err);
        }
    }
    // Host to guest. Bytes are read into `to_guest` first, since
    // `send_slice` only accepts what the send buffer has room for, and
    // the rest is already read out of the host socket.
    if proxy.to_guest.is_empty() && !proxy.host_closed && socket.can_send() {
        let mut chunk = vec![0u8; CHUNK];
        match proxy.host.read(&mut chunk) {
            Ok(0) => proxy.host_closed = true,
            Ok(len) => {
                chunk.truncate(len);
                proxy.to_guest = chunk;
                proxy.fed = 0;
            }
            Err(err) if err.kind() == io::ErrorKind::WouldBlock => {}
            Err(err) if err.kind() == io::ErrorKind::Interrupted => {}
            Err(err) => return Err(err),
        }
    }
    while proxy.fed < proxy.to_guest.len() {
        match socket.send_slice(&proxy.to_guest[proxy.fed..]) {
            Ok(0) | Err(_) => break,
            Ok(put) => {
                proxy.fed += put;
                moved = true;
            }
        }
    }
    if proxy.fed == proxy.to_guest.len() {
        proxy.to_guest.clear();
        proxy.fed = 0;
    }
    // Close only after `to_guest` is drained, otherwise FIN goes ahead
    // of the bytes still waiting.
    if proxy.host_closed && proxy.to_guest.is_empty() && socket.may_send() {
        socket.close();
        moved = true;
    }
    Ok(moved)
}

/// Seed for sequence numbers of smoltcp, from the clock and the pid.
fn seed() -> u64 {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|since| since.as_nanos() as u64)
        .unwrap_or(0);
    nanos ^ (u64::from(std::process::id()) << 32)
}

impl Carrier for Stack {
    fn take(&mut self, into: &mut [u8]) -> io::Result<Option<usize>> {
        self.poll();
        while let Some(frame) = self.pipe.to_guest.pop_front() {
            if frame.len() > into.len() {
                debug!(
                    "frame of {} bytes dropped, does not fit in buffer",
                    frame.len()
                );
                self.counted.dropped += 1;
                continue;
            }
            into[..frame.len()].copy_from_slice(&frame);
            return Ok(Some(frame.len()));
        }
        Ok(None)
    }

    fn give(&mut self, frame: &[u8]) -> io::Result<bool> {
        if frame.len() > MAX_FRAME {
            debug!(
                "frame of {} bytes dropped, longer than MAX_FRAME",
                frame.len()
            );
            self.counted.dropped += 1;
            return Ok(true);
        }
        if self.pipe.from_guest.len() >= QUEUE {
            debug!(
                "frame of {} bytes dropped, stack queue is full",
                frame.len()
            );
            self.counted.dropped += 1;
            return Ok(true);
        }
        if self.inspect(frame) {
            self.pipe.from_guest.push_back(frame.to_vec());
        }
        self.poll();
        Ok(true)
    }

    fn resume(&mut self) -> io::Result<bool> {
        Ok(true)
    }

    fn counts(&self) -> Vec<(&'static str, u64)> {
        vec![
            ("connections", self.counted.connections),
            ("failed", self.counted.failed),
            ("refused", self.counted.refused),
            ("flows", self.counted.flows),
            ("dropped", self.counted.dropped),
        ]
    }

    /// Returns host sockets, a connection for reading while the guest has
    /// room and for writing while its connect or bytes are pending, a UDP
    /// sender for reading.
    fn outside(&self) -> Vec<(RawFd, Interest)> {
        let mut waited = Vec::new();
        for (handle, proxy) in &self.proxies {
            let socket = self.sockets.get::<tcp::Socket>(*handle);
            let read = proxy.connected && !proxy.host_closed && socket.can_send();
            let write = !proxy.connected || proxy.sent < proxy.to_host.len();
            let interest = match (read, write) {
                (true, true) => Interest::Both,
                (true, false) => Interest::Read,
                (false, true) => Interest::Write,
                (false, false) => continue,
            };
            waited.push((proxy.host.as_raw_fd(), interest));
        }
        for flow in self.flows.values() {
            for (sender, _) in flow.senders.values() {
                waited.push((sender.as_raw_fd(), Interest::Read));
            }
        }
        waited
    }

    /// Returns zero while frames wait for the guest, otherwise time to the
    /// next deadline of smoltcp, capped to the UDP idle check.
    fn wake_after(&self) -> Option<Duration> {
        if !self.pipe.to_guest.is_empty() {
            return Some(Duration::ZERO);
        }
        let now = self.now();
        let mut after = match self.due {
            Some(due) if due <= now => Some(Duration::ZERO),
            Some(due) => Some(Duration::from_micros((due - now).total_micros())),
            None => None,
        };
        if !self.flows.is_empty() {
            after = Some(after.map_or(UDP_IDLE, |held| held.min(UDP_IDLE)));
        }
        after
    }
}

#[cfg(test)]
mod tests {
    use std::net::TcpListener;

    use smoltcp::wire::{ArpOperation, ArpPacket, ArpRepr, DhcpMessageType};

    use crate::devices::virtio::net::stack::*;

    /// MAC of the guest in the tests.
    const GUEST_MAC: EthernetAddress = EthernetAddress([0x02, 0, 0, 0, 0, 0x0f]);

    /// Guest end of the stack in the tests, a smoltcp interface owning the
    /// leased address, connected to the stack frame by frame.
    struct Guest {
        iface: Interface,
        sockets: SocketSet<'static>,
        pipe: Pipe,
        started: Instant,
    }

    impl Guest {
        fn new(config: &StackConfig) -> Self {
            let mut pipe = Pipe {
                from_guest: VecDeque::new(),
                to_guest: VecDeque::new(),
                mtu: config.mtu,
            };
            let mut setup = Config::new(HardwareAddress::Ethernet(GUEST_MAC));
            setup.random_seed = 7;
            let mut iface = Interface::new(setup, &mut pipe, Tick::from_micros(0));
            iface.update_ip_addrs(|addrs| {
                addrs
                    .push(IpCidr::Ipv4(Ipv4Cidr::new(config.ip, config.prefix)))
                    .unwrap();
            });
            iface
                .routes_mut()
                .add_default_ipv4_route(config.gateway)
                .unwrap();
            Guest {
                iface,
                sockets: SocketSet::new(Vec::new()),
                pipe,
                started: Instant::now(),
            }
        }

        fn now(&self) -> Tick {
            Tick::from_micros(self.started.elapsed().as_micros() as i64)
        }

        /// Run both ends until no frame moves, at most `rounds` times.
        fn exchange(&mut self, stack: &mut Stack, rounds: usize) {
            for _ in 0..rounds {
                let now = self.now();
                self.iface.poll(now, &mut self.pipe, &mut self.sockets);
                // Frames of the guest go through `give`, frames of the stack
                // return through `take`, the same way `Net` drives it.
                let mut moved = false;
                while let Some(frame) = self.pipe.to_guest.pop_front() {
                    stack.give(&frame).unwrap();
                    moved = true;
                }
                let mut into = vec![0u8; MAX_FRAME];
                while let Some(len) = stack.take(&mut into).unwrap() {
                    self.pipe.from_guest.push_back(into[..len].to_vec());
                    moved = true;
                }
                if !moved {
                    std::thread::sleep(Duration::from_millis(2));
                }
            }
        }
    }

    /// Logger printing warnings of the stack, so a failing test shows the
    /// refusal of the stack.
    struct Stderr;

    impl log::Log for Stderr {
        fn enabled(&self, _: &log::Metadata) -> bool {
            true
        }

        fn log(&self, record: &log::Record) {
            eprintln!("{}: {}", record.level(), record.args());
        }

        fn flush(&self) {}
    }

    static LOGGER: Stderr = Stderr;

    fn stack() -> Stack {
        if log::set_logger(&LOGGER).is_ok() {
            log::set_max_level(log::LevelFilter::Warn);
        }
        Stack::new(StackConfig::default()).unwrap()
    }

    /// Returns an ARP request from the guest for `ip`, as a frame.
    fn arp_request(config: &StackConfig, ip: Ipv4Addr) -> Vec<u8> {
        let arp = ArpRepr::EthernetIpv4 {
            operation: ArpOperation::Request,
            source_hardware_addr: GUEST_MAC,
            source_protocol_addr: config.ip,
            target_hardware_addr: EthernetAddress::BROADCAST,
            target_protocol_addr: ip,
        };
        let ethernet = smoltcp::wire::EthernetRepr {
            src_addr: GUEST_MAC,
            dst_addr: EthernetAddress::BROADCAST,
            ethertype: EthernetProtocol::Arp,
        };
        let mut frame = vec![0u8; 14 + arp.buffer_len()];
        let mut layer2 = EthernetFrame::new_unchecked(&mut frame[..]);
        ethernet.emit(&mut layer2);
        arp.emit(&mut ArpPacket::new_unchecked(layer2.payload_mut()));
        frame
    }

    #[test]
    fn test_arp_for_gateway_and_dns_is_answered() {
        let mut stack = stack();
        let config = StackConfig::default();
        let mut into = vec![0u8; MAX_FRAME];
        for ip in [config.gateway, config.dns] {
            stack.give(&arp_request(&config, ip)).unwrap();
            let len = stack.take(&mut into).unwrap().expect("ARP reply");
            let layer2 = EthernetFrame::new_checked(&into[..len]).unwrap();
            assert_eq!(layer2.ethertype(), EthernetProtocol::Arp);
            let reply = ArpRepr::parse(&ArpPacket::new_checked(layer2.payload()).unwrap()).unwrap();
            match reply {
                ArpRepr::EthernetIpv4 {
                    operation,
                    source_hardware_addr,
                    source_protocol_addr,
                    ..
                } => {
                    assert_eq!(operation, ArpOperation::Reply);
                    assert_eq!(source_protocol_addr, ip);
                    assert_eq!(source_hardware_addr, config.server_mac());
                }
                _ => panic!("not an IPv4 ARP reply"),
            }
        }
        assert!(stack.take(&mut into).unwrap().is_none());
    }

    #[test]
    fn test_dhcp_is_answered_before_smoltcp() {
        // Discover frame built by hand, offer has to come from `dhcp`.
        let mut stack = stack();
        let lease = dhcp::tests::lease();
        let body = dhcp::tests::message(DhcpMessageType::Discover);
        // A DHCP discover as the guest broadcasts it, from 0.0.0.0.
        let frame = {
            let caps = smoltcp::phy::ChecksumCapabilities::default();
            let mut frame = vec![0u8; 14 + 20 + 8 + body.len()];
            let mut layer2 = EthernetFrame::new_unchecked(&mut frame[..]);
            smoltcp::wire::EthernetRepr {
                src_addr: GUEST_MAC,
                dst_addr: EthernetAddress::BROADCAST,
                ethertype: EthernetProtocol::Ipv4,
            }
            .emit(&mut layer2);
            let mut layer3 = Ipv4Packet::new_unchecked(layer2.payload_mut());
            smoltcp::wire::Ipv4Repr {
                src_addr: Ipv4Addr::UNSPECIFIED,
                dst_addr: Ipv4Addr::BROADCAST,
                next_header: IpProtocol::Udp,
                payload_len: 8 + body.len(),
                hop_limit: 64,
            }
            .emit(&mut layer3, &caps);
            let mut layer4 = UdpPacket::new_unchecked(layer3.payload_mut());
            smoltcp::wire::UdpRepr {
                src_port: dhcp::CLIENT_PORT,
                dst_port: dhcp::SERVER_PORT,
            }
            .emit(
                &mut layer4,
                &IpAddress::Ipv4(Ipv4Addr::UNSPECIFIED),
                &IpAddress::Ipv4(Ipv4Addr::BROADCAST),
                body.len(),
                |payload| payload.copy_from_slice(&body),
                &caps,
            );
            frame
        };
        stack.give(&frame).unwrap();
        assert_eq!(
            stack.wake_after(),
            Some(Duration::ZERO),
            "reply waits for the guest"
        );
        let mut into = vec![0u8; MAX_FRAME];
        let len = stack.take(&mut into).unwrap().expect("DHCP offer");
        let offer = dhcp::tests::unwrap(&into[..len]);
        assert_eq!(offer.kind, DhcpMessageType::Offer);
        assert_eq!(offer.your_ip, lease.ip);
        assert!(stack.bound.is_empty(), "DHCP opened a UDP flow");
    }

    #[test]
    fn test_tcp_connection_reaches_host_and_back() {
        // Guest connects to the gateway, which is loopback of the host,
        // sends a line and reads the echo, then closes.
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let echo = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut got = Vec::new();
            stream.read_to_end(&mut got).unwrap();
            stream.write_all(&got).unwrap();
            got
        });
        let config = StackConfig::default();
        let mut stack = stack();
        let mut guest = Guest::new(&config);
        let socket = tcp::Socket::new(
            tcp::SocketBuffer::new(vec![0; 4096]),
            tcp::SocketBuffer::new(vec![0; 4096]),
        );
        let handle = guest.sockets.add(socket);
        let context = guest.iface.context();
        guest
            .sockets
            .get_mut::<tcp::Socket>(handle)
            .connect(context, (config.gateway, port), 40000)
            .unwrap();
        let deadline = Instant::now() + Duration::from_secs(10);
        while !guest.sockets.get::<tcp::Socket>(handle).may_send() {
            assert!(Instant::now() < deadline, "handshake did not complete");
            guest.exchange(&mut stack, 4);
        }
        guest
            .sockets
            .get_mut::<tcp::Socket>(handle)
            .send_slice(b"hello through the stack")
            .unwrap();
        guest.sockets.get_mut::<tcp::Socket>(handle).close();
        let mut got = Vec::new();
        while Instant::now() < deadline {
            guest.exchange(&mut stack, 4);
            let socket = guest.sockets.get_mut::<tcp::Socket>(handle);
            if socket.can_recv() {
                let mut chunk = [0u8; 64];
                let len = socket.recv_slice(&mut chunk).unwrap();
                got.extend_from_slice(&chunk[..len]);
            }
            if got.len() == 23 && !socket.may_recv() {
                break;
            }
        }
        assert_eq!(got, b"hello through the stack");
        assert_eq!(echo.join().unwrap(), b"hello through the stack");
        // Both ends closed, the proxy goes away.
        while Instant::now() < deadline && !stack.proxies.is_empty() {
            guest.exchange(&mut stack, 4);
        }
        assert!(stack.proxies.is_empty(), "connection left behind");
        assert!(stack.listening.is_empty(), "listener left behind");
        assert_eq!(stack.counted.connections, 1, "connection not counted");
        assert_eq!(stack.counted.failed, 0, "connection counted as failed");
    }

    #[test]
    fn test_host_send_over_buffer_not_dropped() {
        // Make sure no byte is dropped once the send buffer runs full.
        const SENT: usize = 128 * 1024;
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let sending = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let payload: Vec<u8> = (0..SENT).map(|i| (i % 251) as u8).collect();
            stream.write_all(&payload).unwrap();
            drop(stream);
            payload
        });
        let config = StackConfig::default();
        let mut stack = stack();
        let mut guest = Guest::new(&config);
        // A small receive buffer keeps the guest behind the host.
        let socket = tcp::Socket::new(
            tcp::SocketBuffer::new(vec![0; 4096]),
            tcp::SocketBuffer::new(vec![0; 4096]),
        );
        let handle = guest.sockets.add(socket);
        let context = guest.iface.context();
        guest
            .sockets
            .get_mut::<tcp::Socket>(handle)
            .connect(context, (config.gateway, port), 40001)
            .unwrap();
        let deadline = Instant::now() + Duration::from_secs(60);
        let mut got = Vec::new();
        loop {
            assert!(
                Instant::now() < deadline,
                "guest only got {} of {SENT} bytes",
                got.len()
            );
            guest.exchange(&mut stack, 4);
            let socket = guest.sockets.get_mut::<tcp::Socket>(handle);
            while socket.can_recv() {
                let mut chunk = [0u8; 2048];
                let len = socket.recv_slice(&mut chunk).unwrap();
                got.extend_from_slice(&chunk[..len]);
            }
            if !socket.may_recv() && got.len() >= SENT {
                break;
            }
        }
        assert_eq!(got.len(), SENT, "guest did not get every byte");
        assert_eq!(
            got,
            sending.join().unwrap(),
            "bytes do not match what host sent"
        );
    }

    #[test]
    fn test_connection_gets_timeout() {
        // Make sure connection carries a timeout for a guest gone quiet.
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let held = std::thread::spawn(move || listener.accept().unwrap());
        let config = StackConfig::default();
        let mut stack = stack();
        let mut guest = Guest::new(&config);
        let socket = tcp::Socket::new(
            tcp::SocketBuffer::new(vec![0; 4096]),
            tcp::SocketBuffer::new(vec![0; 4096]),
        );
        let handle = guest.sockets.add(socket);
        let context = guest.iface.context();
        guest
            .sockets
            .get_mut::<tcp::Socket>(handle)
            .connect(context, (config.gateway, port), 40002)
            .unwrap();
        let deadline = Instant::now() + Duration::from_secs(10);
        while stack.proxies.is_empty() {
            assert!(Instant::now() < deadline, "guest never got through");
            guest.exchange(&mut stack, 4);
        }
        let opened = *stack.proxies.keys().next().unwrap();
        assert_eq!(
            stack.sockets.get::<tcp::Socket>(opened).timeout(),
            Some(TCP_IDLE.into()),
            "connection left without a timeout"
        );
        drop(held.join().unwrap());
    }

    #[test]
    fn test_udp_datagram_reaches_host_and_back() {
        let server = UdpSocket::bind("127.0.0.1:0").unwrap();
        let port = server.local_addr().unwrap().port();
        server
            .set_read_timeout(Some(Duration::from_secs(10)))
            .unwrap();
        let echo = std::thread::spawn(move || {
            let mut buf = [0u8; 64];
            let (len, from) = server.recv_from(&mut buf).unwrap();
            server.send_to(&buf[..len], from).unwrap();
            buf[..len].to_vec()
        });
        let config = StackConfig::default();
        let mut stack = stack();
        let mut guest = Guest::new(&config);
        let socket = udp::Socket::new(
            udp::PacketBuffer::new(vec![udp::PacketMetadata::EMPTY; 4], vec![0; 4096]),
            udp::PacketBuffer::new(vec![udp::PacketMetadata::EMPTY; 4], vec![0; 4096]),
        );
        let handle = guest.sockets.add(socket);
        guest
            .sockets
            .get_mut::<udp::Socket>(handle)
            .bind(50000)
            .unwrap();
        guest
            .sockets
            .get_mut::<udp::Socket>(handle)
            .send_slice(
                b"ping",
                IpEndpoint::new(IpAddress::Ipv4(config.gateway), port),
            )
            .unwrap();
        let deadline = Instant::now() + Duration::from_secs(10);
        let mut got = None;
        while Instant::now() < deadline && got.is_none() {
            guest.exchange(&mut stack, 4);
            let socket = guest.sockets.get_mut::<udp::Socket>(handle);
            if socket.can_recv() {
                let (data, meta) = socket.recv().unwrap();
                got = Some((data.to_vec(), meta.endpoint));
            }
        }
        let (data, from) = got.expect("no reply reached the guest");
        assert_eq!(data, b"ping");
        assert_eq!(from, IpEndpoint::new(IpAddress::Ipv4(config.gateway), port));
        assert_eq!(echo.join().unwrap(), b"ping");
    }

    #[test]
    fn test_refused_connection_is_reset() {
        // No listener is on the port once it is dropped, the guest sees
        // the connection reset.
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        drop(listener);
        let config = StackConfig::default();
        let mut stack = stack();
        let mut guest = Guest::new(&config);
        let socket = tcp::Socket::new(
            tcp::SocketBuffer::new(vec![0; 4096]),
            tcp::SocketBuffer::new(vec![0; 4096]),
        );
        let handle = guest.sockets.add(socket);
        let context = guest.iface.context();
        guest
            .sockets
            .get_mut::<tcp::Socket>(handle)
            .connect(context, (config.gateway, port), 40001)
            .unwrap();
        let deadline = Instant::now() + Duration::from_secs(10);
        while Instant::now() < deadline && guest.sockets.get::<tcp::Socket>(handle).is_open() {
            guest.exchange(&mut stack, 4);
        }
        assert!(
            !guest.sockets.get::<tcp::Socket>(handle).is_open(),
            "connection stayed open"
        );
        assert!(stack.proxies.is_empty(), "connection left behind");
        assert_eq!(stack.counted.failed, 1, "refused connect not counted");
    }
}
