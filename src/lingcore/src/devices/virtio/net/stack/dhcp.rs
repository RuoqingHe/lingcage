// SPDX-FileCopyrightText: 2026 LingCage <opensource@lingcage.com>
//
// SPDX-License-Identifier: Apache-2.0

//! DHCP server of the stack, which hands out one lease to the guest.

use std::net::Ipv4Addr;

use smoltcp::phy::ChecksumCapabilities;
use smoltcp::wire::{
    DhcpMessageType, DhcpPacket, DhcpRepr, EthernetAddress, EthernetFrame, EthernetProtocol,
    EthernetRepr, IpAddress, IpProtocol, Ipv4Packet, Ipv4Repr, UdpPacket, UdpRepr,
};

/// UDP port the server listens on.
pub const SERVER_PORT: u16 = 67;

/// UDP port the client listens on.
pub const CLIENT_PORT: u16 = 68;

/// Lease time in seconds, long enough that guest does not renew.
const LEASE_SECS: u32 = 365 * 24 * 3600;

/// Bytes of Ethernet, IPv4 and UDP header ahead of the DHCP message.
const HEADERS: usize = 14 + 20 + 8;

/// Lease handed to the guest, together with address of the server.
#[derive(Debug, Clone, Copy)]
pub struct Lease {
    /// Address of the guest.
    pub ip: Ipv4Addr,
    /// Subnet mask of the guest.
    pub mask: Ipv4Addr,
    /// Gateway, source address of the replies.
    pub gateway: Ipv4Addr,
    /// DNS server named in the lease.
    pub dns: Ipv4Addr,
    /// Source MAC address of the replies.
    pub server_mac: EthernetAddress,
}

/// Returns reply frame for the DHCP message in `request`, `None` for a
/// message which takes no reply. Discover gets an offer and request
/// gets an ack, both broadcast since the guest has no address yet.
pub fn reply(lease: &Lease, request: &[u8]) -> Option<Vec<u8>> {
    let packet = DhcpPacket::new_checked(request).ok()?;
    let asked = DhcpRepr::parse(&packet).ok()?;
    let kind = match asked.message_type {
        DhcpMessageType::Discover => DhcpMessageType::Offer,
        DhcpMessageType::Request => DhcpMessageType::Ack,
        _ => return None,
    };
    let mut answer = DhcpRepr {
        message_type: kind,
        transaction_id: asked.transaction_id,
        secs: 0,
        client_hardware_address: asked.client_hardware_address,
        client_ip: Ipv4Addr::UNSPECIFIED,
        your_ip: lease.ip,
        server_ip: lease.gateway,
        router: Some(lease.gateway),
        subnet_mask: Some(lease.mask),
        relay_agent_ip: Ipv4Addr::UNSPECIFIED,
        broadcast: true,
        requested_ip: None,
        client_identifier: None,
        server_identifier: Some(lease.gateway),
        parameter_request_list: None,
        dns_servers: Some(Default::default()),
        max_size: None,
        lease_duration: Some(LEASE_SECS),
        renew_duration: None,
        rebind_duration: None,
        additional_options: &[],
    };
    if let Some(servers) = &mut answer.dns_servers {
        servers.push(lease.dns).ok()?;
    }
    let mut body = vec![0u8; answer.buffer_len()];
    answer
        .emit(&mut DhcpPacket::new_unchecked(&mut body[..]))
        .ok()?;
    Some(frame(lease, &body))
}

/// Wrap `body` into a broadcast frame from server to client port.
fn frame(lease: &Lease, body: &[u8]) -> Vec<u8> {
    let caps = ChecksumCapabilities::default();
    let mut frame = vec![0u8; HEADERS + body.len()];
    let ethernet = EthernetRepr {
        src_addr: lease.server_mac,
        dst_addr: EthernetAddress::BROADCAST,
        ethertype: EthernetProtocol::Ipv4,
    };
    let ip = Ipv4Repr {
        src_addr: lease.gateway,
        dst_addr: Ipv4Addr::BROADCAST,
        next_header: IpProtocol::Udp,
        payload_len: 8 + body.len(),
        hop_limit: 64,
    };
    let udp = UdpRepr {
        src_port: SERVER_PORT,
        dst_port: CLIENT_PORT,
    };
    let mut layer2 = EthernetFrame::new_unchecked(&mut frame[..]);
    ethernet.emit(&mut layer2);
    let mut layer3 = Ipv4Packet::new_unchecked(layer2.payload_mut());
    ip.emit(&mut layer3, &caps);
    let mut layer4 = UdpPacket::new_unchecked(layer3.payload_mut());
    udp.emit(
        &mut layer4,
        &IpAddress::Ipv4(lease.gateway),
        &IpAddress::Ipv4(Ipv4Addr::BROADCAST),
        body.len(),
        |payload| payload.copy_from_slice(body),
        &caps,
    );
    frame
}

#[cfg(test)]
pub(crate) mod tests {
    use crate::devices::virtio::net::stack::dhcp::*;

    /// MAC of the guest in the tests.
    pub const GUEST_MAC: EthernetAddress = EthernetAddress([0x02, 0, 0, 0, 0, 0x0f]);

    pub fn lease() -> Lease {
        Lease {
            ip: Ipv4Addr::new(10, 0, 2, 15),
            mask: Ipv4Addr::new(255, 255, 255, 0),
            gateway: Ipv4Addr::new(10, 0, 2, 2),
            dns: Ipv4Addr::new(10, 0, 2, 3),
            server_mac: EthernetAddress([0x52, 0x55, 0x0a, 0, 2, 2]),
        }
    }

    /// Returns DHCP message of `kind` a client sends, as its bytes.
    pub fn message(kind: DhcpMessageType) -> Vec<u8> {
        let repr = DhcpRepr {
            message_type: kind,
            transaction_id: 0x1234,
            secs: 0,
            client_hardware_address: GUEST_MAC,
            client_ip: Ipv4Addr::UNSPECIFIED,
            your_ip: Ipv4Addr::UNSPECIFIED,
            server_ip: Ipv4Addr::UNSPECIFIED,
            router: None,
            subnet_mask: None,
            relay_agent_ip: Ipv4Addr::UNSPECIFIED,
            broadcast: true,
            requested_ip: None,
            client_identifier: None,
            server_identifier: None,
            parameter_request_list: None,
            dns_servers: None,
            max_size: None,
            lease_duration: None,
            renew_duration: None,
            rebind_duration: None,
            additional_options: &[],
        };
        let mut bytes = vec![0u8; repr.buffer_len()];
        repr.emit(&mut DhcpPacket::new_unchecked(&mut bytes[..]))
            .unwrap();
        bytes
    }

    /// Fields of a reply the tests look at, copied out of the frame.
    pub struct Reply {
        pub kind: DhcpMessageType,
        pub transaction_id: u32,
        pub your_ip: Ipv4Addr,
        pub router: Option<Ipv4Addr>,
        pub subnet_mask: Option<Ipv4Addr>,
        pub dns: Option<Ipv4Addr>,
        pub lease_duration: Option<u32>,
        pub server_identifier: Option<Ipv4Addr>,
    }

    /// Returns DHCP message inside the reply frame `frame`.
    pub fn unwrap(frame: &[u8]) -> Reply {
        let layer2 = EthernetFrame::new_checked(frame).unwrap();
        assert_eq!(layer2.ethertype(), EthernetProtocol::Ipv4);
        assert_eq!(layer2.dst_addr(), EthernetAddress::BROADCAST);
        let layer3 = Ipv4Packet::new_checked(layer2.payload()).unwrap();
        assert_eq!(layer3.next_header(), IpProtocol::Udp);
        let layer4 = UdpPacket::new_checked(layer3.payload()).unwrap();
        assert_eq!(layer4.dst_port(), CLIENT_PORT);
        let packet = DhcpPacket::new_checked(layer4.payload()).unwrap();
        let repr = DhcpRepr::parse(&packet).unwrap();
        Reply {
            kind: repr.message_type,
            transaction_id: repr.transaction_id,
            your_ip: repr.your_ip,
            router: repr.router,
            subnet_mask: repr.subnet_mask,
            dns: repr
                .dns_servers
                .and_then(|servers| servers.first().copied()),
            lease_duration: repr.lease_duration,
            server_identifier: repr.server_identifier,
        }
    }

    #[test]
    fn test_discover_gets_offer_with_lease() {
        let frame = reply(&lease(), &message(DhcpMessageType::Discover)).unwrap();
        let offer = unwrap(&frame);
        assert_eq!(offer.kind, DhcpMessageType::Offer);
        assert_eq!(offer.transaction_id, 0x1234);
        assert_eq!(offer.your_ip, Ipv4Addr::new(10, 0, 2, 15));
        assert_eq!(offer.router, Some(Ipv4Addr::new(10, 0, 2, 2)));
        assert_eq!(offer.subnet_mask, Some(Ipv4Addr::new(255, 255, 255, 0)));
        assert_eq!(offer.dns, Some(Ipv4Addr::new(10, 0, 2, 3)));
        assert_eq!(offer.lease_duration, Some(LEASE_SECS));
    }

    #[test]
    fn test_request_gets_ack() {
        let frame = reply(&lease(), &message(DhcpMessageType::Request)).unwrap();
        let ack = unwrap(&frame);
        assert_eq!(ack.kind, DhcpMessageType::Ack);
        assert_eq!(ack.server_identifier, Some(Ipv4Addr::new(10, 0, 2, 2)));
    }

    #[test]
    fn test_other_messages_get_no_reply() {
        assert!(reply(&lease(), &message(DhcpMessageType::Release)).is_none());
        assert!(reply(&lease(), b"not a dhcp message").is_none());
    }
}
