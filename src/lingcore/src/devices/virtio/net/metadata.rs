// SPDX-FileCopyrightText: 2026 LingCage <opensource@lingcage.com>
//
// SPDX-License-Identifier: Apache-2.0

//! Metadata service of a guest, a carrier wrapped around another. `PUT
//! /latest/api/token` and `GET /` of Firecracker MMDS V2 are answered at one
//! address from a document given at assembly; other frames pass to the link.

use std::collections::VecDeque;
use std::fs::File;
use std::io::{self, Read};
use std::net::Ipv4Addr;
use std::os::fd::RawFd;
use std::time::{Duration, Instant};

use log::{debug, info, warn};
use smoltcp::iface::{Config, Interface, SocketHandle, SocketSet};
use smoltcp::socket::tcp;
use smoltcp::time::Instant as Tick;
use smoltcp::wire::{EthernetAddress, HardwareAddress, IpCidr, Ipv4Address};

use crate::devices::virtio::net::carrier::Carrier;
use crate::devices::virtio::net::frame::MAX_FRAME;
use crate::devices::virtio::net::pipe::Pipe;
use crate::hv::Interest;

/// Port the service listens on.
const PORT: u16 = 80;

/// TCP connections listening at once. A guest sends one request at a time,
/// the rest cover a guest which reconnects before its last one closed.
const CONNECTIONS: usize = 4;

/// Bytes of receive room per connection, a request line and a few headers.
/// A request past it is refused.
const REQUEST: usize = 2048;

/// Bytes of send room per connection on top of the document, for the
/// headers of an answer.
const HEADERS: usize = 1024;

/// Tokens kept at once. The oldest is forgotten past it, so memory is bounded.
const TOKENS: usize = 16;

/// Random bytes in a token, issued as hex.
const TOKEN_BYTES: usize = 16;

/// Peers kept by address and MAC, a guest and a few earlier addresses of it.
const PEERS: usize = 8;

/// Longest TTL of a token in seconds, six hours, the limit of Firecracker
/// MMDS.
const TOKEN_TTL_MAX: u32 = 21_600;

/// Time an idle connection is kept before it is closed. A guest which opens
/// one and sends no request would hold it, and the service has few.
const IDLE: Duration = Duration::from_secs(10);

/// Host file random bytes of tokens are read from.
const ENTROPY: &str = "/dev/urandom";

/// Path a token is requested at.
const TOKEN_AT: &str = "/latest/api/token";

/// Header a token is carried in.
const TOKEN_HEADER: &str = "x-metadata-token";

/// Header the TTL of a token is requested in, seconds.
const TTL_HEADER: &str = "x-metadata-token-ttl-seconds";

/// Fixed fields of an ARP request over Ethernet for IPv4, EtherType to
/// operation: HTYPE 1, PTYPE 0x0800, HLEN 6, PLEN 4, request.
const ARP_REQUEST: [u8; 10] = [0x08, 0x06, 0, 1, 0x08, 0x00, 6, 4, 0, 1];

/// Same fields of an ARP reply.
const ARP_REPLY: [u8; 10] = [0x08, 0x06, 0, 1, 0x08, 0x00, 6, 4, 0, 2];

/// Carrier answering the metadata requests of a guest and passing other
/// frames to `inner`.
pub struct Metadata {
    /// Link the service is wrapped around.
    inner: Box<dyn Carrier>,
    /// Address the service listens on.
    ip: Ipv4Address,
    /// MAC of the service on the wire.
    mac: EthernetAddress,
    /// Document served to a token holder.
    document: Vec<u8>,
    iface: Interface,
    sockets: SocketSet<'static>,
    pipe: Pipe,
    /// Tokens issued and not expired, oldest first.
    issued: Vec<Token>,
    /// Address and MAC of guests seen, newest last. smoltcp sends ARP for a
    /// guest from off its subnet and may get no reply, so the service replies
    /// out of this list.
    peers: Vec<(Ipv4Address, EthernetAddress)>,
    /// Host file random bytes of tokens are read from.
    entropy: File,
    started: Instant,
    /// Next moment smoltcp is due a poll.
    due: Option<Tick>,
    /// Requests answered 200.
    served: u64,
    /// Requests answered 4xx or 5xx.
    refused: u64,
    /// Frames for the service dropped, over the frame size.
    dropped: u64,
}

/// One token issued, valid until `until`.
struct Token {
    /// Hex text of the token.
    text: String,
    /// Moment the token expires.
    until: Instant,
}

impl Metadata {
    /// Wrap `inner` with the service at `ip`, serving `document`.
    pub fn over(inner: Box<dyn Carrier>, ip: Ipv4Addr, document: Vec<u8>) -> io::Result<Self> {
        // smoltcp panics on an interface address which is not unicast, so
        // broadcast, multicast and 0.0.0.0 are refused here.
        if ip.is_broadcast() || ip.is_multicast() || ip.is_unspecified() {
            return Err(io::Error::from(io::ErrorKind::InvalidInput));
        }
        let ip = Ipv4Address::from_octets(ip.octets());
        // MAC is derived from the address. Any MAC works, the guest reaches
        // the service by IP.
        let [a, b, c, d] = ip.octets();
        let mac = EthernetAddress([0x02, 0x00, a, b, c, d]);
        let mut pipe = Pipe {
            from_guest: VecDeque::new(),
            to_guest: VecDeque::new(),
            mtu: MAX_FRAME,
        };
        let mut entropy = File::open(ENTROPY)?;
        let mut setup = Config::new(HardwareAddress::Ethernet(mac));
        setup.random_seed = seed(&mut entropy)?;
        let started = Instant::now();
        let mut iface = Interface::new(setup, &mut pipe, Tick::from_micros(0));
        // Prefix zero puts a peer of any address on the link. smoltcp routes
        // inside its prefix only and sends no ARP without a route, so a
        // narrower prefix leaves the guest unanswered.
        iface.update_ip_addrs(|addrs| {
            let _ = addrs.push(IpCidr::new(ip.into(), 0));
        });
        // Send room holds one answer, headers and document, since
        // `send_slice` is called once per connection.
        let answer = document.len() + HEADERS;
        let mut sockets = SocketSet::new(Vec::new());
        for _ in 0..CONNECTIONS {
            let mut socket = tcp::Socket::new(
                tcp::SocketBuffer::new(vec![0u8; REQUEST]),
                tcp::SocketBuffer::new(vec![0u8; answer]),
            );
            socket.set_timeout(Some(IDLE.into()));
            // A closed connection is put back to listening in the same poll,
            // and `listen` drops a delayed ACK, so the ACK of a FIN is sent
            // at once.
            socket.set_ack_delay(None);
            socket
                .listen((ip, PORT))
                .map_err(|_| io::Error::from(io::ErrorKind::AddrInUse))?;
            sockets.add(socket);
        }
        info!("metadata service at {ip} serves {} bytes", document.len());
        Ok(Metadata {
            inner,
            ip,
            mac,
            document,
            iface,
            sockets,
            pipe,
            issued: Vec::new(),
            peers: Vec::new(),
            entropy,
            started,
            due: None,
            served: 0,
            refused: 0,
            dropped: 0,
        })
    }

    /// Returns `true` for a frame for the service, an IPv4 packet to its
    /// address or an ARP request for it.
    fn for_service(&self, frame: &[u8]) -> bool {
        const ETHERNET: usize = 14;
        if frame.len() < ETHERNET {
            return false;
        }
        let kind = u16::from_be_bytes([frame[12], frame[13]]);
        match kind {
            // IPv4, destination at offset 16 of the packet.
            0x0800 => {
                frame.len() >= ETHERNET + 20
                    && frame[ETHERNET + 16..ETHERNET + 20] == self.ip.octets()
            }
            // ARP over Ethernet for IPv4, target address last.
            0x0806 => {
                frame.len() >= ETHERNET + 28
                    && frame[ETHERNET + 24..ETHERNET + 28] == self.ip.octets()
            }
            _ => false,
        }
    }

    /// Returns smoltcp time of now.
    fn now(&self) -> Tick {
        Tick::from_micros(self.started.elapsed().as_micros() as i64)
    }

    /// Returns `true` once a frame waits in a queue or a timer of smoltcp
    /// is due.
    fn has_work(&self) -> bool {
        !self.pipe.from_guest.is_empty()
            || !self.pipe.to_guest.is_empty()
            || self.due.is_some_and(|due| due <= self.now())
    }

    /// Poll smoltcp, answer the requests received, and poll again so the
    /// answers are in frames before the caller reads them.
    fn poll(&mut self) {
        let now = self.now();
        self.iface.poll(now, &mut self.pipe, &mut self.sockets);
        let handles: Vec<SocketHandle> = self.sockets.iter().map(|(handle, _)| handle).collect();
        self.answer(&handles);
        self.listen_again(&handles);
        self.answer_arp();
        self.iface.poll(now, &mut self.pipe, &mut self.sockets);
        self.due = self.iface.poll_at(now, &self.sockets);
    }

    /// Keep the address and MAC `frame` came from.
    fn remember(&mut self, frame: &[u8]) {
        let peer = Ipv4Address::from_octets([frame[26], frame[27], frame[28], frame[29]]);
        let mac = EthernetAddress::from_bytes(&frame[6..12]);
        self.peers.retain(|(known, _)| *known != peer);
        self.peers.push((peer, mac));
        if self.peers.len() > PEERS {
            self.peers.remove(0);
        }
    }

    /// Reply to the ARP requests smoltcp queued for a peer in `peers`, in
    /// place of the peer, since a guest off the subnet of the service may not
    /// reply to them.
    fn answer_arp(&mut self) {
        let mut kept = VecDeque::new();
        while let Some(frame) = self.pipe.to_guest.pop_front() {
            let asks = frame.len() >= 42 && frame[12..22] == ARP_REQUEST;
            let asked = asks.then(|| {
                let asked = Ipv4Address::from_octets([frame[38], frame[39], frame[40], frame[41]]);
                self.peers
                    .iter()
                    .find(|(peer, _)| *peer == asked)
                    .map(|(_, mac)| *mac)
            });
            let Some(Some(mac)) = asked else {
                kept.push_back(frame);
                continue;
            };
            let mut reply = vec![0u8; 42];
            reply[..6].copy_from_slice(&frame[6..12]);
            reply[6..12].copy_from_slice(mac.as_bytes());
            reply[12..22].copy_from_slice(&ARP_REPLY);
            reply[22..28].copy_from_slice(mac.as_bytes());
            reply[28..32].copy_from_slice(&frame[38..42]);
            reply[32..38].copy_from_slice(&frame[22..28]);
            reply[38..42].copy_from_slice(&frame[28..32]);
            self.pipe.from_guest.push_back(reply);
        }
        self.pipe.to_guest = kept;
    }

    /// Read a complete request of each connection and send its answer. A
    /// partial request waits for the next poll, one with no end within
    /// `REQUEST` bytes is refused.
    fn answer(&mut self, handles: &[SocketHandle]) {
        let mut answers: Vec<(SocketHandle, Option<String>)> = Vec::new();
        for handle in handles {
            let socket = self.sockets.get_mut::<tcp::Socket>(*handle);
            // A connection answered and closed can still receive but no longer
            // send, so a request on it is left alone.
            if !socket.can_recv() || !socket.may_send() {
                continue;
            }
            // `listen` resets the receive room, so a request starts at its
            // head and one `peek` sees it.
            let seen = socket.peek(REQUEST).unwrap_or_default();
            let Some(end) = find(seen, b"\r\n\r\n") else {
                if seen.len() >= REQUEST {
                    let _ = socket.recv(|bytes| (bytes.len(), ()));
                    answers.push((*handle, None));
                }
                continue;
            };
            let request = String::from_utf8_lossy(&seen[..end + 4]).into_owned();
            let _ = socket.recv(|bytes| (bytes.len(), ()));
            answers.push((*handle, Some(request)));
        }
        for (handle, request) in answers {
            let answer = match request {
                Some(request) => self.answer_to(&request),
                None => {
                    self.refused += 1;
                    http(400, "text/plain", b"request is too long\n")
                }
            };
            let socket = self.sockets.get_mut::<tcp::Socket>(handle);
            let _ = socket.send_slice(&answer);
            socket.close();
        }
    }

    /// Put a closed connection back to listening, since the service has
    /// `CONNECTIONS` sockets and a guest requests again and again.
    fn listen_again(&mut self, handles: &[SocketHandle]) {
        for handle in handles {
            let socket = self.sockets.get_mut::<tcp::Socket>(*handle);
            if socket.is_open() {
                continue;
            }
            if let Err(refused) = socket.listen((self.ip, PORT)) {
                debug!("service socket not put back to listen: {refused}");
            }
        }
    }

    /// Returns the answer to `request`, headers included.
    fn answer_to(&mut self, request: &str) -> Vec<u8> {
        let mut lines = request.split("\r\n");
        let Some(first) = lines.next() else {
            self.refused += 1;
            return http(400, "text/plain", b"no request line\n");
        };
        let mut words = first.split_whitespace();
        let (Some(method), Some(path)) = (words.next(), words.next()) else {
            self.refused += 1;
            return http(400, "text/plain", b"no method or path\n");
        };
        debug!("metadata service got {method:?} {path:?}");
        let headers: Vec<(&str, &str)> = lines
            .filter_map(|line| line.split_once(':'))
            .map(|(name, value)| (name.trim(), value.trim()))
            .collect();
        let header = |wanted: &str| {
            headers
                .iter()
                .find(|(name, _)| name.eq_ignore_ascii_case(wanted))
                .map(|(_, value)| *value)
        };
        match (method, path) {
            ("PUT", TOKEN_AT) => {
                // TTL header is required, as in Firecracker MMDS V2. Missing,
                // or past `TOKEN_TTL_MAX`, is refused with 400.
                let ttl = header(TTL_HEADER)
                    .and_then(|value| value.parse::<u32>().ok())
                    .filter(|ttl| (1..=TOKEN_TTL_MAX).contains(ttl));
                let Some(ttl) = ttl else {
                    self.refused += 1;
                    return http(400, "text/plain", b"a token ttl in seconds is needed\n");
                };
                match self.issue(Duration::from_secs(u64::from(ttl))) {
                    Ok(token) => {
                        self.served += 1;
                        http(200, "text/plain", token.as_bytes())
                    }
                    Err(err) => {
                        warn!("token not read from {ENTROPY}: {err}");
                        self.refused += 1;
                        http(500, "text/plain", b"no token could be issued\n")
                    }
                }
            }
            ("PUT", _) => {
                self.refused += 1;
                http(404, "text/plain", b"only the token path takes PUT\n")
            }
            ("GET", _) => {
                // A read without a token, or with an expired one, gets 401 as
                // in Firecracker.
                let now = Instant::now();
                self.issued.retain(|token| token.until > now);
                let carried = header(TOKEN_HEADER);
                let valid = carried
                    .is_some_and(|carried| self.issued.iter().any(|token| token.text == carried));
                if !valid {
                    self.refused += 1;
                    return http(401, "text/plain", b"a token of this service is needed\n");
                }
                if path != "/" {
                    self.refused += 1;
                    return http(404, "text/plain", b"only the document is served\n");
                }
                self.served += 1;
                http(200, "application/json", &self.document)
            }
            _ => {
                self.refused += 1;
                http(405, "text/plain", b"only GET and PUT are answered\n")
            }
        }
    }

    /// Issue a token valid for `ttl` and keep it, forgetting the oldest past
    /// `TOKENS`.
    fn issue(&mut self, ttl: Duration) -> io::Result<String> {
        let mut bytes = [0u8; TOKEN_BYTES];
        self.entropy.read_exact(&mut bytes)?;
        let text: String = bytes.iter().map(|byte| format!("{byte:02x}")).collect();
        self.issued.push(Token {
            text: text.clone(),
            until: Instant::now() + ttl,
        });
        if self.issued.len() > TOKENS {
            self.issued.remove(0);
        }
        Ok(text)
    }
}

impl Carrier for Metadata {
    fn take(&mut self, into: &mut [u8]) -> io::Result<Option<usize>> {
        if self.has_work() {
            self.poll();
        }
        while let Some(frame) = self.pipe.to_guest.pop_front() {
            if frame.len() > into.len() {
                debug!("answer of {} bytes dropped, buffer is shorter", frame.len());
                self.dropped += 1;
                continue;
            }
            into[..frame.len()].copy_from_slice(&frame);
            return Ok(Some(frame.len()));
        }
        self.inner.take(into)
    }

    fn give(&mut self, frame: &[u8]) -> io::Result<bool> {
        if !self.for_service(frame) {
            return self.inner.give(frame);
        }
        if frame.len() > MAX_FRAME {
            debug!("frame of {} bytes for the service dropped", frame.len());
            self.dropped += 1;
            return Ok(true);
        }
        if frame[12..14] == [0x08, 0x00] {
            self.remember(frame);
        }
        // Guest sends the frame to its gateway MAC with the service address in
        // the packet. Destination MAC is rewritten to the MAC of the service,
        // since smoltcp drops a frame for another MAC.
        self.pipe.from_guest.push_back(readdressed(frame, self.mac));
        self.poll();
        Ok(true)
    }

    fn resume(&mut self) -> io::Result<bool> {
        self.inner.resume()
    }

    fn outside(&self) -> Vec<(RawFd, Interest)> {
        self.inner.outside()
    }

    /// Returns zero while frames wait for the guest, otherwise time to the
    /// next deadline of smoltcp or of the link, the smaller.
    fn wake_after(&self) -> Option<Duration> {
        if !self.pipe.to_guest.is_empty() {
            return Some(Duration::ZERO);
        }
        let mine = self.due.map(|due| {
            let now = self.now();
            match due > now {
                true => Duration::from_micros((due - now).total_micros()),
                false => Duration::ZERO,
            }
        });
        match (mine, self.inner.wake_after()) {
            (Some(mine), Some(theirs)) => Some(mine.min(theirs)),
            (mine, theirs) => mine.or(theirs),
        }
    }

    fn counts(&self) -> Vec<(&'static str, u64)> {
        let mut counts = vec![
            ("served", self.served),
            ("refused", self.refused),
            ("dropped", self.dropped),
        ];
        counts.extend(self.inner.counts());
        counts
    }
}

/// Returns `frame` addressed to `mac`.
fn readdressed(frame: &[u8], mac: EthernetAddress) -> Vec<u8> {
    let mut frame = frame.to_vec();
    frame[..6].copy_from_slice(mac.as_bytes());
    frame
}

/// Returns the offset of `needle` in `haystack`, if it is there.
fn find(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
}

/// Returns a seed for smoltcp read from `entropy`.
fn seed(entropy: &mut File) -> io::Result<u64> {
    let mut bytes = [0u8; 8];
    entropy.read_exact(&mut bytes)?;
    Ok(u64::from_ne_bytes(bytes))
}

/// Returns an answer of `status` with `content_type` and `body`.
fn http(status: u16, content_type: &str, body: &[u8]) -> Vec<u8> {
    let reason = match status {
        200 => "OK",
        400 => "Bad Request",
        401 => "Unauthorized",
        404 => "Not Found",
        405 => "Method Not Allowed",
        _ => "Internal Server Error",
    };
    let mut answer = format!(
        "HTTP/1.1 {status} {reason}\r\nContent-Type: {content_type}\r\nContent-Length: \
         {}\r\nConnection: close\r\n\r\n",
        body.len()
    )
    .into_bytes();
    answer.extend_from_slice(body);
    answer
}

#[cfg(test)]
mod tests {
    use std::sync::{Arc, Mutex};

    use smoltcp::wire::Ipv4Cidr;

    use super::*;

    const AT: Ipv4Addr = Ipv4Addr::new(169, 254, 169, 254);

    /// Ethernet frame with an IPv4 packet for `to`.
    fn ipv4_to(to: Ipv4Addr) -> Vec<u8> {
        let mut frame = vec![0u8; 14 + 20];
        frame[12..14].copy_from_slice(&0x0800u16.to_be_bytes());
        frame[14 + 16..14 + 20].copy_from_slice(&to.octets());
        frame
    }

    /// Carrier keeping the frames given to it, in place of the link.
    #[derive(Default)]
    struct Kept(Vec<Vec<u8>>);

    impl Carrier for Kept {
        fn take(&mut self, _into: &mut [u8]) -> io::Result<Option<usize>> {
            Ok(None)
        }

        fn give(&mut self, frame: &[u8]) -> io::Result<bool> {
            self.0.push(frame.to_vec());
            Ok(true)
        }

        fn resume(&mut self) -> io::Result<bool> {
            Ok(true)
        }

        fn outside(&self) -> Vec<(RawFd, Interest)> {
            Vec::new()
        }
    }

    fn service() -> Metadata {
        Metadata::over(
            Box::new(Kept::default()),
            AT,
            b"{\"instanceID\":\"one\"}".to_vec(),
        )
        .expect("service")
    }

    fn token_request() -> &'static str {
        "PUT /latest/api/token HTTP/1.1\r\nHost: x\r\nX-metadata-token-ttl-seconds: 60\r\n\r\n"
    }

    fn token_of(answer: &[u8]) -> String {
        let answer = String::from_utf8_lossy(answer);
        assert!(answer.starts_with("HTTP/1.1 200 "), "{answer}");
        answer.rsplit("\r\n\r\n").next().expect("token").to_owned()
    }

    #[test]
    fn test_frame_for_service_taken() {
        let service = service();
        assert!(service.for_service(&ipv4_to(AT)));
    }

    #[test]
    fn test_other_frame_passed_to_link() {
        let mut service = service();
        let frame = ipv4_to(Ipv4Addr::new(10, 0, 0, 1));
        assert!(!service.for_service(&frame));
        service.give(&frame).expect("link");
        assert!(
            service.pipe.from_guest.is_empty(),
            "frame of the link queued for the service"
        );
    }

    #[test]
    fn test_frame_for_service_readdressed() {
        let service = service();
        let mut frame = ipv4_to(AT);
        // Addressed to the gateway of the guest, as the guest sends it.
        frame[..6].copy_from_slice(&[0x02, 0x00, 0x00, 0x00, 0x00, 0x22]);

        let taken = readdressed(&frame, service.mac);
        assert_eq!(&taken[..6], service.mac.as_bytes(), "frame not readdressed");
        assert_eq!(&taken[6..], &frame[6..], "frame body changed");
    }

    #[test]
    fn test_closed_connection_listens_again() {
        let mut service = service();
        let handles: Vec<SocketHandle> = service.sockets.iter().map(|(h, _)| h).collect();
        service.sockets.get_mut::<tcp::Socket>(handles[0]).abort();
        assert!(
            !service
                .sockets
                .get_mut::<tcp::Socket>(handles[0])
                .is_listening()
        );

        service.listen_again(&handles);

        assert!(
            service
                .sockets
                .get_mut::<tcp::Socket>(handles[0])
                .is_listening(),
            "connection not put back"
        );
    }

    #[test]
    fn test_read_without_token_refused() {
        let mut service = service();
        let answer = service.answer_to("GET / HTTP/1.1\r\nHost: x\r\n\r\n");
        assert!(String::from_utf8_lossy(&answer).starts_with("HTTP/1.1 401 "));
    }

    #[test]
    fn test_read_with_token_serves_document() {
        let mut service = service();
        let token = token_of(&service.answer_to(token_request()));
        assert_eq!(
            token.len(),
            TOKEN_BYTES * 2,
            "token {token} is not hex of the bytes read"
        );

        let answer = service.answer_to(&format!(
            "GET / HTTP/1.1\r\nX-metadata-token: {token}\r\n\r\n"
        ));
        let answer = String::from_utf8_lossy(&answer);
        assert!(answer.starts_with("HTTP/1.1 200 "), "{answer}");
        assert!(answer.ends_with("{\"instanceID\":\"one\"}"), "{answer}");
    }

    #[test]
    fn test_header_case_ignored() {
        let mut service = service();
        let token = token_of(&service.answer_to(
            "PUT /latest/api/token HTTP/1.1\r\nX-METADATA-TOKEN-TTL-SECONDS: 60\r\n\r\n",
        ));
        let answer = service.answer_to(&format!(
            "GET / HTTP/1.1\r\nx-Metadata-Token: {token}\r\n\r\n"
        ));
        assert!(String::from_utf8_lossy(&answer).starts_with("HTTP/1.1 200 "));
    }

    #[test]
    fn test_token_without_ttl_refused() {
        let mut service = service();
        let answer = service.answer_to("PUT /latest/api/token HTTP/1.1\r\n\r\n");
        assert!(String::from_utf8_lossy(&answer).starts_with("HTTP/1.1 400 "));
        let answer = service.answer_to(
            "PUT /latest/api/token HTTP/1.1\r\nX-metadata-token-ttl-seconds: 99999\r\n\r\n",
        );
        assert!(String::from_utf8_lossy(&answer).starts_with("HTTP/1.1 400 "));
    }

    #[test]
    fn test_expired_token_refused() {
        let mut service = service();
        let token = token_of(&service.answer_to(
            "PUT /latest/api/token HTTP/1.1\r\nX-metadata-token-ttl-seconds: 1\r\n\r\n",
        ));
        service.issued[0].until = Instant::now() - Duration::from_secs(1);

        let answer = service.answer_to(&format!(
            "GET / HTTP/1.1\r\nX-metadata-token: {token}\r\n\r\n"
        ));
        assert!(String::from_utf8_lossy(&answer).starts_with("HTTP/1.1 401 "));
        assert!(service.issued.is_empty(), "expired token kept");
    }

    #[test]
    fn test_tokens_issued_bounded() {
        let mut service = service();
        for _ in 0..(TOKENS + 8) {
            service.answer_to(token_request());
        }
        assert_eq!(service.issued.len(), TOKENS, "tokens over TOKENS kept");

        let newest = service.issued.last().expect("token").text.clone();
        let answer = service.answer_to(&format!(
            "GET / HTTP/1.1\r\nX-metadata-token: {newest}\r\n\r\n"
        ));
        assert!(String::from_utf8_lossy(&answer).starts_with("HTTP/1.1 200 "));
    }

    #[test]
    fn test_answer_fits_document() {
        let document = vec![b'x'; 200 * 1024];
        let mut service = Metadata::over(Box::new(Kept::default()), AT, document).expect("service");
        let token = token_of(&service.answer_to(token_request()));

        let answer = service.answer_to(&format!(
            "GET / HTTP/1.1\r\nX-metadata-token: {token}\r\n\r\n"
        ));
        let handle = service.sockets.iter().next().expect("socket").0;
        assert!(
            service
                .sockets
                .get_mut::<tcp::Socket>(handle)
                .send_capacity()
                >= answer.len(),
            "answer of {} bytes does not fit its room",
            answer.len()
        );
    }

    #[test]
    fn test_read_of_other_path_not_found() {
        let mut service = service();
        let token = token_of(&service.answer_to(token_request()));
        let answer = service.answer_to(&format!(
            "GET /nothing HTTP/1.1\r\nX-metadata-token: {token}\r\n\r\n"
        ));
        assert!(String::from_utf8_lossy(&answer).starts_with("HTTP/1.1 404 "));
    }

    #[test]
    fn test_put_of_other_path_not_found() {
        let mut service = service();
        let answer = service.answer_to("PUT /latest HTTP/1.1\r\n\r\n");
        assert!(String::from_utf8_lossy(&answer).starts_with("HTTP/1.1 404 "));
    }

    #[test]
    fn test_other_method_refused() {
        let mut service = service();
        let answer = service.answer_to("POST / HTTP/1.1\r\n\r\n");
        assert!(String::from_utf8_lossy(&answer).starts_with("HTTP/1.1 405 "));
        let answer = service.answer_to("GET\r\n\r\n");
        assert!(String::from_utf8_lossy(&answer).starts_with("HTTP/1.1 400 "));
    }

    #[test]
    fn test_wake_after_zero_with_answer_waiting() {
        let mut service = service();
        assert_eq!(service.wake_after(), None);
        service.pipe.to_guest.push_back(vec![0u8; 60]);
        assert_eq!(service.wake_after(), Some(Duration::ZERO));
        let mut into = vec![0u8; MAX_FRAME];
        assert_eq!(service.take(&mut into).expect("frame"), Some(60));
        assert_eq!(service.wake_after(), None);
    }

    const GUEST_MAC: EthernetAddress = EthernetAddress([0x02, 0, 0, 0, 0, 0x0f]);
    const GUEST_IP: Ipv4Addr = Ipv4Addr::new(10, 0, 2, 15);
    const GATEWAY_IP: Ipv4Addr = Ipv4Addr::new(10, 0, 2, 2);
    const GATEWAY_MAC: EthernetAddress = EthernetAddress([0x52, 0x55, 10, 0, 2, 2]);

    /// Guest end of the tests, a smoltcp interface past the service. Frames
    /// move one at a time through `give` and `take`, as `Net` drives a carrier.
    struct Guest {
        iface: Interface,
        sockets: SocketSet<'static>,
        pipe: Pipe,
        started: Instant,
        next_port: u16,
        /// Frames taken from the service, kept for the assertions.
        taken: Vec<Vec<u8>>,
    }

    impl Guest {
        /// A guest on `prefix`, with a route to `gateway` if one is given.
        fn new(prefix: u8, gateway: Option<Ipv4Addr>) -> Self {
            let mut pipe = Pipe {
                from_guest: VecDeque::new(),
                to_guest: VecDeque::new(),
                mtu: MAX_FRAME,
            };
            let mut setup = Config::new(HardwareAddress::Ethernet(GUEST_MAC));
            setup.random_seed = 7;
            let mut iface = Interface::new(setup, &mut pipe, Tick::from_micros(0));
            iface.update_ip_addrs(|addrs| {
                addrs
                    .push(IpCidr::Ipv4(Ipv4Cidr::new(GUEST_IP, prefix)))
                    .unwrap();
            });
            if let Some(gateway) = gateway {
                iface.routes_mut().add_default_ipv4_route(gateway).unwrap();
            }
            Guest {
                iface,
                sockets: SocketSet::new(Vec::new()),
                pipe,
                started: Instant::now(),
                next_port: 40_000,
                taken: Vec::new(),
            }
        }

        fn now(&self) -> Tick {
            Tick::from_micros(self.started.elapsed().as_micros() as i64)
        }

        /// Run both ends until no frame moves, at most `rounds` times.
        fn exchange(&mut self, service: &mut Metadata, rounds: usize) {
            for _ in 0..rounds {
                let now = self.now();
                self.iface.poll(now, &mut self.pipe, &mut self.sockets);
                let mut moved = false;
                while let Some(frame) = self.pipe.to_guest.pop_front() {
                    service.give(&frame).unwrap();
                    moved = true;
                }
                let mut into = vec![0u8; MAX_FRAME];
                while let Some(len) = service.take(&mut into).unwrap() {
                    self.taken.push(into[..len].to_vec());
                    self.pipe.from_guest.push_back(into[..len].to_vec());
                    moved = true;
                }
                if !moved {
                    std::thread::sleep(Duration::from_millis(2));
                }
            }
        }

        /// Returns a socket connected to the service.
        fn connect(&mut self) -> SocketHandle {
            let socket = tcp::Socket::new(
                tcp::SocketBuffer::new(vec![0u8; 256 * 1024]),
                tcp::SocketBuffer::new(vec![0u8; 4096]),
            );
            let handle = self.sockets.add(socket);
            self.next_port += 1;
            self.sockets
                .get_mut::<tcp::Socket>(handle)
                .connect(self.iface.context(), (AT, PORT), self.next_port)
                .expect("connect");
            handle
        }

        /// Open a connection to the service, send `request` and return the
        /// answer, read until the service closed.
        fn ask(&mut self, service: &mut Metadata, request: &str) -> String {
            let handle = self.connect();
            let mut sent = false;
            let mut answer = Vec::new();
            for _ in 0..400 {
                self.exchange(service, 1);
                let socket = self.sockets.get_mut::<tcp::Socket>(handle);
                if !sent && socket.can_send() {
                    socket.send_slice(request.as_bytes()).expect("send");
                    sent = true;
                }
                while socket.can_recv() {
                    socket
                        .recv(|bytes| {
                            answer.extend_from_slice(bytes);
                            (bytes.len(), ())
                        })
                        .expect("recv");
                }
                // Service closes once answered; close back, so its end
                // listens again.
                if sent && !socket.may_recv() {
                    socket.close();
                }
                if sent && !socket.is_active() {
                    break;
                }
            }
            // The service ACKs the FIN of the guest at once, so the socket is
            // closed inside the rounds; one left in LAST-ACK saw no ACK.
            let state = self.sockets.get::<tcp::Socket>(handle).state();
            assert_eq!(state, tcp::State::Closed, "connection not closed");
            self.sockets.remove(handle);
            String::from_utf8_lossy(&answer).into_owned()
        }

        /// Returns the frames taken which carry a TCP reset.
        fn resets(&self) -> usize {
            self.taken
                .iter()
                .filter(|frame| {
                    frame.len() > 34 && frame[12..14] == [0x08, 0x00] && frame[23] == 6 && {
                        let ihl = usize::from(frame[14] & 0x0f) * 4;
                        frame.len() > 14 + ihl + 13 && frame[14 + ihl + 13] & 0x04 != 0
                    }
                })
                .count()
        }
    }

    /// Carrier in place of a link with a gateway on it: ARP for the gateway
    /// is answered, other frames are kept in `kept`, shared with the test.
    #[derive(Default)]
    struct Gateway {
        kept: Arc<Mutex<Vec<Vec<u8>>>>,
        replies: VecDeque<Vec<u8>>,
    }

    impl Carrier for Gateway {
        fn take(&mut self, into: &mut [u8]) -> io::Result<Option<usize>> {
            let Some(frame) = self.replies.pop_front() else {
                return Ok(None);
            };
            into[..frame.len()].copy_from_slice(&frame);
            Ok(Some(frame.len()))
        }

        fn give(&mut self, frame: &[u8]) -> io::Result<bool> {
            let asks_gateway = frame.len() >= 42
                && frame[12..22] == ARP_REQUEST
                && frame[38..42] == GATEWAY_IP.octets();
            if !asks_gateway {
                self.kept.lock().unwrap().push(frame.to_vec());
                return Ok(true);
            }
            let mut reply = vec![0u8; 42];
            reply[..6].copy_from_slice(&frame[6..12]);
            reply[6..12].copy_from_slice(GATEWAY_MAC.as_bytes());
            reply[12..22].copy_from_slice(&ARP_REPLY);
            reply[22..28].copy_from_slice(GATEWAY_MAC.as_bytes());
            reply[28..32].copy_from_slice(&GATEWAY_IP.octets());
            reply[32..38].copy_from_slice(&frame[22..28]);
            reply[38..42].copy_from_slice(&frame[28..32]);
            self.replies.push_back(reply);
            Ok(true)
        }

        fn resume(&mut self) -> io::Result<bool> {
            Ok(true)
        }

        fn outside(&self) -> Vec<(RawFd, Interest)> {
            Vec::new()
        }
    }

    /// Returns a service over a `Gateway` and the frames the gateway keeps.
    fn service_over_gateway() -> (Metadata, Arc<Mutex<Vec<Vec<u8>>>>) {
        let kept = Arc::new(Mutex::new(Vec::new()));
        let gateway = Gateway {
            kept: Arc::clone(&kept),
            replies: VecDeque::new(),
        };
        let service = Metadata::over(Box::new(gateway), AT, b"{\"instanceID\":\"one\"}".to_vec())
            .expect("service");
        (service, kept)
    }

    fn reads_document(guest: &mut Guest, service: &mut Metadata) {
        let answer = guest.ask(service, token_request());
        assert!(answer.starts_with("HTTP/1.1 200 "), "no token: {answer:?}");
        let token = answer.rsplit("\r\n\r\n").next().unwrap().to_owned();
        let answer = guest.ask(
            service,
            &format!("GET / HTTP/1.1\r\nX-metadata-token: {token}\r\n\r\n"),
        );
        assert!(
            answer.starts_with("HTTP/1.1 200 "),
            "no document: {answer:?}"
        );
        assert!(answer.ends_with("{\"instanceID\":\"one\"}"), "{answer:?}");
    }

    #[test]
    fn test_guest_on_link_answered() {
        // Guest on 10.0.2.15/0 has the service on its link and sends ARP for
        // it.
        let mut service = service();
        let mut guest = Guest::new(0, None);
        reads_document(&mut guest, &mut service);
        assert_eq!(service.served, 2);
        assert_eq!(guest.resets(), 0, "a connection ended in a reset");
    }

    #[test]
    fn test_guest_behind_gateway_answered() {
        // Guest on 10.0.2.15/24 sends to its gateway, so frames reach the
        // service addressed to the gateway and are readdressed.
        let (mut service, _) = service_over_gateway();
        let mut guest = Guest::new(24, Some(GATEWAY_IP));
        reads_document(&mut guest, &mut service);
        assert_eq!(service.served, 2);
        assert_eq!(guest.resets(), 0, "a connection ended in a reset");
    }

    #[test]
    fn test_arp_for_guest_stays_off_link() {
        // ARP smoltcp sends for the guest is replied by the service, so none
        // reaches the link.
        let (mut service, kept) = service_over_gateway();
        let mut guest = Guest::new(24, Some(GATEWAY_IP));
        reads_document(&mut guest, &mut service);
        let asked_guest = |frame: &Vec<u8>| {
            frame.len() >= 42 && frame[12..22] == ARP_REQUEST && frame[38..42] == GUEST_IP.octets()
        };
        assert!(
            !kept.lock().unwrap().iter().any(asked_guest),
            "ARP for the guest reached the link"
        );
    }

    #[test]
    fn test_request_in_two_segments_answered() {
        // Token request sent as two segments is answered once its end arrives.
        let mut service = service();
        let mut guest = Guest::new(0, None);
        let handle = guest.connect();
        let (head, tail) = token_request().split_at(20);
        let mut answer = Vec::new();
        let mut stage = 0;
        for _ in 0..400 {
            guest.exchange(&mut service, 1);
            let socket = guest.sockets.get_mut::<tcp::Socket>(handle);
            if stage == 0 && socket.can_send() {
                socket.send_slice(head.as_bytes()).unwrap();
                stage = 1;
                continue;
            }
            if stage == 1 && socket.send_queue() == 0 {
                socket.send_slice(tail.as_bytes()).unwrap();
                stage = 2;
            }
            while socket.can_recv() {
                socket
                    .recv(|bytes| {
                        answer.extend_from_slice(bytes);
                        (bytes.len(), ())
                    })
                    .unwrap();
            }
            if stage == 2 && !socket.is_active() {
                break;
            }
        }
        let answer = String::from_utf8_lossy(&answer);
        assert!(answer.starts_with("HTTP/1.1 200 "), "{answer:?}");
    }

    #[test]
    fn test_long_request_refused() {
        // A request with no end within `REQUEST` bytes is answered 400.
        let mut service = service();
        let mut guest = Guest::new(0, None);
        let request = "a".repeat(REQUEST + 100);
        let answer = guest.ask(&mut service, &request);
        assert!(answer.starts_with("HTTP/1.1 400 "), "{answer:?}");
        assert_eq!(service.refused, 1);
    }

    #[test]
    fn test_fifth_connection_refused() {
        // Four connections are served at once, a fifth gets a reset.
        let mut service = service();
        let mut guest = Guest::new(0, None);
        let handles: Vec<SocketHandle> = (0..CONNECTIONS + 1).map(|_| guest.connect()).collect();
        guest.exchange(&mut service, 40);
        let established = handles
            .iter()
            .filter(|handle| {
                guest.sockets.get::<tcp::Socket>(**handle).state() == tcp::State::Established
            })
            .count();
        assert_eq!(established, CONNECTIONS, "connections established");
        assert_eq!(guest.resets(), 1, "resets taken");
    }
}
