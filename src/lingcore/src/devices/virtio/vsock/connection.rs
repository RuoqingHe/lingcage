// SPDX-FileCopyrightText: 2026 LingCage <opensource@lingcage.com>
//
// SPDX-License-Identifier: Apache-2.0

//! A single vsock connection. A guest port paired with a host port, the
//! credit of both ends, and the reply to each packet sent by the guest.
//!
//! Connection touches no ring and no socket. The device around it moves
//! the bytes, so refusals here are tested without a guest.

use crate::devices::virtio::vsock::packet::{HOST_CID, Header, Op, STREAM};

/// Bytes held per connection from the guest until the host end takes
/// them, sent to the guest as `buf_alloc`.
pub const WINDOW: u32 = 64 * 1024;

/// Shutdown directions, `VIRTIO_VSOCK_SHUTDOWN_RCV` and `_SEND`. Sender
/// receives no more, or sends no more.
pub const SHUTDOWN_RECEIVE: u32 = 1;
pub const SHUTDOWN_SEND: u32 = 2;
const SHUTDOWN_BOTH: u32 = SHUTDOWN_RECEIVE | SHUTDOWN_SEND;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Stage {
    /// Requested by this end, no `Response` from the guest yet.
    Asking,
    /// Open at both ends. Data is taken in the directions not shut.
    Open,
    /// Closed by either end. Device drops the connection.
    Closed,
}

/// Action taken by the device after `Connection::guest_sent`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Answer {
    /// Send the header to the guest without payload.
    Reply(Header),
    /// Payload is held in `Connection::waiting` until the host end takes it.
    /// `forwarded` then sends the `fwd_cnt` which counts it.
    Took,
    /// `Response` from the guest to the request sent by `Connection::asks`.
    /// Device acknowledges the incoming connection on the host end.
    Opened,
    /// Drop the connection without reply.
    Drop,
    /// No action.
    Nothing,
}

/// Connection from a guest port to a host port.
pub struct Connection {
    guest_port: u32,
    host_port: u32,
    guest_cid: u64,
    stage: Stage,
    /// Directions shut by the guest, as `SHUTDOWN_*` bits.
    guest_shut: u32,
    /// Directions shut by the host end, as `SHUTDOWN_*` bits, each one is
    /// told to the guest in a `Shutdown`.
    host_shut: u32,
    /// `buf_alloc` of the guest.
    peer_window: u32,
    /// `fwd_cnt` of the guest.
    peer_taken: u32,
    /// Bytes sent to the guest.
    sent: u32,
    /// Bytes from the guest already written to the host end, sent as
    /// `fwd_cnt`.
    taken: u32,
    /// Bytes from the guest not yet written to the host end. At most
    /// `WINDOW`, which is the `buf_alloc` sent to the guest.
    pending: Vec<u8>,
}

impl Connection {
    /// Create the connection requested by `asked`, a packet from `guest_cid`.
    pub fn new(guest_cid: u64, asked: &Header) -> Self {
        Connection {
            guest_port: asked.src_port,
            host_port: asked.dst_port,
            guest_cid,
            stage: Stage::Open,
            guest_shut: 0,
            host_shut: 0,
            peer_window: asked.buf_alloc,
            peer_taken: asked.fwd_cnt,
            sent: 0,
            taken: 0,
            pending: Vec::new(),
        }
    }

    /// Create the connection which a host process connected to `guest_port`.
    /// It is opened by `Response` of the guest to `Connection::asks`.
    pub fn asking(guest_cid: u64, guest_port: u32, host_port: u32) -> Self {
        Connection {
            guest_port,
            host_port,
            guest_cid,
            stage: Stage::Asking,
            guest_shut: 0,
            host_shut: 0,
            // `buf_alloc` of the guest arrives with its `Response`, `room`
            // is zero until then.
            peer_window: 0,
            peer_taken: 0,
            sent: 0,
            taken: 0,
            pending: Vec::new(),
        }
    }

    /// Returns the response to the request, the first header sent.
    pub fn opened(&self) -> Header {
        self.to_guest(Op::Response)
    }

    /// Returns the request for an incoming connection, the first header sent.
    pub fn asks(&self) -> Header {
        self.to_guest(Op::Request)
    }

    /// Returns guest port and host port, the pair the device looks up a
    /// packet by.
    pub fn ports(&self) -> (u32, u32) {
        (self.guest_port, self.host_port)
    }

    /// Returns whether the connection is closed.
    pub fn done(&self) -> bool {
        self.stage == Stage::Closed
    }

    /// Returns whether the connection is waiting for a packet from the
    /// guest, either the `Response` to a request or the `Reset` after a
    /// `Shutdown` of both directions.
    pub fn waiting_on_guest(&self) -> bool {
        self.stage == Stage::Asking || self.host_shut == SHUTDOWN_BOTH
    }

    /// Returns whether the guest has shut its send direction. No more data
    /// comes from it, and its waiting bytes are the last ones.
    pub fn guest_sends_no_more(&self) -> bool {
        self.guest_shut & SHUTDOWN_SEND != 0
    }

    /// Returns whether the guest has shut both directions. Device closes
    /// with a `Reset` once the waiting bytes are written.
    pub fn guest_closed(&self) -> bool {
        self.guest_shut == SHUTDOWN_BOTH
    }

    /// Returns a header for `op` addressed to the guest, with the credit
    /// carried.
    fn to_guest(&self, op: Op) -> Header {
        Header {
            src_cid: HOST_CID,
            dst_cid: self.guest_cid,
            src_port: self.host_port,
            dst_port: self.guest_port,
            len: 0,
            kind: STREAM,
            op,
            flags: 0,
            buf_alloc: WINDOW,
            fwd_cnt: self.taken,
        }
    }

    /// Returns the answer to `header` and `payload` from the guest.
    /// `buf_alloc` and `fwd_cnt` are read from each packet, same as the
    /// driver does (`virtio_transport_space_update`).
    pub fn guest_sent(&mut self, header: &Header, payload: &[u8]) -> Answer {
        self.peer_window = header.buf_alloc;
        self.peer_taken = header.fwd_cnt;
        match header.op {
            // Second request on an open connection.
            Op::Request => Answer::Reply(self.to_guest(Op::Reset)),
            Op::Reset => {
                self.stage = Stage::Closed;
                Answer::Drop
            }
            // Shutdown itself closes nothing. Bytes sent by the guest before
            // it still go to the host end, and the other direction stays
            // open until its own end shuts it.
            Op::Shutdown => {
                self.guest_shut |= header.flags & SHUTDOWN_BOTH;
                Answer::Nothing
            }
            Op::Data => {
                if self.stage != Stage::Open || self.guest_sends_no_more() {
                    return Answer::Reply(self.to_guest(Op::Reset));
                }
                // Serving the shorter one of `len` and payload would leave the
                // counts of two ends apart.
                if header.len as usize != payload.len() {
                    self.stage = Stage::Closed;
                    return Answer::Reply(self.to_guest(Op::Reset));
                }
                // Data beyond the `buf_alloc` sent to the guest is refused.
                if self.pending.len() + payload.len() > WINDOW as usize {
                    self.stage = Stage::Closed;
                    return Answer::Reply(self.to_guest(Op::Reset));
                }
                self.pending.extend_from_slice(payload);
                Answer::Took
            }
            Op::CreditRequest => Answer::Reply(self.to_guest(Op::CreditUpdate)),
            Op::CreditUpdate => Answer::Nothing,
            Op::Response => {
                // Only an incoming connection has a request out, `Response`
                // on any other is reset.
                if self.stage != Stage::Asking {
                    return Answer::Reply(self.to_guest(Op::Reset));
                }
                self.stage = Stage::Open;
                Answer::Opened
            }
        }
    }

    /// Returns bytes not yet written to the host end.
    pub fn waiting(&self) -> &[u8] {
        &self.pending
    }

    /// Count the first `count` waiting bytes as written to the host end and
    /// return the `CreditUpdate` carrying the advanced `fwd_cnt`.
    pub fn forwarded(&mut self, count: usize) -> Header {
        let count = count.min(self.pending.len());
        self.pending.drain(..count);
        self.taken = self.taken.wrapping_add(count as u32);
        self.to_guest(Op::CreditUpdate)
    }

    /// Returns bytes the guest can take, which is its `buf_alloc` minus the
    /// bytes sent past its `fwd_cnt` (`virtio_transport_has_space`). Zero
    /// once the guest receives no more or the host end sends no more.
    pub fn room(&self) -> u32 {
        if self.guest_shut & SHUTDOWN_RECEIVE != 0 || self.host_shut & SHUTDOWN_SEND != 0 {
            return 0;
        }
        self.peer_window
            .saturating_sub(self.sent.wrapping_sub(self.peer_taken))
    }

    /// Returns the data header for `len` bytes from the host end, which are
    /// counted as sent.
    pub fn host_sent(&mut self, len: u32) -> Header {
        self.sent = self.sent.wrapping_add(len);
        let mut header = self.to_guest(Op::Data);
        header.len = len;
        header
    }

    /// Returns the shutdown of send direction of the host end, at its end of
    /// stream. No more bytes reach the guest, while bytes of the guest still
    /// reach the host end.
    pub fn host_sends_no_more(&mut self) -> Header {
        self.host_shut |= SHUTDOWN_SEND;
        self.to_guest_shutdown()
    }

    /// Returns the shutdown of receive direction of the host end, after a
    /// write to it failed. Waiting bytes are dropped since nothing takes
    /// them.
    pub fn host_receives_no_more(&mut self) -> Header {
        self.host_shut |= SHUTDOWN_RECEIVE;
        self.pending.clear();
        self.to_guest_shutdown()
    }

    /// Returns the shutdown of both directions once neither end sends and
    /// the waiting bytes are written, only sent once. `Reset` from the guest
    /// then drops the connection.
    pub fn finished(&mut self) -> Option<Header> {
        let neither_sends = self.guest_sends_no_more() && self.host_shut & SHUTDOWN_SEND != 0;
        if !neither_sends || !self.pending.is_empty() || self.host_shut == SHUTDOWN_BOTH {
            return None;
        }
        self.host_shut = SHUTDOWN_BOTH;
        Some(self.to_guest_shutdown())
    }

    /// Returns a `Shutdown` carrying the directions shut by the host end.
    fn to_guest_shutdown(&self) -> Header {
        let mut header = self.to_guest(Op::Shutdown);
        header.flags = self.host_shut;
        header
    }

    /// Returns the reset which closes the connection, for a host end which
    /// refused an incoming connection, a guest which shut both directions,
    /// or a guest which sends nothing. Connection is done after this.
    pub fn host_done(&mut self) -> Header {
        self.stage = Stage::Closed;
        self.to_guest(Op::Reset)
    }
}

#[cfg(test)]
mod tests {
    use crate::devices::virtio::vsock::connection::*;

    const GUEST_CID: u64 = 3;
    const GUEST_PORT: u32 = 1024;
    const HOST_PORT: u32 = 5555;

    /// Header from the guest for `op` and `len`, with full window of credit.
    fn from_guest(op: Op, len: u32) -> Header {
        Header {
            src_cid: GUEST_CID,
            dst_cid: HOST_CID,
            src_port: GUEST_PORT,
            dst_port: HOST_PORT,
            len,
            kind: STREAM,
            op,
            flags: 0,
            buf_alloc: WINDOW,
            fwd_cnt: 0,
        }
    }

    fn opened() -> Connection {
        Connection::new(GUEST_CID, &from_guest(Op::Request, 0))
    }

    /// Header of `answer`. Panics on `Drop` and `Nothing`.
    fn replied(answer: &Answer) -> Header {
        match answer {
            Answer::Reply(header) => *header,
            other => panic!("expected a header, got {other:?}"),
        }
    }

    #[test]
    fn test_reply_addressing() {
        let mut open = opened();
        assert_eq!(open.ports(), (GUEST_PORT, HOST_PORT));
        let header = replied(&open.guest_sent(&from_guest(Op::CreditRequest, 0), &[]));
        assert_eq!(header.src_cid, HOST_CID);
        assert_eq!(header.dst_cid, GUEST_CID);
        assert_eq!(header.src_port, HOST_PORT);
        assert_eq!(header.dst_port, GUEST_PORT);
    }

    #[test]
    fn test_data_forwarded_and_counted() {
        let mut open = opened();
        assert_eq!(
            open.guest_sent(&from_guest(Op::Data, 5), b"hello"),
            Answer::Took
        );
        assert_eq!(
            open.guest_sent(&from_guest(Op::Data, 3), b"abc"),
            Answer::Took
        );
        assert_eq!(open.waiting(), b"helloabc", "bytes not kept");

        // `fwd_cnt` counts bytes instead of packets.
        assert_eq!(open.forwarded(5).fwd_cnt, 5);
        assert_eq!(open.forwarded(3).fwd_cnt, 8);
        assert!(open.waiting().is_empty());
    }

    #[test]
    fn test_reject_len_payload_mismatch() {
        for (claimed, sent) in [(5u32, &b"ab"[..]), (1, &b"abcdef"[..]), (0, &b"x"[..])] {
            let mut open = opened();
            let answer = open.guest_sent(&from_guest(Op::Data, claimed), sent);
            assert_eq!(replied(&answer).op, Op::Reset, "claimed {claimed}");
            assert!(open.done(), "refused connection left open");
        }
    }

    #[test]
    fn test_fwd_cnt_advances_on_forward() {
        // `fwd_cnt` advances when bytes are written to the host end, not
        // when they arrive from the guest.
        let mut open = opened();
        assert_eq!(
            open.guest_sent(&from_guest(Op::Data, 5), b"hello"),
            Answer::Took
        );
        assert_eq!(open.waiting(), b"hello", "bytes not kept");

        // No byte written yet, so `fwd_cnt` is zero.
        let asked = replied(&open.guest_sent(&from_guest(Op::CreditRequest, 0), &[]));
        assert_eq!(asked.fwd_cnt, 0, "bytes were credited before they moved");

        // Host end took three out of the five.
        let note = open.forwarded(3);
        assert_eq!(note.op, Op::CreditUpdate);
        assert_eq!(note.fwd_cnt, 3);
        assert_eq!(open.waiting(), b"lo", "bytes moved were not dropped");
    }

    #[test]
    fn test_reject_data_past_window() {
        // Data beyond `WINDOW` outstanding is reset, so `pending` is
        // bounded.
        let mut open = opened();
        let whole = vec![0u8; WINDOW as usize];
        assert_eq!(
            open.guest_sent(&from_guest(Op::Data, WINDOW), &whole),
            Answer::Took
        );
        let over = replied(&open.guest_sent(&from_guest(Op::Data, 1), b"x"));
        assert_eq!(
            over.op,
            Op::Reset,
            "guest sent past its window but got served"
        );
        assert!(open.done());
    }

    #[test]
    fn test_no_data_after_send_shutdown() {
        let mut open = opened();
        let mut shutdown = from_guest(Op::Shutdown, 0);
        shutdown.flags = SHUTDOWN_SEND;
        assert_eq!(open.guest_sent(&shutdown, &[]), Answer::Nothing);
        assert!(open.guest_sends_no_more());
        let answer = open.guest_sent(&from_guest(Op::Data, 2), b"hi");
        assert_eq!(
            replied(&answer).op,
            Op::Reset,
            "data taken after shutdown of send direction"
        );
    }

    #[test]
    fn test_guest_still_sends_after_recv_shutdown() {
        // Guest which receives no more still sends. Its bytes are taken,
        // and nothing is sent to it.
        let mut open = opened();
        let mut shutdown = from_guest(Op::Shutdown, 0);
        shutdown.flags = SHUTDOWN_RECEIVE;
        assert_eq!(open.guest_sent(&shutdown, &[]), Answer::Nothing);
        assert_eq!(
            open.room(),
            0,
            "room to send to guest which receives no more"
        );
        assert_eq!(
            open.guest_sent(&from_guest(Op::Data, 2), b"hi"),
            Answer::Took
        );
        assert!(!open.done());
    }

    #[test]
    fn test_last_bytes_kept_after_shutdown() {
        // Guest shutting both directions closes nothing by itself. Bytes
        // it sent before still go to the host end.
        let mut open = opened();
        assert_eq!(
            open.guest_sent(&from_guest(Op::Data, 3), b"bye"),
            Answer::Took
        );
        let mut shutdown = from_guest(Op::Shutdown, 0);
        shutdown.flags = SHUTDOWN_RECEIVE | SHUTDOWN_SEND;
        assert_eq!(open.guest_sent(&shutdown, &[]), Answer::Nothing);
        assert!(open.guest_closed());
        assert!(!open.done(), "closed before the bytes were written");
        assert_eq!(open.waiting(), b"bye", "last bytes dropped");
        assert_eq!(open.host_done().op, Op::Reset);
        assert!(open.done());
    }

    #[test]
    fn test_host_send_shutdown() {
        // End of stream on the host end only shuts its send direction.
        // Guest reads no more but still sends.
        let mut open = opened();
        let shutdown = open.host_sends_no_more();
        assert_eq!(shutdown.op, Op::Shutdown);
        assert_eq!(shutdown.flags, SHUTDOWN_SEND);
        assert_eq!(open.room(), 0, "room to send after the end of stream");
        assert!(!open.done(), "end of stream closed the connection");
        assert!(!open.waiting_on_guest());
        assert_eq!(
            open.guest_sent(&from_guest(Op::Data, 2), b"hi"),
            Answer::Took
        );
    }

    #[test]
    fn test_finished_shuts_both_ways() {
        // Once neither end sends and waiting bytes are written, both
        // directions are shut, only once. `Reset` from the guest then
        // drops it.
        let mut open = opened();
        assert_eq!(
            open.guest_sent(&from_guest(Op::Data, 2), b"hi"),
            Answer::Took
        );
        open.host_sends_no_more();
        assert_eq!(open.finished(), None, "finished with bytes waiting");
        let mut shutdown = from_guest(Op::Shutdown, 0);
        shutdown.flags = SHUTDOWN_SEND;
        assert_eq!(open.guest_sent(&shutdown, &[]), Answer::Nothing);
        assert_eq!(open.finished(), None, "finished with bytes waiting");
        open.forwarded(2);
        let both = open.finished().expect("shutdown of both directions");
        assert_eq!(both.op, Op::Shutdown);
        assert_eq!(both.flags, SHUTDOWN_RECEIVE | SHUTDOWN_SEND);
        assert_eq!(open.finished(), None, "shut both ways twice");
        assert!(open.waiting_on_guest(), "not waiting for reset from guest");
        assert_eq!(
            open.guest_sent(&from_guest(Op::Reset, 0), &[]),
            Answer::Drop
        );
        assert!(open.done());
    }

    #[test]
    fn test_host_recv_shutdown_drops_pending() {
        // Host end which takes no more bytes has the waiting ones dropped.
        let mut open = opened();
        assert_eq!(
            open.guest_sent(&from_guest(Op::Data, 2), b"hi"),
            Answer::Took
        );
        let shutdown = open.host_receives_no_more();
        assert_eq!(shutdown.flags, SHUTDOWN_RECEIVE);
        assert!(
            open.waiting().is_empty(),
            "bytes kept with nobody to take them"
        );
        assert_eq!(open.room(), WINDOW, "other direction was shut too");
    }

    #[test]
    fn test_reject_unexpected_request_response() {
        // Duplicate request, and response without a request behind it.
        for op in [Op::Request, Op::Response] {
            let mut open = opened();
            assert_eq!(
                replied(&open.guest_sent(&from_guest(op, 0), &[])).op,
                Op::Reset
            );
        }
    }

    #[test]
    fn test_room_follows_guest_credit() {
        let mut open = opened();
        assert_eq!(open.room(), WINDOW);
        open.host_sent(WINDOW - 10);
        assert_eq!(open.room(), 10, "room left is wrong");
        open.host_sent(10);
        assert_eq!(open.room(), 0, "room left at a full window");

        // Advancing `fwd_cnt` gives the room back.
        let mut taken = from_guest(Op::CreditUpdate, 0);
        taken.fwd_cnt = WINDOW;
        assert_eq!(open.guest_sent(&taken, &[]), Answer::Nothing);
        assert_eq!(open.room(), WINDOW, "reading did not give the room back");
    }

    /// Connection from the host end, before `Response` of the guest.
    fn incoming() -> Connection {
        Connection::asking(GUEST_CID, GUEST_PORT, HOST_PORT)
    }

    #[test]
    fn test_incoming_request_addressing() {
        let asks = incoming().asks();
        assert_eq!(asks.op, Op::Request);
        assert_eq!(asks.src_cid, HOST_CID);
        assert_eq!(asks.dst_cid, GUEST_CID);
        assert_eq!(asks.src_port, HOST_PORT);
        assert_eq!(asks.dst_port, GUEST_PORT);
    }

    #[test]
    fn test_room_zero_before_response() {
        let mut asking = incoming();
        assert_eq!(asking.room(), 0, "room is not zero before the response");
        assert_eq!(
            asking.guest_sent(&from_guest(Op::Response, 0), &[]),
            Answer::Opened
        );
        assert_eq!(asking.room(), WINDOW, "room after the response was lost");
    }

    #[test]
    fn test_data_only_after_response() {
        let mut asking = incoming();
        // Data before the `Response` is refused, connection is not open yet.
        assert_eq!(
            replied(&asking.guest_sent(&from_guest(Op::Data, 2), b"hi")).op,
            Op::Reset
        );

        let mut open = incoming();
        assert_eq!(
            open.guest_sent(&from_guest(Op::Response, 0), &[]),
            Answer::Opened
        );
        assert_eq!(
            open.guest_sent(&from_guest(Op::Data, 2), b"hi"),
            Answer::Took
        );
        assert_eq!(open.waiting(), b"hi");
    }

    #[test]
    fn test_waiting_on_guest() {
        assert!(
            incoming().waiting_on_guest(),
            "incoming connection waits for response"
        );
        assert!(
            !opened().waiting_on_guest(),
            "open connection is not waiting"
        );

        let mut half = opened();
        let mut shutdown = from_guest(Op::Shutdown, 0);
        shutdown.flags = SHUTDOWN_SEND;
        assert_eq!(half.guest_sent(&shutdown, &[]), Answer::Nothing);
        assert!(
            !half.waiting_on_guest(),
            "half shutdown waits on nothing, other direction is open"
        );

        let mut answered = incoming();
        assert_eq!(
            answered.guest_sent(&from_guest(Op::Response, 0), &[]),
            Answer::Opened
        );
        assert!(
            !answered.waiting_on_guest(),
            "answered connect is still waiting"
        );
    }

    #[test]
    fn test_drop_refused_incoming() {
        let mut asking = incoming();
        assert_eq!(
            asking.guest_sent(&from_guest(Op::Reset, 0), &[]),
            Answer::Drop
        );
        assert!(asking.done());
    }

    #[test]
    fn test_drop_on_guest_reset() {
        let mut open = opened();
        assert_eq!(
            open.guest_sent(&from_guest(Op::Reset, 0), &[]),
            Answer::Drop
        );
        assert!(open.done());
    }
}
