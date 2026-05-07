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

/// Shutdown directions, `VIRTIO_VSOCK_SHUTDOWN_RCV` and `_SEND`.
const SHUTDOWN_RECEIVE: u32 = 1;
const SHUTDOWN_SEND: u32 = 2;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Stage {
    /// Opened on request of the guest.
    Open,
    /// Shut down by the guest in one direction, data is refused.
    Closing,
    /// Closed by either end, device drops the connection.
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
            peer_window: asked.buf_alloc,
            peer_taken: asked.fwd_cnt,
            sent: 0,
            taken: 0,
            pending: Vec::new(),
        }
    }

    /// Returns the response to the request, the first header sent.
    pub fn opened(&self) -> Header {
        self.to_guest(Op::Response)
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
            Op::Shutdown => {
                let both = SHUTDOWN_RECEIVE | SHUTDOWN_SEND;
                if header.flags & both == both {
                    self.stage = Stage::Closed;
                    Answer::Reply(self.to_guest(Op::Reset))
                } else {
                    self.stage = Stage::Closing;
                    Answer::Nothing
                }
            }
            Op::Data => {
                if self.stage != Stage::Open {
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
            // Connections are initiated by guest, so there is no request for
            // the guest to answer.
            Op::Response => Answer::Reply(self.to_guest(Op::Reset)),
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
    /// bytes sent past its `fwd_cnt` (`virtio_transport_has_space`).
    pub fn room(&self) -> u32 {
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

    /// Returns the reset sent when the host end closes, connection is done
    /// after this.
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
    fn test_no_data_after_shutdown() {
        let mut open = opened();
        let mut shutdown = from_guest(Op::Shutdown, 0);
        shutdown.flags = SHUTDOWN_SEND;
        assert_eq!(open.guest_sent(&shutdown, &[]), Answer::Nothing);
        let answer = open.guest_sent(&from_guest(Op::Data, 2), b"hi");
        assert_eq!(replied(&answer).op, Op::Reset, "data taken after shutdown");
    }

    #[test]
    fn test_done_after_shutdown_both_ways() {
        let mut open = opened();
        let mut shutdown = from_guest(Op::Shutdown, 0);
        shutdown.flags = SHUTDOWN_RECEIVE | SHUTDOWN_SEND;
        assert_eq!(replied(&open.guest_sent(&shutdown, &[])).op, Op::Reset);
        assert!(open.done());
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
