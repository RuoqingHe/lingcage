// SPDX-FileCopyrightText: 2026 LingCage <opensource@lingcage.com>
//
// SPDX-License-Identifier: Apache-2.0

//! Vsock packet header. Context id and port of each end, the operation
//! and credit counts, laid out as `struct virtio_vsock_hdr`.

/// Length of the header in bytes (`struct virtio_vsock_hdr` in
/// `include/uapi/linux/virtio_vsock.h`).
pub const ROOM: usize = 44;

/// `VIRTIO_VSOCK_TYPE_STREAM`, the only connection kind served.
pub const STREAM: u16 = 1;

/// Context id of the host, `VMADDR_CID_HOST` in
/// `include/uapi/linux/vm_sockets.h`.
pub const HOST_CID: u64 = 2;

/// Operation of a packet, values of `enum virtio_vsock_op` except
/// `VIRTIO_VSOCK_OP_INVALID`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Op {
    /// Connection request.
    Request,
    /// Acceptance of a request.
    Response,
    /// Refuse a request, or close an open connection.
    Reset,
    /// Close one direction or both, directions are held in `Header::flags`.
    Shutdown,
    Data,
    /// Credit of the sender, without payload.
    CreditUpdate,
    /// Request for credit update from the other end.
    CreditRequest,
}

impl Op {
    /// Returns value of the operation in `enum virtio_vsock_op`.
    pub fn number(self) -> u16 {
        match self {
            Op::Request => 1,
            Op::Response => 2,
            Op::Reset => 3,
            Op::Shutdown => 4,
            Op::Data => 5,
            Op::CreditUpdate => 6,
            Op::CreditRequest => 7,
        }
    }

    /// Returns the operation numbered `number`, or `None` for zero and for
    /// values beyond the last one named by the kernel.
    pub fn from_number(number: u16) -> Option<Self> {
        match number {
            1 => Some(Op::Request),
            2 => Some(Op::Response),
            3 => Some(Op::Reset),
            4 => Some(Op::Shutdown),
            5 => Some(Op::Data),
            6 => Some(Op::CreditUpdate),
            7 => Some(Op::CreditRequest),
            _ => None,
        }
    }
}

/// Packet header, fields of `struct virtio_vsock_hdr`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Header {
    /// Context id of the sender.
    pub src_cid: u64,
    /// Context id of the receiver.
    pub dst_cid: u64,
    /// Port of the sender.
    pub src_port: u32,
    /// Port of the receiver.
    pub dst_port: u32,
    /// Length of payload in bytes.
    pub len: u32,
    /// Connection kind, [`STREAM`] in the `type` field of the header.
    pub kind: u16,
    pub op: Op,
    /// Directions of a shutdown, `VIRTIO_VSOCK_SHUTDOWN_RCV` and `_SEND`.
    /// Zero for other operations.
    pub flags: u32,
    /// Size of receive buffer of the sender in bytes.
    pub buf_alloc: u32,
    /// Bytes the sender has flushed out of its receive buffer. Together with
    /// `buf_alloc` this is the credit, the other end sends at most
    /// `buf_alloc` bytes beyond `fwd_cnt`.
    pub fwd_cnt: u32,
}

impl Header {
    /// Read a header from the front of `bytes`. Returns `None` for a buffer
    /// shorter than [`ROOM`] or an operation refused by `Op::from_number`.
    pub fn read(bytes: &[u8]) -> Option<Self> {
        if bytes.len() < ROOM {
            return None;
        }
        let long = |at: usize| {
            let mut held = [0u8; 8];
            held.copy_from_slice(&bytes[at..at + 8]);
            u64::from_le_bytes(held)
        };
        let word = |at: usize| {
            let mut held = [0u8; 4];
            held.copy_from_slice(&bytes[at..at + 4]);
            u32::from_le_bytes(held)
        };
        let short = |at: usize| {
            let mut held = [0u8; 2];
            held.copy_from_slice(&bytes[at..at + 2]);
            u16::from_le_bytes(held)
        };
        Some(Header {
            src_cid: long(0),
            dst_cid: long(8),
            src_port: word(16),
            dst_port: word(20),
            len: word(24),
            kind: short(28),
            op: Op::from_number(short(30))?,
            flags: word(32),
            buf_alloc: word(36),
            fwd_cnt: word(40),
        })
    }

    /// Write the header to the front of `bytes`. Panics on a buffer shorter
    /// than [`ROOM`].
    pub fn write(&self, bytes: &mut [u8]) {
        assert!(bytes.len() >= ROOM, "header needs {ROOM} bytes");
        bytes[0..8].copy_from_slice(&self.src_cid.to_le_bytes());
        bytes[8..16].copy_from_slice(&self.dst_cid.to_le_bytes());
        bytes[16..20].copy_from_slice(&self.src_port.to_le_bytes());
        bytes[20..24].copy_from_slice(&self.dst_port.to_le_bytes());
        bytes[24..28].copy_from_slice(&self.len.to_le_bytes());
        bytes[28..30].copy_from_slice(&self.kind.to_le_bytes());
        bytes[30..32].copy_from_slice(&self.op.number().to_le_bytes());
        bytes[32..36].copy_from_slice(&self.flags.to_le_bytes());
        bytes[36..40].copy_from_slice(&self.buf_alloc.to_le_bytes());
        bytes[40..44].copy_from_slice(&self.fwd_cnt.to_le_bytes());
    }

    /// Returns the reply header for `op`. Source and destination are
    /// swapped, `len`, `flags` and credit counts are zero.
    pub fn answer(&self, op: Op) -> Self {
        Header {
            src_cid: self.dst_cid,
            dst_cid: self.src_cid,
            src_port: self.dst_port,
            dst_port: self.src_port,
            len: 0,
            kind: STREAM,
            op,
            flags: 0,
            buf_alloc: 0,
            fwd_cnt: 0,
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::devices::virtio::vsock::packet::*;

    /// Header with a distinct value in each field.
    fn header() -> Header {
        Header {
            src_cid: 3,
            dst_cid: HOST_CID,
            src_port: 0x1111_1111,
            dst_port: 0x2222_2222,
            len: 0x3333_3333,
            kind: STREAM,
            op: Op::Data,
            flags: 0x4444_4444,
            buf_alloc: 0x5555_5555,
            fwd_cnt: 0x6666_6666,
        }
    }

    #[test]
    fn test_header_round_trip() {
        let mut bytes = [0u8; ROOM];
        header().write(&mut bytes);
        assert_eq!(Header::read(&bytes), Some(header()));
    }

    #[test]
    fn test_header_field_offsets() {
        let mut bytes = [0u8; ROOM];
        header().write(&mut bytes);
        // Offsets are the ones of `struct virtio_vsock_hdr`, which a round
        // trip through `read` can not check.
        assert_eq!(&bytes[0..8], &3u64.to_le_bytes(), "src_cid");
        assert_eq!(&bytes[16..20], &0x1111_1111u32.to_le_bytes(), "src_port");
        assert_eq!(&bytes[24..28], &0x3333_3333u32.to_le_bytes(), "len");
        assert_eq!(&bytes[30..32], &5u16.to_le_bytes(), "op");
        assert_eq!(&bytes[40..44], &0x6666_6666u32.to_le_bytes(), "fwd_cnt");
    }

    #[test]
    fn test_reject_short_buffer() {
        let mut bytes = [0u8; ROOM];
        header().write(&mut bytes);
        assert_eq!(Header::read(&bytes[..ROOM - 1]), None);
    }

    #[test]
    fn test_reject_unknown_op() {
        let mut bytes = [0u8; ROOM];
        header().write(&mut bytes);
        // Zero is `VIRTIO_VSOCK_OP_INVALID`, eight is one past
        // `VIRTIO_VSOCK_OP_CREDIT_REQUEST`, the last one named by the kernel.
        for named in [0u16, 8, 0xffff] {
            bytes[30..32].copy_from_slice(&named.to_le_bytes());
            assert_eq!(Header::read(&bytes), None, "operation {named} is accepted");
        }
    }

    #[test]
    fn test_answer_swaps_ends() {
        let asked = header();
        let answered = asked.answer(Op::Response);
        assert_eq!(answered.src_cid, asked.dst_cid);
        assert_eq!(answered.dst_cid, asked.src_cid);
        assert_eq!(answered.src_port, asked.dst_port);
        assert_eq!(answered.dst_port, asked.src_port);
        assert_eq!(answered.op, Op::Response);
        // Counts describe the replying end, so they are not copied over.
        assert_eq!(
            (answered.len, answered.buf_alloc, answered.fwd_cnt),
            (0, 0, 0)
        );
    }
}
