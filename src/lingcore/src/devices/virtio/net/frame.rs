// SPDX-FileCopyrightText: 2026 LingCage <opensource@lingcage.com>
//
// SPDX-License-Identifier: Apache-2.0

//! Virtio-net frame on the ring and on the host stream.
//!
//! On the ring a frame is `struct virtio_net_hdr_v1` plus the Ethernet
//! bytes. On the host stream it is a length prefix plus the Ethernet
//! bytes, header is left out since no offload is offered.

/// Length of the header in bytes (`struct virtio_net_hdr_v1` in
/// `include/uapi/linux/virtio_net.h`). `drivers/net/virtio_net.c` sets
/// `vi->hdr_len` to this under `VIRTIO_F_VERSION_1`, no matter
/// `VIRTIO_NET_F_MRG_RXBUF` is negotiated or not.
pub const ROOM: usize = 12;

/// Length of the frame length prefix on host stream, in bytes.
pub const PREFIX: usize = 4;

/// Longest frame carried in both directions, 64 KiB plus a 14-byte
/// Ethernet header. No MTU is offered to the guest.
pub const MAX_FRAME: usize = 64 * 1024 + 14;

/// Frame header on the ring, `struct virtio_net_hdr_v1`.
///
/// No offload is offered, so `flags` and `gso_type` are written as zero.
/// `asks_for_an_offload` reports a frame with either of them set.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Header {
    /// Checksum flags, `VIRTIO_NET_HDR_F_*`.
    pub flags: u8,
    /// Segmentation kind, `VIRTIO_NET_HDR_GSO_*`.
    pub gso_type: u8,
    /// Ethernet, IP and TCP/UDP header bytes.
    pub hdr_len: u16,
    /// Bytes per segment after `hdr_len`.
    pub gso_size: u16,
    /// Offset to compute the checksum from.
    pub csum_start: u16,
    /// Offset of the checksum field after `csum_start`.
    pub csum_offset: u16,
    /// Receive buffers spanned by the frame.
    pub num_buffers: u16,
}

/// `VIRTIO_NET_HDR_GSO_NONE`, frame without segmentation.
pub const GSO_NONE: u8 = 0;

impl Header {
    /// Decode the header at the start of `bytes`. Returns `None` if there
    /// are fewer than `ROOM` bytes.
    pub fn read(bytes: &[u8]) -> Option<Self> {
        if bytes.len() < ROOM {
            return None;
        }
        // `bytes` holds `ROOM` bytes, so slices below are in bounds.
        let short = |at: usize| {
            let mut held = [0u8; 2];
            held.copy_from_slice(&bytes[at..at + 2]);
            u16::from_le_bytes(held)
        };
        Some(Header {
            flags: bytes[0],
            gso_type: bytes[1],
            hdr_len: short(2),
            gso_size: short(4),
            csum_start: short(6),
            csum_offset: short(8),
            num_buffers: short(10),
        })
    }

    /// Encode the header into the first `ROOM` bytes of `bytes`.
    pub fn write(&self, bytes: &mut [u8]) {
        assert!(bytes.len() >= ROOM, "header needs {ROOM} bytes");
        bytes[0] = self.flags;
        bytes[1] = self.gso_type;
        bytes[2..4].copy_from_slice(&self.hdr_len.to_le_bytes());
        bytes[4..6].copy_from_slice(&self.gso_size.to_le_bytes());
        bytes[6..8].copy_from_slice(&self.csum_start.to_le_bytes());
        bytes[8..10].copy_from_slice(&self.csum_offset.to_le_bytes());
        bytes[10..12].copy_from_slice(&self.num_buffers.to_le_bytes());
    }

    /// Returns whether the header sets any `flags` bit or a `gso_type` other
    /// than `GSO_NONE`. No offload is offered to the driver.
    pub fn asks_for_an_offload(&self) -> bool {
        self.flags != 0 || self.gso_type != GSO_NONE
    }
}

/// Returns the frame length named by a prefix, or `None` for zero or for
/// anything more than `MAX_FRAME`.
pub fn length(prefix: [u8; PREFIX]) -> Option<usize> {
    let named = u32::from_be_bytes(prefix) as usize;
    (1..=MAX_FRAME).contains(&named).then_some(named)
}

/// Encode `len` as a prefix.
pub fn lay(len: usize) -> [u8; PREFIX] {
    (len as u32).to_be_bytes()
}

#[cfg(test)]
mod tests {
    use crate::devices::virtio::net::frame::*;

    /// Header with a distinct value in each field.
    fn filled() -> Header {
        Header {
            flags: 0x11,
            gso_type: 0x22,
            hdr_len: 0x3344,
            gso_size: 0x5566,
            csum_start: 0x7788,
            csum_offset: 0x99aa,
            num_buffers: 0xbbcc,
        }
    }

    #[test]
    fn test_header_field_offsets() {
        let mut bytes = [0u8; ROOM];
        filled().write(&mut bytes);
        // Offsets are the ones of `struct virtio_net_hdr_v1`.
        assert_eq!(bytes[0], 0x11, "flags");
        assert_eq!(bytes[1], 0x22, "gso_type");
        assert_eq!(&bytes[2..4], &0x3344u16.to_le_bytes(), "hdr_len");
        assert_eq!(&bytes[4..6], &0x5566u16.to_le_bytes(), "gso_size");
        assert_eq!(&bytes[6..8], &0x7788u16.to_le_bytes(), "csum_start");
        assert_eq!(&bytes[8..10], &0x99aau16.to_le_bytes(), "csum_offset");
        assert_eq!(&bytes[10..12], &0xbbccu16.to_le_bytes(), "num_buffers");
    }

    #[test]
    fn test_header_round_trip() {
        let mut bytes = [0u8; ROOM];
        filled().write(&mut bytes);
        assert_eq!(Header::read(&bytes), Some(filled()));
    }

    #[test]
    fn test_reject_short_buffer() {
        assert_eq!(Header::read(&[0u8; ROOM - 1]), None);
    }

    #[test]
    fn test_offload_header_detection() {
        assert!(!Header::default().asks_for_an_offload());
        assert!(
            Header {
                gso_type: 1,
                ..Header::default()
            }
            .asks_for_an_offload(),
            "`gso_type` is missed"
        );
        assert!(
            Header {
                flags: 1,
                ..Header::default()
            }
            .asks_for_an_offload(),
            "`flags` bit is missed"
        );
    }

    #[test]
    fn test_reject_bad_length_prefix() {
        assert_eq!(length(lay(MAX_FRAME)), Some(MAX_FRAME));
        assert_eq!(length(lay(1)), Some(1));
        assert_eq!(length(lay(MAX_FRAME + 1)), None, "length past the cap");
        assert_eq!(length(lay(0)), None, "zero length");
    }
}
