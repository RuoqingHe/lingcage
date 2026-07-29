// SPDX-FileCopyrightText: 2026 LingCage <opensource@lingcage.com>
//
// SPDX-License-Identifier: Apache-2.0

//! Wire format of FUSE, the protocol a virtio-fs device carries.
//!
//! A request opens with [`InHeader`] and an answer with [`OutHeader`].
//! Structures are laid out the way `include/uapi/linux/fuse.h` lays them
//! out, so each one is read and written byte by byte, not cast.

/// Version of the protocol carried here.
pub const MAJOR: u32 = 7;

/// Minor version. 31 is what a virtio-fs guest of Linux 5.4 and later
/// asks for, and the layout below matches it.
pub const MINOR: u32 = 31;

/// Bytes of [`InHeader`].
pub const IN_HEADER: usize = 40;

/// Bytes of [`OutHeader`].
pub const OUT_HEADER: usize = 16;

/// Bytes of `fuse_attr`.
pub const ATTR: usize = 88;

/// Bytes of `fuse_entry_out`, an `fuse_attr` behind six fields: the node
/// and its generation, two lifetimes and the nanoseconds of each.
pub const ENTRY_OUT: usize = 40 + ATTR;

/// Bytes of `fuse_dirent` ahead of the name.
pub const DIRENT: usize = 24;

/// Largest write a guest is told it may send.
pub const MAX_WRITE: u32 = 1 << 20;

/// Opcodes of the requests answered here.
pub mod op {
    pub const LOOKUP: u32 = 1;
    pub const FORGET: u32 = 2;
    pub const GETATTR: u32 = 3;
    pub const SETATTR: u32 = 4;
    pub const READLINK: u32 = 5;
    pub const SYMLINK: u32 = 6;
    pub const MKNOD: u32 = 8;
    pub const MKDIR: u32 = 9;
    pub const UNLINK: u32 = 10;
    pub const RMDIR: u32 = 11;
    pub const RENAME: u32 = 12;
    pub const LINK: u32 = 13;
    pub const OPEN: u32 = 14;
    pub const READ: u32 = 15;
    pub const WRITE: u32 = 16;
    pub const STATFS: u32 = 17;
    pub const RELEASE: u32 = 18;
    pub const FSYNC: u32 = 20;
    pub const SETXATTR: u32 = 21;
    pub const GETXATTR: u32 = 22;
    pub const LISTXATTR: u32 = 23;
    pub const REMOVEXATTR: u32 = 24;
    pub const FLUSH: u32 = 25;
    pub const INIT: u32 = 26;
    pub const OPENDIR: u32 = 27;
    pub const READDIR: u32 = 28;
    pub const RELEASEDIR: u32 = 29;
    pub const FSYNCDIR: u32 = 30;
    pub const ACCESS: u32 = 34;
    pub const CREATE: u32 = 35;
    pub const INTERRUPT: u32 = 36;
    pub const DESTROY: u32 = 38;
    pub const BATCH_FORGET: u32 = 42;
    pub const READDIRPLUS: u32 = 44;
    pub const RENAME2: u32 = 45;
    pub const LSEEK: u32 = 46;
    pub const SYNCFS: u32 = 50;
}

/// Feature bits of `fuse_init_out.flags` offered here.
pub mod flag {
    /// `FUSE_ASYNC_READ`.
    pub const ASYNC_READ: u32 = 1 << 0;
    /// `FUSE_BIG_WRITES`, writes past one page are accepted.
    pub const BIG_WRITES: u32 = 1 << 5;
    /// `FUSE_DO_READDIRPLUS`, `READDIRPLUS` is answered.
    pub const DO_READDIRPLUS: u32 = 1 << 13;
    /// `FUSE_MAX_PAGES`, `max_pages` of the answer is read.
    pub const MAX_PAGES: u32 = 1 << 22;
}

/// Header ahead of a request.
#[derive(Debug, Clone, Copy, Default)]
pub struct InHeader {
    /// Bytes of the whole request, this header included.
    pub len: u32,
    /// Request kind, one of [`op`].
    pub opcode: u32,
    /// Identity the answer carries back.
    pub unique: u64,
    /// Node the request is against.
    pub nodeid: u64,
    pub uid: u32,
    pub gid: u32,
    pub pid: u32,
}

impl InHeader {
    /// Read a header off the front of `bytes`.
    pub fn read(bytes: &[u8]) -> Option<Self> {
        if bytes.len() < IN_HEADER {
            return None;
        }
        Some(InHeader {
            len: u32(bytes, 0),
            opcode: u32(bytes, 4),
            unique: u64(bytes, 8),
            nodeid: u64(bytes, 16),
            uid: u32(bytes, 24),
            gid: u32(bytes, 28),
            pid: u32(bytes, 32),
        })
    }
}

/// Answer built for one request.
pub struct Answer {
    /// Bytes behind the header.
    pub body: Vec<u8>,
    /// Negated errno, or zero.
    pub error: i32,
}

impl Answer {
    /// An answer carrying `body`.
    pub fn ok(body: Vec<u8>) -> Self {
        Answer { body, error: 0 }
    }

    /// An answer carrying nothing.
    pub fn empty() -> Self {
        Answer {
            body: Vec::new(),
            error: 0,
        }
    }

    /// An answer carrying `errno`, which is written negated.
    pub fn error(errno: i32) -> Self {
        Answer {
            body: Vec::new(),
            error: -errno,
        }
    }

    /// Lay the header and the body out for the guest.
    pub fn lay(&self, unique: u64) -> Vec<u8> {
        let len = (OUT_HEADER + self.body.len()) as u32;
        let mut out = Vec::with_capacity(len as usize);
        out.extend_from_slice(&len.to_le_bytes());
        out.extend_from_slice(&self.error.to_le_bytes());
        out.extend_from_slice(&unique.to_le_bytes());
        out.extend_from_slice(&self.body);
        out
    }
}

/// Read a little-endian `u32` at `at`.
pub fn u32(bytes: &[u8], at: usize) -> u32 {
    let mut four = [0u8; 4];
    four.copy_from_slice(&bytes[at..at + 4]);
    u32::from_le_bytes(four)
}

/// Read a little-endian `u64` at `at`.
pub fn u64(bytes: &[u8], at: usize) -> u64 {
    let mut eight = [0u8; 8];
    eight.copy_from_slice(&bytes[at..at + 8]);
    u64::from_le_bytes(eight)
}

/// Attributes of one node, the `fuse_attr` a guest caches.
#[derive(Debug, Clone, Copy, Default)]
pub struct Attr {
    pub ino: u64,
    pub size: u64,
    pub blocks: u64,
    pub atime: u64,
    pub mtime: u64,
    pub ctime: u64,
    pub atimensec: u32,
    pub mtimensec: u32,
    pub ctimensec: u32,
    pub mode: u32,
    pub nlink: u32,
    pub uid: u32,
    pub gid: u32,
    pub rdev: u32,
    pub blksize: u32,
}

impl Attr {
    /// Lay the attributes out as `fuse_attr`.
    pub fn lay(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(&self.ino.to_le_bytes());
        out.extend_from_slice(&self.size.to_le_bytes());
        out.extend_from_slice(&self.blocks.to_le_bytes());
        out.extend_from_slice(&self.atime.to_le_bytes());
        out.extend_from_slice(&self.mtime.to_le_bytes());
        out.extend_from_slice(&self.ctime.to_le_bytes());
        out.extend_from_slice(&self.atimensec.to_le_bytes());
        out.extend_from_slice(&self.mtimensec.to_le_bytes());
        out.extend_from_slice(&self.ctimensec.to_le_bytes());
        out.extend_from_slice(&self.mode.to_le_bytes());
        out.extend_from_slice(&self.nlink.to_le_bytes());
        out.extend_from_slice(&self.uid.to_le_bytes());
        out.extend_from_slice(&self.gid.to_le_bytes());
        out.extend_from_slice(&self.rdev.to_le_bytes());
        out.extend_from_slice(&self.blksize.to_le_bytes());
        // `flags`, none of which are set.
        out.extend_from_slice(&0u32.to_le_bytes());
    }
}

/// Time a guest may hold an answer about a node, in seconds. Files under
/// the shared directory are not changed behind the guest in the sandbox
/// served here, so a second keeps lookups off the queue without holding a
/// stale answer for long.
pub const VALID: u64 = 1;

/// Lay `fuse_entry_out` for node `nodeid` out.
pub fn entry(out: &mut Vec<u8>, nodeid: u64, attr: &Attr) {
    out.extend_from_slice(&nodeid.to_le_bytes());
    // `generation`, nodes here are never reused under another identity.
    out.extend_from_slice(&0u64.to_le_bytes());
    out.extend_from_slice(&VALID.to_le_bytes());
    out.extend_from_slice(&VALID.to_le_bytes());
    out.extend_from_slice(&0u32.to_le_bytes());
    out.extend_from_slice(&0u32.to_le_bytes());
    attr.lay(out);
}

/// Lay `fuse_attr_out` out.
pub fn attr_out(attr: &Attr) -> Vec<u8> {
    let mut out = Vec::with_capacity(16 + ATTR);
    out.extend_from_slice(&VALID.to_le_bytes());
    out.extend_from_slice(&0u32.to_le_bytes());
    out.extend_from_slice(&0u32.to_le_bytes());
    attr.lay(&mut out);
    out
}

/// Lay one `fuse_dirent` out, name behind it and padding to eight bytes.
pub fn dirent(out: &mut Vec<u8>, ino: u64, offset: u64, kind: u32, name: &[u8]) {
    out.extend_from_slice(&ino.to_le_bytes());
    out.extend_from_slice(&offset.to_le_bytes());
    out.extend_from_slice(&(name.len() as u32).to_le_bytes());
    out.extend_from_slice(&kind.to_le_bytes());
    out.extend_from_slice(name);
    let padding = (8 - (DIRENT + name.len()) % 8) % 8;
    out.extend_from_slice(&vec![0u8; padding]);
}

/// Bytes one `fuse_dirent` and its name take, padding included.
pub fn dirent_len(name: &[u8]) -> usize {
    let len = DIRENT + name.len();
    len + (8 - len % 8) % 8
}

#[cfg(test)]
mod tests {
    use crate::devices::virtio::fs::fuse::*;

    #[test]
    fn test_read_header_off_request() {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&56u32.to_le_bytes());
        bytes.extend_from_slice(&op::LOOKUP.to_le_bytes());
        bytes.extend_from_slice(&7u64.to_le_bytes());
        bytes.extend_from_slice(&1u64.to_le_bytes());
        bytes.extend_from_slice(&[0u8; 16]);
        let header = InHeader::read(&bytes).expect("a header which fits");
        assert_eq!(header.len, 56);
        assert_eq!(header.opcode, op::LOOKUP);
        assert_eq!(header.unique, 7);
        assert_eq!(header.nodeid, 1);
    }

    #[test]
    fn test_reject_short_header() {
        assert!(InHeader::read(&[0u8; IN_HEADER - 1]).is_none());
    }

    #[test]
    fn test_error_is_written_negated() {
        let laid = Answer::error(libc::ENOENT).lay(9);
        assert_eq!(u32(&laid, 0), OUT_HEADER as u32);
        assert_eq!(u32(&laid, 4) as i32, -libc::ENOENT);
        assert_eq!(u64(&laid, 8), 9);
    }

    #[test]
    fn test_dirent_padded_to_eight() {
        for name in ["a", "ab", "abcdefgh", "abcdefghi"] {
            let mut out = Vec::new();
            dirent(&mut out, 1, 1, 4, name.as_bytes());
            assert_eq!(out.len() % 8, 0, "{name} is not padded");
            assert_eq!(out.len(), dirent_len(name.as_bytes()));
        }
    }
}
