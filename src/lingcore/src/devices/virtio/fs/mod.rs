// SPDX-FileCopyrightText: 2026 LingCage <opensource@lingcage.com>
//
// SPDX-License-Identifier: Apache-2.0

//! Virtio filesystem device, section 5.11 of virtio 1.2.
//!
//! A guest mounts a directory of the host through it instead of a disk
//! image, which is what a sandbox layer above needs when it hands the
//! guest a root built on the host. Requests on the queue are FUSE, so
//! the device is a FUSE server with virtio underneath.
//!
//! One chain carries the request in its readable descriptors and takes
//! the answer in its writable ones.

pub mod fuse;
pub mod passthrough;

use std::path::PathBuf;

use log::debug;

use crate::devices::virtio::fs::fuse::{Answer, InHeader, op};
use crate::devices::virtio::fs::passthrough::{ROOT, Shared};
use crate::devices::virtio::queue::{Chain, Queue};
use crate::devices::virtio::{Device, Error, Result};
use crate::mem::GuestRam;

/// Device ID of the filesystem device, section 5.11.
const DEVICE_ID: u32 = 26;

/// Bytes of the tag in configuration space.
const TAG: usize = 36;

/// Queues: one for high priority requests and one for the rest.
const QUEUES: u16 = 2;

/// Index of the request queue. Queue zero carries high priority
/// requests, sent to cancel one already on its way.
const REQUEST_QUEUE: u16 = 1;

/// Largest answer built for one request. A guest asking for more than
/// this is answered short, so no file is read into memory unbounded.
const MAX_ANSWER: usize = 1 << 20;

/// Filesystem device over a directory of the host.
pub struct Fs {
    /// Name the guest mounts by, `mount -t virtiofs TAG ...`.
    tag: String,
    shared: Shared,
    /// Requests answered, for the log at teardown.
    served: u64,
    /// Requests refused, the same.
    refused: u64,
}

impl Fs {
    /// Serve `at` to the guest under `tag`. `writable` false refuses a
    /// change of what is served.
    pub fn new(tag: &str, at: PathBuf, writable: bool) -> std::io::Result<Self> {
        if tag.is_empty() || tag.len() > TAG {
            return Err(std::io::Error::from(std::io::ErrorKind::InvalidInput));
        }
        Ok(Fs {
            tag: tag.to_string(),
            shared: Shared::new(at, writable)?,
            served: 0,
            refused: 0,
        })
    }

    /// Read the request out of the readable descriptors of `chain`.
    fn request(&self, chain: &Chain, ram: &GuestRam) -> Option<Vec<u8>> {
        let mut bytes = Vec::new();
        for descriptor in chain.descriptors.iter().filter(|one| !one.writable()) {
            let mut part = vec![0u8; descriptor.len as usize];
            ram.read(descriptor.addr, &mut part).ok()?;
            bytes.extend_from_slice(&part);
        }
        Some(bytes)
    }

    /// Room the writable descriptors of `chain` leave for an answer.
    fn room(chain: &Chain) -> usize {
        chain
            .descriptors
            .iter()
            .filter(|one| one.writable())
            .map(|one| one.len as usize)
            .sum()
    }

    /// Write `answer` across the writable descriptors of `chain`. Returns
    /// bytes written.
    fn answer(&self, chain: &Chain, ram: &GuestRam, answer: &[u8]) -> u32 {
        let mut written = 0;
        for descriptor in chain.descriptors.iter().filter(|one| one.writable()) {
            if written >= answer.len() {
                break;
            }
            let room = (descriptor.len as usize).min(answer.len() - written);
            if ram
                .write(descriptor.addr, &answer[written..written + room])
                .is_err()
            {
                break;
            }
            written += room;
        }
        written as u32
    }

    /// Carry one request out.
    fn serve(&mut self, header: &InHeader, body: &[u8], room: usize) -> Answer {
        match header.opcode {
            op::INIT => self.init(body),
            op::DESTROY | op::SYNCFS => Answer::empty(),
            op::FORGET => {
                self.shared.forget(header.nodeid);
                // A forget is never answered.
                Answer::empty()
            }
            op::BATCH_FORGET => Answer::empty(),
            op::LOOKUP => self.lookup(header.nodeid, body),
            op::GETATTR => self.getattr(header.nodeid),
            op::SETATTR => self.setattr(header.nodeid, body),
            op::READLINK => self.readlink(header.nodeid),
            op::OPEN => self.open(header.nodeid, body),
            op::READ => self.read(body, room),
            op::WRITE => self.write(body),
            op::RELEASE | op::RELEASEDIR => self.release(body),
            op::FLUSH => Answer::empty(),
            op::FSYNC | op::FSYNCDIR => self.fsync(body),
            op::OPENDIR => self.opendir(header.nodeid),
            op::READDIR => self.readdir(body, room, false),
            op::READDIRPLUS => self.readdir(body, room, true),
            op::STATFS => self.statfs(header.nodeid),
            op::CREATE => self.create(header.nodeid, body),
            op::MKDIR => self.mkdir(header.nodeid, body),
            op::UNLINK => self.unlink(header.nodeid, body, false),
            op::RMDIR => self.unlink(header.nodeid, body, true),
            op::RENAME => self.rename(header.nodeid, body, false),
            op::RENAME2 => self.rename(header.nodeid, body, true),
            op::SYMLINK => self.symlink(header.nodeid, body),
            op::ACCESS => Answer::empty(),
            op::INTERRUPT => Answer::empty(),
            // Extended attributes and what is left are not served, and a
            // guest reading `ENOSYS` stops asking.
            _ => {
                debug!("fs refuses opcode {}", header.opcode);
                Answer::error(libc::ENOSYS)
            }
        }
    }

    /// `FUSE_INIT`, the first request. Version and limits settle here.
    fn init(&mut self, body: &[u8]) -> Answer {
        if body.len() < 16 {
            return Answer::error(libc::EINVAL);
        }
        let major = fuse::u32(body, 0);
        if major < fuse::MAJOR {
            // A guest older than the protocol here is told the version it
            // would have to speak, which is how FUSE negotiates down.
            return Answer::error(libc::EPROTO);
        }
        let asked = fuse::u32(body, 12);
        let offered = fuse::flag::ASYNC_READ
            | fuse::flag::BIG_WRITES
            | fuse::flag::DO_READDIRPLUS
            | fuse::flag::MAX_PAGES;
        let mut out = Vec::with_capacity(64);
        out.extend_from_slice(&fuse::MAJOR.to_le_bytes());
        out.extend_from_slice(&fuse::MINOR.to_le_bytes());
        // `max_readahead`, carried back as the guest asked for it.
        out.extend_from_slice(&fuse::u32(body, 8).to_le_bytes());
        out.extend_from_slice(&(asked & offered).to_le_bytes());
        // `max_background` and `congestion_threshold`.
        out.extend_from_slice(&16u16.to_le_bytes());
        out.extend_from_slice(&12u16.to_le_bytes());
        out.extend_from_slice(&fuse::MAX_WRITE.to_le_bytes());
        // `time_gran`, timestamps of the host are kept to the nanosecond.
        out.extend_from_slice(&1u32.to_le_bytes());
        out.extend_from_slice(&((fuse::MAX_WRITE / 4096) as u16).to_le_bytes());
        // `map_alignment`, no window is mapped so it is zero.
        out.extend_from_slice(&0u16.to_le_bytes());
        out.extend_from_slice(&[0u8; 32]);
        Answer::ok(out)
    }

    /// Name out of the body of a request, which FUSE ends with a zero.
    fn name(body: &[u8]) -> Option<&[u8]> {
        let end = body.iter().position(|byte| *byte == 0)?;
        Some(&body[..end])
    }

    fn lookup(&mut self, parent: u64, body: &[u8]) -> Answer {
        let Some(name) = Fs::name(body) else {
            return Answer::error(libc::EINVAL);
        };
        let Some(at) = self.shared.under(parent, name) else {
            return Answer::error(libc::ENOENT);
        };
        let attr = match self.shared.attr(&at) {
            Ok(attr) => attr,
            Err(err) => return Answer::error(errno(&err)),
        };
        let nodeid = self.shared.number(&at);
        let mut out = Vec::with_capacity(fuse::ENTRY_OUT);
        fuse::entry(&mut out, nodeid, &attr);
        Answer::ok(out)
    }

    fn getattr(&mut self, nodeid: u64) -> Answer {
        let Some(at) = self.shared.path(nodeid).cloned() else {
            return Answer::error(libc::ENOENT);
        };
        match self.shared.attr(&at) {
            Ok(attr) => Answer::ok(fuse::attr_out(&attr)),
            Err(err) => Answer::error(errno(&err)),
        }
    }

    fn readlink(&mut self, nodeid: u64) -> Answer {
        let Some(at) = self.shared.path(nodeid).cloned() else {
            return Answer::error(libc::ENOENT);
        };
        match std::fs::read_link(&at) {
            Ok(to) => Answer::ok(to.into_os_string().into_encoded_bytes()),
            Err(err) => Answer::error(errno(&err)),
        }
    }

    fn open(&mut self, nodeid: u64, body: &[u8]) -> Answer {
        if body.len() < 4 {
            return Answer::error(libc::EINVAL);
        }
        let Some(at) = self.shared.path(nodeid).cloned() else {
            return Answer::error(libc::ENOENT);
        };
        match self.shared.open(&at, fuse::u32(body, 0)) {
            Ok(handle) => Answer::ok(open_out(handle)),
            Err(err) => Answer::error(errno(&err)),
        }
    }

    fn opendir(&mut self, nodeid: u64) -> Answer {
        let Some(at) = self.shared.path(nodeid).cloned() else {
            return Answer::error(libc::ENOENT);
        };
        match self.shared.open_dir(&at) {
            Ok(handle) => Answer::ok(open_out(handle)),
            Err(err) => Answer::error(errno(&err)),
        }
    }

    fn release(&mut self, body: &[u8]) -> Answer {
        if body.len() < 8 {
            return Answer::error(libc::EINVAL);
        }
        self.shared.close(fuse::u64(body, 0));
        Answer::empty()
    }

    fn fsync(&mut self, body: &[u8]) -> Answer {
        if body.len() < 8 {
            return Answer::error(libc::EINVAL);
        }
        match self.shared.sync(fuse::u64(body, 0)) {
            Ok(()) => Answer::empty(),
            Err(err) => Answer::error(errno(&err)),
        }
    }

    fn read(&mut self, body: &[u8], room: usize) -> Answer {
        if body.len() < 20 {
            return Answer::error(libc::EINVAL);
        }
        let handle = fuse::u64(body, 0);
        let offset = fuse::u64(body, 8);
        let asked = fuse::u32(body, 16) as usize;
        let size = asked
            .min(room.saturating_sub(fuse::OUT_HEADER))
            .min(MAX_ANSWER);
        match self.shared.read(handle, offset, size as u32) {
            Ok(bytes) => Answer::ok(bytes),
            Err(err) => Answer::error(errno(&err)),
        }
    }

    fn write(&mut self, body: &[u8]) -> Answer {
        if body.len() < 40 {
            return Answer::error(libc::EINVAL);
        }
        let handle = fuse::u64(body, 0);
        let offset = fuse::u64(body, 8);
        let size = fuse::u32(body, 16) as usize;
        let bytes = &body[40..];
        if bytes.len() < size {
            return Answer::error(libc::EINVAL);
        }
        match self.shared.write(handle, offset, &bytes[..size]) {
            Ok(written) => {
                let mut out = Vec::with_capacity(8);
                out.extend_from_slice(&written.to_le_bytes());
                out.extend_from_slice(&0u32.to_le_bytes());
                Answer::ok(out)
            }
            Err(err) => Answer::error(errno(&err)),
        }
    }

    fn readdir(&mut self, body: &[u8], room: usize, plus: bool) -> Answer {
        if body.len() < 20 {
            return Answer::error(libc::EINVAL);
        }
        let handle = fuse::u64(body, 0);
        let offset = fuse::u64(body, 8);
        let asked = (fuse::u32(body, 16) as usize).min(room.saturating_sub(fuse::OUT_HEADER));
        let Some((dir, names)) = self.shared.listing(handle, offset) else {
            return Answer::error(libc::EBADF);
        };
        let mut out = Vec::new();
        for (index, (name, ino, kind)) in names.iter().enumerate() {
            let ahead = if plus { fuse::ENTRY_OUT } else { 0 };
            if out.len() + ahead + fuse::dirent_len(name) > asked {
                break;
            }
            let next = offset + index as u64 + 1;
            if plus {
                // `.` and `..` are reported with node zero, so the guest
                // looks them up instead of caching this answer.
                let found = if name == b"." || name == b".." {
                    None
                } else {
                    let at = dir.join(String::from_utf8_lossy(name).as_ref());
                    self.shared
                        .attr(&at)
                        .ok()
                        .map(|attr| (self.shared.number(&at), attr))
                };
                let (nodeid, attr) = found.unwrap_or((0, fuse::Attr::default()));
                fuse::entry(&mut out, nodeid, &attr);
            }
            fuse::dirent(&mut out, *ino, next, *kind, name);
        }
        Answer::ok(out)
    }

    fn statfs(&mut self, nodeid: u64) -> Answer {
        let Some(at) = self.shared.path(nodeid.max(ROOT)).cloned() else {
            return Answer::error(libc::ENOENT);
        };
        // SAFETY: `statvfs` holds only integers, so all zero is a valid
        // value for the call to fill in.
        let mut stat = unsafe { std::mem::zeroed::<libc::statvfs>() };
        let path = std::ffi::CString::new(at.as_os_str().as_encoded_bytes()).unwrap_or_default();
        // SAFETY: `path` is a zero-terminated string and `stat` is a
        // `statvfs` the call fills in.
        if unsafe { libc::statvfs(path.as_ptr(), &mut stat) } != 0 {
            return Answer::error(errno(&std::io::Error::last_os_error()));
        }
        let mut out = Vec::with_capacity(80);
        out.extend_from_slice(&(stat.f_blocks as u64).to_le_bytes());
        out.extend_from_slice(&(stat.f_bfree as u64).to_le_bytes());
        out.extend_from_slice(&(stat.f_bavail as u64).to_le_bytes());
        out.extend_from_slice(&(stat.f_files as u64).to_le_bytes());
        out.extend_from_slice(&(stat.f_ffree as u64).to_le_bytes());
        out.extend_from_slice(&(stat.f_bsize as u32).to_le_bytes());
        out.extend_from_slice(&(stat.f_namemax as u32).to_le_bytes());
        out.extend_from_slice(&(stat.f_frsize as u32).to_le_bytes());
        out.extend_from_slice(&[0u8; 28]);
        Answer::ok(out)
    }

    fn setattr(&mut self, nodeid: u64, body: &[u8]) -> Answer {
        if !self.shared.writable() {
            return Answer::error(libc::EROFS);
        }
        if body.len() < 16 {
            return Answer::error(libc::EINVAL);
        }
        let Some(at) = self.shared.path(nodeid).cloned() else {
            return Answer::error(libc::ENOENT);
        };
        // `FATTR_SIZE` is the one change which has to reach the file, not
        // its metadata alone.
        if fuse::u32(body, 0) & (1 << 3) != 0 {
            let size = fuse::u64(body, 24);
            if let Err(err) = std::fs::OpenOptions::new().write(true).open(&at) {
                return Answer::error(errno(&err));
            } else if let Ok(file) = std::fs::OpenOptions::new().write(true).open(&at)
                && let Err(err) = file.set_len(size)
            {
                return Answer::error(errno(&err));
            }
        }
        match self.shared.attr(&at) {
            Ok(attr) => Answer::ok(fuse::attr_out(&attr)),
            Err(err) => Answer::error(errno(&err)),
        }
    }

    fn create(&mut self, parent: u64, body: &[u8]) -> Answer {
        if !self.shared.writable() {
            return Answer::error(libc::EROFS);
        }
        if body.len() < 16 {
            return Answer::error(libc::EINVAL);
        }
        let Some(name) = Fs::name(&body[16..]) else {
            return Answer::error(libc::EINVAL);
        };
        let Some(at) = self.shared.under(parent, name) else {
            return Answer::error(libc::EINVAL);
        };
        let flags = fuse::u32(body, 0);
        let made = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(flags & libc::O_TRUNC as u32 != 0)
            .open(&at);
        if let Err(err) = made {
            return Answer::error(errno(&err));
        }
        let attr = match self.shared.attr(&at) {
            Ok(attr) => attr,
            Err(err) => return Answer::error(errno(&err)),
        };
        let nodeid = self.shared.number(&at);
        let handle = match self.shared.open(&at, flags) {
            Ok(handle) => handle,
            Err(err) => return Answer::error(errno(&err)),
        };
        let mut out = Vec::with_capacity(fuse::ENTRY_OUT + 16);
        fuse::entry(&mut out, nodeid, &attr);
        out.extend_from_slice(&open_out(handle));
        Answer::ok(out)
    }

    fn mkdir(&mut self, parent: u64, body: &[u8]) -> Answer {
        if !self.shared.writable() {
            return Answer::error(libc::EROFS);
        }
        if body.len() < 8 {
            return Answer::error(libc::EINVAL);
        }
        let Some(name) = Fs::name(&body[8..]) else {
            return Answer::error(libc::EINVAL);
        };
        let Some(at) = self.shared.under(parent, name) else {
            return Answer::error(libc::EINVAL);
        };
        if let Err(err) = std::fs::create_dir(&at) {
            return Answer::error(errno(&err));
        }
        let attr = match self.shared.attr(&at) {
            Ok(attr) => attr,
            Err(err) => return Answer::error(errno(&err)),
        };
        let nodeid = self.shared.number(&at);
        let mut out = Vec::with_capacity(fuse::ENTRY_OUT);
        fuse::entry(&mut out, nodeid, &attr);
        Answer::ok(out)
    }

    fn unlink(&mut self, parent: u64, body: &[u8], directory: bool) -> Answer {
        if !self.shared.writable() {
            return Answer::error(libc::EROFS);
        }
        let Some(name) = Fs::name(body) else {
            return Answer::error(libc::EINVAL);
        };
        let Some(at) = self.shared.under(parent, name) else {
            return Answer::error(libc::EINVAL);
        };
        let gone = if directory {
            std::fs::remove_dir(&at)
        } else {
            std::fs::remove_file(&at)
        };
        match gone {
            Ok(()) => Answer::empty(),
            Err(err) => Answer::error(errno(&err)),
        }
    }

    fn rename(&mut self, parent: u64, body: &[u8], two: bool) -> Answer {
        if !self.shared.writable() {
            return Answer::error(libc::EROFS);
        }
        let ahead = if two { 16 } else { 8 };
        if body.len() < ahead {
            return Answer::error(libc::EINVAL);
        }
        let to_parent = fuse::u64(body, 0);
        let names = &body[ahead..];
        let Some(from) = Fs::name(names) else {
            return Answer::error(libc::EINVAL);
        };
        let Some(to) = Fs::name(&names[from.len() + 1..]) else {
            return Answer::error(libc::EINVAL);
        };
        let (Some(from), Some(to)) = (
            self.shared.under(parent, from),
            self.shared.under(to_parent, to),
        ) else {
            return Answer::error(libc::EINVAL);
        };
        match std::fs::rename(&from, &to) {
            Ok(()) => Answer::empty(),
            Err(err) => Answer::error(errno(&err)),
        }
    }

    fn symlink(&mut self, parent: u64, body: &[u8]) -> Answer {
        if !self.shared.writable() {
            return Answer::error(libc::EROFS);
        }
        let Some(name) = Fs::name(body) else {
            return Answer::error(libc::EINVAL);
        };
        let Some(to) = Fs::name(&body[name.len() + 1..]) else {
            return Answer::error(libc::EINVAL);
        };
        let Some(at) = self.shared.under(parent, name) else {
            return Answer::error(libc::EINVAL);
        };
        let to = PathBuf::from(String::from_utf8_lossy(to).into_owned());
        if let Err(err) = std::os::unix::fs::symlink(&to, &at) {
            return Answer::error(errno(&err));
        }
        let attr = match self.shared.attr(&at) {
            Ok(attr) => attr,
            Err(err) => return Answer::error(errno(&err)),
        };
        let nodeid = self.shared.number(&at);
        let mut out = Vec::with_capacity(fuse::ENTRY_OUT);
        fuse::entry(&mut out, nodeid, &attr);
        Answer::ok(out)
    }
}

/// Lay `fuse_open_out` for `handle` out.
fn open_out(handle: u64) -> Vec<u8> {
    let mut out = Vec::with_capacity(16);
    out.extend_from_slice(&handle.to_le_bytes());
    // `open_flags` and `backing_id`, neither of which is used here.
    out.extend_from_slice(&0u32.to_le_bytes());
    out.extend_from_slice(&0u32.to_le_bytes());
    out
}

/// Errno of `err`, `EIO` for an error the host gave no number for.
fn errno(err: &std::io::Error) -> i32 {
    err.raw_os_error().unwrap_or(libc::EIO)
}

impl Device for Fs {
    fn device_id(&self) -> u32 {
        DEVICE_ID
    }

    fn queue_count(&self) -> u16 {
        QUEUES
    }

    fn read_config(&mut self, offset: u64, size: u8) -> u64 {
        // Configuration space is the tag, zero padded, and the count of
        // request queues behind it.
        let mut space = [0u8; TAG + 4];
        let tag = self.tag.as_bytes();
        space[..tag.len()].copy_from_slice(tag);
        space[TAG..].copy_from_slice(&1u32.to_le_bytes());
        let mut value = 0u64;
        for index in 0..size as usize {
            let at = offset as usize + index;
            let byte = space.get(at).copied().unwrap_or(0);
            value |= u64::from(byte) << (index * 8);
        }
        value
    }

    fn counts(&self) -> Vec<(&'static str, u64)> {
        vec![("served", self.served), ("refused", self.refused)]
    }

    fn notify(&mut self, index: u16, queue: &mut Queue, ram: &GuestRam) -> Result<()> {
        while let Some(chain) = queue.pop(ram)? {
            if index != REQUEST_QUEUE {
                // High priority queue carries cancellations, and a
                // request answered before one arrives needs none.
                queue.add_used(ram, chain.head, 0)?;
                continue;
            }
            let Some(request) = self.request(&chain, ram) else {
                return Err(Error::Request);
            };
            let Some(header) = InHeader::read(&request) else {
                return Err(Error::Request);
            };
            let body = &request[fuse::IN_HEADER.min(request.len())..];
            let room = Fs::room(&chain);
            let answer = self.serve(&header, body, room);
            if answer.error != 0 {
                self.refused += 1;
            } else {
                self.served += 1;
            }
            // A forget takes no answer.
            let written = if header.opcode == op::FORGET || header.opcode == op::BATCH_FORGET {
                0
            } else {
                self.answer(&chain, ram, &answer.lay(header.unique))
            };
            queue.add_used(ram, chain.head, written)?;
        }
        Ok(())
    }

    fn restored(&mut self, _index: u16, _queue: &mut Queue, _ram: &GuestRam) -> Result<()> {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use crate::devices::virtio::fs::passthrough::tests::tempdir;
    use crate::devices::virtio::fs::*;

    fn served() -> (tempdir::Dir, Fs) {
        let dir = tempdir::Dir::new();
        std::fs::write(dir.at().join("one"), b"hello").expect("write a file");
        let fs = Fs::new("shared", dir.at().to_path_buf(), true).expect("serve it");
        (dir, fs)
    }

    fn header(opcode: u32, nodeid: u64) -> InHeader {
        InHeader {
            len: 0,
            opcode,
            unique: 1,
            nodeid,
            uid: 0,
            gid: 0,
            pid: 0,
        }
    }

    #[test]
    fn test_config_space_carries_tag() {
        let (_dir, mut fs) = served();
        let first = fs.read_config(0, 1);
        assert_eq!(first as u8, b's');
        assert_eq!(fs.read_config(TAG as u64, 4), 1, "one request queue");
    }

    #[test]
    fn test_init_settles_version() {
        let (_dir, mut fs) = served();
        let mut body = Vec::new();
        body.extend_from_slice(&fuse::MAJOR.to_le_bytes());
        body.extend_from_slice(&40u32.to_le_bytes());
        body.extend_from_slice(&0u32.to_le_bytes());
        body.extend_from_slice(&fuse::flag::DO_READDIRPLUS.to_le_bytes());
        let answer = fs.serve(&header(op::INIT, ROOT), &body, 4096);
        assert_eq!(answer.error, 0);
        assert_eq!(fuse::u32(&answer.body, 0), fuse::MAJOR);
        assert_eq!(
            fuse::u32(&answer.body, 12) & fuse::flag::DO_READDIRPLUS,
            fuse::flag::DO_READDIRPLUS,
            "a flag the guest asked for was dropped"
        );
    }

    #[test]
    fn test_lookup_then_read() {
        let (_dir, mut fs) = served();
        let answer = fs.serve(&header(op::LOOKUP, ROOT), b"one\0", 4096);
        assert_eq!(answer.error, 0);
        let nodeid = fuse::u64(&answer.body, 0);
        assert_ne!(nodeid, 0);

        let opened = fs.serve(&header(op::OPEN, nodeid), &[0u8; 8], 4096);
        assert_eq!(opened.error, 0);
        let handle = fuse::u64(&opened.body, 0);

        let mut request = Vec::new();
        request.extend_from_slice(&handle.to_le_bytes());
        request.extend_from_slice(&0u64.to_le_bytes());
        request.extend_from_slice(&16u32.to_le_bytes());
        request.extend_from_slice(&[0u8; 20]);
        let read = fs.serve(&header(op::READ, nodeid), &request, 4096);
        assert_eq!(read.body, b"hello");
    }

    #[test]
    fn test_lookup_outside_share_is_refused() {
        let (_dir, mut fs) = served();
        let answer = fs.serve(&header(op::LOOKUP, ROOT), b"..\0", 4096);
        assert_eq!(answer.error, -libc::ENOENT);
    }

    #[test]
    fn test_unknown_opcode_answers_enosys() {
        let (_dir, mut fs) = served();
        let answer = fs.serve(&header(9999, ROOT), &[], 4096);
        assert_eq!(answer.error, -libc::ENOSYS);
    }
}
