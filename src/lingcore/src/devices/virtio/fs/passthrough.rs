// SPDX-FileCopyrightText: 2026 LingCage <opensource@lingcage.com>
//
// SPDX-License-Identifier: Apache-2.0

//! A directory of the host, served to a guest over FUSE.
//!
//! Nodes are numbered as the guest meets them and each number is kept
//! with the path it stands for. Root is node one, as FUSE fixes it. A
//! path is held, not an open descriptor, since a guest may keep far more
//! nodes than a process may keep descriptors.

use std::collections::HashMap;
use std::fs::{File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::{Component, Path, PathBuf};

use crate::devices::virtio::fs::fuse::Attr;

/// Node number of the root, fixed by FUSE.
pub const ROOT: u64 = 1;

/// One name under a directory: the name, the inode of the host and the
/// kind `DT_` of it.
pub type Named = (Vec<u8>, u64, u32);

/// Block size reported for a node.
const BLKSIZE: u32 = 4096;

/// An open file or directory a guest holds by its handle.
enum Open {
    /// A file the guest reads or writes.
    File(File),
    /// A directory and the names under it, read once when it was opened
    /// so a guest reading it in pieces sees one listing.
    Dir { at: PathBuf, names: Vec<Named> },
}

/// A directory of the host and the nodes a guest has met under it.
pub struct Shared {
    root: PathBuf,
    /// Path of each node the guest has been told about.
    nodes: HashMap<u64, PathBuf>,
    /// Node of each path, so a second lookup answers with the same number.
    numbers: HashMap<PathBuf, u64>,
    /// Number the next node takes.
    next: u64,
    open: HashMap<u64, Open>,
    /// Handle the next open takes.
    handle: u64,
    /// Set if the guest may write.
    writable: bool,
}

impl Shared {
    /// Serve `root` to a guest. `writable` false refuses a change.
    pub fn new(root: PathBuf, writable: bool) -> std::io::Result<Self> {
        let root = root.canonicalize()?;
        let mut nodes = HashMap::new();
        nodes.insert(ROOT, root.clone());
        let mut numbers = HashMap::new();
        numbers.insert(root.clone(), ROOT);
        Ok(Shared {
            root,
            nodes,
            numbers,
            next: ROOT + 1,
            open: HashMap::new(),
            handle: 1,
            writable,
        })
    }

    /// Returns whether a change of what is served is allowed.
    pub fn writable(&self) -> bool {
        self.writable
    }

    /// Path of node `nodeid`, or `None` if the guest never met it.
    pub fn path(&self, nodeid: u64) -> Option<&PathBuf> {
        self.nodes.get(&nodeid)
    }

    /// Path of `name` under node `parent`. A name which would leave the
    /// shared directory is refused.
    pub fn under(&self, parent: u64, name: &[u8]) -> Option<PathBuf> {
        let name = std::str::from_utf8(name).ok()?;
        if name.is_empty() || name.contains('/') || name == ".." {
            // `..` of the root would leave the directory, and a name with
            // a separator in it is not a name.
            return None;
        }
        let at = self.nodes.get(&parent)?.join(name);
        // A symlink of the host could still point outside, so the joined
        // path is held to the shared directory here as well.
        if !at.starts_with(&self.root) || at.components().any(|part| part == Component::ParentDir) {
            return None;
        }
        Some(at)
    }

    /// Number `at` holds, giving it one if the guest has not met it.
    pub fn number(&mut self, at: &Path) -> u64 {
        if let Some(number) = self.numbers.get(at) {
            return *number;
        }
        let number = self.next;
        self.next += 1;
        self.nodes.insert(number, at.to_path_buf());
        self.numbers.insert(at.to_path_buf(), number);
        number
    }

    /// Drop a node the guest no longer holds. Root is kept.
    pub fn forget(&mut self, nodeid: u64) {
        if nodeid == ROOT {
            return;
        }
        if let Some(at) = self.nodes.remove(&nodeid) {
            self.numbers.remove(&at);
        }
    }

    /// Attributes of `at`, read without following a symlink.
    pub fn attr(&self, at: &Path) -> std::io::Result<Attr> {
        let meta = std::fs::symlink_metadata(at)?;
        Ok(Attr {
            ino: meta.ino(),
            size: meta.size(),
            blocks: meta.blocks(),
            atime: meta.atime() as u64,
            mtime: meta.mtime() as u64,
            ctime: meta.ctime() as u64,
            atimensec: meta.atime_nsec() as u32,
            mtimensec: meta.mtime_nsec() as u32,
            ctimensec: meta.ctime_nsec() as u32,
            mode: meta.mode(),
            nlink: meta.nlink() as u32,
            uid: meta.uid(),
            gid: meta.gid(),
            rdev: meta.rdev() as u32,
            blksize: BLKSIZE,
        })
    }

    /// Open `at` with `flags` of the guest and return its handle.
    pub fn open(&mut self, at: &Path, flags: u32) -> std::io::Result<u64> {
        let write = flags & (libc::O_WRONLY | libc::O_RDWR) as u32 != 0;
        if write && !self.writable {
            return Err(std::io::Error::from_raw_os_error(libc::EROFS));
        }
        let file = OpenOptions::new()
            .read(true)
            .write(write)
            .custom_flags(libc::O_NOFOLLOW)
            .open(at)?;
        let handle = self.handle;
        self.handle += 1;
        self.open.insert(handle, Open::File(file));
        Ok(handle)
    }

    /// Read the names under `at` and return a handle to the listing. `.`
    /// and `..` open it, as a guest is given them.
    pub fn open_dir(&mut self, at: &Path) -> std::io::Result<u64> {
        let mut names: Vec<Named> = vec![
            (b".".to_vec(), 0u64, libc::DT_DIR as u32),
            (b"..".to_vec(), 0u64, libc::DT_DIR as u32),
        ];
        for entry in std::fs::read_dir(at)? {
            let entry = entry?;
            let kind = match entry.file_type() {
                Ok(kind) if kind.is_dir() => libc::DT_DIR,
                Ok(kind) if kind.is_symlink() => libc::DT_LNK,
                Ok(_) => libc::DT_REG,
                Err(_) => libc::DT_UNKNOWN,
            };
            let ino = entry.metadata().map(|meta| meta.ino()).unwrap_or(0);
            names.push((entry.file_name().as_bytes().to_vec(), ino, kind as u32));
        }
        let handle = self.handle;
        self.handle += 1;
        self.open.insert(
            handle,
            Open::Dir {
                at: at.to_path_buf(),
                names,
            },
        );
        Ok(handle)
    }

    /// Directory behind `handle` and the names under it from `offset` on.
    pub fn listing(&self, handle: u64, offset: u64) -> Option<(PathBuf, Vec<Named>)> {
        match self.open.get(&handle)? {
            Open::Dir { at, names } => Some((
                at.clone(),
                names.get(offset as usize..).unwrap_or(&[]).to_vec(),
            )),
            Open::File(_) => None,
        }
    }

    /// Read `size` bytes of the file behind `handle` at `offset`.
    pub fn read(&mut self, handle: u64, offset: u64, size: u32) -> std::io::Result<Vec<u8>> {
        let Some(Open::File(file)) = self.open.get_mut(&handle) else {
            return Err(std::io::Error::from_raw_os_error(libc::EBADF));
        };
        file.seek(SeekFrom::Start(offset))?;
        let mut into = vec![0u8; size as usize];
        let mut taken = 0;
        while taken < into.len() {
            match file.read(&mut into[taken..]) {
                Ok(0) => break,
                Ok(got) => taken += got,
                Err(err) if err.kind() == std::io::ErrorKind::Interrupted => {}
                Err(err) => return Err(err),
            }
        }
        into.truncate(taken);
        Ok(into)
    }

    /// Write `bytes` to the file behind `handle` at `offset`.
    pub fn write(&mut self, handle: u64, offset: u64, bytes: &[u8]) -> std::io::Result<u32> {
        if !self.writable {
            return Err(std::io::Error::from_raw_os_error(libc::EROFS));
        }
        let Some(Open::File(file)) = self.open.get_mut(&handle) else {
            return Err(std::io::Error::from_raw_os_error(libc::EBADF));
        };
        file.seek(SeekFrom::Start(offset))?;
        file.write_all(bytes)?;
        Ok(bytes.len() as u32)
    }

    /// Flush the file behind `handle` to the disk of the host.
    pub fn sync(&mut self, handle: u64) -> std::io::Result<()> {
        match self.open.get_mut(&handle) {
            Some(Open::File(file)) => file.sync_all(),
            _ => Ok(()),
        }
    }

    /// Drop the handle, closing whatever it held.
    pub fn close(&mut self, handle: u64) {
        self.open.remove(&handle);
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use crate::devices::virtio::fs::passthrough::*;

    /// A shared directory holding one file and one directory.
    fn shared() -> (tempdir::Dir, Shared) {
        let dir = tempdir::Dir::new();
        std::fs::write(dir.at().join("one"), b"hello").expect("write a file");
        std::fs::create_dir(dir.at().join("sub")).expect("make a directory");
        let shared = Shared::new(dir.at().to_path_buf(), true).expect("share it");
        (dir, shared)
    }

    /// A directory of the host removed when the test ends.
    pub mod tempdir {
        use std::path::{Path, PathBuf};

        pub struct Dir(PathBuf);

        impl Dir {
            pub fn new() -> Self {
                let at = std::env::temp_dir().join(format!(
                    "lingcore-fs-{}-{:?}",
                    std::process::id(),
                    std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .unwrap()
                        .as_nanos()
                ));
                std::fs::create_dir_all(&at).expect("make the directory");
                Dir(at)
            }

            pub fn at(&self) -> &Path {
                &self.0
            }
        }

        impl Drop for Dir {
            fn drop(&mut self) {
                let _ = std::fs::remove_dir_all(&self.0);
            }
        }
    }

    #[test]
    fn test_root_is_node_one() {
        let (dir, shared) = shared();
        assert_eq!(shared.path(ROOT), Some(&dir.at().to_path_buf()));
    }

    #[test]
    fn test_same_path_keeps_its_number() {
        let (_dir, mut shared) = shared();
        let at = shared.under(ROOT, b"one").expect("a name under root");
        let first = shared.number(&at);
        assert_eq!(shared.number(&at), first, "a second lookup renumbered it");
        assert_ne!(first, ROOT);
    }

    #[test]
    fn test_refuse_name_leaving_shared_directory() {
        let (_dir, shared) = shared();
        assert!(shared.under(ROOT, b"..").is_none());
        assert!(shared.under(ROOT, b"../etc").is_none());
        assert!(shared.under(ROOT, b"sub/../..").is_none());
        assert!(shared.under(ROOT, b"").is_none());
        assert!(shared.under(ROOT, b"one").is_some());
    }

    #[test]
    fn test_read_file_back() {
        let (_dir, mut shared) = shared();
        let at = shared.under(ROOT, b"one").expect("a name");
        let handle = shared.open(&at, libc::O_RDONLY as u32).expect("open it");
        assert_eq!(shared.read(handle, 0, 16).expect("read"), b"hello");
        assert_eq!(shared.read(handle, 1, 3).expect("read"), b"ell");
        shared.close(handle);
    }

    #[test]
    fn test_refuse_write_to_read_only_share() {
        let dir = tempdir::Dir::new();
        std::fs::write(dir.at().join("one"), b"hello").expect("write");
        let mut shared = Shared::new(dir.at().to_path_buf(), false).expect("share");
        let at = shared.under(ROOT, b"one").expect("a name");
        let refused = shared.open(&at, libc::O_RDWR as u32);
        assert_eq!(
            refused.err().and_then(|err| err.raw_os_error()),
            Some(libc::EROFS)
        );
    }

    #[test]
    fn test_directory_opens_with_dot_entries() {
        let (_dir, mut shared) = shared();
        let at = shared.path(ROOT).expect("root").clone();
        let handle = shared.open_dir(&at).expect("open the directory");
        let (_, names) = shared.listing(handle, 0).expect("names");
        assert_eq!(names[0].0, b".");
        assert_eq!(names[1].0, b"..");
        assert!(names.iter().any(|(name, _, _)| name == b"one"));
        assert!(names.iter().any(|(name, _, _)| name == b"sub"));
    }
}
