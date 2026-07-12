// SPDX-FileCopyrightText: 2026 LingCage <opensource@lingcage.com>
//
// SPDX-License-Identifier: Apache-2.0

//! Capture of the link into a pcap file, a carrier wrapped around
//! another one. Each frame taken or given is written as one record, so
//! file is read by tcpdump or wireshark as it grows.

use std::fs::File;
use std::io::{self, Write};
use std::os::fd::RawFd;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use log::warn;

use crate::devices::virtio::net::carrier::Carrier;
use crate::devices::virtio::net::frame::MAX_FRAME;
use crate::hv::Interest;

/// Magic of a pcap file with microsecond timestamps, written in byte
/// order of the host.
const MAGIC: u32 = 0xa1b2_c3d4;

/// Version of the pcap file format.
const VERSION_MAJOR: u16 = 2;
const VERSION_MINOR: u16 = 4;

/// Link type of the records, `LINKTYPE_ETHERNET`.
const LINKTYPE_ETHERNET: u32 = 1;

/// Bytes of a frame a record keeps at most, `MAX_FRAME`, so no frame is
/// cut.
const SNAPLEN: u32 = MAX_FRAME as u32;

/// Bytes of file header.
const FILE_HEADER: usize = 24;

/// Bytes of a record header ahead of the frame.
const RECORD_HEADER: usize = 16;

/// Carrier which writes each frame passing through `inner` to `file`.
pub struct Captured {
    inner: Box<dyn Carrier>,
    file: File,
    /// Set once a write failed, no more records go out after that.
    broken: bool,
}

impl Captured {
    /// Wrap `inner` and write file header.
    pub fn new(inner: Box<dyn Carrier>, mut file: File) -> io::Result<Self> {
        file.write_all(&header())?;
        Ok(Captured {
            inner,
            file,
            broken: false,
        })
    }

    /// Write `frame` as one record. A write which fails is warned about
    /// once, the frame goes on and the capture stops, so the link is not
    /// held up.
    fn record(&mut self, frame: &[u8]) {
        if self.broken {
            return;
        }
        if let Err(err) = self.file.write_all(&record(frame, since_epoch())) {
            warn!("capture of the link stopped, write failed: {err}");
            self.broken = true;
        }
    }
}

impl Carrier for Captured {
    fn take(&mut self, into: &mut [u8]) -> io::Result<Option<usize>> {
        let taken = self.inner.take(into)?;
        if let Some(len) = taken {
            self.record(&into[..len]);
        }
        Ok(taken)
    }

    fn give(&mut self, frame: &[u8]) -> io::Result<bool> {
        let given = self.inner.give(frame)?;
        if given {
            self.record(frame);
        }
        Ok(given)
    }

    fn resume(&mut self) -> io::Result<bool> {
        self.inner.resume()
    }

    fn outside(&self) -> Vec<(RawFd, Interest)> {
        self.inner.outside()
    }

    fn wake_after(&self) -> Option<Duration> {
        self.inner.wake_after()
    }
}

/// Returns file header.
fn header() -> [u8; FILE_HEADER] {
    let mut out = [0u8; FILE_HEADER];
    out[0..4].copy_from_slice(&MAGIC.to_ne_bytes());
    out[4..6].copy_from_slice(&VERSION_MAJOR.to_ne_bytes());
    out[6..8].copy_from_slice(&VERSION_MINOR.to_ne_bytes());
    // Timezone offset and timestamp accuracy, both zero by the format.
    out[16..20].copy_from_slice(&SNAPLEN.to_ne_bytes());
    out[20..24].copy_from_slice(&LINKTYPE_ETHERNET.to_ne_bytes());
    out
}

/// Returns record for `frame` stamped `at`, header and frame in one
/// buffer so that one write carries it.
fn record(frame: &[u8], at: Duration) -> Vec<u8> {
    let mut out = Vec::with_capacity(RECORD_HEADER + frame.len());
    out.extend_from_slice(&(at.as_secs() as u32).to_ne_bytes());
    out.extend_from_slice(&at.subsec_micros().to_ne_bytes());
    out.extend_from_slice(&(frame.len() as u32).to_ne_bytes());
    out.extend_from_slice(&(frame.len() as u32).to_ne_bytes());
    out.extend_from_slice(frame);
    out
}

/// Returns time since the epoch, zero if the clock is before it.
fn since_epoch() -> Duration {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or(Duration::ZERO)
}

#[cfg(test)]
mod tests {
    use std::io::Read;
    use std::os::fd::AsRawFd;
    use std::os::unix::net::UnixStream;
    use std::sync::{Arc, Mutex};

    use crate::devices::virtio::net::pcap::*;

    /// Frames given to the carrier in memory, shared with the test.
    type Given = Arc<Mutex<Vec<Vec<u8>>>>;

    /// Carrier in memory, frames given are kept and frames queued are
    /// taken.
    struct Wired {
        given: Given,
        bringing: Vec<Vec<u8>>,
        held: UnixStream,
    }

    impl Carrier for Wired {
        fn take(&mut self, into: &mut [u8]) -> io::Result<Option<usize>> {
            if self.bringing.is_empty() {
                return Ok(None);
            }
            let frame = self.bringing.remove(0);
            into[..frame.len()].copy_from_slice(&frame);
            Ok(Some(frame.len()))
        }

        fn give(&mut self, frame: &[u8]) -> io::Result<bool> {
            self.given.lock().unwrap().push(frame.to_vec());
            Ok(true)
        }

        fn resume(&mut self) -> io::Result<bool> {
            Ok(true)
        }

        fn outside(&self) -> Vec<(RawFd, Interest)> {
            vec![(self.held.as_raw_fd(), Interest::Read)]
        }
    }

    fn wired(bringing: Vec<Vec<u8>>) -> (Box<dyn Carrier>, Given) {
        let given = Arc::new(Mutex::new(Vec::new()));
        let carrier = Wired {
            given: Arc::clone(&given),
            bringing,
            held: UnixStream::pair().expect("socket pair").0,
        };
        (Box::new(carrier), given)
    }

    /// Path of a capture file under the temp dir, named after `tag`.
    fn capture_at(tag: &str) -> std::path::PathBuf {
        std::env::temp_dir().join(format!("lingcore-pcap-{tag}-{}", std::process::id()))
    }

    /// Returns frames of the records in `bytes`, file header first.
    fn frames_in(bytes: &[u8]) -> Vec<Vec<u8>> {
        let mut frames = Vec::new();
        let mut at = FILE_HEADER;
        while at + RECORD_HEADER <= bytes.len() {
            let len = u32::from_ne_bytes(bytes[at + 8..at + 12].try_into().unwrap()) as usize;
            frames.push(bytes[at + RECORD_HEADER..at + RECORD_HEADER + len].to_vec());
            at += RECORD_HEADER + len;
        }
        frames
    }

    #[test]
    fn test_file_header_names_ethernet() {
        let bytes = header();
        assert_eq!(u32::from_ne_bytes(bytes[0..4].try_into().unwrap()), MAGIC);
        assert_eq!(u16::from_ne_bytes(bytes[4..6].try_into().unwrap()), 2);
        assert_eq!(u16::from_ne_bytes(bytes[6..8].try_into().unwrap()), 4);
        assert_eq!(
            u32::from_ne_bytes(bytes[20..24].try_into().unwrap()),
            LINKTYPE_ETHERNET
        );
    }

    #[test]
    fn test_record_carries_stamp_and_length() {
        let bytes = record(b"abc", Duration::new(7, 5_000));
        assert_eq!(bytes.len(), RECORD_HEADER + 3);
        assert_eq!(u32::from_ne_bytes(bytes[0..4].try_into().unwrap()), 7);
        assert_eq!(u32::from_ne_bytes(bytes[4..8].try_into().unwrap()), 5);
        assert_eq!(u32::from_ne_bytes(bytes[8..12].try_into().unwrap()), 3);
        assert_eq!(u32::from_ne_bytes(bytes[12..16].try_into().unwrap()), 3);
        assert_eq!(&bytes[16..], b"abc");
    }

    #[test]
    fn test_frames_of_both_directions_recorded() {
        // A frame given and a frame taken are written in that order.
        let path = capture_at("both");
        let (inner, given) = wired(vec![b"from the host".to_vec()]);
        let file = File::create(&path).expect("create the capture");
        let mut captured = Captured::new(inner, file).expect("write the header");

        assert!(captured.give(b"from the guest").expect("give"));
        let mut into = [0u8; 64];
        assert_eq!(captured.take(&mut into).expect("take"), Some(13));
        assert_eq!(given.lock().unwrap().len(), 1, "frame kept from inner");

        let mut bytes = Vec::new();
        File::open(&path)
            .expect("open the capture")
            .read_to_end(&mut bytes)
            .expect("read the capture");
        std::fs::remove_file(&path).expect("remove the capture");
        assert_eq!(
            frames_in(&bytes),
            vec![b"from the guest".to_vec(), b"from the host".to_vec()]
        );
    }

    #[test]
    fn test_failed_write_stops_capture_frames_pass() {
        // A file opened for reading refuses the write, frames still pass.
        let path = capture_at("broken");
        File::create(&path).expect("create the capture");
        let file = File::open(&path).expect("open for reading");
        std::fs::remove_file(&path).expect("remove the capture");
        let (inner, given) = wired(Vec::new());
        assert!(
            Captured::new(inner, file).is_err(),
            "header written to a file opened for reading"
        );

        let (inner, _) = wired(Vec::new());
        let mut captured = Captured {
            inner,
            file: File::open("/dev/null").expect("open /dev/null"),
            broken: false,
        };
        assert!(captured.give(b"one").expect("give"));
        assert!(
            captured.broken,
            "write to /dev/null opened for reading passed"
        );
        assert!(captured.give(b"two").expect("give again"));
        drop(given);
    }
}
