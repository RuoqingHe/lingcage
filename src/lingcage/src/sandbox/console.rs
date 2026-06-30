// SPDX-FileCopyrightText: 2026 LingCage <opensource@lingcage.com>
//
// SPDX-License-Identifier: Apache-2.0

//! Console of a sandbox, which keeps recent guest serial output in a ring
//! buffer, notifies taps on new output and sends input to the guest.

use std::collections::VecDeque;
use std::io::Write;
use std::sync::{Arc, Mutex, mpsc};

use crate::error::{Error, Result};

/// Maximum bytes of output kept in ring, oldest output is dropped first.
const OUTPUT_BOUND: usize = 1 << 20;

/// Number of writes buffered for a tap before a slow subscriber starts
/// missing them. Since UART writes one byte per call to the sink, this
/// also bounds the number of bytes buffered.
const TAP_WRITES: usize = 8192;

/// Machine side of console input.
pub type Input = Arc<dyn lingcore::devices::Receive>;

/// Ring buffer and taps shared between the sink and console handles.
#[derive(Default)]
struct Shared {
    ring: Mutex<VecDeque<u8>>,
    taps: Mutex<Vec<mpsc::SyncSender<Vec<u8>>>>,
}

/// Console of a sandbox, which provides recent output and input to the
/// guest. Cloned handles share the same ring buffer.
#[derive(Clone)]
pub struct Console {
    shared: Arc<Shared>,
    input: Input,
}

impl Console {
    /// Create a console over the ring written by `sink`, `input` is the
    /// guest side of console input.
    pub fn new(sink: &Sink, input: Input) -> Console {
        Console {
            shared: Arc::clone(&sink.shared),
            input,
        }
    }

    /// Returns the last `bytes` of output converted to text.
    pub fn tail(&self, bytes: usize) -> String {
        let ring = self.shared.ring.lock().unwrap();
        let skip = ring.len().saturating_sub(bytes);
        let kept: Vec<u8> = ring.iter().skip(skip).copied().collect();
        String::from_utf8_lossy(&kept).into_owned()
    }

    /// Subscribe to output written from now on. A tap falling behind by
    /// `TAP_WRITES` writes would miss the following writes.
    pub fn subscribe(&self) -> mpsc::Receiver<Vec<u8>> {
        let (tx, rx) = mpsc::sync_channel(TAP_WRITES);
        self.shared.taps.lock().unwrap().push(tx);
        rx
    }

    /// Queue `bytes` for the guest to read, returns the number of bytes
    /// queued. UART only holds a page of unread input and drops anything
    /// beyond, so a short count means the remaining bytes are dropped.
    pub fn send(&self, bytes: &[u8]) -> Result<usize> {
        self.input.receive(bytes).map_err(Error::Io)
    }
}

/// Console output of the machine, which is written into the ring and
/// the taps. Default is an empty ring with no taps, a clone writes to
/// the same ring.
#[derive(Clone, Default)]
pub struct Sink {
    shared: Arc<Shared>,
}

impl Write for Sink {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        {
            let mut ring = self.shared.ring.lock().unwrap();
            let keep = bytes.len().min(OUTPUT_BOUND);
            let over = (ring.len() + keep).saturating_sub(OUTPUT_BOUND);
            drop(ring.drain(..over));
            ring.extend(bytes[bytes.len() - keep..].iter().copied());
        }
        // A tap with full buffer misses this chunk, a disconnected tap is
        // removed from the list.
        self.shared.taps.lock().unwrap().retain(|tap| {
            !matches!(
                tap.try_send(bytes.to_vec()),
                Err(mpsc::TrySendError::Disconnected(_))
            )
        });
        Ok(bytes.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use crate::sandbox::console::*;

    /// Input end which accepts up to `room` bytes and records them, like
    /// the UART does with its page of unread input.
    struct Spy {
        room: usize,
        taken: Mutex<Vec<u8>>,
    }

    impl Spy {
        fn with_room(room: usize) -> Arc<Spy> {
            Arc::new(Spy {
                room,
                taken: Mutex::new(Vec::new()),
            })
        }
    }

    impl lingcore::devices::Receive for Spy {
        fn receive(&self, bytes: &[u8]) -> std::io::Result<usize> {
            let mut taken = self.taken.lock().unwrap();
            let room = self.room.saturating_sub(taken.len());
            let fits = bytes.len().min(room);
            taken.extend_from_slice(&bytes[..fits]);
            Ok(fits)
        }
    }

    /// Console over a new sink, with a spy of `room` bytes as its input.
    fn console_with_room(room: usize) -> (Console, Sink, Arc<Spy>) {
        let sink = Sink::default();
        let spy = Spy::with_room(room);
        let console = Console::new(&sink, spy.clone());
        (console, sink, spy)
    }

    /// Console with an input end which accepts unlimited input.
    fn console() -> (Console, Sink, Arc<Spy>) {
        console_with_room(usize::MAX)
    }

    #[test]
    fn test_ring_drops_oldest_output() {
        let (console, mut sink, _spy) = console();
        sink.write_all(&[0x61; OUTPUT_BOUND]).expect("fill ring");
        sink.write_all(b"tail").expect("write past bound");
        assert_eq!(console.tail(4), "tail");
        assert_eq!(console.tail(OUTPUT_BOUND + 4).len(), OUTPUT_BOUND);
    }

    #[test]
    fn test_tail_returns_lossy_text() {
        let (console, mut sink, _spy) = console();
        sink.write_all(b"boot log line\n").expect("write a line");
        assert_eq!(console.tail(5), "line\n");
        assert_eq!(console.tail(1024), "boot log line\n");
        sink.write_all(&[0xff]).expect("write invalid byte");
        assert!(console.tail(1).ends_with('\u{fffd}'));
    }

    #[test]
    fn test_tap_gets_output_after_subscribe() {
        let (console, mut sink, _spy) = console();
        sink.write_all(b"before").expect("write before subscribing");
        let tap = console.subscribe();
        sink.write_all(b"after").expect("write after subscribing");
        let chunk = tap
            .recv_timeout(Duration::from_secs(5))
            .expect("tapped chunk");
        assert_eq!(chunk, b"after");
        assert!(matches!(tap.try_recv(), Err(mpsc::TryRecvError::Empty)));
    }

    #[test]
    fn test_slow_tap_misses_and_gone_tap_removed() {
        // Slow tap misses chunks over the bound, dropped tap gets removed.
        let (console, mut sink, _spy) = console();
        let tap = console.subscribe();
        for _ in 0..=TAP_WRITES {
            sink.write_all(b"x").expect("write a chunk");
        }
        let mut got = 0;
        while tap.try_recv().is_ok() {
            got += 1;
        }
        assert_eq!(got, TAP_WRITES, "slow tap kept more chunks than bound");

        drop(tap);
        sink.write_all(b"y").expect("write after tap dropped");
        assert!(
            console.shared.taps.lock().unwrap().is_empty(),
            "dropped tap not removed"
        );
    }

    #[test]
    fn test_send_writes_input_end() {
        let (console, _sink, spy) = console();
        assert_eq!(console.send(b"ls\n").expect("send a line"), 3);
        assert_eq!(spy.taken.lock().unwrap().as_slice(), b"ls\n");
    }

    #[test]
    fn test_send_short_count_on_full_queue() {
        let (console, _sink, spy) = console_with_room(4);
        assert_eq!(console.send(b"abcdef").expect("send more than room"), 4);
        assert_eq!(console.send(b"g").expect("send to full queue"), 0);
        assert_eq!(spy.taken.lock().unwrap().as_slice(), b"abcd");
    }
}
