// SPDX-FileCopyrightText: 2026 LingCage <opensource@lingcage.com>
//
// SPDX-License-Identifier: Apache-2.0

//! Orders taken over a socket while a guest runs.
//!
//! Flags describe a guest before it boots. Holding one still, writing it
//! out and letting it go again are asked for after, so they arrive on a
//! socket instead.
//!
//! An order decides here what it does to a guest, not at the caller. A
//! failed order which left the guest alone and one which stopped part
//! way look the same from outside, so [`Refused`] tells them apart.

use std::fs::File;
use std::io::{BufRead, BufReader, BufWriter, Write};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::mpsc::{Receiver, Sender, channel};

use log::{debug, warn};

use crate::hv::hypervisor::Hypervisor;
use crate::machine::{Machine, State};

/// Name of the memory image inside a directory written by `Snapshot`.
pub const MEMORY: &str = "memory";

/// Name of the device and vCPU document in such a directory.
pub const DOCUMENT: &str = "state.json";

/// An order against a running guest.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Action {
    /// Report state of the guest.
    State,
    /// Hold the guest still. vCPUs stop, devices keep their state.
    Pause,
    /// Let a held guest go again.
    Resume,
    /// Write the guest to `at`, memory beside the document. Guest is held
    /// still first and left held, so `Resume` follows when it is wanted
    /// back. `dirty` writes the pages written since assembly and skips the
    /// rest.
    Snapshot { at: PathBuf, dirty: bool },
    /// Stop the guest.
    Stop,
}

/// Reason an order was not carried out.
#[derive(Debug)]
pub enum Refused {
    /// Guest is in a state the order does not apply to.
    NotNow(State),
    /// Order failed and left the guest as it was found.
    Held(String),
    /// Order changed the guest before it failed, so it is no longer one
    /// a caller can run.
    Mutated(String),
}

impl std::fmt::Display for Refused {
    fn fmt(&self, out: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Refused::NotNow(state) => write!(out, "guest is {state:?}"),
            Refused::Held(why) => write!(out, "{why}"),
            Refused::Mutated(why) => write!(out, "{why}, guest was changed"),
        }
    }
}

/// Result an order left behind.
#[derive(Debug)]
pub enum Outcome {
    /// State of the guest, for `Action::State`.
    State(State),
    /// Order was carried out.
    Done,
    /// Order was carried out and the guest was told to stop.
    Stopping,
}

/// Carry `action` out on `machine`.
pub fn apply<H: Hypervisor>(machine: &mut Machine<H>, action: &Action) -> Result<Outcome, Refused> {
    match action {
        Action::State => Ok(Outcome::State(machine.state())),
        Action::Pause => machine
            .pause()
            .map(|()| Outcome::Done)
            .map_err(|err| Refused::Held(err.to_string())),
        Action::Resume => machine
            .resume()
            .map(|()| Outcome::Done)
            .map_err(|err| Refused::Held(err.to_string())),
        Action::Snapshot { at, dirty } => snapshot(machine, at, *dirty).map(|()| Outcome::Done),
        Action::Stop => machine
            .stop()
            .map(|()| Outcome::Stopping)
            .map_err(|err| Refused::Held(err.to_string())),
    }
}

/// Hold the guest still and write it to `at`.
///
/// Guest is held before a page is read, so image holds one moment of it.
/// A failure past that point leaves guest held and is reported as such:
/// pages of a running guest would not match the document.
fn snapshot<H: Hypervisor>(
    machine: &mut Machine<H>,
    at: &Path,
    dirty: bool,
) -> Result<(), Refused> {
    if machine.state() != State::Paused {
        machine
            .pause()
            .map_err(|err| Refused::Held(err.to_string()))?;
    }
    std::fs::create_dir_all(at).map_err(|err| Refused::Held(err.to_string()))?;
    let taken = machine
        .capture()
        .map_err(|err| Refused::Held(err.to_string()))?;
    // Pages of the guest are read out past this point, and one released
    // in the middle would leave an image of two moments.
    let mut memory = File::create(at.join(MEMORY)).map_err(|err| Refused::Held(err.to_string()))?;
    match dirty {
        true => machine.write_dirty(&mut memory),
        false => machine.write_memory(&mut memory),
    }
    .map_err(|err| Refused::Mutated(err.to_string()))?;
    let document =
        File::create(at.join(DOCUMENT)).map_err(|err| Refused::Mutated(err.to_string()))?;
    // The document is written field by field, so a plain `File` costs one
    // `write` per field. `BufWriter` ignores a failed flush on drop, so the
    // flush is called here to report it.
    let mut document = BufWriter::new(document);
    taken
        .write_to(&mut document)
        .map_err(|err| Refused::Mutated(err.to_string()))?;
    document
        .flush()
        .map_err(|err| Refused::Mutated(err.to_string()))?;
    Ok(())
}

/// Read one field out of an order. Wire is small enough that a JSON
/// parser is not pulled in for it.
fn field<'a>(line: &'a str, name: &str) -> Option<&'a str> {
    let key = format!("\"{name}\"");
    let at = line.find(&key)? + key.len();
    let rest = line[at..].trim_start().strip_prefix(':')?.trim_start();
    let rest = rest.strip_prefix('"')?;
    let end = rest.find('"')?;
    Some(&rest[..end])
}

/// Read an order off one line. Returns `None` for a line naming no
/// order this version knows.
pub fn parse(line: &str) -> Option<Action> {
    match field(line, "do")? {
        "state" => Some(Action::State),
        "pause" => Some(Action::Pause),
        "resume" => Some(Action::Resume),
        "snapshot" => field(line, "at").map(|at| Action::Snapshot {
            at: PathBuf::from(at),
            dirty: field(line, "pages") == Some("dirty"),
        }),
        "stop" => Some(Action::Stop),
        _ => None,
    }
}

/// One order and the line it is answered on.
pub struct Order {
    action: Option<Action>,
    what: String,
    back: Sender<String>,
}

impl Order {
    /// Carry the order out and write back one line. Returns `true` once
    /// the guest was told to stop.
    pub fn serve<H: Hypervisor>(self, machine: &mut Machine<H>) -> bool {
        let Some(action) = self.action else {
            let _ = self.back.send(format!(
                "{{\"ok\":false,\"error\":\"no order named {}\"}}",
                self.what
            ));
            return false;
        };
        let (answer, stopping) = match apply(machine, &action) {
            Ok(Outcome::State(state)) => {
                (format!("{{\"ok\":true,\"state\":\"{state:?}\"}}"), false)
            }
            Ok(Outcome::Done) => ("{\"ok\":true}".to_string(), false),
            Ok(Outcome::Stopping) => ("{\"ok\":true}".to_string(), true),
            Err(refused) => {
                let mutated = matches!(refused, Refused::Mutated(_));
                debug!("guest refused an order: {refused}");
                (
                    format!("{{\"ok\":false,\"mutated\":{mutated},\"error\":\"{refused}\"}}"),
                    false,
                )
            }
        };
        let _ = self.back.send(answer);
        stopping
    }
}

/// Orders arriving on the socket, read by the holder of the guest.
pub struct Orders {
    taking: Receiver<Order>,
    /// eventfd the control thread writes after it sends an order.
    sent: Arc<OwnedFd>,
    at: PathBuf,
}

impl Orders {
    /// Returns an eventfd, readable once an order waits. Holder polls it
    /// beside its other descriptors.
    pub fn descriptor(&self) -> RawFd {
        self.sent.as_raw_fd()
    }

    /// Returns the orders waiting. The eventfd is read ahead of the channel,
    /// so an order sent after that read makes it readable again.
    pub fn take(&self) -> Vec<Order> {
        let mut count = [0u8; 8];
        // SAFETY: `count` is 8 bytes, the width an eventfd read fills. With
        // no order sent the read fails with `EAGAIN`, so the result is ignored.
        unsafe { libc::read(self.sent.as_raw_fd(), count.as_mut_ptr().cast(), 8) };
        let mut taken = Vec::new();
        while let Ok(order) = self.taking.try_recv() {
            taken.push(order);
        }
        taken
    }
}

impl Drop for Orders {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.at);
    }
}

/// Take orders on the socket at `at`. Socket is served by a thread, so a
/// guest held still keeps answering. It writes the eventfd of
/// `Orders::descriptor` after each order.
pub fn listen(at: &Path) -> std::io::Result<Orders> {
    let _ = std::fs::remove_file(at);
    let listening = UnixListener::bind(at)?;
    // SAFETY: `eventfd(2)` takes a count and flags and returns a
    // descriptor or -1.
    let fd = unsafe { libc::eventfd(0, libc::EFD_NONBLOCK | libc::EFD_CLOEXEC) };
    if fd < 0 {
        return Err(std::io::Error::last_os_error());
    }
    // SAFETY: `fd` was just opened and has no other owner.
    let sent = Arc::new(unsafe { OwnedFd::from_raw_fd(fd) });
    let telling = Arc::clone(&sent);
    let (orders, taking) = channel();
    std::thread::Builder::new()
        .name("control".to_string())
        .spawn(move || serve(listening, orders, &telling))?;
    Ok(Orders {
        taking,
        sent,
        at: at.to_path_buf(),
    })
}

fn serve(listening: UnixListener, orders: Sender<Order>, sent: &OwnedFd) {
    for stream in listening.incoming() {
        match stream {
            Ok(stream) => {
                if let Err(err) = talk(stream, &orders, sent) {
                    warn!("control connection came apart: {err}");
                }
            }
            Err(err) => warn!("control socket refused a connection: {err}"),
        }
    }
}

fn talk(stream: UnixStream, orders: &Sender<Order>, sent: &OwnedFd) -> std::io::Result<()> {
    let mut out = stream.try_clone()?;
    for line in BufReader::new(stream).lines() {
        let line = line?;
        if line.trim().is_empty() {
            continue;
        }
        let (back, answer) = channel();
        let order = Order {
            action: parse(&line),
            what: line,
            back,
        };
        if orders.send(order).is_err() {
            // Holder of the guest is gone, so is the guest.
            return Ok(());
        }
        let one = 1u64.to_ne_bytes();
        // SAFETY: `one` is 8 bytes, the width an eventfd write takes. A
        // write fails only on a full count, and a full count wakes the
        // holder too, so the result is ignored.
        unsafe { libc::write(sent.as_raw_fd(), one.as_ptr().cast(), 8) };
        let Ok(answer) = answer.recv() else {
            return Ok(());
        };
        writeln!(out, "{answer}")?;
        out.flush()?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use crate::machine::control::*;

    #[test]
    fn test_parse_orders() {
        assert_eq!(parse("{\"do\":\"pause\"}"), Some(Action::Pause));
        assert_eq!(parse("{\"do\":\"state\"}"), Some(Action::State));
        assert_eq!(
            parse("{\"do\":\"snapshot\",\"at\":\"/tmp/one\"}"),
            Some(Action::Snapshot {
                at: PathBuf::from("/tmp/one"),
                dirty: false,
            })
        );
        assert_eq!(
            parse("{\"do\":\"snapshot\",\"at\":\"/tmp/one\",\"pages\":\"dirty\"}"),
            Some(Action::Snapshot {
                at: PathBuf::from("/tmp/one"),
                dirty: true,
            })
        );
    }

    #[test]
    fn test_reject_order_without_target() {
        // A snapshot with nowhere to go names no action, so the caller is
        // told instead of a guest written to a path it did not name.
        assert_eq!(parse("{\"do\":\"snapshot\"}"), None);
        assert_eq!(parse("{\"do\":\"fly\"}"), None);
        assert_eq!(parse("not an order"), None);
    }

    #[test]
    fn test_order_wakes_holder() {
        // Order makes the eventfd readable, `take` returns it and reads the
        // eventfd, and the answer reaches the client.
        use std::time::Duration;

        use crate::hv::Interest;
        use crate::hv::os::linux::waiting::Waiting;

        let at = std::env::temp_dir().join(format!("lingcore-orders-{}", std::process::id()));
        let orders = listen(&at).expect("listen");
        let mut waiting = Waiting::new();
        waiting.add(orders.descriptor(), 1, Interest::Read);
        let mut ready = Vec::new();
        waiting.ready(Duration::ZERO, &mut ready).expect("wait");
        assert!(ready.is_empty(), "readable with no order");

        let mut client = UnixStream::connect(&at).expect("connect");
        client.write_all(b"{\"do\":\"state\"}\n").expect("write");
        waiting
            .ready(Duration::from_secs(5), &mut ready)
            .expect("wait");
        assert_eq!(ready, [1], "order did not wake the holder");
        let taken = orders.take();
        assert_eq!(taken.len(), 1);
        waiting.ready(Duration::ZERO, &mut ready).expect("wait");
        assert!(ready.is_empty(), "readable after `take`");

        taken[0]
            .back
            .send("{\"ok\":true}".to_string())
            .expect("answer");
        let mut answer = String::new();
        BufReader::new(&client)
            .read_line(&mut answer)
            .expect("read the answer");
        assert_eq!(answer, "{\"ok\":true}\n");
    }

    #[test]
    fn test_answers_wait_for_slow_client() {
        // Client sends 1000 orders and reads only after 200 ms. Control
        // thread waits on its writes, so each answer reaches the client.
        use std::time::Duration;

        use crate::hv::Interest;
        use crate::hv::os::linux::waiting::Waiting;

        let at = std::env::temp_dir().join(format!("lingcore-orders-slow-{}", std::process::id()));
        let orders = listen(&at).expect("listen");
        let client = std::thread::spawn(move || {
            let mut stream = UnixStream::connect(&at).expect("connect");
            stream
                .write_all(&b"{\"do\":\"state\"}\n".repeat(1000))
                .expect("write");
            std::thread::sleep(Duration::from_millis(200));
            BufReader::new(stream).lines().take(1000).count()
        });
        let mut waiting = Waiting::new();
        waiting.add(orders.descriptor(), 1, Interest::Read);
        let mut ready = Vec::new();
        let mut answered = 0;
        while answered < 1000 {
            waiting
                .ready(Duration::from_secs(5), &mut ready)
                .expect("wait");
            assert_eq!(ready, [1], "order did not wake the holder");
            for order in orders.take() {
                order
                    .back
                    .send("{\"ok\":true}".to_string())
                    .expect("answer");
                answered += 1;
            }
        }
        assert_eq!(client.join().expect("client"), 1000);
    }

    #[test]
    fn test_refusal_reports_changed_guest() {
        assert!(format!("{}", Refused::Mutated("out of room".to_string())).contains("changed"));
        assert!(!format!("{}", Refused::Held("busy".to_string())).contains("changed"));
    }
}
