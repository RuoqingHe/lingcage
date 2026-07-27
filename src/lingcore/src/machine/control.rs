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
use std::io::{BufRead, BufReader, Write};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
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
    /// back.
    Snapshot { at: PathBuf },
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
        Action::Snapshot { at } => snapshot(machine, at).map(|()| Outcome::Done),
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
fn snapshot<H: Hypervisor>(machine: &mut Machine<H>, at: &Path) -> Result<(), Refused> {
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
    machine
        .write_memory(&mut memory)
        .map_err(|err| Refused::Mutated(err.to_string()))?;
    let mut document =
        File::create(at.join(DOCUMENT)).map_err(|err| Refused::Mutated(err.to_string()))?;
    taken
        .write_to(&mut document)
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
    at: PathBuf,
}

impl Orders {
    /// Returns next order, or `None` while none waits.
    pub fn next(&self) -> Option<Order> {
        self.taking.try_recv().ok()
    }
}

impl Drop for Orders {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.at);
    }
}

/// Take orders on the socket at `at`. Socket is served by a thread, so a
/// guest held still keeps answering.
pub fn listen(at: &Path) -> std::io::Result<Orders> {
    let _ = std::fs::remove_file(at);
    let listening = UnixListener::bind(at)?;
    let (orders, taking) = channel();
    std::thread::Builder::new()
        .name("control".to_string())
        .spawn(move || serve(listening, orders))?;
    Ok(Orders {
        taking,
        at: at.to_path_buf(),
    })
}

fn serve(listening: UnixListener, orders: Sender<Order>) {
    for stream in listening.incoming() {
        match stream {
            Ok(stream) => {
                if let Err(err) = talk(stream, &orders) {
                    warn!("control connection came apart: {err}");
                }
            }
            Err(err) => warn!("control socket refused a connection: {err}"),
        }
    }
}

fn talk(stream: UnixStream, orders: &Sender<Order>) -> std::io::Result<()> {
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
                at: PathBuf::from("/tmp/one")
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
    fn test_refusal_reports_changed_guest() {
        assert!(format!("{}", Refused::Mutated("out of room".to_string())).contains("changed"));
        assert!(!format!("{}", Refused::Held("busy".to_string())).contains("changed"));
    }
}
