// SPDX-FileCopyrightText: 2026 LingCage <opensource@lingcage.com>
//
// SPDX-License-Identifier: Apache-2.0

//! Protocol core, which serves one session of the control channel over
//! any descriptor-backed stream.

#![cfg(target_os = "linux")]

use std::fs::File;
use std::io::{self, Read, Write};
use std::os::fd::{AsRawFd, RawFd};
use std::time::{Duration, Instant};

use crate::agent::exec::{Child, Pty, SpawnError};
use crate::lcp::{
    ErrorPayload, Exec, ExecExit, ExecStarted, Frame, Identified, Identify, Ping, Pong, PtySize,
    Signal, flags, kind,
};

/// Host port of the log connection.
const LOG_PORT: u32 = 2;

/// Idle poll timeout, the loop just polls again when it expires.
const IDLE_POLL_MS: libc::c_int = 30_000;

/// Maximum poll timeout while a command is running, which keeps reaps
/// at 1 s interval. A nearer kill deadline shortens it accordingly.
const BUSY_POLL_MS: libc::c_int = 1_000;

/// Size limit of one pump buffer in bytes, the source is no longer
/// polled once the buffer is full.
const PUMP_CAP: usize = 65_536;

/// Connect and identity hooks of a session, replaceable in tests.
pub struct System<'a> {
    /// Connect to the given host port, returns the connection.
    pub connect: &'a (dyn Fn(u32) -> io::Result<File> + Sync + 'a),
    /// Apply the identity, returns the hostname actually in effect.
    pub identify: &'a (dyn Fn(&Identify) -> String + Sync + 'a),
}

/// Serve one session, sends READY first then handles frames until the
/// connection ends. Caller should reconnect on the returned error.
/// Commands of a dead connection are killed along with it.
pub fn serve<S>(control: &mut S, system: &System<'_>) -> Result<(), crate::lcp::Error>
where
    S: Read + Write + AsRawFd,
{
    arm_sigchld();
    // Log connection is best-effort. If there is no listener on the log
    // port, diagnostics stay on the console according to the one-way log
    // port's contract.
    if let Ok(conn) = (system.connect)(LOG_PORT) {
        crate::agent::diag::route(conn);
    }
    crate::agent::diag::line(format_args!("lingcage-agent: control session up"));
    let ready = Frame::with_payload(
        0,
        kind::READY,
        flags::SESSION_START,
        &crate::agent::guest::ready(),
    )?;
    ready.write_to(&mut *control)?;
    let mut children: Vec<Child> = Vec::new();
    let result = session(control, system, &mut children);
    crate::agent::diag::route_off();
    for child in &children {
        // SAFETY: kill has no pointer argument. The child called setsid so
        // its pid is also its process group id, negative pid signals the
        // group.
        unsafe { libc::kill(-child.pid, libc::SIGKILL) };
    }
    for child in &children {
        wait_dead(child.pid);
    }
    result
}

/// Frame loop of one session, runs on the state set up by `serve`.
fn session<S>(
    control: &mut S,
    system: &System<'_>,
    children: &mut Vec<Child>,
) -> Result<(), crate::lcp::Error>
where
    S: Read + Write + AsRawFd,
{
    loop {
        reap(children, &mut *control)?;
        enforce_timeouts(children);
        let (mut set, slots) = poll_set(control.as_raw_fd(), children);
        let timeout = if children.is_empty() {
            IDLE_POLL_MS
        } else {
            next_deadline(children)
        };
        if poll(&mut set, timeout).map_err(crate::lcp::Error::Io)? == 0 {
            continue;
        }
        pump(children, &set[1..], &slots);
        let revents = set[0].revents;
        if revents & libc::POLLIN != 0 {
            let frame = Frame::read_from(&mut *control)?;
            dispatch(&frame, children, &mut *control, system)?;
        } else if revents & (libc::POLLERR | libc::POLLHUP | libc::POLLNVAL) != 0 {
            return Err(crate::lcp::Error::Truncated);
        }
    }
}

/// Block until child `pid` is reaped.
fn wait_dead(pid: libc::pid_t) {
    loop {
        let mut status = 0;
        // SAFETY: `status` is a valid out-pointer.
        let got = unsafe { libc::waitpid(pid, &mut status, 0) };
        if got == -1 {
            let err = io::Error::last_os_error();
            if err.kind() == io::ErrorKind::Interrupted {
                continue;
            }
        }
        return;
    }
}

/// Handle one frame, replies are written to the control channel.
fn dispatch<W: Write>(
    frame: &Frame,
    children: &mut Vec<Child>,
    control: &mut W,
    system: &System<'_>,
) -> Result<(), crate::lcp::Error> {
    match frame.kind {
        kind::IDENTIFY => {
            let identify: Identify = match frame.payload() {
                Ok(identify) => identify,
                Err(_) => return bad_payload(control, frame.id),
            };
            let identified = Identified {
                hostname: (system.identify)(&identify),
            };
            Frame::with_payload(frame.id, kind::IDENTIFIED, 0, &identified)?
                .write_to(&mut *control)?;
        }
        kind::PING => {
            let ping: Ping = match frame.payload() {
                Ok(ping) => ping,
                Err(_) => return bad_payload(control, frame.id),
            };
            Frame::with_payload(frame.id, kind::PONG, 0, &Pong { nonce: ping.nonce })?
                .write_to(&mut *control)?;
        }
        kind::EXEC => {
            let exec: Exec = match frame.payload() {
                Ok(exec) => exec,
                Err(_) => return bad_payload(control, frame.id),
            };
            match crate::agent::exec::start(frame.id, &exec, system.connect) {
                Ok(child) => {
                    let started = ExecStarted {
                        pid: u32::try_from(child.pid).expect("pid fits u32"),
                    };
                    Frame::with_payload(frame.id, kind::EXEC_STARTED, 0, &started)?
                        .write_to(&mut *control)?;
                    children.push(child);
                }
                Err(SpawnError::Failed(failed)) => {
                    Frame::with_payload(frame.id, kind::EXEC_FAILED, 0, &failed)?
                        .write_to(&mut *control)?;
                }
                Err(SpawnError::Other { code, message }) => {
                    error_frame(&mut *control, frame.id, code, &message)?;
                }
            }
        }
        kind::EXEC_RESIZE => {
            let size: PtySize = match frame.payload() {
                Ok(size) => size,
                Err(_) => return bad_payload(control, frame.id),
            };
            resize(children, frame.id, size);
        }
        kind::EXEC_SIGNAL => {
            let signal: Signal = match frame.payload() {
                Ok(signal) => signal,
                Err(_) => return bad_payload(control, frame.id),
            };
            signal_command(children, frame.id, signal.signal);
        }
        kind::SHUTDOWN => crate::agent::guest::power_off(),
        other => {
            let message = format!("unknown frame kind {other}");
            error_frame(&mut *control, frame.id, "proto.unknown-kind", &message)?;
        }
    }
    Ok(())
}

/// Send ERROR frame for bad payload and finish the dispatch.
fn bad_payload<W: Write>(control: &mut W, id: u32) -> Result<(), crate::lcp::Error> {
    error_frame(
        control,
        id,
        "proto.bad-payload",
        "payload can not be decoded",
    )
}

/// Send an ERROR frame with given `code` and `message`.
fn error_frame<W: Write>(
    control: &mut W,
    id: u32,
    code: &str,
    message: &str,
) -> Result<(), crate::lcp::Error> {
    let payload = ErrorPayload {
        code: code.to_string(),
        message: message.to_string(),
    };
    Frame::with_payload(id, kind::ERROR, 0, &payload)?.write_to(control)
}

/// Reap exited commands and send EXEC_EXIT frame for each of them. Each
/// waitpid is called with a specific pid, since waitpid(-1) would also
/// reap children spawned by other code in this process.
fn reap<W: Write>(children: &mut Vec<Child>, control: &mut W) -> Result<(), crate::lcp::Error> {
    let mut at = 0;
    while at < children.len() {
        let Some(status) = wait_child(children[at].pid).map_err(crate::lcp::Error::Io)? else {
            at += 1;
            continue;
        };
        let mut child = children.remove(at);
        drain(&mut child);
        let exit = if libc::WIFEXITED(status) {
            ExecExit {
                code: Some(libc::WEXITSTATUS(status)),
                signal: None,
                timed_out: child.timed_out,
            }
        } else {
            ExecExit {
                code: None,
                signal: Some(libc::WTERMSIG(status)),
                timed_out: child.timed_out,
            }
        };
        Frame::with_payload(child.id, kind::EXEC_EXIT, 0, &exit)?.write_to(&mut *control)?;
    }
    Ok(())
}

/// Non-blocking waitpid(2) on one child. Returns its status once exited.
fn wait_child(pid: libc::pid_t) -> io::Result<Option<libc::c_int>> {
    loop {
        let mut status = 0;
        // SAFETY: `status` is a valid out-pointer.
        let got = unsafe { libc::waitpid(pid, &mut status, libc::WNOHANG) };
        match got {
            0 => return Ok(None),
            -1 => {
                let err = io::Error::last_os_error();
                if err.kind() == io::ErrorKind::Interrupted {
                    continue;
                }
                return Err(err);
            }
            _ => return Ok(Some(status)),
        }
    }
}

/// Milliseconds until the nearest kill deadline, clamped between 1 and
/// `BUSY_POLL_MS`. This makes sure a command with deadline shorter than
/// the poll interval gets killed on time instead of one poll late.
fn next_deadline(children: &[Child]) -> libc::c_int {
    let now = Instant::now();
    let nearest = children
        .iter()
        .filter_map(|child| child.kill_at)
        .map(|at| at.saturating_duration_since(now))
        .min();
    match nearest {
        Some(left) => libc::c_int::try_from(left.as_millis())
            .unwrap_or(BUSY_POLL_MS)
            .clamp(1, BUSY_POLL_MS),
        None => BUSY_POLL_MS,
    }
}

/// Send SIGKILL to commands past their timeout, the reap would then
/// report signal 9. Signal is sent to the process group since children
/// of a command must not outlive it.
fn enforce_timeouts(children: &mut [Child]) {
    let now = Instant::now();
    for child in children {
        let Some(at) = child.kill_at else { continue };
        if at > now {
            continue;
        }
        // SAFETY: kill has no pointer argument, negative pid is the group.
        if unsafe { libc::kill(-child.pid, libc::SIGKILL) } == -1 {
            crate::agent::diag::line(format_args!(
                "lingcage-agent: failed to kill pid {} on timeout: {}",
                child.pid,
                io::Error::last_os_error()
            ));
        }
        child.kill_at = None;
        child.timed_out = true;
    }
}

/// Apply new PTY size to the command with given frame id. The frame is
/// ignored if the command has exited or has no terminal.
fn resize(children: &[Child], id: u32, size: PtySize) {
    for child in children {
        if child.id != id {
            continue;
        }
        let Some(pty) = &child.pty else { return };
        let Some(master) = &pty.master else { return };
        let winsize = libc::winsize {
            ws_row: size.rows,
            ws_col: size.cols,
            ws_xpixel: 0,
            ws_ypixel: 0,
        };
        // SAFETY: `master` is an open terminal fd and `winsize` is valid.
        if unsafe { libc::ioctl(master.as_raw_fd(), libc::TIOCSWINSZ, &winsize) } == -1 {
            crate::agent::diag::line(format_args!(
                "lingcage-agent: failed to resize pty of pid {}: {}",
                child.pid,
                io::Error::last_os_error()
            ));
        }
        return;
    }
}

/// Send signal to the process group of the command with given frame id.
/// The group id is the child's pid since it called `setsid`. Frame for
/// an exited command is ignored, its exit is reported by the reap.
fn signal_command(children: &[Child], id: u32, sig: libc::c_int) {
    for child in children {
        if child.id != id {
            continue;
        }
        // SAFETY: kill has no pointer argument, negative pid is the group.
        if unsafe { libc::kill(-child.pid, sig) } == -1 {
            crate::agent::diag::line(format_args!(
                "lingcage-agent: failed to send signal {sig} to pid {}: {}",
                child.pid,
                io::Error::last_os_error()
            ));
        }
        return;
    }
}

/// Maximum time to flush the last output of a command. The stream is
/// nonblocking, so the wait is bounded even if host stops reading.
const DRAIN_WITHIN: Duration = Duration::from_secs(2);

/// Final pass over the PTY of a command, remaining bytes on the master
/// are pushed to the stdout stream before both of them are closed.
fn drain(child: &mut Child) {
    let Some(pty) = &mut child.pty else { return };
    let mut buf = [0u8; 8192];
    if let Some(master) = &mut pty.master {
        loop {
            match master.read(&mut buf) {
                Ok(0) => break,
                Ok(n) => pty.out_buf.extend(&buf[..n]),
                Err(_) => break,
            }
        }
    }
    if let Some(output) = &mut pty.output {
        let (head, tail) = pty.out_buf.as_slices();
        let deadline = Instant::now() + DRAIN_WITHIN;
        let result = push(output, head, deadline).and_then(|()| push(output, tail, deadline));
        if let Err(err) = result {
            crate::agent::diag::line(format_args!(
                "lingcage-agent: failed to flush last output of pid {}: {err}",
                child.pid
            ));
        }
    }
}

/// Write `bytes` to a nonblocking stream, waits for room until
/// `deadline`. `write_all` is not used since it gives up on the first
/// EAGAIN, which would lose the last output of a command.
fn push(output: &mut File, mut bytes: &[u8], deadline: Instant) -> io::Result<()> {
    while !bytes.is_empty() {
        match output.write(bytes) {
            Ok(0) => return Err(io::Error::from(io::ErrorKind::WriteZero)),
            Ok(n) => bytes = &bytes[n..],
            Err(err) if err.kind() == io::ErrorKind::Interrupted => {}
            Err(err) if err.kind() == io::ErrorKind::WouldBlock => {
                let left = deadline.saturating_duration_since(Instant::now());
                if left.is_zero() {
                    return Err(io::Error::from(io::ErrorKind::TimedOut));
                }
                let mut polled = libc::pollfd {
                    fd: output.as_raw_fd(),
                    events: libc::POLLOUT,
                    revents: 0,
                };
                let ms = libc::c_int::try_from(left.as_millis()).unwrap_or(libc::c_int::MAX);
                // SAFETY: `polled` is a valid pollfd during the call.
                if unsafe { libc::poll(&mut polled, 1, ms) } < 0 {
                    let err = io::Error::last_os_error();
                    if err.kind() != io::ErrorKind::Interrupted {
                        return Err(err);
                    }
                }
            }
            Err(err) => return Err(err),
        }
    }
    Ok(())
}

/// Role of a pump descriptor in the poll set.
enum Slot {
    Master,
    Input,
    Output,
}

/// Build the poll set, control descriptor comes first, followed by one
/// slot for each pump descriptor which has pending work.
fn poll_set(control: RawFd, children: &[Child]) -> (Vec<libc::pollfd>, Vec<(usize, Slot)>) {
    let mut set = vec![libc::pollfd {
        fd: control,
        events: libc::POLLIN,
        revents: 0,
    }];
    let mut slots = Vec::new();
    for (at, child) in children.iter().enumerate() {
        let Some(pty) = &child.pty else { continue };
        if let Some(master) = &pty.master
            && !pty.master_done
        {
            let mut events: libc::c_short = 0;
            if pty.out_buf.len() < PUMP_CAP || pty.output.is_none() {
                events |= libc::POLLIN;
            }
            if !pty.in_buf.is_empty() {
                events |= libc::POLLOUT;
            }
            if events != 0 {
                set.push(libc::pollfd {
                    fd: master.as_raw_fd(),
                    events,
                    revents: 0,
                });
                slots.push((at, Slot::Master));
            }
        }
        if let Some(input) = &pty.input
            && pty.in_buf.len() < PUMP_CAP
        {
            set.push(libc::pollfd {
                fd: input.as_raw_fd(),
                events: libc::POLLIN,
                revents: 0,
            });
            slots.push((at, Slot::Input));
        }
        if let Some(output) = &pty.output
            && !pty.out_buf.is_empty()
        {
            set.push(libc::pollfd {
                fd: output.as_raw_fd(),
                events: libc::POLLOUT,
                revents: 0,
            });
            slots.push((at, Slot::Output));
        }
    }
    (set, slots)
}

/// Move bytes between masters and stream connections of PTY commands,
/// one nonblocking pass for each readable or writable slot.
fn pump(children: &mut [Child], set: &[libc::pollfd], slots: &[(usize, Slot)]) {
    for ((at, slot), polled) in slots.iter().zip(set) {
        let Some(pty) = children[*at].pty.as_mut() else {
            continue;
        };
        match slot {
            Slot::Master => {
                if polled.revents & (libc::POLLIN | libc::POLLERR | libc::POLLHUP) != 0 {
                    read_master(pty);
                }
                if polled.revents & libc::POLLOUT != 0 {
                    write_master(pty);
                }
            }
            Slot::Input => {
                if polled.revents & (libc::POLLIN | libc::POLLERR | libc::POLLHUP) != 0 {
                    read_input(pty);
                }
            }
            Slot::Output => {
                if polled.revents & (libc::POLLOUT | libc::POLLERR) != 0 {
                    write_output(pty);
                }
            }
        }
        if pty.master_done && pty.out_buf.is_empty() {
            pty.output = None;
        }
    }
}

/// Read from the master into the output buffer, bytes are discarded if
/// the output stream is gone. Master is marked done on EOF or error.
fn read_master(pty: &mut Pty) {
    if pty.master_done {
        return;
    }
    let Some(master) = &mut pty.master else {
        return;
    };
    let mut buf = [0u8; 8192];
    let discard = pty.output.is_none();
    let room = if discard {
        buf.len()
    } else {
        PUMP_CAP.saturating_sub(pty.out_buf.len()).min(buf.len())
    };
    if room == 0 {
        return;
    }
    match master.read(&mut buf[..room]) {
        Ok(0) => pty.master_done = true,
        Ok(n) => {
            if !discard {
                pty.out_buf.extend(&buf[..n]);
            }
        }
        Err(err)
            if matches!(
                err.kind(),
                io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted
            ) => {}
        // EIO means the slave side is closed. Mark the master done but
        // keep it open, since closing it would SIGHUP a session which is
        // still exiting. The fd is closed on reap.
        Err(_) => pty.master_done = true,
    }
}

/// Write buffered input to the master.
fn write_master(pty: &mut Pty) {
    if pty.master_done {
        return;
    }
    let Some(master) = &mut pty.master else {
        return;
    };
    let (head, _) = pty.in_buf.as_slices();
    match master.write(head) {
        Ok(n) => drop(pty.in_buf.drain(..n)),
        Err(err)
            if matches!(
                err.kind(),
                io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted
            ) => {}
        Err(_) => {
            pty.in_buf.clear();
            pty.master_done = true;
        }
    }
}

/// Read from the stdin stream into the input buffer, input is ended on
/// EOF or error.
fn read_input(pty: &mut Pty) {
    let Some(input) = &mut pty.input else { return };
    let mut buf = [0u8; 8192];
    let room = PUMP_CAP.saturating_sub(pty.in_buf.len()).min(buf.len());
    if room == 0 {
        return;
    }
    match input.read(&mut buf[..room]) {
        Ok(0) => end_input(pty),
        Ok(n) => pty.in_buf.extend(&buf[..n]),
        Err(err)
            if matches!(
                err.kind(),
                io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted
            ) => {}
        Err(_) => end_input(pty),
    }
}

/// End the input of a PTY command. An EOT byte is queued after pending
/// input so that the terminal reads EOF in the right order.
fn end_input(pty: &mut Pty) {
    pty.in_buf.push_back(0x04);
    pty.input = None;
}

/// Write buffered output into stdout stream.
fn write_output(pty: &mut Pty) {
    let Some(output) = &mut pty.output else {
        return;
    };
    let (head, _) = pty.out_buf.as_slices();
    match output.write(head) {
        Ok(n) => drop(pty.out_buf.drain(..n)),
        Err(err)
            if matches!(
                err.kind(),
                io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted
            ) => {}
        Err(_) => {
            pty.out_buf.clear();
            pty.output = None;
        }
    }
}

/// Wrapper of poll(2) which treats EINTR as a timeout.
fn poll(set: &mut [libc::pollfd], timeout: libc::c_int) -> io::Result<libc::c_int> {
    let count = libc::nfds_t::try_from(set.len()).expect("poll set fits nfds_t");
    // SAFETY: `set` is a valid slice and `count` is its length.
    let n = unsafe { libc::poll(set.as_mut_ptr(), count, timeout) };
    if n == -1 {
        let err = io::Error::last_os_error();
        if err.kind() == io::ErrorKind::Interrupted {
            // Interrupted by SIGCHLD, treat it as timeout so that the
            // loop reaps children at the top right away.
            return Ok(0);
        }
        return Err(err);
    }
    Ok(n)
}

/// Install empty SIGCHLD handler without SA_RESTART, so that child exit
/// interrupts the poll and the reap at the top of the loop reports it
/// right away instead of waiting for the busy poll interval.
fn arm_sigchld() {
    // SAFETY: a zeroed sigaction is a valid empty sigaction.
    let mut action: libc::sigaction = unsafe { std::mem::zeroed() };
    action.sa_sigaction = on_sigchld as *const () as libc::sighandler_t;
    // SAFETY: `action` is a valid sigaction with an empty handler.
    unsafe { libc::sigaction(libc::SIGCHLD, &action, std::ptr::null_mut()) };
}

extern "C" fn on_sigchld(_: libc::c_int) {}

#[cfg(test)]
mod tests {
    use std::collections::{BTreeMap, HashMap};
    use std::fs::File;
    use std::io::{self, Read, Write};
    use std::os::fd::OwnedFd;
    use std::os::unix::net::UnixStream;
    use std::sync::Mutex;
    use std::thread;
    use std::time::Duration;

    use crate::agent::session::{System, serve};
    use crate::lcp::{
        ErrorPayload, Exec, ExecExit, ExecFailed, ExecStarted, Failure, Frame, Identified,
        Identify, Ping, Pong, PtySize, Ready, Signal, Stream, flags, kind,
    };

    /// Connect closure for tests which do not need streams.
    fn unbound(port: u32) -> io::Result<File> {
        Err(io::Error::new(
            io::ErrorKind::NotFound,
            format!("port {port} is not bound"),
        ))
    }

    /// Identify hook for tests which do not send IDENTIFY.
    fn unapplied(_: &Identify) -> String {
        "unused".to_string()
    }

    /// Run `act` as the host side of one session, returns the result of
    /// the session. READY frame is passed to `act`.
    fn session(
        system: &System<'_>,
        act: impl FnOnce(&mut UnixStream, Frame),
    ) -> Result<(), crate::lcp::Error> {
        let (mut host, mut guest) = UnixStream::pair().expect("socket pair");
        host.set_read_timeout(Some(Duration::from_secs(15)))
            .expect("read deadline");
        thread::scope(|scope| {
            let serving = scope.spawn(move || serve(&mut guest, system));
            let ready = Frame::read_from(&mut host).expect("READY frame");
            act(&mut host, ready);
            drop(host);
            serving.join().expect("session panicked")
        })
    }

    /// Create a stream pair for each port. Guest ends are returned by the
    /// connect closure, host ends are collected in the returned map.
    fn streams(ports: &[u32]) -> (impl Fn(u32) -> io::Result<File>, HashMap<u32, UnixStream>) {
        let mut guest_ends = HashMap::new();
        let mut host_ends = HashMap::new();
        for port in ports {
            let (host, guest) = UnixStream::pair().expect("socket pair");
            host.set_read_timeout(Some(Duration::from_secs(15)))
                .expect("read deadline");
            guest_ends.insert(*port, File::from(OwnedFd::from(guest)));
            host_ends.insert(*port, host);
        }
        let guest_ends = Mutex::new(guest_ends);
        let connect = move |port: u32| {
            guest_ends
                .lock()
                .expect("ports map")
                .remove(&port)
                .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "unbound port"))
        };
        (connect, host_ends)
    }

    /// Stream on given `port`, using port number as nonce.
    fn stream(port: u32) -> Stream {
        Stream {
            port,
            nonce: u64::from(port),
        }
    }

    /// Build an Exec with only the two output ports, stdin is not set.
    fn running(program: &str, args: &[&str]) -> Exec {
        Exec {
            program: program.to_string(),
            args: args.iter().map(|arg| arg.to_string()).collect(),
            env: BTreeMap::new(),
            cwd: None,
            user: None,
            pty: None,
            timeout_ms: None,
            stdin: None,
            stdout: stream(1024),
            stderr: stream(1025),
        }
    }

    /// Read the nonce which agent writes first on each of `ports`, and
    /// check it matches the port number.
    fn nonces(ends: &mut HashMap<u32, UnixStream>, ports: &[u32]) {
        for port in ports {
            let mut nonce = [0u8; crate::lcp::NONCE];
            ends.get_mut(port)
                .expect("stream end")
                .read_exact(&mut nonce)
                .expect("read nonce");
            assert_eq!(
                u64::from_be_bytes(nonce),
                u64::from(*port),
                "nonce of port {port}"
            );
        }
    }

    /// Exec which runs given shell line.
    fn shell(line: &str) -> Exec {
        running("/bin/sh", &["-c", line])
    }

    /// Send an EXEC frame and read corresponding EXEC_STARTED.
    fn start_exec(host: &mut UnixStream, id: u32, exec: &Exec) -> ExecStarted {
        Frame::with_payload(id, kind::EXEC, 0, exec)
            .expect("EXEC frame")
            .write_to(host)
            .expect("send EXEC");
        let started = Frame::read_from(host).expect("EXEC_STARTED frame");
        assert_eq!(started.kind, kind::EXEC_STARTED);
        assert_eq!(started.id, id);
        let started: ExecStarted = started.payload().expect("EXEC_STARTED payload");
        assert!(started.pid > 0);
        started
    }

    /// Read an EXEC_EXIT frame, returns its payload.
    fn read_exit(host: &mut UnixStream, id: u32) -> ExecExit {
        let exit = Frame::read_from(host).expect("EXEC_EXIT frame");
        assert_eq!(exit.kind, kind::EXEC_EXIT);
        assert_eq!(exit.id, id);
        exit.payload().expect("EXEC_EXIT payload")
    }

    #[test]
    fn test_identify_after_ready() {
        let seen = Mutex::new(None);
        let system = System {
            connect: &unbound,
            identify: &|identity: &Identify| {
                *seen.lock().expect("record") = Some(identity.clone());
                "applied-host".to_string()
            },
        };
        let ended = session(&system, |host, ready| {
            assert_eq!(ready.kind, kind::READY);
            assert_eq!(ready.flags, flags::SESSION_START);
            let ready: Ready = ready.payload().expect("READY payload");
            assert_eq!(
                ready.agent,
                format!("lingcage-agent {}", env!("CARGO_PKG_VERSION"))
            );
            assert!(
                ready.uptime > 0.0,
                "uptime should be read from /proc/uptime"
            );
            assert!(
                !ready.boot_id.is_empty(),
                "boot id should be read from /proc"
            );

            let identify = Identify {
                hostname: "sandbox-7".to_string(),
                machine_id: "ab".repeat(16),
                generation: 3,
                entropy: [7u8; 32],
                unix_nanos: 0,
            };
            Frame::with_payload(1, kind::IDENTIFY, 0, &identify)
                .expect("IDENTIFY frame")
                .write_to(host)
                .expect("send IDENTIFY");
            let answered = Frame::read_from(host).expect("IDENTIFIED frame");
            assert_eq!(answered.kind, kind::IDENTIFIED);
            assert_eq!(answered.id, 1);
            let answered: Identified = answered.payload().expect("IDENTIFIED payload");
            assert_eq!(answered.hostname, "applied-host");
        });
        assert!(matches!(ended, Err(crate::lcp::Error::Truncated)));
        let seen = seen.lock().expect("record").clone().expect("apply ran");
        assert_eq!(seen.hostname, "sandbox-7");
        assert_eq!(seen.generation, 3);
        assert_eq!(seen.entropy, [7u8; 32]);
    }

    #[test]
    fn test_ping_pong() {
        let system = System {
            connect: &unbound,
            identify: &unapplied,
        };
        let ended = session(&system, |host, _ready| {
            Frame::with_payload(9, kind::PING, 0, &Ping { nonce: 99 })
                .expect("PING frame")
                .write_to(host)
                .expect("send PING");
            let answered = Frame::read_from(host).expect("PONG frame");
            assert_eq!(answered.kind, kind::PONG);
            assert_eq!(answered.id, 9);
            let answered: Pong = answered.payload().expect("PONG payload");
            assert_eq!(answered.nonce, 99);
        });
        assert!(matches!(ended, Err(crate::lcp::Error::Truncated)));
    }

    #[test]
    fn test_unknown_kind_error() {
        let system = System {
            connect: &unbound,
            identify: &unapplied,
        };
        let ended = session(&system, |host, _ready| {
            Frame::new(5, 0xbeef, Vec::new())
                .write_to(host)
                .expect("send garbage frame");
            let answered = Frame::read_from(host).expect("ERROR frame");
            assert_eq!(answered.kind, kind::ERROR);
            assert_eq!(answered.id, 5);
            let answered: ErrorPayload = answered.payload().expect("ERROR payload");
            assert_eq!(answered.code, "proto.unknown-kind");
        });
        assert!(matches!(ended, Err(crate::lcp::Error::Truncated)));
    }

    #[test]
    fn test_bad_payload_error() {
        let system = System {
            connect: &unbound,
            identify: &unapplied,
        };
        let ended = session(&system, |host, _ready| {
            Frame::new(6, kind::EXEC, b"not json".to_vec())
                .write_to(host)
                .expect("send the frame");
            let answered = Frame::read_from(host).expect("ERROR frame");
            assert_eq!(answered.kind, kind::ERROR);
            assert_eq!(answered.id, 6);
            let answered: ErrorPayload = answered.payload().expect("ERROR payload");
            assert_eq!(answered.code, "proto.bad-payload");
        });
        assert!(matches!(ended, Err(crate::lcp::Error::Truncated)));
    }

    #[test]
    fn test_unbound_stream_port_error() {
        let system = System {
            connect: &unbound,
            identify: &unapplied,
        };
        let ended = session(&system, |host, _ready| {
            Frame::with_payload(3, kind::EXEC, 0, &shell("true"))
                .expect("EXEC frame")
                .write_to(host)
                .expect("send EXEC");
            let answered = Frame::read_from(host).expect("ERROR frame");
            assert_eq!(answered.kind, kind::ERROR);
            assert_eq!(answered.id, 3);
            let answered: ErrorPayload = answered.payload().expect("ERROR payload");
            assert_eq!(answered.code, "exec.connect");
        });
        assert!(matches!(ended, Err(crate::lcp::Error::Truncated)));
    }

    #[test]
    fn test_reject_exec_as_other_user() {
        let (connect, _ends) = streams(&[1024, 1025]);
        let system = System {
            connect: &connect,
            identify: &unapplied,
        };
        let ended = session(&system, |host, _ready| {
            let mut exec = shell("true");
            exec.user = Some("nobody".to_string());
            Frame::with_payload(4, kind::EXEC, 0, &exec)
                .expect("EXEC frame")
                .write_to(host)
                .expect("send EXEC");
            let answered = Frame::read_from(host).expect("ERROR frame");
            assert_eq!(answered.kind, kind::ERROR);
            assert_eq!(answered.id, 4);
            let answered: ErrorPayload = answered.payload().expect("ERROR payload");
            assert_eq!(answered.code, "exec.unsupported");
        });
        assert!(matches!(ended, Err(crate::lcp::Error::Truncated)));
    }

    #[test]
    fn test_exec_stdin_stdout() {
        let (connect, mut ends) = streams(&[1024, 1025, 1026]);
        let system = System {
            connect: &connect,
            identify: &unapplied,
        };
        let ended = session(&system, |host, _ready| {
            let mut exec = running("/bin/cat", &[]);
            exec.stdin = Some(stream(1026));
            start_exec(host, 7, &exec);
            nonces(&mut ends, &[1024, 1025, 1026]);

            ends.get_mut(&1026)
                .expect("stdin end")
                .write_all(b"hello\n")
                .expect("write to stdin");
            let mut echoed = [0u8; 6];
            ends.get_mut(&1024)
                .expect("stdout end")
                .read_exact(&mut echoed)
                .expect("read echo");
            assert_eq!(&echoed, b"hello\n");
            drop(ends.remove(&1026));

            let mut rest = Vec::new();
            ends.get_mut(&1024)
                .expect("stdout end")
                .read_to_end(&mut rest)
                .expect("read stream to end");
            assert!(rest.is_empty(), "no output after echo");
            let exit = read_exit(host, 7);
            assert_eq!(exit.code, Some(0));
            assert_eq!(exit.signal, None);
        });
        assert!(matches!(ended, Err(crate::lcp::Error::Truncated)));
    }

    #[test]
    fn test_exec_exit_code() {
        let (connect, _ends) = streams(&[1024, 1025]);
        let system = System {
            connect: &connect,
            identify: &unapplied,
        };
        let ended = session(&system, |host, _ready| {
            start_exec(host, 1, &shell("exit 42"));
            let exit = read_exit(host, 1);
            assert_eq!(exit.code, Some(42));
            assert_eq!(exit.signal, None);
        });
        assert!(matches!(ended, Err(crate::lcp::Error::Truncated)));
    }

    #[test]
    fn test_exec_exit_signal() {
        let (connect, _ends) = streams(&[1024, 1025]);
        let system = System {
            connect: &connect,
            identify: &unapplied,
        };
        let ended = session(&system, |host, _ready| {
            start_exec(host, 2, &shell("kill -TERM $$"));
            let exit = read_exit(host, 2);
            assert_eq!(exit.code, None);
            assert_eq!(exit.signal, Some(libc::SIGTERM));
        });
        assert!(matches!(ended, Err(crate::lcp::Error::Truncated)));
    }

    #[test]
    fn test_exec_signal_forward() {
        let (connect, _ends) = streams(&[1024, 1025]);
        let system = System {
            connect: &connect,
            identify: &unapplied,
        };
        let ended = session(&system, |host, _ready| {
            start_exec(host, 8, &shell("sleep 30"));
            Frame::with_payload(
                8,
                kind::EXEC_SIGNAL,
                0,
                &Signal {
                    signal: libc::SIGTERM,
                },
            )
            .expect("EXEC_SIGNAL frame")
            .write_to(host)
            .expect("send EXEC_SIGNAL");
            let exit = read_exit(host, 8);
            assert_eq!(exit.code, None);
            assert_eq!(exit.signal, Some(libc::SIGTERM));
        });
        assert!(matches!(ended, Err(crate::lcp::Error::Truncated)));
    }

    #[test]
    fn test_exec_signal_process_group() {
        // Grandchild is killed along with the command.
        let (connect, mut ends) = streams(&[1024, 1025]);
        let system = System {
            connect: &connect,
            identify: &unapplied,
        };
        let mut grandchild = 0;
        let ended = session(&system, |host, _ready| {
            start_exec(host, 11, &shell("sleep 300 & echo $!; wait"));
            nonces(&mut ends, &[1024]);
            // Pid of the grandchild is printed to stdout stream.
            let mut out = ends.remove(&1024).expect("stdout stream");
            let mut line = [0u8; 16];
            let read = out.read(&mut line).expect("read grandchild pid");
            grandchild = std::str::from_utf8(&line[..read])
                .expect("pid as text")
                .trim()
                .parse()
                .expect("pid number");
            Frame::with_payload(
                11,
                kind::EXEC_SIGNAL,
                0,
                &Signal {
                    signal: libc::SIGKILL,
                },
            )
            .expect("EXEC_SIGNAL frame")
            .write_to(host)
            .expect("send EXEC_SIGNAL");
            let exit = read_exit(host, 11);
            assert_eq!(exit.signal, Some(libc::SIGKILL));
        });
        assert!(matches!(ended, Err(crate::lcp::Error::Truncated)));
        // `sleep` is killed together with its shell, and its pid is gone once
        // init has reaped it.
        let pid = grandchild;
        let deadline = std::time::Instant::now() + Duration::from_secs(5);
        // SAFETY: kill takes no pointer, signal 0 only checks if pid exists.
        while unsafe { libc::kill(pid, 0) } != -1 {
            assert!(
                std::time::Instant::now() < deadline,
                "grandchild survived group signal"
            );
            std::thread::sleep(Duration::from_millis(20));
        }
    }

    #[test]
    fn test_dead_connection_kills_command() {
        let (connect, _ends) = streams(&[1024, 1025]);
        let system = System {
            connect: &connect,
            identify: &unapplied,
        };
        let mut pid = 0;
        let ended = session(&system, |host, _ready| {
            pid = start_exec(host, 15, &shell("sleep 30")).pid;
        });
        assert!(matches!(ended, Err(crate::lcp::Error::Truncated)));
        // SAFETY: kill takes no pointer, signal 0 only checks if pid exists.
        let alive = unsafe { libc::kill(i32::try_from(pid).expect("pid"), 0) };
        assert_eq!(alive, -1, "command survived connection loss");
    }

    #[test]
    fn test_exec_timeout_kill() {
        let (connect, _ends) = streams(&[1024, 1025]);
        let system = System {
            connect: &connect,
            identify: &unapplied,
        };
        let ended = session(&system, |host, _ready| {
            let mut exec = shell("sleep 30");
            exec.timeout_ms = Some(200);
            start_exec(host, 10, &exec);
            let exit = read_exit(host, 10);
            assert_eq!(exit.code, None);
            assert_eq!(exit.signal, Some(libc::SIGKILL));
            assert!(exit.timed_out, "exit does not report timeout");
        });
        assert!(matches!(ended, Err(crate::lcp::Error::Truncated)));
    }

    #[test]
    fn test_exec_failed_not_found() {
        // Missing program is reported as EXEC_FAILED with reason and
        // errno.
        let (connect, mut ends) = streams(&[1024, 1025]);
        let system = System {
            connect: &connect,
            identify: &unapplied,
        };
        let ended = session(&system, |host, _ready| {
            Frame::with_payload(11, kind::EXEC, 0, &running("/nonexistent/program", &[]))
                .expect("EXEC frame")
                .write_to(host)
                .expect("send EXEC");
            let answer = Frame::read_from(host).expect("EXEC_FAILED frame");
            assert_eq!(
                answer.kind,
                kind::EXEC_FAILED,
                "no EXEC_STARTED for failed spawn"
            );
            assert_eq!(answer.id, 11);
            let failed: ExecFailed = answer.payload().expect("EXEC_FAILED payload");
            assert_eq!(failed.reason, Failure::NotFound);
            assert_eq!(failed.errno, libc::ENOENT);
            // Text form of the reason is still written to stderr stream after
            // the nonce.
            nonces(&mut ends, &[1024, 1025]);
            let mut reason = Vec::new();
            ends.get_mut(&1025)
                .expect("stderr end")
                .read_to_end(&mut reason)
                .expect("read stderr stream");
            let reason = String::from_utf8(reason).expect("text reason");
            assert!(reason.contains("/nonexistent/program"), "got: {reason}");
        });
        assert!(matches!(ended, Err(crate::lcp::Error::Truncated)));
    }

    #[test]
    fn test_exec_failed_permission() {
        let (connect, _ends) = streams(&[1024, 1025]);
        let system = System {
            connect: &connect,
            identify: &unapplied,
        };
        let dir = std::env::temp_dir().join(format!("lingcage-agent-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("create test dir");
        let not_exec = dir.join("not-exec");
        std::fs::write(&not_exec, b"text, not a program\n").expect("write non-executable file");
        let path = not_exec.to_string_lossy().to_string();
        let ended = session(&system, |host, _ready| {
            Frame::with_payload(12, kind::EXEC, 0, &running(&path, &[]))
                .expect("EXEC frame")
                .write_to(host)
                .expect("send EXEC");
            let answer = Frame::read_from(host).expect("EXEC_FAILED frame");
            assert_eq!(answer.kind, kind::EXEC_FAILED);
            let failed: ExecFailed = answer.payload().expect("EXEC_FAILED payload");
            assert_eq!(failed.reason, Failure::Permission);
        });
        assert!(matches!(ended, Err(crate::lcp::Error::Truncated)));
        std::fs::remove_dir_all(&dir).expect("remove test dir");
    }

    #[test]
    fn test_push_waits_for_room() {
        // `push` waits on EAGAIN instead of dropping bytes.
        use std::os::fd::{AsRawFd as _, OwnedFd};

        let (mut host, guest) = UnixStream::pair().expect("socket pair");
        let guest = File::from(OwnedFd::from(guest));
        // SAFETY: descriptor stays open during the call.
        let flags = unsafe { libc::fcntl(guest.as_raw_fd(), libc::F_GETFL) };
        // SAFETY: new flags are the flags read above plus O_NONBLOCK.
        let set =
            unsafe { libc::fcntl(guest.as_raw_fd(), libc::F_SETFL, flags | libc::O_NONBLOCK) };
        assert_ne!(set, -1, "failed to set stream nonblocking");
        let sent = vec![b'x'; 512 * 1024];
        let reading = thread::spawn(move || {
            // Delay the read so that the first write fills up the buffer and
            // remaining bytes have to wait for room.
            thread::sleep(Duration::from_millis(200));
            let mut read = Vec::new();
            host.read_to_end(&mut read).expect("read stream");
            read.len()
        });
        let mut guest = guest;
        super::push(
            &mut guest,
            &sent,
            std::time::Instant::now() + Duration::from_secs(10),
        )
        .expect("push bytes");
        drop(guest);
        assert_eq!(
            reading.join().expect("reader thread panicked"),
            sent.len(),
            "push dropped bytes which did not fit"
        );
    }

    #[test]
    fn test_exec_with_pty() {
        let (connect, mut ends) = streams(&[1024, 1025]);
        let system = System {
            connect: &connect,
            identify: &unapplied,
        };
        let ended = session(&system, |host, _ready| {
            let mut exec = running("/bin/echo", &["hi"]);
            exec.pty = Some(PtySize { rows: 24, cols: 80 });
            start_exec(host, 12, &exec);
            nonces(&mut ends, &[1024, 1025]);
            Frame::with_payload(
                12,
                kind::EXEC_RESIZE,
                0,
                &PtySize {
                    rows: 40,
                    cols: 100,
                },
            )
            .expect("EXEC_RESIZE frame")
            .write_to(host)
            .expect("send EXEC_RESIZE");
            let mut output = Vec::new();
            ends.get_mut(&1024)
                .expect("stdout end")
                .read_to_end(&mut output)
                .expect("read pty output");
            assert_eq!(output, b"hi\r\n", "pty should map LF to CRLF");
            let exit = read_exit(host, 12);
            assert_eq!(exit.code, Some(0));
        });
        assert!(matches!(ended, Err(crate::lcp::Error::Truncated)));
    }

    #[test]
    fn test_pty_stdin_close_eof() {
        // PTY command should read EOF after stdin stream is closed.
        let (connect, mut ends) = streams(&[1024, 1025, 1026]);
        let system = System {
            connect: &connect,
            identify: &unapplied,
        };
        let ended = session(&system, |host, _ready| {
            let mut exec = running("/bin/cat", &[]);
            exec.pty = Some(PtySize { rows: 24, cols: 80 });
            exec.stdin = Some(stream(1026));
            start_exec(host, 13, &exec);
            nonces(&mut ends, &[1024, 1025, 1026]);
            let input = ends.remove(&1026).expect("stdin end");
            let mut input = input;
            input.write_all(b"hello\n").expect("write input");
            // Close the input, an EOT is queued after the bytes so that cat
            // reads EOF.
            drop(input);
            let mut output = Vec::new();
            ends.get_mut(&1024)
                .expect("stdout end")
                .read_to_end(&mut output)
                .expect("read pty output");
            // Terminal echoes the input first, then cat prints its copy, and
            // the EOT comes after both.
            assert_eq!(output, b"hello\r\nhello\r\n", "echo followed by copy");
            let exit = read_exit(host, 13);
            assert_eq!(exit.code, Some(0), "cat should exit on EOF");
        });
        assert!(matches!(ended, Err(crate::lcp::Error::Truncated)));
    }

    #[test]
    fn test_exec_env_and_path() {
        let (connect, mut ends) = streams(&[1024, 1025]);
        let system = System {
            connect: &connect,
            identify: &unapplied,
        };
        let ended = session(&system, |host, _ready| {
            let mut exec = running("sh", &["-c", "echo $MARKER"]);
            exec.env = BTreeMap::from([
                ("PATH".to_string(), "/bin".to_string()),
                ("MARKER".to_string(), "yes".to_string()),
            ]);
            start_exec(host, 13, &exec);
            nonces(&mut ends, &[1024, 1025]);
            let mut output = Vec::new();
            ends.get_mut(&1024)
                .expect("stdout end")
                .read_to_end(&mut output)
                .expect("read output");
            assert_eq!(output, b"yes\n");
            let exit = read_exit(host, 13);
            assert_eq!(exit.code, Some(0));
        });
        assert!(matches!(ended, Err(crate::lcp::Error::Truncated)));
    }

    #[test]
    fn test_exec_cwd() {
        let (connect, mut ends) = streams(&[1024, 1025]);
        let system = System {
            connect: &connect,
            identify: &unapplied,
        };
        let ended = session(&system, |host, _ready| {
            let mut exec = shell("pwd");
            exec.cwd = Some("/".to_string());
            start_exec(host, 14, &exec);
            nonces(&mut ends, &[1024, 1025]);
            let mut output = Vec::new();
            ends.get_mut(&1024)
                .expect("stdout end")
                .read_to_end(&mut output)
                .expect("read output");
            assert_eq!(output, b"/\n");
            let exit = read_exit(host, 14);
            assert_eq!(exit.code, Some(0));
        });
        assert!(matches!(ended, Err(crate::lcp::Error::Truncated)));
    }
}
