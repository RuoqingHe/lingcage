// SPDX-FileCopyrightText: 2026 LingCage <opensource@lingcage.com>
//
// SPDX-License-Identifier: Apache-2.0

//! Running a command in the guest: stream connections opened with
//! nonce, optional PTY set up, then fork and exec.

#![cfg(target_os = "linux")]

use std::collections::VecDeque;
use std::ffi::CString;
use std::fs::{File, OpenOptions};
use std::io::{self, Write};
use std::os::fd::{AsRawFd, FromRawFd, RawFd};
use std::time::{Duration, Instant};

use crate::lcp::{Exec, ExecFailed, Failure, PtySize, Stream};

/// Errors thrown while starting a command.
#[derive(Debug)]
pub enum SpawnError {
    /// Failed to run the program, reason is carried in `EXEC_FAILED` payload.
    Failed(ExecFailed),
    /// Failed to open stream or to spawn, with code for ERROR frame.
    Other {
        /// Stable machine-readable code.
        code: &'static str,
        /// Human-readable description of the error.
        message: String,
    },
}

impl SpawnError {
    /// Failed to open a stream on given port.
    fn connect(port: u32, err: io::Error) -> Self {
        SpawnError::Other {
            code: "exec.connect",
            message: format!("port {port}: {err}"),
        }
    }

    /// Spawn procedure itself failed.
    fn spawn(what: &str, err: io::Error) -> Self {
        SpawnError::Other {
            code: "exec.spawn",
            message: format!("{what}: {err}"),
        }
    }
}

/// Open one stream to its port, nonce is written first so that host could
/// wire it up properly.
fn open_stream(connect: &dyn Fn(u32) -> io::Result<File>, stream: &Stream) -> io::Result<File> {
    let mut opened = connect(stream.port)?;
    opened.write_all(&stream.nonce.to_be_bytes())?;
    Ok(opened)
}

/// Running command which is tracked by session loop.
pub struct Child {
    /// Frame id of the EXEC, replies and later frames are correlated by it.
    pub id: u32,
    /// Pid of the command.
    pub pid: libc::pid_t,
    /// Time point after which command is SIGKILLed, `None` means no timeout.
    pub kill_at: Option<Instant>,
    /// Set to true once the command is killed by its timeout.
    pub timed_out: bool,
    /// Terminal side of the command, `None` if it is not run under a PTY.
    pub pty: Option<Pty>,
}

/// Agent side of a PTY exec, including the master, the streams and
/// buffered bytes not yet forwarded.
pub struct Pty {
    /// Master side of the terminal, set to `None` once it is finished.
    pub master: Option<File>,
    /// Stdin stream of the command, `None` if not given or already ended.
    pub input: Option<File>,
    /// Stdout stream of the command, `None` once it fails or is drained.
    pub output: Option<File>,
    /// Bytes read from `input` which are not yet written to master.
    pub in_buf: VecDeque<u8>,
    /// Bytes read from the master and pending to be written to `output`.
    pub out_buf: VecDeque<u8>,
    /// Set once master is no longer served. The fd is closed at reap time,
    /// since closing it earlier would SIGHUP an exiting session.
    pub master_done: bool,
}

/// Connect streams of the command and fork it, parent side is tracked in
/// the returned [`Child`]. On failure, related code for ERROR frame is
/// returned.
pub fn start(
    id: u32,
    exec: &Exec,
    connect: &dyn Fn(u32) -> io::Result<File>,
) -> Result<Child, SpawnError> {
    if exec.user.is_some() {
        return Err(SpawnError::Other {
            code: "exec.unsupported",
            message: "running as another user is not supported".to_string(),
        });
    }
    let stdout = open_stream(connect, &exec.stdout)
        .map_err(|err| SpawnError::connect(exec.stdout.port, err))?;
    let stderr = open_stream(connect, &exec.stderr)
        .map_err(|err| SpawnError::connect(exec.stderr.port, err))?;
    let stdin = exec
        .stdin
        .as_ref()
        .map(|stream| {
            open_stream(connect, stream).map_err(|err| SpawnError::connect(stream.port, err))
        })
        .transpose()?;
    let pty = match exec.pty {
        Some(size) => Some(openpty(size).map_err(|err| SpawnError::spawn("the pty", err))?),
        None => None,
    };
    // Use /dev/null as stdin if stdin is not given and no PTY is used.
    let devnull = match (&pty, &stdin) {
        (None, None) => Some(open_devnull().map_err(|err| SpawnError::spawn("/dev/null", err))?),
        _ => None,
    };
    let stdio: [RawFd; 3] = match &pty {
        Some((_, slave)) => [slave.as_raw_fd(); 3],
        None => [
            stdin
                .as_ref()
                .or(devnull.as_ref())
                .expect("stdin or /dev/null")
                .as_raw_fd(),
            stdout.as_raw_fd(),
            stderr.as_raw_fd(),
        ],
    };
    let mut spec = Spec {
        program: cstring(&exec.program, "the program")?,
        args: exec
            .args
            .iter()
            .map(|arg| cstring(arg, "an argument"))
            .collect::<Result<_, _>>()?,
        env: exec
            .env
            .iter()
            .map(|(name, value)| {
                Ok((
                    cstring(name, "environment name")?,
                    cstring(value, "environment value")?,
                ))
            })
            .collect::<Result<_, SpawnError>>()?,
        cwd: exec
            .cwd
            .as_deref()
            .map(|cwd| cstring(cwd, "working directory"))
            .transpose()?,
        stdio,
        controlling: pty.is_some(),
        report: None,
    };
    let (read_fd, write_fd) =
        report_pipe().map_err(|err| SpawnError::spawn("failure pipe", err))?;
    spec.report = Some(write_fd.as_raw_fd());
    let pid = spawn(&spec).map_err(|err| SpawnError::spawn("the fork", err))?;
    // EOF on the pipe means exec succeeded, four bytes means errno.
    drop(write_fd);
    if let Some(failed) =
        reported(&read_fd).map_err(|err| SpawnError::spawn("failure report", err))?
    {
        reap_now(pid);
        return Err(SpawnError::Failed(failed));
    }
    let pty = match pty {
        Some((master, slave)) => {
            drop(slave);
            drop(stderr);
            let mut pumping = vec![&master, &stdout];
            if let Some(input) = &stdin {
                pumping.push(input);
            }
            for file in pumping {
                if let Err(err) = set_nonblocking(file) {
                    // SAFETY: no pointer is passed to kill, negative pid
                    // means the process group, and the pid is reaped below.
                    unsafe { libc::kill(-pid, libc::SIGKILL) };
                    reap_now(pid);
                    return Err(SpawnError::spawn("pump setup", err));
                }
            }
            Some(Pty {
                master: Some(master),
                input: stdin,
                output: Some(stdout),
                in_buf: VecDeque::new(),
                out_buf: VecDeque::new(),
                master_done: false,
            })
        }
        None => None,
    };
    Ok(Child {
        id,
        pid,
        kill_at: exec
            .timeout_ms
            .map(|within| Instant::now() + Duration::from_millis(within)),
        timed_out: false,
        pty,
    })
}

/// Inputs of fork, prepared before forking. The child only allocates when
/// setting environment and in PATH search of execvp.
struct Spec {
    program: CString,
    args: Vec<CString>,
    env: Vec<(CString, CString)>,
    cwd: Option<CString>,
    stdio: [RawFd; 3],
    controlling: bool,
    /// Write end of failure pipe, which gets closed by a successful exec.
    report: Option<RawFd>,
}

/// Fork and run `spec` in the child. Failures after the last dup are
/// reported as text on fd 2 and as errno on the report pipe. The pipe is
/// CLOEXEC, so EOF on it means exec succeeded.
fn spawn(spec: &Spec) -> io::Result<libc::pid_t> {
    let mut argv: Vec<*const libc::c_char> = Vec::with_capacity(spec.args.len() + 2);
    argv.push(spec.program.as_ptr());
    argv.extend(spec.args.iter().map(|arg| arg.as_ptr()));
    argv.push(std::ptr::null());
    // SAFETY: fork has no pointer argument.
    let pid = unsafe { libc::fork() };
    if pid == -1 {
        return Err(io::Error::last_os_error());
    }
    if pid == 0 {
        child_main(spec, &argv);
    }
    Ok(pid)
}

/// Child side of the fork, which sets up descriptors, session, working
/// directory and environment, then execs.
fn child_main(spec: &Spec, argv: &[*const libc::c_char]) -> ! {
    for (slot, fd) in spec.stdio.iter().enumerate() {
        let slot = libc::c_int::try_from(slot).expect("three slots");
        // SAFETY: `fd` is open, kernel duplicates it onto `slot`.
        if unsafe { libc::dup2(*fd, slot) } == -1 {
            die(
                spec,
                &spec.program,
                "could not move stream onto its descriptor",
            );
        }
    }
    // SAFETY: kernel closes given ranges and skips unopened slots, report
    // descriptor is excluded from the ranges since `die` still needs it.
    let spans = match spec.report {
        Some(report) => [
            (3, libc::c_long::from(report) - 1),
            (libc::c_long::from(report) + 1, libc::c_long::from(u32::MAX)),
        ],
        None => [(3, libc::c_long::from(u32::MAX)), (1, 0)],
    };
    for (from, to) in spans {
        if to < from {
            continue;
        }
        // SAFETY: ranges are plain descriptor numbers, no pointer involved.
        let closed = unsafe { libc::syscall(libc::SYS_close_range, from, to, 0) };
        if closed == -1 {
            die(spec, &spec.program, "could not close leftover descriptors");
        }
    }
    // SAFETY: setsid has no pointer argument.
    if unsafe { libc::setsid() } == -1 {
        die(spec, &spec.program, "could not start a new session");
    }
    if spec.controlling {
        // SAFETY: fd 0 is the slave side and the child is session leader.
        if unsafe { libc::ioctl(0, libc::TIOCSCTTY, std::ptr::null::<libc::c_void>()) } == -1 {
            die(spec, &spec.program, "could not set controlling terminal");
        }
    }
    if let Some(cwd) = &spec.cwd {
        // SAFETY: `cwd` is a valid C string.
        if unsafe { libc::chdir(cwd.as_ptr()) } == -1 {
            let what = format!("could not chdir to {}", cwd.to_string_lossy());
            die(spec, &spec.program, &what);
        }
    }
    // SAFETY: clearenv has no pointer argument.
    if unsafe { libc::clearenv() } != 0 {
        die(spec, &spec.program, "could not clear environment");
    }
    for (name, value) in &spec.env {
        // SAFETY: both `name` and `value` are valid C strings.
        if unsafe { libc::setenv(name.as_ptr(), value.as_ptr(), 1) } == -1 {
            die(spec, &spec.program, "could not set environment");
        }
    }
    // SAFETY: `argv` is NUL-terminated, its strings are alive during the call.
    unsafe { libc::execvp(spec.program.as_ptr(), argv.as_ptr()) };
    let reason = io::Error::last_os_error().to_string();
    die(spec, &spec.program, &reason);
}

/// Report `what` on fd 2 and errno on the report pipe, then exit the
/// child with code 127.
fn die(spec: &Spec, program: &CString, what: &str) -> ! {
    let errno = io::Error::last_os_error().raw_os_error().unwrap_or(0);
    let line = format!("lingcage-agent: {}: {what}\n", program.to_string_lossy());
    // SAFETY: pointer and length of `line` are valid.
    unsafe { libc::write(2, line.as_ptr().cast::<libc::c_void>(), line.len()) };
    if let Some(report) = spec.report {
        let bytes = errno.to_ne_bytes();
        // SAFETY: pointer of `bytes` is valid and its length is 4.
        unsafe { libc::write(report, bytes.as_ptr().cast::<libc::c_void>(), 4) };
    }
    // SAFETY: _exit terminates current process.
    unsafe { libc::_exit(127) }
}

/// Pipe for a failed exec to report its errno. It is opened with
/// `O_CLOEXEC`, so a successful exec closes it and parent reads EOF.
fn report_pipe() -> io::Result<(File, File)> {
    let mut fds = [-1; 2];
    // SAFETY: `fds` is a valid out-pointer.
    if unsafe { libc::pipe2(fds.as_mut_ptr(), libc::O_CLOEXEC) } == -1 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: both descriptors are newly created and not owned elsewhere.
    Ok(unsafe { (File::from_raw_fd(fds[0]), File::from_raw_fd(fds[1])) })
}

/// Read exec result from the report pipe. EOF means success, four bytes
/// means errno, which is mapped to a reason for the host.
fn reported(read_fd: &File) -> io::Result<Option<ExecFailed>> {
    use std::io::Read as _;
    let mut bytes = [0u8; 4];
    let mut read = 0;
    while read < bytes.len() {
        match (&*read_fd).read(&mut bytes[read..]) {
            Ok(0) => break,
            Ok(n) => read += n,
            Err(err) if err.kind() == io::ErrorKind::Interrupted => {}
            Err(err) => return Err(err),
        }
    }
    if read == 0 {
        return Ok(None);
    }
    let errno = i32::from_ne_bytes(bytes);
    let reason = match errno {
        libc::ENOENT => Failure::NotFound,
        libc::EACCES => Failure::Permission,
        libc::ENOEXEC => Failure::Format,
        _ => Failure::Other,
    };
    Ok(Some(ExecFailed { reason, errno }))
}

/// Reap `pid`, caller has already ended it.
fn reap_now(pid: libc::pid_t) {
    loop {
        let mut status = 0;
        // SAFETY: `status` is a valid out-pointer.
        let got = unsafe { libc::waitpid(pid, &mut status, 0) };
        if got != -1 {
            return;
        }
        if io::Error::last_os_error().kind() != io::ErrorKind::Interrupted {
            return;
        }
    }
}

/// Open a (master, slave) terminal pair with given `size`.
fn openpty(size: PtySize) -> io::Result<(File, File)> {
    let mut master = -1;
    let mut slave = -1;
    // SAFETY: both are valid out-pointers, other arguments accept null.
    let rc = unsafe {
        libc::openpty(
            &mut master,
            &mut slave,
            std::ptr::null_mut(),
            std::ptr::null(),
            std::ptr::null(),
        )
    };
    if rc == -1 {
        return Err(io::Error::last_os_error());
    }
    let winsize = libc::winsize {
        ws_row: size.rows,
        ws_col: size.cols,
        ws_xpixel: 0,
        ws_ypixel: 0,
    };
    // SAFETY: `slave` is an open terminal and `winsize` is a valid struct.
    if unsafe { libc::ioctl(slave, libc::TIOCSWINSZ, &winsize) } == -1 {
        let err = io::Error::last_os_error();
        // SAFETY: both descriptors are owned here, not yet wrapped in File.
        unsafe {
            libc::close(master);
            libc::close(slave);
        }
        return Err(err);
    }
    // SAFETY: both descriptors are open and owned by this function.
    Ok(unsafe { (File::from_raw_fd(master), File::from_raw_fd(slave)) })
}

/// Open /dev/null, used as stdin if none is given and by helper children.
fn open_devnull() -> io::Result<File> {
    OpenOptions::new().read(true).write(true).open("/dev/null")
}

/// Set O_NONBLOCK. The loop polls before touching a pump descriptor.
fn set_nonblocking(file: &File) -> io::Result<()> {
    let fd = file.as_raw_fd();
    // SAFETY: `fd` is open, F_GETFL needs no third argument.
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
    if flags == -1 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: `fd` is open, and the new flags only add O_NONBLOCK.
    if unsafe { libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) } == -1 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// Convert `text` to C string for exec, a NUL inside is a spawn error.
fn cstring(text: &str, what: &str) -> Result<CString, SpawnError> {
    CString::new(text).map_err(|_| SpawnError::Other {
        code: "exec.spawn",
        message: format!("{what} contains NUL byte"),
    })
}

#[cfg(test)]
mod tests {
    use std::collections::{BTreeMap, HashMap};
    use std::fs::File;
    use std::io::{self, Read, Write};
    use std::os::fd::OwnedFd;
    use std::os::unix::net::UnixStream;
    use std::sync::Mutex;
    use std::time::Duration;

    use crate::agent::exec::{SpawnError, report_pipe, reported, start};
    use crate::lcp::{Exec, Failure, Stream};

    /// Create stream pairs for given ports. Agent ends are returned via the
    /// connect closure, host ends are returned in the map.
    fn streams(ports: &[u32]) -> (impl Fn(u32) -> io::Result<File>, HashMap<u32, UnixStream>) {
        let mut agent_ends = HashMap::new();
        let mut host_ends = HashMap::new();
        for port in ports {
            let (host, agent) = UnixStream::pair().expect("socket pair");
            host.set_read_timeout(Some(Duration::from_secs(15)))
                .expect("read deadline");
            agent_ends.insert(*port, File::from(OwnedFd::from(agent)));
            host_ends.insert(*port, host);
        }
        let agent_ends = Mutex::new(agent_ends);
        let connect = move |port: u32| {
            agent_ends
                .lock()
                .expect("ports map")
                .remove(&port)
                .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "unbound port"))
        };
        (connect, host_ends)
    }

    /// Build an `Exec` of `program` on ports 1 and 2 without stdin.
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
            stdout: Stream {
                port: 1,
                nonce: 0x0102_0304_0506_0708,
            },
            stderr: Stream {
                port: 2,
                nonce: 0xffee_ddcc_bbaa_9988,
            },
        }
    }

    /// Reap `pid`, returns its wait status.
    fn reap(pid: libc::pid_t) -> libc::c_int {
        let mut status = 0;
        // SAFETY: `status` is a valid out-pointer.
        assert_eq!(unsafe { libc::waitpid(pid, &mut status, 0) }, pid);
        status
    }

    #[test]
    fn test_nonce_written_before_output() {
        // Nonce of each stream is written before command output.
        let (connect, mut ends) = streams(&[1, 2]);
        let exec = running("/bin/echo", &["hi"]);
        let child = start(3, &exec, &connect).expect("start echo");
        let mut out = Vec::new();
        ends.get_mut(&1)
            .expect("stdout end")
            .read_to_end(&mut out)
            .expect("read stdout to end");
        assert_eq!(&out[..8], &0x0102_0304_0506_0708u64.to_be_bytes());
        assert_eq!(&out[8..], b"hi\n");
        let mut err = Vec::new();
        ends.get_mut(&2)
            .expect("stderr end")
            .read_to_end(&mut err)
            .expect("read stderr to end");
        assert_eq!(err, 0xffee_ddcc_bbaa_9988u64.to_be_bytes());
        assert_eq!(libc::WEXITSTATUS(reap(child.pid)), 0);
    }

    #[test]
    fn test_missing_program_failed_with_errno() {
        let (connect, _ends) = streams(&[1, 2]);
        match start(4, &running("/nonexistent/program", &[]), &connect) {
            Err(SpawnError::Failed(failed)) => {
                assert_eq!(failed.reason, Failure::NotFound);
                assert_eq!(failed.errno, libc::ENOENT);
            }
            Err(other) => panic!("expected Failed error, got {other:?}"),
            Ok(_) => panic!("nonexistent program started"),
        }
    }

    #[test]
    fn test_unbound_stream_is_error() {
        // Unbound stream should be `SpawnError::Other`, not `Failed`.
        let (connect, _ends) = streams(&[1]);
        match start(5, &running("/bin/true", &[]), &connect) {
            Err(SpawnError::Other { code, .. }) => assert_eq!(code, "exec.connect"),
            Err(other) => panic!("expected Other error, got {other:?}"),
            Ok(_) => panic!("command started with unbound stream"),
        }
    }

    #[test]
    fn test_report_pipe_errno_to_reason() {
        for (errno, reason) in [
            (libc::ENOENT, Failure::NotFound),
            (libc::EACCES, Failure::Permission),
            (libc::ENOEXEC, Failure::Format),
            (libc::E2BIG, Failure::Other),
        ] {
            let (read_fd, mut write_fd) = report_pipe().expect("pipe");
            write_fd.write_all(&errno.to_ne_bytes()).expect("report");
            drop(write_fd);
            let failed = reported(&read_fd).expect("read").expect("failure");
            assert_eq!(failed.reason, reason);
            assert_eq!(failed.errno, errno);
        }
        // EOF with no bytes written means a successful exec.
        let (read_fd, write_fd) = report_pipe().expect("pipe");
        drop(write_fd);
        assert!(reported(&read_fd).expect("read").is_none());
    }
}
