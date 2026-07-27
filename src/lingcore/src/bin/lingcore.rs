// SPDX-FileCopyrightText: 2026 LingCage <opensource@lingcage.com>
//
// SPDX-License-Identifier: Apache-2.0

//! `lingcore` binary boots a plain guest from a kernel image, with its
//! serial console attached to the terminal. `lingcore --help` prints the
//! flags.

#[cfg(all(
    target_os = "linux",
    any(
        target_arch = "aarch64",
        target_arch = "x86_64",
        target_arch = "riscv64"
    )
))]
mod imp {
    use std::fs::File;
    use std::io::{self, Read, Write};
    use std::os::fd::AsRawFd;
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicBool, AtomicI32, Ordering};
    use std::time::{Duration, Instant};

    use lingcore::devices::Receive;
    use lingcore::devices::virtio::net::stack::StackConfig;
    use lingcore::hv::backend::kvm::hypervisor::KvmHv;
    use lingcore::hv::vcpu::VmExit;
    use lingcore::logging::{Logger, level_of};
    use lingcore::machine::snapshot::Snapshot;
    use lingcore::machine::{Config, Link, Machine, Network, StopHandle, control};
    use lingcore::seccomp::Refusal;

    /// Byte typed on the terminal to end the guest, `Ctrl-]`.
    const ESCAPE: u8 = 0x1d;

    /// Exit code for a usage error.
    const EXIT_USAGE: i32 = 1;
    /// Exit code for a failure on host side.
    const EXIT_FAILURE: i32 = 2;
    /// Exit code for a reboot asked by guest, which is not served.
    const EXIT_REBOOT: i32 = 3;
    /// Exit code if `--timeout` elapsed before guest powered off, same as
    /// `timeout(1)`.
    const EXIT_TIMEOUT: i32 = 124;

    /// Time the guest is waited on between two rounds of orders.
    const SLICE: Duration = Duration::from_millis(50);

    /// Time to wait before retrying if console input queue is full.
    const INPUT_RETRY: Duration = Duration::from_millis(5);

    /// Errors thrown by the command line.
    #[derive(Debug, thiserror::Error)]
    enum CliError {
        /// Failed to parse command line, with the usage text attached.
        #[error("{what}")]
        Usage {
            /// Message describing the parse failure.
            what: String,
            /// Usage text, the synopsis generated from the flag table.
            usage: String,
        },
        /// Error from the machine layer of lingcore.
        #[error(transparent)]
        Machine(#[from] lingcore::machine::Error),
        /// Failed to perform host IO operation.
        #[error(transparent)]
        Io(#[from] io::Error),
    }

    impl CliError {
        /// Returns exit code of the error, 1 for usage error and 2 for the
        /// rest.
        fn code(&self) -> i32 {
            match self {
                CliError::Usage { .. } => EXIT_USAGE,
                _ => EXIT_FAILURE,
            }
        }
    }

    /// Result alias used by the command line.
    type Result<T> = std::result::Result<T, CliError>;

    /// A flag of the command line, with its name, value placeholder and
    /// help text.
    struct Flag {
        /// Flag name without leading dashes.
        name: &'static str,
        /// Placeholder of the value shown in help, e.g. `K`.
        value: &'static str,
        /// Set to true if the flag is required.
        required: bool,
        /// Help text of the flag, one line.
        help: &'static str,
    }

    /// One-line description of the binary, shown in help.
    const ABOUT: &str = "boot a guest and attach its serial console to the terminal";

    /// Table of flags, parsing and help are generated from it.
    const FLAGS: &[Flag] = &[
        Flag {
            name: "kernel",
            value: "K",
            required: true,
            help: "kernel image path, bzImage on x86_64 or Image on aarch64 and riscv64",
        },
        Flag {
            name: "initrd",
            value: "I",
            required: false,
            help: "initramfs path, cpio archive",
        },
        Flag {
            name: "cmdline",
            value: "C",
            required: false,
            help: "kernel command line (default console=ttyS0)",
        },
        Flag {
            name: "memory",
            value: "SIZE",
            required: false,
            help: "guest RAM in MiB or with K/M/G suffix (default 512M)",
        },
        Flag {
            name: "vcpus",
            value: "N",
            required: false,
            help: "number of vCPUs (default 1)",
        },
        Flag {
            name: "disk",
            value: "FILE",
            required: false,
            help: "file attached as a virtio-blk disk, /dev/vda in the guest, given once per disk",
        },
        Flag {
            name: "network",
            value: "LINK",
            required: false,
            help: "guest network, user for the stack in this process, unix:PATH for a host socket \
                   carrying Ethernet frames, or tap:NAME for a tap of the host",
        },
        Flag {
            name: "mac",
            value: "ADDR",
            required: false,
            help: "MAC address of the virtio-net device, aa:bb:cc:dd:ee:ff",
        },
        Flag {
            name: "pcap",
            value: "FILE",
            required: false,
            help: "write frames of the network link to FILE in pcap format, needs --network",
        },
        Flag {
            name: "control",
            value: "PATH",
            required: false,
            help: "take orders on the Unix socket at PATH while the guest runs, one JSON object \
                   per line",
        },
        Flag {
            name: "restore",
            value: "DIR",
            required: false,
            help: "lay a guest written by a snapshot order over this one before starting it",
        },
        Flag {
            name: "seccomp",
            value: "MODE",
            required: false,
            help: "syscall allowlist of guest threads, trap, errno or none (default trap)",
        },
        Flag {
            name: "timeout",
            value: "SECS",
            required: false,
            help: "stop the guest after SECS seconds and exit with 124",
        },
        Flag {
            name: "log-file",
            value: "FILE",
            required: false,
            help: "write log lines to FILE instead of stderr",
        },
        Flag {
            name: "verbose",
            value: "",
            required: false,
            help: "log more, -v for info, -vv for debug, -vvv for trace",
        },
    ];

    /// Flags parsed from the command line.
    #[derive(Debug, Default)]
    struct Parsed {
        /// Flag values by name, last one is used if a flag repeats.
        values: Vec<(&'static str, String)>,
        /// Times `-v` or `--verbose` was given.
        verbose: u8,
    }

    impl Parsed {
        /// Returns the last value given for flag `name`.
        fn value(&self, name: &str) -> Option<&str> {
            self.values
                .iter()
                .rev()
                .find(|(flag, _)| *flag == name)
                .map(|(_, value)| value.as_str())
        }

        /// Returns the values given for flag `name`, in the order given.
        fn each(&self, name: &str) -> Vec<&str> {
            self.values
                .iter()
                .filter(|(flag, _)| *flag == name)
                .map(|(_, value)| value.as_str())
                .collect()
        }
    }

    /// Build a usage error with the synopsis attached.
    fn usage_err(what: String) -> CliError {
        CliError::Usage {
            what,
            usage: format!("usage: {}\n", synopsis()),
        }
    }

    /// Returns one-line usage generated from the flag table.
    fn synopsis() -> String {
        let mut out = String::from("lingcore");
        for flag in FLAGS {
            if flag.required {
                out.push_str(&format!(" --{} {}", flag.name, flag.value));
            } else if flag.value.is_empty() {
                out.push_str(&format!(" [--{}]", flag.name));
            } else {
                out.push_str(&format!(" [--{} {}]", flag.name, flag.value));
            }
        }
        out
    }

    /// Returns help text generated from the flag table.
    fn cli_help() -> String {
        let mut out = format!("usage: {}\n\n{ABOUT}\n\nflags:\n", synopsis());
        for flag in FLAGS {
            let name = format!("--{} {}", flag.name, flag.value);
            out.push_str(&format!("  {name:<18} {}\n", flag.help));
        }
        out.push_str(
            "\nlingcore --version prints the version.\n\nexit codes:\n  0    guest powered off, \
             or was ended from the terminal with Ctrl-]\n  1    usage error\n  2    failure on \
             host side\n  3    guest asked for a reboot\n  124  --timeout elapsed\n  128+N ended \
             by signal N\n",
        );
        out
    }

    /// Parse `args` against the flag table.
    fn parse(args: &[String]) -> Result<Parsed> {
        let mut parsed = Parsed::default();
        let mut at = 0;
        while at < args.len() {
            let arg = &args[at];
            at += 1;
            // `-v` counts once, `-vv` twice, same as `--verbose` repeated.
            if let Some(more) = arg.strip_prefix("-v")
                && more.chars().all(|c| c == 'v')
            {
                parsed.verbose = parsed.verbose.saturating_add(1 + more.len() as u8);
                continue;
            }
            let Some(name) = arg.strip_prefix("--") else {
                return Err(usage_err(format!("unexpected argument {arg}")));
            };
            let (name, inline) = match name.split_once('=') {
                Some((name, value)) => (name, Some(value)),
                None => (name, None),
            };
            let Some(flag) = FLAGS.iter().find(|flag| flag.name == name) else {
                return Err(usage_err(format!("unknown flag --{name}")));
            };
            if flag.value.is_empty() {
                if inline.is_some() {
                    return Err(usage_err(format!("flag --{name} takes no value")));
                }
                parsed.verbose = parsed.verbose.saturating_add(1);
                continue;
            }
            let value = match inline {
                Some(value) => value.to_string(),
                None => {
                    let Some(value) = args.get(at) else {
                        return Err(usage_err(format!("flag --{name} needs a value")));
                    };
                    at += 1;
                    value.clone()
                }
            };
            parsed.values.push((flag.name, value));
        }
        for flag in FLAGS {
            if flag.required && parsed.value(flag.name).is_none() {
                return Err(usage_err(format!("flag --{} is required", flag.name)));
            }
        }
        Ok(parsed)
    }

    /// Parse the command line and boot, unless help or version is asked.
    fn cli(args: &[String]) -> Result<i32> {
        if args.is_empty() || args.iter().any(|arg| arg == "--help" || arg == "-h") {
            print!("{}", cli_help());
            return Ok(0);
        }
        if args.iter().any(|arg| arg == "--version" || arg == "-V") {
            println!("lingcore {}", lingcore::VERSION);
            return Ok(0);
        }
        let parsed = parse(args)?;
        boot(&parsed)
    }

    /// Parse, boot and report errors, returns the process exit code.
    pub(crate) fn run(args: &[String]) -> i32 {
        match cli(args) {
            Ok(code) => code,
            Err(error) => {
                report(&error);
                error.code()
            }
        }
    }

    /// Print the error and its chain of causes. Usage error is followed by
    /// the usage text.
    fn report(error: &CliError) {
        eprintln!("lingcore: {error}");
        if let CliError::Usage { usage, .. } = error {
            eprint!("{usage}");
            return;
        }
        let mut cause = std::error::Error::source(error);
        while let Some(source) = cause {
            eprintln!("  caused by: {source}");
            cause = source.source();
        }
    }

    /// Parse `text` as digits with an optional scaling suffix.
    fn parse_scaled(text: &str, suffixes: &[(char, u64)], bare: u64) -> Option<u64> {
        let (digits, scale) = match text.chars().last() {
            Some(last) if last.is_ascii_alphabetic() => {
                let scale = suffixes
                    .iter()
                    .find(|(suffix, _)| *suffix == last.to_ascii_lowercase())
                    .map(|(_, scale)| *scale)?;
                (&text[..text.len() - 1], scale)
            }
            _ => (text, bare),
        };
        let count: u64 = digits.parse().ok()?;
        count.checked_mul(scale)
    }

    /// Parse guest RAM size, bare number is MiB and K/M/G are suffixes.
    fn parse_memory(text: &str) -> std::result::Result<u64, String> {
        match parse_scaled(
            text,
            &[('k', 1 << 10), ('m', 1 << 20), ('g', 1 << 30)],
            1 << 20,
        ) {
            Some(bytes) if bytes > 0 => Ok(bytes),
            _ => Err(format!(
                "invalid memory size {text}, use MiB or a K/M/G suffix"
            )),
        }
    }

    /// Parse a MAC address written as six hex bytes with colons.
    fn parse_mac(text: &str) -> std::result::Result<[u8; 6], String> {
        let mut mac = [0u8; 6];
        let parts: Vec<&str> = text.split(':').collect();
        if parts.len() != 6 {
            return Err(format!("invalid MAC address {text}, use aa:bb:cc:dd:ee:ff"));
        }
        for (slot, part) in mac.iter_mut().zip(parts) {
            *slot = u8::from_str_radix(part, 16)
                .map_err(|_| format!("invalid MAC address {text}, use aa:bb:cc:dd:ee:ff"))?;
        }
        Ok(mac)
    }

    /// Parse `--network`, `user` for the stack in this process,
    /// `unix:PATH` for a host socket and `tap:NAME` for a tap of the host.
    fn parse_link(text: &str) -> std::result::Result<Link, String> {
        if text == "user" {
            return Ok(Link::User(StackConfig::default()));
        }
        if let Some(name) = text.strip_prefix("tap:")
            && !name.is_empty()
        {
            return Ok(Link::Tap(name.to_string()));
        }
        match text.strip_prefix("unix:") {
            Some(path) if !path.is_empty() => Ok(Link::Socket(PathBuf::from(path))),
            _ => Err(format!(
                "invalid network {text}, use user, unix:PATH or tap:NAME"
            )),
        }
    }

    /// Parse `--seccomp` mode, `None` means no allowlist.
    fn parse_seccomp(text: &str) -> std::result::Result<Option<Refusal>, String> {
        match text {
            "trap" => Ok(Some(Refusal::Trap)),
            "errno" => Ok(Some(Refusal::Errno)),
            "none" => Ok(None),
            other => Err(format!(
                "unknown seccomp mode {other}, use trap, errno or none"
            )),
        }
    }

    /// Build guest `Config` from the parsed flags.
    fn config_of(parsed: &Parsed) -> Result<Config> {
        let mut config = Config {
            kernel: PathBuf::from(parsed.value("kernel").expect("required flag")),
            initrd: parsed.value("initrd").map(PathBuf::from),
            cmdline: parsed
                .value("cmdline")
                .unwrap_or("console=ttyS0")
                .to_string(),
            memory: 512 << 20,
            disks: parsed.each("disk").into_iter().map(PathBuf::from).collect(),
            confine: Some(Refusal::Trap),
            ..Default::default()
        };
        if let Some(memory) = parsed.value("memory") {
            config.memory = parse_memory(memory).map_err(usage_err)?;
        }
        if let Some(vcpus) = parsed.value("vcpus") {
            config.vcpus = match vcpus.parse::<u16>() {
                Ok(count) if count > 0 => count,
                _ => return Err(usage_err(format!("invalid vCPU count {vcpus}"))),
            };
        }
        if let Some(link) = parsed.value("network") {
            let mac = parsed
                .value("mac")
                .map(parse_mac)
                .transpose()
                .map_err(usage_err)?;
            let link = parse_link(link).map_err(usage_err)?;
            config.network = Some(Network {
                link,
                mac,
                pcap: parsed.value("pcap").map(PathBuf::from),
            });
        } else if parsed.value("mac").is_some() || parsed.value("pcap").is_some() {
            return Err(usage_err("--mac and --pcap need --network".to_string()));
        }
        if let Some(mode) = parsed.value("seccomp") {
            config.confine = parse_seccomp(mode).map_err(usage_err)?;
        }
        Ok(config)
    }

    /// Parse `--timeout`, `None` if not given.
    fn timeout_of(parsed: &Parsed) -> Result<Option<Duration>> {
        match parsed.value("timeout") {
            None => Ok(None),
            Some(text) => match text.parse::<u64>() {
                Ok(secs) => Ok(Some(Duration::from_secs(secs))),
                Err(_) => Err(usage_err(format!(
                    "invalid timeout {text}, use bare seconds"
                ))),
            },
        }
    }

    /// Install the logger, writing to `--log-file` or stderr at level `-v`
    /// asks for. File is opened here, before any allowlist goes on.
    fn log_to(parsed: &Parsed) -> Result<()> {
        let file = parsed.value("log-file").map(File::create).transpose()?;
        Logger::new("lingcore", level_of(parsed.verbose), file)
            .install()
            .map_err(|err| io::Error::other(err.to_string()))?;
        Ok(())
    }

    /// Console sink writing guest output to stdout right away. Stdout is line
    /// buffered by default, which would hold back a prompt without newline.
    struct Sink;

    impl Write for Sink {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            let mut out = io::stdout().lock();
            out.write_all(buf)?;
            out.flush()?;
            Ok(buf.len())
        }

        fn flush(&mut self) -> io::Result<()> {
            io::stdout().flush()
        }
    }

    /// Terminal settings of stdin saved before raw mode, restored on drop.
    /// Holds `None` if stdin is not a terminal.
    struct Terminal(Option<libc::termios>);

    impl Terminal {
        /// Put stdin into raw mode if it is a terminal, so that each key
        /// reaches the guest as typed and `Ctrl-C` is not a signal here.
        fn raw() -> io::Result<Terminal> {
            let fd = io::stdin().as_raw_fd();
            // SAFETY: `isatty` takes a descriptor and touches no memory.
            if unsafe { libc::isatty(fd) } == 0 {
                return Ok(Terminal(None));
            }
            // SAFETY: a zeroed termios is filled by `tcgetattr` before use.
            let mut saved: libc::termios = unsafe { std::mem::zeroed() };
            // SAFETY: `saved` is a valid termios to fill.
            if unsafe { libc::tcgetattr(fd, &mut saved) } == -1 {
                return Err(io::Error::last_os_error());
            }
            let mut raw = saved;
            // SAFETY: `raw` is a valid termios copied from the terminal.
            unsafe { libc::cfmakeraw(&mut raw) };
            // SAFETY: `raw` is a valid termios.
            if unsafe { libc::tcsetattr(fd, libc::TCSANOW, &raw) } == -1 {
                return Err(io::Error::last_os_error());
            }
            Ok(Terminal(Some(saved)))
        }

        /// Returns true if stdin is a terminal in raw mode.
        fn is_tty(&self) -> bool {
            self.0.is_some()
        }
    }

    impl Drop for Terminal {
        fn drop(&mut self) {
            if let Some(saved) = self.0.take() {
                // SAFETY: `saved` is the termios read from this terminal.
                unsafe { libc::tcsetattr(io::stdin().as_raw_fd(), libc::TCSANOW, &saved) };
            }
        }
    }

    /// Set to true once `Ctrl-]` ended the guest from the terminal.
    static ESCAPED: AtomicBool = AtomicBool::new(false);

    /// Forward stdin to the guest console on a separate thread. On a
    /// terminal `Ctrl-]` stops the guest, otherwise bytes are forwarded until
    /// EOF and the guest keeps running.
    fn forward_input(console: std::sync::Arc<dyn Receive>, stop: StopHandle, tty: bool) {
        std::thread::spawn(move || {
            let mut stdin = io::stdin().lock();
            let mut buf = [0u8; 256];
            loop {
                let count = match stdin.read(&mut buf) {
                    Ok(0) | Err(_) => return,
                    Ok(count) => count,
                };
                let bytes = &buf[..count];
                let bytes = match (tty, bytes.iter().position(|byte| *byte == ESCAPE)) {
                    (true, Some(at)) => {
                        queue(&*console, &bytes[..at]);
                        ESCAPED.store(true, Ordering::SeqCst);
                        if let Err(err) = stop.stop() {
                            eprintln!("lingcore: failed to stop the guest: {err}");
                        }
                        return;
                    }
                    _ => bytes,
                };
                queue(&*console, bytes);
            }
        });
    }

    /// Queue `bytes` on the console, waiting for room if the guest has not
    /// read the earlier ones yet.
    fn queue(console: &dyn Receive, mut bytes: &[u8]) {
        while !bytes.is_empty() {
            match console.receive(bytes) {
                Ok(0) => std::thread::sleep(INPUT_RETRY),
                Ok(taken) => bytes = &bytes[taken..],
                Err(_) => return,
            }
        }
    }

    /// Write end of the pipe for signal handler to report signals, -1 until
    /// armed.
    static SIGNAL_PIPE: AtomicI32 = AtomicI32::new(-1);

    /// Signal which stopped the guest, 0 if no signal is received yet.
    static SIGNALLED: AtomicI32 = AtomicI32::new(0);

    /// Set up handlers for SIGTERM, SIGINT and SIGHUP. Handler writes the
    /// signal number to a pipe, and a thread reading the pipe stops the
    /// guest through `stop`.
    fn arm_signals(stop: StopHandle) -> Result<()> {
        let mut fds = [0; 2];
        // SAFETY: `fds` is a valid array of two file descriptors.
        if unsafe { libc::pipe2(fds.as_mut_ptr(), libc::O_CLOEXEC) } == -1 {
            return Err(io::Error::last_os_error().into());
        }
        let (reader, writer) = (fds[0], fds[1]);
        SIGNAL_PIPE.store(writer, Ordering::SeqCst);
        for signal in [libc::SIGTERM, libc::SIGINT, libc::SIGHUP] {
            // SAFETY: a zeroed sigaction is a valid empty sigaction.
            let mut action: libc::sigaction = unsafe { std::mem::zeroed() };
            action.sa_sigaction = on_signal as *const () as libc::sighandler_t;
            // SAFETY: `action` is properly initialized with a valid handler.
            if unsafe { libc::sigaction(signal, &action, std::ptr::null_mut()) } == -1 {
                return Err(io::Error::last_os_error().into());
            }
        }
        std::thread::spawn(move || {
            let mut byte = [0u8; 1];
            loop {
                // SAFETY: `byte` is a valid one-byte buffer.
                let read = unsafe { libc::read(reader, byte.as_mut_ptr().cast(), 1) };
                if read == 1 {
                    break;
                }
                // Read is interrupted if a handler runs on this thread. Other
                // results mean the pipe is gone, exit the thread accordingly.
                if read == 0 || io::Error::last_os_error().kind() != io::ErrorKind::Interrupted {
                    return;
                }
            }
            SIGNALLED.store(i32::from(byte[0]), Ordering::SeqCst);
            if let Err(err) = stop.stop() {
                eprintln!(
                    "lingcore: failed to stop the guest on signal {}: {err}",
                    byte[0]
                );
            }
        });
        Ok(())
    }

    /// Returns exit code for the signal which stopped the guest, if any. The
    /// code is 128 plus signal number, same as shell does.
    fn signalled() -> Option<i32> {
        match SIGNALLED.load(Ordering::SeqCst) {
            0 => None,
            signal => Some(128 + signal),
        }
    }

    extern "C" fn on_signal(signal: libc::c_int) {
        let fd = SIGNAL_PIPE.load(Ordering::SeqCst);
        if fd < 0 {
            return;
        }
        let byte = [signal as u8];
        // SAFETY: `byte` is a valid one-byte buffer and `write` is
        // async-signal-safe.
        unsafe { libc::write(fd, byte.as_ptr().cast(), 1) };
    }

    /// Disable heap trimming of glibc. Trim path opens a `/proc` file, a
    /// syscall outside allowlist of the guest threads, and freeing buffers
    /// of a connection is enough to trigger it.
    #[cfg(target_env = "gnu")]
    fn keep_heap() {
        // SAFETY: `mallopt` takes no pointer.
        unsafe { libc::mallopt(libc::M_TRIM_THRESHOLD, -1) };
    }

    #[cfg(not(target_env = "gnu"))]
    fn keep_heap() {}

    /// Boot the guest and attach its console, returns the exit code.
    fn boot(parsed: &Parsed) -> Result<i32> {
        let config = config_of(parsed)?;
        let timeout = timeout_of(parsed)?;
        log_to(parsed)?;
        keep_heap();
        let control = parsed.value("control").map(PathBuf::from);
        let restore = parsed.value("restore").map(PathBuf::from);
        let hv = KvmHv::new().map_err(lingcore::machine::Error::from)?;
        let mut machine = match &restore {
            // A guest laid over a captured one shares pages of the image
            // until it writes to them.
            Some(from) => {
                let image = File::open(from.join(control::MEMORY))
                    .map_err(|_| lingcore::machine::Error::Snapshot)?;
                let mut machine = Machine::cloned(&hv, &config, Sink, &image)?;
                let mut document = File::open(from.join(control::DOCUMENT))
                    .map_err(|_| lingcore::machine::Error::Snapshot)?;
                let taken = Snapshot::read_from(&mut document)?;
                machine.restore(&taken)?;
                machine
            }
            None => Machine::new(&hv, &config, Sink)?,
        };
        let orders = match &control {
            Some(at) => Some(control::listen(at).map_err(lingcore::machine::Error::Network)?),
            None => None,
        };

        let stop = machine.stop_handle();
        arm_signals(stop.clone())?;
        let terminal = Terminal::raw()?;
        machine.start()?;
        forward_input(machine.console(), stop.clone(), terminal.is_tty());
        if let Some(orders) = &orders {
            // Orders are served between two waits on the guest, so the one
            // thread which holds the guest is the one which changes it.
            let exit = drive(&mut machine, orders, timeout)?;
            drop(terminal);
            if let Some(code) = signalled() {
                return Ok(code);
            }
            return Ok(exit_code(exit));
        }
        let exit = match timeout {
            Some(within) => match machine.wait_timeout(within)? {
                Some(exit) => exit,
                None => {
                    stop.stop()?;
                    machine.wait()?;
                    drop(terminal);
                    eprintln!("lingcore: guest stopped after {} seconds", within.as_secs());
                    return Ok(EXIT_TIMEOUT);
                }
            },
            None => machine.wait()?,
        };
        drop(terminal);
        if let Some(code) = signalled() {
            return Ok(code);
        }
        if ESCAPED.load(Ordering::SeqCst) {
            return Ok(0);
        }
        Ok(exit_code(exit))
    }

    /// Returns the status a guest which stopped on `exit` leaves behind.
    fn exit_code(exit: VmExit) -> i32 {
        match exit {
            VmExit::Shutdown => 0,
            VmExit::Reboot => {
                eprintln!("lingcore: guest asked for a reboot");
                EXIT_REBOOT
            }
            other => {
                eprintln!("lingcore: guest stopped on {other:?}");
                EXIT_FAILURE
            }
        }
    }

    /// Run the guest until it stops, serving orders in between. A guest
    /// held still still answers, since the wait is a short one.
    fn drive(
        machine: &mut Machine<KvmHv>,
        orders: &control::Orders,
        timeout: Option<Duration>,
    ) -> Result<VmExit> {
        let deadline = timeout.map(|within| Instant::now() + within);
        loop {
            while let Some(order) = orders.next() {
                order.serve(machine);
            }
            if let Some(exit) = machine.wait_timeout(SLICE)? {
                return Ok(exit);
            }
            if deadline.is_some_and(|deadline| Instant::now() >= deadline) {
                machine.stop()?;
                return Ok(machine.wait()?);
            }
        }
    }

    #[cfg(test)]
    mod tests {
        use crate::imp::*;

        #[test]
        fn test_help_lists_flags_and_exit_codes() {
            let help = cli_help();
            assert!(help.contains("--kernel K"), "help: {help}");
            assert!(help.contains("[--verbose]"), "help: {help}");
            assert!(help.contains("124"), "help: {help}");
        }

        #[test]
        fn test_parse_flags() {
            let args: Vec<String> = ["--kernel", "bzImage", "--vcpus=2", "--memory", "1G"]
                .iter()
                .map(|s| s.to_string())
                .collect();
            let parsed = parse(&args).unwrap();
            assert_eq!(parsed.value("kernel"), Some("bzImage"));
            assert_eq!(parsed.value("vcpus"), Some("2"));
            let config = config_of(&parsed).unwrap();
            assert_eq!(config.vcpus, 2);
            assert_eq!(config.memory, 1 << 30);
            assert_eq!(config.cmdline, "console=ttyS0");
            assert_eq!(config.confine, Some(Refusal::Trap));
        }

        #[test]
        fn test_reject_bad_flags() {
            for args in [
                vec![],
                vec!["--kernel"],
                vec!["--kernel", "k", "--vcpus", "0"],
                vec!["--kernel", "k", "--memory", "0"],
                vec!["--kernel", "k", "--seccomp", "maybe"],
                vec!["--kernel", "k", "--mac", "aa:bb:cc:dd:ee:ff"],
                vec!["--kernel", "k", "--network", "tap0"],
                vec!["--kernel", "k", "--network", "unix:"],
                vec!["--kernel", "k", "--pcap", "link.pcap"],
                vec!["--kernel", "k", "--timeout", "soon"],
                vec!["--kernel", "k", "--verbose=2"],
                vec!["--kernel", "k", "-vx"],
                vec!["--kernel", "k", "extra"],
                vec!["--kernel", "k", "--flag"],
            ] {
                let args: Vec<String> = args.iter().map(|s| s.to_string()).collect();
                let outcome = parse(&args).and_then(|parsed| {
                    config_of(&parsed)?;
                    timeout_of(&parsed)
                });
                assert!(
                    matches!(outcome, Err(CliError::Usage { .. })),
                    "accepted {args:?}: {outcome:?}"
                );
            }
        }

        #[test]
        fn test_parse_verbose_counts() {
            for (args, count) in [
                (vec!["--kernel", "k"], 0),
                (vec!["--kernel", "k", "-v"], 1),
                (vec!["-vv", "--kernel", "k"], 2),
                (vec!["--kernel", "k", "--verbose", "-v", "--verbose"], 3),
            ] {
                let args: Vec<String> = args.iter().map(|s| s.to_string()).collect();
                assert_eq!(parse(&args).unwrap().verbose, count, "args {args:?}");
            }
        }

        #[test]
        fn test_parse_memory() {
            assert_eq!(parse_memory("256"), Ok(256 << 20));
            assert_eq!(parse_memory("64k"), Ok(64 << 10));
            assert_eq!(parse_memory("2G"), Ok(2 << 30));
            assert!(parse_memory("lots").is_err());
        }

        #[test]
        fn test_parse_link() {
            assert!(matches!(parse_link("user"), Ok(Link::User(_))));
            assert!(matches!(
                parse_link("unix:/tmp/net.sock"),
                Ok(Link::Socket(_))
            ));
            assert!(parse_link("/tmp/net.sock").is_err());
            assert!(parse_link("tcp:1").is_err());
        }

        #[test]
        fn test_parse_pcap_with_network() {
            let args: Vec<String> = ["--kernel", "k", "--network", "user", "--pcap", "link.pcap"]
                .iter()
                .map(|s| s.to_string())
                .collect();
            let config = config_of(&parse(&args).unwrap()).unwrap();
            let network = config.network.expect("network link");
            assert_eq!(
                network.pcap.as_deref(),
                Some(std::path::Path::new("link.pcap"))
            );
        }

        #[test]
        fn test_parse_mac() {
            assert_eq!(parse_mac("02:00:00:00:00:01"), Ok([2, 0, 0, 0, 0, 1]));
            assert!(parse_mac("02:00:00:00:00").is_err());
            assert!(parse_mac("zz:00:00:00:00:01").is_err());
        }

        #[test]
        fn test_exit_code_of_errors() {
            assert_eq!(usage_err(String::new()).code(), EXIT_USAGE);
            assert_eq!(CliError::Io(io::Error::other("host")).code(), EXIT_FAILURE);
        }
    }
}

#[cfg(all(
    target_os = "linux",
    any(
        target_arch = "aarch64",
        target_arch = "x86_64",
        target_arch = "riscv64"
    )
))]
fn main() {
    use std::io::Write as _;
    let args: Vec<String> = std::env::args().skip(1).collect();
    let code = imp::run(&args);
    // `process::exit` skips the stdout flush done on return from main, flush
    // it here.
    if let Err(err) = std::io::stdout().flush() {
        eprintln!("lingcore: failed to write to stdout: {err}");
        std::process::exit(2);
    }
    std::process::exit(code);
}

// `machine` layer only supports Linux on aarch64, x86_64 and riscv64 for
// now.
#[cfg(not(all(
    target_os = "linux",
    any(
        target_arch = "aarch64",
        target_arch = "x86_64",
        target_arch = "riscv64"
    )
)))]
fn main() {}
