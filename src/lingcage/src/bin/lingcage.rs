// SPDX-FileCopyrightText: 2026 LingCage <opensource@lingcage.com>
//
// SPDX-License-Identifier: Apache-2.0

//! `lingcage` is the operator front end of LingCage. Each verb
//! corresponds to library calls made by an embedder.
//! `lingcage <verb> --help` prints flags of a specific verb.

#[cfg(all(
    target_os = "linux",
    any(target_arch = "x86_64", target_arch = "riscv64")
))]
mod imp {
    use std::path::{Path, PathBuf};
    use std::time::{Duration, SystemTime};

    use lingcage::template::{
        DeviceSet, Digest, TemplateId, TemplateMeta, TemplatePlan, TemplateStore,
    };

    /// Store root used when neither `--store` nor `LINGCAGE_STORE` is set.
    const DEFAULT_STORE: &str = "/var/lib/lingcage";

    /// Maximum size of socket address path in bytes, NUL included.
    const SUN_PATH: usize = 108;

    /// Errors thrown by the command line.
    #[derive(Debug, thiserror::Error)]
    enum CliError {
        /// Failed to parse command line, with the usage text attached.
        #[error("{what}")]
        Usage {
            /// Message describing the parse failure.
            what: String,
            /// Usage text of the verb, or of CLI when no verb is matched.
            usage: String,
        },
        /// Failed to open the store root, it can not be created or written.
        #[error("failed to open store at {root}")]
        Store {
            /// Store root being opened.
            root: String,
            /// Error returned by `TemplateStore::open`.
            #[source]
            source: lingcage::Error,
        },
        /// Error from lingcage library.
        #[error(transparent)]
        Engine(#[from] lingcage::Error),
        /// Failed to perform host IO operation.
        #[error(transparent)]
        Io(#[from] std::io::Error),
        /// Failed to encode listing as JSON.
        #[error(transparent)]
        Json(#[from] serde_json::Error),
        /// Host check failed, the message is the failing line.
        #[error("{0}")]
        Check(String),
    }

    impl CliError {
        /// Returns exit code of the error: 1 for usage error, 2 for other
        /// failures.
        fn code(&self) -> i32 {
            match self {
                CliError::Usage { .. } => 1,
                _ => 2,
            }
        }
    }

    /// Result alias used by the command line.
    type Result<T> = std::result::Result<T, CliError>;

    /// A flag of a verb, with its name, value placeholder and help text.
    struct Flag {
        /// Flag name without leading dashes.
        name: &'static str,
        /// Placeholder of the value shown in help, e.g. `K`.
        value: &'static str,
        /// Set to true if the flag is required by the verb.
        required: bool,
        /// Help text of the flag, one line.
        help: &'static str,
    }

    /// A verb of the CLI, with its words, flags and run function.
    struct Verb {
        /// Words of the verb as typed on command line, e.g. `template build`.
        words: &'static str,
        /// Synopsis of positional arguments, empty if the verb has none.
        args: &'static str,
        /// One-line description of the verb, shown in help.
        about: &'static str,
        /// Flags supported by the verb.
        flags: &'static [Flag],
        /// Runs the verb with parsed command line and returns exit code.
        run: fn(&Verb, &Parsed) -> Result<i32>,
    }

    /// `--store` flag, shared by verbs which access the store.
    const STORE: Flag = Flag {
        name: "store",
        value: "DIR",
        required: false,
        help: "store root, defaults to LINGCAGE_STORE, then /var/lib/lingcage",
    };

    /// `--format` flag of the listing verbs.
    const FORMAT: Flag = Flag {
        name: "format",
        value: "json",
        required: false,
        help: "output as JSON",
    };

    /// Table of CLI verbs, dispatch and help are generated from it.
    const VERBS: &[Verb] = &[
        Verb {
            words: "template build",
            args: "",
            about: "boot a guest from the plan, capture and register it as template",
            flags: &[
                Flag {
                    name: "kernel",
                    value: "K",
                    required: true,
                    help: "kernel image path, bzImage on x86_64",
                },
                Flag {
                    name: "initrd",
                    value: "I",
                    required: false,
                    help: "initramfs path, cpio archive",
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
                    help: "number of vCPUs (default 2)",
                },
                Flag {
                    name: "name",
                    value: "NAME",
                    required: false,
                    help: "alias to register template under",
                },
                Flag {
                    name: "ready-timeout",
                    value: "DUR",
                    required: false,
                    help: "readiness deadline of the build boot; bare seconds or an s/m/h suffix \
                           (default 60s)",
                },
                STORE,
                FORMAT,
            ],
            run: template_build,
        },
        Verb {
            words: "template list",
            args: "",
            about: "list registered templates",
            flags: &[STORE, FORMAT],
            run: template_list,
        },
        Verb {
            words: "template inspect",
            args: "ID",
            about: "print registered metadata of a template",
            flags: &[STORE, FORMAT],
            run: template_inspect,
        },
        Verb {
            words: "template verify",
            args: "ID",
            about: "re-run registration checks on a template",
            flags: &[STORE],
            run: template_verify,
        },
        Verb {
            words: "template rm",
            args: "ID",
            about: "remove template from the store",
            flags: &[STORE],
            run: template_rm,
        },
        Verb {
            words: "check",
            args: "",
            about: "check host prerequisites, one per line",
            flags: &[
                Flag {
                    name: "kernel",
                    value: "K",
                    required: false,
                    help: "kernel image path to check for readability",
                },
                STORE,
            ],
            run: check_verb,
        },
    ];

    /// Flags and positional arguments parsed for a verb.
    #[derive(Debug, Default)]
    struct Parsed {
        /// Flag values by name, the last one is used when a flag repeats.
        values: Vec<(&'static str, String)>,
        /// Positional arguments, including everything after `--`.
        positional: Vec<String>,
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
    }

    /// Build a usage error for `verb` with its synopsis attached.
    fn usage_err(verb: &Verb, what: String) -> CliError {
        CliError::Usage {
            what,
            usage: format!("usage: {}\n", synopsis(verb)),
        }
    }

    /// Returns one-line usage of a verb generated from its flags.
    fn synopsis(verb: &Verb) -> String {
        let mut out = format!("lingcage {}", verb.words);
        for flag in verb.flags {
            if flag.required {
                out.push_str(&format!(" --{} {}", flag.name, flag.value));
            } else {
                out.push_str(&format!(" [--{} {}]", flag.name, flag.value));
            }
        }
        if !verb.args.is_empty() {
            out.push(' ');
            out.push_str(verb.args);
        }
        out
    }

    /// Returns help text of the CLI generated from the verb table.
    fn cli_help() -> String {
        let mut out = String::from("lingcage - the operator front end of LingCage\n\nusage:\n");
        for verb in VERBS {
            out.push_str(&format!("  {}\n", synopsis(verb)));
        }
        out.push_str("\n`lingcage <verb> --help` prints flags of a specific verb.\n");
        out.push_str(
            "\nexit codes:\n  0    success\n  1    usage\n  2    an operational failure\n",
        );
        out
    }

    /// Returns help text of a verb, including description, usage and flags.
    fn verb_help(verb: &Verb) -> String {
        let mut out = format!(
            "lingcage {} - {}\n\nusage:\n  {}\n",
            verb.words,
            verb.about,
            synopsis(verb)
        );
        if verb.flags.is_empty() {
            return out;
        }
        let labels: Vec<String> = verb
            .flags
            .iter()
            .map(|flag| format!("--{} {}", flag.name, flag.value))
            .chain(std::iter::once("--help".to_string()))
            .collect();
        let width = labels.iter().map(String::len).max().unwrap_or(0);
        out.push_str("\nflags:\n");
        for (flag, label) in verb.flags.iter().zip(&labels) {
            out.push_str(&format!("  {label:<width$}  {}\n", flag.help));
        }
        out.push_str(&format!("  {:<width$}  this help\n", "--help"));
        out
    }

    /// Find the verb matching `args`, returns it with remaining arguments.
    fn find_verb(args: &[String]) -> Option<(&'static Verb, &[String])> {
        VERBS.iter().find_map(|verb| {
            let words = verb.words.split(' ').count();
            if args.len() < words
                || args[..words]
                    .iter()
                    .map(String::as_str)
                    .ne(verb.words.split(' '))
            {
                return None;
            }
            Some((verb, &args[words..]))
        })
    }

    /// Parse `args` for `verb`, arguments after `--` are treated as positional.
    fn parse(verb: &Verb, args: &[String]) -> Result<Parsed> {
        let mut parsed = Parsed::default();
        let mut positional_only = false;
        let mut at = 0;
        while at < args.len() {
            let arg = &args[at];
            at += 1;
            if positional_only {
                parsed.positional.push(arg.clone());
                continue;
            }
            if arg == "--" {
                positional_only = true;
                continue;
            }
            let Some(name) = arg.strip_prefix("--") else {
                parsed.positional.push(arg.clone());
                continue;
            };
            let (name, inline) = match name.split_once('=') {
                Some((name, value)) => (name, Some(value)),
                None => (name, None),
            };
            let Some(flag) = verb.flags.iter().find(|flag| flag.name == name) else {
                return Err(usage_err(verb, format!("unknown flag --{name}")));
            };
            let value = match inline {
                Some(value) => value.to_string(),
                None => {
                    let Some(value) = args.get(at) else {
                        return Err(usage_err(verb, format!("flag --{name} needs a value")));
                    };
                    at += 1;
                    value.clone()
                }
            };
            parsed.values.push((flag.name, value));
        }
        for flag in verb.flags {
            if flag.required && parsed.value(flag.name).is_none() {
                return Err(usage_err(verb, format!("flag --{} is required", flag.name)));
            }
        }
        Ok(parsed)
    }

    /// Parse the command line and dispatch to the matching verb.
    fn cli(args: &[String]) -> Result<i32> {
        let Some(first) = args.first() else {
            print!("{}", cli_help());
            return Ok(0);
        };
        if first == "--help" || first == "-h" {
            print!("{}", cli_help());
            return Ok(0);
        }
        let Some((verb, rest)) = find_verb(args) else {
            return Err(CliError::Usage {
                what: format!("unknown verb {first}"),
                usage: cli_help(),
            });
        };
        if rest
            .iter()
            .take_while(|arg| arg.as_str() != "--")
            .any(|arg| arg == "--help" || arg == "-h")
        {
            print!("{}", verb_help(verb));
            return Ok(0);
        }
        let parsed = parse(verb, rest)?;
        (verb.run)(verb, &parsed)
    }

    /// Parse, dispatch and report errors, returns the process exit code.
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
        eprintln!("lingcage: {error}");
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

    /// Returns store root, `--store` first, then `LINGCAGE_STORE`, then
    /// `DEFAULT_STORE`.
    fn store_root(parsed: &Parsed) -> PathBuf {
        if let Some(dir) = parsed.value("store") {
            return PathBuf::from(dir);
        }
        if let Some(dir) = std::env::var_os("LINGCAGE_STORE") {
            return PathBuf::from(dir);
        }
        PathBuf::from(DEFAULT_STORE)
    }

    /// Open the store, store root is attached to the error on failure.
    fn open_store(root: &Path) -> Result<TemplateStore> {
        TemplateStore::open(root).map_err(|source| CliError::Store {
            root: root.display().to_string(),
            source,
        })
    }

    /// Returns the single positional argument of a verb, it is called
    /// `name` in error messages.
    fn one_positional(verb: &Verb, parsed: &Parsed, name: &str) -> Result<String> {
        match parsed.positional.as_slice() {
            [one] => Ok(one.clone()),
            [] => Err(usage_err(verb, format!("{name} is required"))),
            _ => Err(usage_err(verb, format!("only one {name} is accepted"))),
        }
    }

    /// Fail with usage error if positional arguments are given, since the
    /// verb accepts none.
    fn no_positional(verb: &Verb, parsed: &Parsed) -> Result<()> {
        match parsed.positional.first() {
            Some(extra) => Err(usage_err(verb, format!("unexpected argument {extra}"))),
            None => Ok(()),
        }
    }

    /// Returns `true` if JSON output is requested. `--format` only accepts
    /// `json`.
    fn wants_json(verb: &Verb, parsed: &Parsed) -> Result<bool> {
        match parsed.value("format") {
            None => Ok(false),
            Some("json") => Ok(true),
            Some(other) => Err(usage_err(verb, format!("unknown format {other}"))),
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
        let value: u64 = digits.parse().ok()?;
        value.checked_mul(scale)
    }

    /// Parse memory size, bare number is taken as MiB, K/M/G suffix such as
    /// 512M is also supported.
    fn parse_memory(text: &str) -> std::result::Result<u64, String> {
        const KIB: u64 = 1 << 10;
        const MIB: u64 = 1 << 20;
        const GIB: u64 = 1 << 30;
        match parse_scaled(text, &[('k', KIB), ('m', MIB), ('g', GIB)], MIB) {
            Some(memory) => Ok(memory),
            None => Err(format!(
                "invalid memory size {text}, use bare MiB or K/M/G suffix"
            )),
        }
    }

    /// Parse duration in seconds, with optional s/m/h suffix such as 30s.
    fn parse_duration(text: &str) -> std::result::Result<Duration, String> {
        match parse_scaled(text, &[('s', 1), ('m', 60), ('h', 3600)], 1) {
            Some(secs) => Ok(Duration::from_secs(secs)),
            None => Err(format!(
                "invalid duration {text}, use bare seconds or s/m/h suffix"
            )),
        }
    }

    /// `template build` boots the plan and registers the result, then prints
    /// its meta.
    fn template_build(verb: &Verb, parsed: &Parsed) -> Result<i32> {
        no_positional(verb, parsed)?;
        let json = wants_json(verb, parsed)?;
        let mut plan = TemplatePlan {
            kernel: PathBuf::from(parsed.value("kernel").expect("required flag")),
            ..Default::default()
        };
        if let Some(initrd) = parsed.value("initrd") {
            plan.initrd = Some(PathBuf::from(initrd));
        }
        if let Some(memory) = parsed.value("memory") {
            plan.memory = parse_memory(memory).map_err(|what| usage_err(verb, what))?;
        }
        if let Some(vcpus) = parsed.value("vcpus") {
            plan.vcpus = vcpus
                .parse::<u16>()
                .map_err(|_| usage_err(verb, format!("invalid vcpu count {vcpus}")))?;
        }
        if let Some(name) = parsed.value("name") {
            plan.name = Some(name.to_string());
        }
        if let Some(timeout) = parsed.value("ready-timeout") {
            plan.ready_timeout = parse_duration(timeout).map_err(|what| usage_err(verb, what))?;
        }
        let store = open_store(&store_root(parsed))?;
        let template = store.build(&plan)?;
        print_meta(template.meta(), json)?;
        Ok(0)
    }

    /// `template list` prints registered templates as a table, or in JSON.
    fn template_list(verb: &Verb, parsed: &Parsed) -> Result<i32> {
        no_positional(verb, parsed)?;
        let json = wants_json(verb, parsed)?;
        let store = open_store(&store_root(parsed))?;
        let metas = store.list()?;
        if json {
            println!("{}", serde_json::to_string_pretty(&metas)?);
            return Ok(0);
        }
        println!(
            "{:<64} {:>9} {:>5} {:<20} {:>12}",
            "ID", "MEMORY", "VCPUS", "DEVICES", "BYTES"
        );
        for meta in &metas {
            println!(
                "{:<64} {:>9} {:>5} {:<20} {:>12}",
                meta.id,
                human_size(meta.shape.memory),
                meta.shape.vcpus,
                devices(meta.shape.devices),
                meta.bytes
            );
        }
        Ok(0)
    }

    /// `template inspect` prints meta of the given template, one field per
    /// line, or in JSON.
    fn template_inspect(verb: &Verb, parsed: &Parsed) -> Result<i32> {
        let json = wants_json(verb, parsed)?;
        let id = TemplateId::from(one_positional(verb, parsed, "ID")?);
        let store = open_store(&store_root(parsed))?;
        let template = store.get(&id)?;
        print_meta(template.meta(), json)?;
        Ok(0)
    }

    /// `template verify` re-runs registration checks on a stored template,
    /// one line per check. Exits with 2 if any check fails.
    fn template_verify(verb: &Verb, parsed: &Parsed) -> Result<i32> {
        let id = one_positional(verb, parsed, "ID")?;
        let root = store_root(parsed);
        let store = open_store(&root)?;
        let dir = template_dir(&root, &id);
        let mut ok = true;
        match read_meta(&dir) {
            Ok(meta) => {
                println!("meta: ok");
                match Digest::of_file(&dir.join("kernel.img")) {
                    Ok(digest) if digest == meta.kernel => println!("kernel digest: ok"),
                    Ok(digest) => {
                        println!(
                            "kernel digest: FAILED: registered {}, computed {digest}",
                            meta.kernel
                        );
                        ok = false;
                    }
                    Err(err) => {
                        println!("kernel digest: FAILED: {err}");
                        ok = false;
                    }
                }
            }
            Err(err) => {
                println!("meta: FAILED: {err}");
                ok = false;
            }
        }
        match store.register(&dir) {
            Ok(template) => {
                let stamp = &template.meta().stamp;
                println!("stamp: ok (lingcore {}, {})", stamp.lingcore, stamp.arch);
                let shape = template.meta().shape;
                println!("shape: ok ({} bytes, {} vcpus)", shape.memory, shape.vcpus);
            }
            Err(err) => {
                println!("register: FAILED: {err}");
                ok = false;
            }
        }
        Ok(if ok { 0 } else { 2 })
    }

    /// Read template.json under `dir`.
    fn read_meta(dir: &Path) -> Result<TemplateMeta> {
        let bytes = std::fs::read(dir.join("template.json"))?;
        Ok(serde_json::from_slice(&bytes)?)
    }

    /// `template rm` removes the given template and prints the removed id.
    fn template_rm(verb: &Verb, parsed: &Parsed) -> Result<i32> {
        let id = TemplateId::from(one_positional(verb, parsed, "ID")?);
        let store = open_store(&store_root(parsed))?;
        store.remove(&id)?;
        println!("removed {id}");
        Ok(0)
    }

    /// `check` checks host prerequisites and prints one line for each,
    /// exits with 2 at the first failure.
    fn check_verb(verb: &Verb, parsed: &Parsed) -> Result<i32> {
        no_positional(verb, parsed)?;
        let root = store_root(parsed);
        check_line("kvm", check_kvm())?;
        check_line("zcat", check_tool("zcat"))?;
        check_line("cpio", check_tool("cpio"))?;
        check_line("store", check_store(&root))?;
        check_line("sockets", check_socket_room(&root))?;
        if let Some(kernel) = parsed.value("kernel") {
            check_line("kernel", check_kernel(kernel))?;
        }
        Ok(0)
    }

    /// Print template meta, one field per line, or dump it in JSON.
    fn print_meta(meta: &TemplateMeta, json: bool) -> Result<()> {
        if json {
            println!("{}", serde_json::to_string_pretty(meta)?);
            return Ok(());
        }
        println!("id: {}", meta.id);
        println!("memory: {}", meta.shape.memory);
        println!("vcpus: {}", meta.shape.vcpus);
        println!("devices: {}", devices(meta.shape.devices));
        println!("lingcore: {}", meta.stamp.lingcore);
        println!("layout: {}", meta.stamp.layout);
        println!("arch: {}", meta.stamp.arch);
        println!("kernel: {}", meta.kernel);
        match meta.rootfs {
            Some(rootfs) => println!("rootfs: {rootfs}"),
            None => println!("rootfs: none"),
        }
        println!("built: {}", unix_secs(meta.built_at));
        println!("bytes: {}", meta.bytes);
        Ok(())
    }

    /// Format device set as `disk+channel+network`, devices not present are
    /// left out.
    fn devices(set: DeviceSet) -> String {
        let mut parts = Vec::new();
        if set.disk {
            parts.push("disk");
        }
        if set.channel {
            parts.push("channel");
        }
        if set.network {
            parts.push("network");
        }
        if parts.is_empty() {
            return "none".to_string();
        }
        parts.join("+")
    }

    /// Format byte size in MiB or GiB for the table.
    fn human_size(bytes: u64) -> String {
        const GIB: u64 = 1 << 30;
        if bytes >= GIB && bytes.is_multiple_of(GIB) {
            return format!("{} GiB", bytes / GIB);
        }
        format!("{} MiB", bytes / (1 << 20))
    }

    /// Returns seconds since Unix epoch, used to print build time.
    fn unix_secs(time: SystemTime) -> u64 {
        match time.duration_since(SystemTime::UNIX_EPOCH) {
            Ok(since) => since.as_secs(),
            Err(_) => 0,
        }
    }

    /// Store directory of a template is `templates/<id>`, fall back to the
    /// alias symlink if `id` is actually a name.
    fn template_dir(root: &Path, id: &str) -> PathBuf {
        let plain = root.join("templates").join(id);
        if plain.is_dir() {
            return plain;
        }
        root.join("templates").join("aliases").join(id)
    }

    /// Print ok line for a passed check, otherwise fail the verb with the
    /// failing line.
    fn check_line(name: &str, result: std::result::Result<String, String>) -> Result<()> {
        match result {
            Ok(detail) => {
                println!("{name}: ok ({detail})");
                Ok(())
            }
            Err(why) => Err(CliError::Check(format!("{name}: FAILED: {why}"))),
        }
    }

    /// Check /dev/kvm is readable and writable.
    fn check_kvm() -> std::result::Result<String, String> {
        match std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open("/dev/kvm")
        {
            Ok(_) => Ok("/dev/kvm readable and writable".to_string()),
            Err(err) => Err(format!("/dev/kvm is not readable and writable: {err}")),
        }
    }

    /// Check the tool is available on PATH.
    fn check_tool(name: &str) -> std::result::Result<String, String> {
        match on_path(name) {
            Some(path) => Ok(path.display().to_string()),
            None => Err(format!("{name} not found on PATH")),
        }
    }

    /// Check store root is usable, create it if missing, then write a probe
    /// file and remove it.
    fn check_store(root: &Path) -> std::result::Result<String, String> {
        if let Err(err) = std::fs::create_dir_all(root) {
            return Err(format!("failed to create {}: {err}", root.display()));
        }
        let probe = root.join(".lingcage-check");
        if let Err(err) = std::fs::write(&probe, b"probe") {
            return Err(format!("failed to write to {}: {err}", root.display()));
        }
        if let Err(err) = std::fs::remove_file(&probe) {
            return Err(format!(
                "failed to remove probe file {}: {err}",
                probe.display()
            ));
        }
        Ok(format!("{} usable", root.display()))
    }

    /// Check socket paths of a sandbox fit in socket address. The longest
    /// path is `<root>/run/<id>/vs_<port>` with a 12-char id and a port of
    /// up to 10 digits, NUL terminator included.
    fn check_socket_room(root: &Path) -> std::result::Result<String, String> {
        let longest = root.as_os_str().len() + "/run/".len() + 12 + "/vs_".len() + 10 + 1;
        if longest <= SUN_PATH {
            return Ok(format!(
                "longest socket path is {longest} bytes, limit is {SUN_PATH}"
            ));
        }
        Err(format!(
            "the longest socket path under {} is {longest} bytes, over the {SUN_PATH} of a socket \
             address; use a shorter --store",
            root.display()
        ))
    }

    /// Check kernel image is readable.
    fn check_kernel(path: &str) -> std::result::Result<String, String> {
        match std::fs::File::open(path) {
            Ok(_) => Ok(format!("{path} readable")),
            Err(err) => Err(format!("failed to read {path}: {err}")),
        }
    }

    /// Look up `name` on PATH, returns the first executable file found.
    fn on_path(name: &str) -> Option<PathBuf> {
        let path = std::env::var_os("PATH")?;
        std::env::split_paths(&path)
            .map(|dir| dir.join(name))
            .find(|candidate| is_executable(candidate))
    }

    /// Returns whether `path` is a regular file with execute bit set.
    fn is_executable(path: &Path) -> bool {
        use std::os::unix::fs::PermissionsExt as _;
        match path.metadata() {
            Ok(meta) => meta.is_file() && meta.permissions().mode() & 0o111 != 0,
            Err(_) => false,
        }
    }

    #[cfg(test)]
    mod tests {
        use std::time::Duration;

        use crate::imp::{
            VERBS, Verb, check_socket_room, cli_help, find_verb, parse, parse_duration,
            parse_memory, verb_help,
        };

        /// Look up the verb named `words` in `VERBS` table.
        fn verb(words: &str) -> &'static Verb {
            VERBS
                .iter()
                .find(|verb| verb.words == words)
                .expect("verb in the table")
        }

        /// Helper to convert args into owned strings as in argv.
        fn strings(args: &[&str]) -> Vec<String> {
            args.iter().map(|arg| (*arg).to_string()).collect()
        }

        #[test]
        fn test_dispatch_template_build() {
            let args = strings(&["template", "build", "--kernel", "k"]);
            let (verb, rest) = find_verb(&args).expect("dispatch");
            assert_eq!(verb.words, "template build");
            let expected = strings(&["--kernel", "k"]);
            assert_eq!(rest, expected.as_slice());
        }

        #[test]
        fn test_reject_unknown_verb() {
            assert!(find_verb(&strings(&["frob"])).is_none());
            assert!(find_verb(&strings(&["template"])).is_none());
            assert!(find_verb(&strings(&["template", "frob"])).is_none());
        }

        #[test]
        fn test_parse_memory_size() {
            assert_eq!(parse_memory("512M").expect("size"), 512 << 20);
            assert_eq!(parse_memory("1G").expect("size"), 1 << 30);
            assert_eq!(parse_memory("256").expect("size"), 256 << 20);
            assert_eq!(parse_memory("1g").expect("size"), 1 << 30);
            for bad in ["", "M", "10T", "1.5G", "-5"] {
                assert!(parse_memory(bad).is_err(), "{bad}");
            }
        }

        #[test]
        fn test_parse_duration() {
            assert_eq!(
                parse_duration("30s").expect("duration"),
                Duration::from_secs(30)
            );
            assert_eq!(
                parse_duration("5m").expect("duration"),
                Duration::from_secs(300)
            );
            assert_eq!(
                parse_duration("1h").expect("duration"),
                Duration::from_secs(3600)
            );
            assert_eq!(
                parse_duration("45").expect("duration"),
                Duration::from_secs(45)
            );
            assert!(parse_duration("1d").is_err());
        }

        #[test]
        fn test_reject_unknown_flag() {
            let err = parse(
                verb("template build"),
                &strings(&["--kernel", "k", "--bogus"]),
            )
            .expect_err("a usage error");
            assert!(format!("{err}").contains("unknown flag --bogus"));
            assert_eq!(err.code(), 1);
        }

        #[test]
        fn test_reject_flag_without_value() {
            let err =
                parse(verb("template build"), &strings(&["--kernel"])).expect_err("a usage error");
            assert!(format!("{err}").contains("--kernel needs a value"));
        }

        #[test]
        fn test_reject_missing_required_flag() {
            let err = parse(verb("template build"), &strings(&["--memory", "256"]))
                .expect_err("a usage error");
            assert!(format!("{err}").contains("--kernel is required"));
        }

        #[test]
        fn test_format_json_on_listing_verbs() {
            let cases: [(&str, &[&str]); 3] = [
                ("template build", &["--kernel", "k", "--format", "json"]),
                ("template list", &["--format", "json"]),
                ("template inspect", &["--format", "json"]),
            ];
            for (words, args) in cases {
                let parsed = parse(verb(words), &strings(args)).expect("parse");
                assert_eq!(parsed.value("format"), Some("json"), "{words}");
            }
        }

        #[test]
        fn test_cli_help_lists_verbs_and_exit_codes() {
            let help = cli_help();
            for verb in VERBS {
                assert!(help.contains(verb.words), "help misses {}", verb.words);
            }
            for code in ["126", "127", "137"] {
                assert!(help.contains(code), "exit code {code} missing from help");
            }
        }

        #[test]
        fn test_verb_help_lists_flags() {
            for verb in VERBS {
                let help = verb_help(verb);
                for flag in verb.flags {
                    assert!(
                        help.contains(&format!("--{}", flag.name)),
                        "{} misses --{}",
                        verb.words,
                        flag.name
                    );
                }
            }
        }

        #[test]
        fn test_socket_room_check_longest_path() {
            assert!(check_socket_room(std::path::Path::new("/var/lib/lingcage")).is_ok());
            let long = format!("/{}", "a".repeat(90));
            assert!(check_socket_room(std::path::Path::new(&long)).is_err());
        }
    }
}

#[cfg(all(
    target_os = "linux",
    any(target_arch = "x86_64", target_arch = "riscv64")
))]
fn main() {
    use std::io::Write as _;
    let args: Vec<String> = std::env::args().skip(1).collect();
    let code = imp::run(&args);
    // `process::exit` skips the stdout flush done on return from main, flush
    // it here.
    if let Err(err) = std::io::stdout().flush() {
        eprintln!("lingcage: failed to write to stdout: {err}");
        std::process::exit(2);
    }
    std::process::exit(code);
}

// `lingcore` machine layer currently supports Linux on x86_64 and riscv64
// only.
#[cfg(not(all(
    target_os = "linux",
    any(target_arch = "x86_64", target_arch = "riscv64")
)))]
fn main() {}
