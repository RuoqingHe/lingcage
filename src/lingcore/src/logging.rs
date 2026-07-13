// SPDX-FileCopyrightText: 2026 LingCage <opensource@lingcage.com>
//
// SPDX-License-Identifier: Apache-2.0

//! Logger of a program built on lingcore, one line per record to stderr
//! or a file. A line is formatted first and written with one `write`,
//! so a thread under an allowlist which keeps `write` alone can log,
//! and lines of two threads do not mix.
//!
//! Each line carries seconds since the logger was created, the level,
//! the thread and the target:
//!
//! ```text
//! lingcore: 0.012345s WARN  [device] lingcore::devices::virtio::mmio: ...
//! ```

use std::fs::File;
use std::io::{self, Write};
use std::sync::Mutex;
use std::time::Instant;

use log::{LevelFilter, Log, Metadata, Record};

/// Sink of the lines.
enum Sink {
    Stderr,
    /// Lock keeps lines of two threads apart in the file.
    File(Mutex<File>),
}

/// Logger writing one line per record, installed by `install`.
pub struct Logger {
    /// Name of the program, ahead of each line.
    name: &'static str,
    started: Instant,
    /// Records above this level are dropped.
    level: LevelFilter,
    sink: Sink,
}

impl Logger {
    /// Create a logger for program `name`, writing records up to `level`
    /// to `file`, or to stderr without one.
    pub fn new(name: &'static str, level: LevelFilter, file: Option<File>) -> Self {
        Logger {
            name,
            started: Instant::now(),
            level,
            sink: match file {
                Some(file) => Sink::File(Mutex::new(file)),
                None => Sink::Stderr,
            },
        }
    }

    /// Install the logger as the one `log` macros write to. It is leaked,
    /// since it stays for life of the process. A second install fails.
    pub fn install(self) -> Result<(), log::SetLoggerError> {
        let level = self.level;
        log::set_logger(Box::leak(Box::new(self)))?;
        log::set_max_level(level);
        Ok(())
    }

    /// Returns line for `record`, newline included.
    fn line(&self, record: &Record<'_>) -> String {
        let thread = std::thread::current();
        format!(
            "{}: {:.6}s {:<5} [{}] {}: {}\n",
            self.name,
            self.started.elapsed().as_secs_f64(),
            record.level(),
            thread.name().unwrap_or("?"),
            record.target(),
            record.args()
        )
    }
}

impl Log for Logger {
    fn enabled(&self, metadata: &Metadata<'_>) -> bool {
        metadata.level() <= self.level
    }

    /// Write line of `record`. A write which fails drops the line, there
    /// is no one to tell.
    fn log(&self, record: &Record<'_>) {
        if !self.enabled(record.metadata()) {
            return;
        }
        let line = self.line(record);
        let _ = match &self.sink {
            Sink::Stderr => io::stderr().write_all(line.as_bytes()),
            Sink::File(file) => file
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .write_all(line.as_bytes()),
        };
    }

    fn flush(&self) {}
}

/// Returns level for `verbosity` counts of `-v`, warnings alone with
/// none, then info, debug and trace.
pub fn level_of(verbosity: u8) -> LevelFilter {
    match verbosity {
        0 => LevelFilter::Warn,
        1 => LevelFilter::Info,
        2 => LevelFilter::Debug,
        _ => LevelFilter::Trace,
    }
}

#[cfg(test)]
mod tests {
    use std::io::Read;

    use log::Level;

    use crate::logging::*;

    /// Path of a log file under the temp dir, named after `tag`.
    fn log_at(tag: &str) -> std::path::PathBuf {
        std::env::temp_dir().join(format!("lingcore-log-{tag}-{}", std::process::id()))
    }

    #[test]
    fn test_level_of_verbosity() {
        assert_eq!(level_of(0), LevelFilter::Warn);
        assert_eq!(level_of(1), LevelFilter::Info);
        assert_eq!(level_of(2), LevelFilter::Debug);
        assert_eq!(level_of(3), LevelFilter::Trace);
        assert_eq!(level_of(9), LevelFilter::Trace);
    }

    #[test]
    fn test_line_carries_level_thread_and_target() {
        let logger = Logger::new("test", LevelFilter::Debug, None);
        let line = std::thread::Builder::new()
            .name("device".to_string())
            .spawn(move || {
                logger.line(
                    &Record::builder()
                        .args(format_args!("hello {}", 7))
                        .level(Level::Warn)
                        .target("lingcore::x")
                        .build(),
                )
            })
            .expect("spawn")
            .join()
            .expect("join");
        assert!(line.starts_with("test: "), "line: {line}");
        assert!(
            line.ends_with("s WARN  [device] lingcore::x: hello 7\n"),
            "line: {line}"
        );
    }

    #[test]
    fn test_records_above_level_dropped() {
        let logger = Logger::new("test", LevelFilter::Info, None);
        assert!(logger.enabled(&Metadata::builder().level(Level::Warn).build()));
        assert!(logger.enabled(&Metadata::builder().level(Level::Info).build()));
        assert!(!logger.enabled(&Metadata::builder().level(Level::Debug).build()));
    }

    #[test]
    fn test_file_gets_line() {
        let path = log_at("file");
        let file = File::create(&path).expect("create the log");
        let logger = Logger::new("test", LevelFilter::Info, Some(file));
        logger.log(
            &Record::builder()
                .args(format_args!("kept"))
                .level(Level::Info)
                .target("t")
                .build(),
        );
        logger.log(
            &Record::builder()
                .args(format_args!("dropped"))
                .level(Level::Debug)
                .target("t")
                .build(),
        );
        let mut text = String::new();
        File::open(&path)
            .expect("open the log")
            .read_to_string(&mut text)
            .expect("read the log");
        std::fs::remove_file(&path).expect("remove the log");
        assert_eq!(text.lines().count(), 1, "log: {text}");
        assert!(text.ends_with(" t: kept\n"), "log: {text}");
    }
}
