// SPDX-FileCopyrightText: 2026 LingCage <opensource@lingcage.com>
//
// SPDX-License-Identifier: Apache-2.0

//! Event monitor, one JSON line per event of a sandbox or a template,
//! written to a file the embedder hands over. A program driving many
//! sandboxes reads the lines, the log is for a person.
//!
//! A line carries time since the epoch, the source, the event and its
//! properties, on one line in the file:
//!
//! ```text
//! {"event":"ready","properties":{"id":"3f9c"},"source":"sandbox",
//!  "timestamp":{"nanos":5,"secs":1}}
//! ```

use std::fs::File;
use std::io::Write as _;
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

/// File the events go to, `None` until `route` is called or after a
/// write failed.
static SINK: Mutex<Option<File>> = Mutex::new(None);

/// Route events to `file`, each one as a single write. No event is
/// written before this is called.
pub fn route(file: File) {
    *SINK.lock().unwrap_or_else(|poisoned| poisoned.into_inner()) = Some(file);
}

/// Write event `event` of `source` with `properties`. A write which
/// fails closes the monitor, with a warning for the log.
pub fn emit(source: &str, event: &str, properties: serde_json::Value) {
    let mut sink = SINK.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
    let Some(file) = sink.as_mut() else {
        return;
    };
    let since = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default();
    let mut line = serde_json::json!({
        "timestamp": { "secs": since.as_secs(), "nanos": since.subsec_nanos() },
        "source": source,
        "event": event,
        "properties": properties,
    })
    .to_string();
    line.push('\n');
    if let Err(err) = file.write_all(line.as_bytes()) {
        log::warn!("event monitor closed, write failed: {err}");
        *sink = None;
    }
}

#[cfg(test)]
mod tests {
    use std::io::Read as _;

    use crate::event::*;

    #[test]
    fn test_events_land_one_per_line() {
        // Two events make two lines, each with source, event and
        // properties. Sink is one per process, so one test routes and
        // reads.
        let path = std::env::temp_dir().join(format!("lingcage-events-{}", std::process::id()));
        route(File::create(&path).expect("create the file"));
        emit("sandbox", "ready", serde_json::json!({ "id": "abc" }));
        emit(
            "sandbox",
            "stopped",
            serde_json::json!({ "id": "abc", "how": "powered off" }),
        );
        let mut text = String::new();
        File::open(&path)
            .expect("open the file")
            .read_to_string(&mut text)
            .expect("read the file");
        std::fs::remove_file(&path).expect("remove the file");

        let lines: Vec<serde_json::Value> = text
            .lines()
            .map(|line| serde_json::from_str(line).expect("a JSON line"))
            .collect();
        assert_eq!(lines.len(), 2, "text: {text}");
        assert_eq!(lines[0]["source"], "sandbox");
        assert_eq!(lines[0]["event"], "ready");
        assert_eq!(lines[0]["properties"]["id"], "abc");
        assert!(lines[0]["timestamp"]["secs"].as_u64().unwrap() > 0);
        assert_eq!(lines[1]["event"], "stopped");
        assert_eq!(lines[1]["properties"]["how"], "powered off");
    }
}
