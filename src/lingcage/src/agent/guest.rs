// SPDX-FileCopyrightText: 2026 LingCage <opensource@lingcage.com>
//
// SPDX-License-Identifier: Apache-2.0

//! Guest side actions of the agent: applying identity, mixing entropy,
//! powering off.

#![cfg(target_os = "linux")]

use std::io::Read;
use std::os::fd::AsRawFd;
use std::{fs, io};

use crate::lcp::{Identify, Ready};

/// ioctl request which mixes pool data into kernel input pool.
const RNDADDENTROPY: libc::Ioctl = 0x4008_5203;

/// ioctl request which forces CRNG to reseed.
const RNDRESEEDCRNG: libc::Ioctl = 0x5207;

/// Payload of RNDADDENTROPY, laid out according to linux/random.h.
#[repr(C)]
struct RandPoolInfo {
    /// Entropy credited to the pool, in bits.
    entropy_count: u32,
    /// Size of pool data after the header, in bytes.
    buf_size: u32,
    /// Pool data.
    buf: [u8; 32],
}

/// Returns the READY payload with agent version, guest uptime and boot id.
pub fn ready() -> Ready {
    let uptime = match fs::read_to_string("/proc/uptime") {
        Ok(text) => parse_uptime(&text).unwrap_or(0.0),
        Err(_) => 0.0,
    };
    let boot_id = match fs::read_to_string("/proc/sys/kernel/random/boot_id") {
        Ok(text) => text.trim().to_string(),
        Err(_) => String::new(),
    };
    Ready {
        agent: format!("lingcage-agent {}", env!("CARGO_PKG_VERSION")),
        uptime,
        boot_id,
        protocol: crate::lcp::PROTOCOL,
        init_ms: u64::try_from(
            crate::agent::START
                .get_or_init(std::time::Instant::now)
                .elapsed()
                .as_millis(),
        )
        .unwrap_or(u64::MAX),
    }
}

/// Parse the first number of /proc/uptime text as seconds, returns
/// `None` if there is no such number.
fn parse_uptime(text: &str) -> Option<f64> {
    let number = text.split_whitespace().next()?;
    number.parse().ok()
}

/// Apply identity of the sandbox and return the hostname currently in
/// effect. Each step is best-effort, failure is reported on stderr and
/// following steps still run.
pub fn apply(identity: &Identify) -> String {
    note(
        "the hostname",
        set_hostname(&identity.hostname)
            .and_then(|()| fs::write("/proc/sys/kernel/hostname", &identity.hostname)),
    );
    note(
        "/etc/machine-id",
        fs::write("/etc/machine-id", format!("{}\n", identity.machine_id)),
    );
    note("entropy mix", mix_entropy(&identity.entropy));
    step_clock(identity.unix_nanos);
    note("boot id", replace_boot_id());
    read_back_hostname().unwrap_or_else(|| identity.hostname.clone())
}

/// Maximum drift allowed before the clock gets stepped.
const STEP_PAST_NANOS: u64 = 100 * 1_000_000;

/// Step the clock to the time in identity if guest clock has drifted
/// more than `STEP_PAST_NANOS`. Target of 0 means the host predates this
/// field and no step is done, failure is reported on stderr.
fn step_clock(unix_nanos: u64) {
    if !step_needed(now_nanos(), unix_nanos) {
        return;
    }
    let at = libc::timespec {
        tv_sec: i64::try_from(unix_nanos / 1_000_000_000).unwrap_or(i64::MAX),
        tv_nsec: i64::try_from(unix_nanos % 1_000_000_000).unwrap_or(0),
    };
    // SAFETY: `at` is a valid timespec and outlives the call.
    if unsafe { libc::clock_settime(libc::CLOCK_REALTIME, &at) } == -1 {
        note("clock step", Err(io::Error::last_os_error()));
    }
}

/// Returns time of the realtime clock, in nanoseconds since the epoch.
fn now_nanos() -> u64 {
    let mut at = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    // SAFETY: `at` is a valid timespec to write into.
    if unsafe { libc::clock_gettime(libc::CLOCK_REALTIME, &mut at) } == -1 {
        return 0;
    }
    u64::try_from(at.tv_sec)
        .unwrap_or(0)
        .saturating_mul(1_000_000_000)
        .saturating_add(u64::try_from(at.tv_nsec).unwrap_or(0))
}

/// Returns whether clock step is needed. Target of 0 (host predating
/// the field) or drift within `STEP_PAST_NANOS` needs no step.
fn step_needed(now: u64, target: u64) -> bool {
    target != 0 && now.abs_diff(target) > STEP_PAST_NANOS
}

/// Set kernel hostname with sethostname(2).
fn set_hostname(hostname: &str) -> io::Result<()> {
    // SAFETY: bytes of `hostname` stay valid during the call.
    let rc = unsafe { libc::syscall(libc::SYS_sethostname, hostname.as_ptr(), hostname.len()) };
    if rc == -1 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// Mix `entropy` into kernel pool, then force CRNG to reseed.
fn mix_entropy(entropy: &[u8; 32]) -> io::Result<()> {
    let pool = fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open("/dev/urandom")?;
    let mut info = RandPoolInfo {
        entropy_count: 256,
        buf_size: 32,
        buf: *entropy,
    };
    // SAFETY: `pool` is an open fd, `info` is a valid rand_pool_info.
    if unsafe { libc::ioctl(pool.as_raw_fd(), RNDADDENTROPY, &mut info) } == -1 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: `pool` is an open fd and RNDRESEEDCRNG takes no argument.
    if unsafe {
        libc::ioctl(
            pool.as_raw_fd(),
            RNDRESEEDCRNG,
            std::ptr::null::<libc::c_void>(),
        )
    } == -1
    {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// Replace kernel boot id. Boot id of the template can not be modified
/// directly, so generate a new v4 UUID from the reseeded pool and bind
/// mount it over `/proc/sys/kernel/random/boot_id` with `MS_BIND`.
fn replace_boot_id() -> io::Result<()> {
    let mut bytes = [0u8; 16];
    fs::File::open("/dev/urandom")?.read_exact(&mut bytes)?;
    let id = uuid_of(&bytes);
    std::fs::create_dir_all("/run/lingcage")?;
    let at = "/run/lingcage/boot_id";
    fs::write(at, format!("{id}\n"))?;
    // SAFETY: both paths are NUL-terminated literals, data pointer may be
    // null for MS_BIND.
    let rc = unsafe {
        libc::mount(
            c"/run/lingcage/boot_id".as_ptr(),
            c"/proc/sys/kernel/random/boot_id".as_ptr(),
            std::ptr::null(),
            libc::MS_BIND,
            std::ptr::null(),
        )
    };
    if rc == -1 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// Format 16 bytes as a v4 UUID with version 4 and RFC 4122 variant set.
fn uuid_of(b: &[u8; 16]) -> String {
    format!(
        "{:02x}{:02x}{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:\
         02x}{:02x}{:02x}",
        b[0],
        b[1],
        b[2],
        b[3],
        b[4],
        b[5],
        b[6] & 0x0f | 0x40,
        b[7],
        b[8] & 0x3f | 0x80,
        b[9],
        b[10],
        b[11],
        b[12],
        b[13],
        b[14],
        b[15],
    )
}

/// Returns hostname currently in effect, read back by gethostname(2).
fn read_back_hostname() -> Option<String> {
    let mut buf = [0u8; 65];
    // SAFETY: `buf` is a valid 65-byte buffer, its length is passed as size.
    if unsafe { libc::gethostname(buf.as_mut_ptr().cast(), buf.len()) } == -1 {
        return None;
    }
    let end = buf.iter().position(|byte| *byte == 0).unwrap_or(buf.len());
    Some(String::from_utf8_lossy(&buf[..end]).into_owned())
}

/// Sync filesystems and power off the guest. If reboot call fails,
/// report on stderr and return.
pub fn power_off() {
    // SAFETY: `sync` takes no argument.
    unsafe { libc::sync() };
    // SAFETY: reboot command is a plain integer, no pointer is passed.
    if unsafe { libc::reboot(libc::LINUX_REBOOT_CMD_POWER_OFF) } == -1 {
        crate::agent::diag::line(format_args!(
            "lingcage-agent: power off: {}",
            io::Error::last_os_error()
        ));
    }
}

/// Report failure of a best-effort step on stderr.
fn note(what: &str, result: io::Result<()>) {
    if let Err(err) = result {
        crate::agent::diag::line(format_args!("lingcage-agent: {what}: {err}"));
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn test_boot_id_v4_uuid() {
        let id = crate::agent::guest::uuid_of(&[0xab; 16]);
        assert_eq!(id.len(), 36);
        assert_eq!(id.as_bytes()[14], b'4');
        assert!(matches!(id.as_bytes()[19], b'8' | b'9' | b'a' | b'b'));
        assert_eq!(&id[..8], "abababab");
        assert_eq!(&id[9..13], "abab");
    }

    #[test]
    fn test_clock_step_past_drift() {
        // Clock steps only when drift exceeds `STEP_PAST_NANOS`.
        use crate::agent::guest::{STEP_PAST_NANOS, step_needed};
        assert!(
            !step_needed(1_000, 0),
            "target of 0 should not step the clock"
        );
        assert!(!step_needed(
            1_000_000_000,
            1_000_000_000 + STEP_PAST_NANOS - 1
        ));
        assert!(step_needed(
            1_000_000_000,
            1_000_000_000 + STEP_PAST_NANOS + 1
        ));
        assert!(step_needed(
            1_000_000_000 + STEP_PAST_NANOS + 1,
            1_000_000_000
        ));
    }

    use crate::agent::guest::{parse_uptime, read_back_hostname, ready};

    #[test]
    fn test_parse_uptime_first_number() {
        assert_eq!(parse_uptime("1234.56 7890.12\n"), Some(1234.56));
        assert_eq!(parse_uptime("0.00 0.00"), Some(0.0));
        assert_eq!(parse_uptime("garbage"), None);
        assert_eq!(parse_uptime(""), None);
    }

    #[test]
    fn test_ready_payload_from_proc() {
        let ready = ready();
        assert!(ready.agent.starts_with("lingcage-agent "));
        assert!(
            ready.uptime > 0.0,
            "uptime should be read from /proc/uptime"
        );
        assert!(
            !ready.boot_id.is_empty(),
            "boot id should be read from /proc"
        );
    }

    #[test]
    fn test_read_back_hostname() {
        assert!(!read_back_hostname().expect("hostname").is_empty());
    }
}
