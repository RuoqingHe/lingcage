// SPDX-FileCopyrightText: 2026 LingCage <opensource@lingcage.com>
//
// SPDX-License-Identifier: Apache-2.0

//! Listing check of an initramfs before it is baked into a template, so
//! that no seed, credential or identity file is shared between clones
//! and the template. Runs `zcat` and `cpio` on the build host.

use std::path::Path;

use crate::error::{Error, Result};

/// Paths an initramfs must not carry, random seeds and credentials
/// reused by clones, and identity files rewritten per sandbox by the
/// handshake.
const FORBIDDEN: &[&str] = &[
    "var/lib/systemd/random-seed",
    "loader/random-seed",
    "var/lib/systemd/credential.secret",
    "etc/hostname",
    "etc/machine-info",
];

/// Prefix of SSH host keys, forbidden with any suffix.
const HOST_KEYS: &str = "etc/ssh/ssh_host_";

/// Member name of the machine id. A populated one is treated as a hit.
const MACHINE_ID: &str = "etc/machine-id";

/// Check the initramfs at `initrd`, forbidden paths found are returned
/// as `Error::Sanitize` when the list is not empty.
pub fn check(initrd: &Path) -> Result<()> {
    let listing = list_members(initrd)?;
    let machine_id = listing
        .lines()
        .find(|line| normalize(line) == MACHINE_ID)
        .map(|member| read_member(initrd, member.trim()))
        .transpose()?;
    let found = forbidden(&listing, machine_id.as_deref());
    if found.is_empty() {
        return Ok(());
    }
    Err(Error::Sanitize { found })
}

// TODO: An initramfs compressed with zstd or xz is not yet listed.
/// Returns member names of the archive at `initrd`, one per line.
fn list_members(initrd: &Path) -> Result<String> {
    let out = run("zcat -f \"$1\" | cpio -t", initrd, None)?;
    Ok(String::from_utf8_lossy(&out.stdout).into_owned())
}

/// Returns content of `member` in the archive at `initrd`.
fn read_member(initrd: &Path, member: &str) -> Result<Vec<u8>> {
    let out = run(
        "zcat -f \"$1\" | cpio -i --quiet --to-stdout \"$2\"",
        initrd,
        Some(member),
    )?;
    Ok(out.stdout)
}

/// Run `pipeline` under `sh` with the initrd as $1 and `member` as $2,
/// stdout and stderr are captured.
fn run(pipeline: &str, initrd: &Path, member: Option<&str>) -> Result<std::process::Output> {
    let mut command = std::process::Command::new("sh");
    command.args(["-c", pipeline, "_"]).arg(initrd);
    if let Some(member) = member {
        command.arg(member);
    }
    let out = command.output().map_err(|err| {
        Error::Io(std::io::Error::new(
            err.kind(),
            format!("sanitize check requires zcat and cpio commands: {err}"),
        ))
    })?;
    if !out.status.success() {
        let stderr = String::from_utf8_lossy(&out.stderr);
        return Err(Error::Io(std::io::Error::other(format!(
            "failed to list initramfs: {}",
            stderr.trim()
        ))));
    }
    Ok(out)
}

/// Returns names in `listing` which a template must not carry, in
/// listing order without duplicates. `machine_id` is content of the
/// machine id member if the listing has one.
fn forbidden(listing: &str, machine_id: Option<&[u8]>) -> Vec<String> {
    let mut found = Vec::new();
    for name in listing.lines().map(normalize) {
        if FORBIDDEN.contains(&name) || name.starts_with(HOST_KEYS) {
            found.push(name.to_string());
        }
    }
    if let Some(content) = machine_id {
        let marker = String::from_utf8_lossy(content);
        // Empty and `uninitialized` are first-boot markers of systemd. A real
        // id baked in would be shared by all clones.
        if !marker.trim().is_empty() && marker.trim() != "uninitialized" {
            found.push(MACHINE_ID.to_string());
        }
    }
    found.dedup();
    found
}

/// Returns the member name with leading `./` or `/` stripped, which a
/// packer may have stored it under.
fn normalize(line: &str) -> &str {
    let mut name = line.trim();
    while let Some(rest) = name.strip_prefix("./") {
        name = rest;
    }
    name.trim_start_matches('/')
}

#[cfg(test)]
mod tests {
    use crate::template::sanitize::*;

    #[test]
    fn test_clean_listing_passes() {
        let listing = "bin\nbin/busybox\nbin/lingcage-agent\netc\netc/machine-id\ninit\n";
        assert!(forbidden(listing, Some(b"")).is_empty());
    }

    #[test]
    fn test_forbidden_paths_with_leading_dots() {
        let listing = "./var/lib/systemd/random-seed\n/loader/random-seed\nvar/lib/systemd/\
                       credential.secret\netc/hostname\n./etc/machine-info\netc/ssh/\
                       ssh_host_ed25519_key\n";
        let found = forbidden(listing, None);
        assert_eq!(
            found,
            vec![
                "var/lib/systemd/random-seed".to_string(),
                "loader/random-seed".to_string(),
                "var/lib/systemd/credential.secret".to_string(),
                "etc/hostname".to_string(),
                "etc/machine-info".to_string(),
                "etc/ssh/ssh_host_ed25519_key".to_string(),
            ]
        );
    }

    #[test]
    fn test_populated_machine_id_flagged() {
        assert!(forbidden("etc/machine-id\n", Some(b"")).is_empty());
        assert!(forbidden("./etc/machine-id\n", Some(b"uninitialized\n")).is_empty());
        assert_eq!(
            forbidden("etc/machine-id\n", Some(b"5f3d2c1b0a94e6f8\n")),
            vec!["etc/machine-id".to_string()]
        );
    }
}
