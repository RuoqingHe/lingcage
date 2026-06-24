// SPDX-FileCopyrightText: 2026 LingCage <opensource@lingcage.com>
//
// SPDX-License-Identifier: Apache-2.0

//! Templates are sealed and immutable spawn sources. Each template keeps
//! RAM image, state document, guest shape and the build which wrote it in
//! a content-addressed directory, which is verified at registration.

use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime};

use lingcore::machine::snapshot::Snapshot;

use crate::error::{Error, Result};

pub mod sanitize;
mod store;

/// Content address of a template, which is stable across hosts. It is the
/// hex of digest over bytes of ram.img, state.json and kernel.img in that
/// order, computed only once at build or registration time.
#[derive(
    Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, serde::Serialize, serde::Deserialize,
)]
pub struct TemplateId(pub(crate) String);

impl TemplateId {
    /// Returns the id as string slice.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl From<String> for TemplateId {
    fn from(id: String) -> Self {
        TemplateId(id)
    }
}

impl From<&str> for TemplateId {
    fn from(id: &str) -> Self {
        TemplateId(id.to_string())
    }
}

impl std::fmt::Display for TemplateId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

/// SHA-256 digest, which is hex encoded in text form.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct Digest(#[serde(with = "hex")] pub(crate) [u8; 32]);

/// Helpers to serialize and deserialize a digest as hex string.
mod hex {
    pub fn serialize<S: serde::Serializer>(bytes: &[u8; 32], s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&bytes.iter().map(|b| format!("{b:02x}")).collect::<String>())
    }

    pub fn deserialize<'de, D: serde::Deserializer<'de>>(d: D) -> Result<[u8; 32], D::Error> {
        use serde::Deserialize as _;
        let text = String::deserialize(d)?;
        let mut out = [0u8; 32];
        for (i, b) in out.iter_mut().enumerate() {
            *b = u8::from_str_radix(text.get(i * 2..i * 2 + 2).unwrap_or(""), 16)
                .map_err(serde::de::Error::custom)?;
        }
        Ok(out)
    }
}

impl Digest {
    /// Digests the file at `path` in a streaming way.
    pub fn of_file(path: &Path) -> Result<Digest> {
        use sha2::Digest as _;

        let mut file = std::fs::File::open(path).map_err(Error::Io)?;
        let mut hasher = sha2::Sha256::new();
        std::io::copy(&mut file, &mut hasher).map_err(Error::Io)?;
        Ok(Digest(hasher.finalize().into()))
    }

    /// Digests given `bytes`.
    pub fn of_bytes(bytes: &[u8]) -> Digest {
        use sha2::Digest as _;

        Digest(sha2::Sha256::digest(bytes).into())
    }
}

impl std::fmt::Display for Digest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        for byte in self.0 {
            write!(f, "{byte:02x}")?;
        }
        Ok(())
    }
}

/// Digest of device layout, computed over canonical string
/// `v1|<arch>|<disk><channel><network>`, each device is either 0 or 1. The
/// format is pinned since stamp compares it byte by byte at registration.
pub(crate) fn layout_digest(arch: &str, devices: DeviceSet) -> Digest {
    let flag = |on: bool| if on { '1' } else { '0' };
    let layout = format!(
        "v1|{arch}|{}{}{}",
        flag(devices.disk),
        flag(devices.channel),
        flag(devices.network)
    );
    Digest::of_bytes(layout.as_bytes())
}

/// Virtio devices of the guest. These three booleans decide device count
/// of the machine, so a clone has to reproduce the same set.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct DeviceSet {
    /// Disk is attached.
    pub disk: bool,
    /// Vsock channel is attached.
    pub channel: bool,
    /// Network link is attached.
    pub network: bool,
}

/// Shape of the guest which a clone must reproduce.
#[derive(Debug, Clone, Copy, serde::Serialize, serde::Deserialize)]
pub struct GuestShape {
    /// Guest RAM size in bytes.
    pub memory: u64,
    /// Number of vCPUs.
    pub vcpus: u16,
    /// Device set.
    pub devices: DeviceSet,
}

/// The build which wrote the template. It is compared at registration
/// only, not at spawn.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct BuildStamp {
    /// `lingcore` crate version.
    pub lingcore: String,
    /// Digest of device layout for this arch.
    pub layout: Digest,
    /// Architecture of the guest.
    pub arch: String,
}

/// Registered metadata of a template.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct TemplateMeta {
    /// Content address.
    pub id: TemplateId,
    /// Guest shape which a clone must reproduce.
    pub shape: GuestShape,
    /// Build which wrote the template.
    pub stamp: BuildStamp,
    /// Digest of the kernel used to build the template.
    pub kernel: Digest,
    /// Digest of the rootfs used to build the template, if attached.
    pub rootfs: Option<Digest>,
    /// Build time.
    pub built_at: SystemTime,
    /// Size of the template on disk in bytes.
    pub bytes: u64,
}

/// Plan to build a template from. `devices.channel` is mandatory, since
/// the incoming connection from agent is the only supported readiness
/// signal.
#[derive(Debug, Clone)]
pub struct TemplatePlan {
    /// Kernel image path, a bzImage on x86_64 or an Image on riscv64.
    pub kernel: PathBuf,
    /// Initramfs path, a cpio archive loaded above the kernel.
    pub initrd: Option<PathBuf>,
    /// Kernel command line.
    pub cmdline: String,
    /// Guest RAM size in bytes.
    pub memory: u64,
    /// Number of vCPUs.
    pub vcpus: u16,
    /// Device set. `disk` and `network` are rejected at build time.
    pub devices: DeviceSet,
    /// Name to register the template with. Digest is used if not set.
    pub name: Option<String>,
    /// Maximum time to wait for READY from agent while booting for build.
    pub ready_timeout: Duration,
}

impl Default for TemplatePlan {
    fn default() -> Self {
        TemplatePlan {
            kernel: PathBuf::new(),
            initrd: None,
            cmdline: "console=ttyS0".to_string(),
            memory: 512 << 20,
            vcpus: 2,
            devices: DeviceSet {
                disk: false,
                channel: true,
                network: false,
            },
            name: None,
            ready_timeout: Duration::from_secs(60),
        }
    }
}

/// Registered template, with its directory, meta and RAM image. The image
/// is held open since truncating it under a live clone would cause SIGBUS.
pub struct Template {
    pub(crate) dir: PathBuf,
    pub(crate) meta: TemplateMeta,
    pub(crate) ram: std::fs::File,
    /// State document, parsed at first clone and cached afterwards.
    pub(crate) state: std::sync::OnceLock<Snapshot>,
}

impl Template {
    /// Returns content address of the template.
    pub fn id(&self) -> &TemplateId {
        &self.meta.id
    }

    /// Returns registered metadata of the template.
    pub fn meta(&self) -> &TemplateMeta {
        &self.meta
    }

    /// Returns the RAM image, which is held open as long as the template
    /// lives. A clone maps it copy-on-write.
    pub fn ram(&self) -> &std::fs::File {
        &self.ram
    }

    /// Returns path of the state document which a clone restores from.
    pub fn state_path(&self) -> PathBuf {
        self.dir.join("state.json")
    }

    /// Returns the state a clone restores from. It is parsed only once per
    /// handle, since the parse costs more than clone and restore together.
    pub fn state(&self) -> Result<&Snapshot> {
        if let Some(state) = self.state.get() {
            return Ok(state);
        }
        let file = std::fs::File::open(self.state_path()).map_err(Error::Io)?;
        let snapshot =
            Snapshot::read_from(&mut std::io::BufReader::new(file)).map_err(Error::Lingcore)?;
        Ok(self.state.get_or_init(|| snapshot))
    }

    /// Returns path of the kernel used to build the template. A clone does
    /// not open it, but `Config::kernel` still has to point to it.
    pub fn kernel_path(&self) -> PathBuf {
        self.dir.join("kernel.img")
    }
}

/// Root directory which holds templates and the runtime directory.
pub struct TemplateStore {
    pub(crate) root: PathBuf,
}

#[cfg(test)]
mod tests {
    use crate::template::*;

    /// Build a meta with a stamp accepted by current build.
    pub(crate) fn test_meta(id: &str) -> TemplateMeta {
        let devices = DeviceSet {
            disk: false,
            channel: true,
            network: false,
        };
        TemplateMeta {
            id: TemplateId(id.to_string()),
            shape: GuestShape {
                memory: 512 << 20,
                vcpus: 2,
                devices,
            },
            stamp: BuildStamp {
                lingcore: lingcore::VERSION.to_string(),
                layout: layout_digest(std::env::consts::ARCH, devices),
                arch: std::env::consts::ARCH.to_string(),
            },
            kernel: Digest::of_bytes(b"kernel"),
            rootfs: None,
            built_at: SystemTime::UNIX_EPOCH,
            bytes: 0,
        }
    }

    #[test]
    fn test_digest_known_input() {
        // sha256("abc") as per FIPS 180-4.
        assert_eq!(
            Digest::of_bytes(b"abc").to_string(),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }

    #[test]
    fn test_digest_file_matches_bytes() {
        let path = std::env::temp_dir().join(format!("lingcage-digest-{}", std::process::id()));
        std::fs::write(&path, b"abc").expect("write the file");
        assert_eq!(
            Digest::of_file(&path).expect("digest file"),
            Digest::of_bytes(b"abc")
        );
        std::fs::remove_file(&path).expect("remove the file");
    }

    #[test]
    fn test_layout_digest_stable() {
        let channel_only = DeviceSet {
            disk: false,
            channel: true,
            network: false,
        };
        assert_eq!(
            layout_digest("x86_64", channel_only),
            Digest::of_bytes(b"v1|x86_64|010")
        );
        // A different device set or arch produces a different digest.
        let with_disk = DeviceSet {
            disk: true,
            ..channel_only
        };
        assert_ne!(
            layout_digest("x86_64", channel_only),
            layout_digest("x86_64", with_disk)
        );
        assert_ne!(
            layout_digest("x86_64", channel_only),
            layout_digest("riscv64", channel_only)
        );
    }

    #[test]
    fn test_template_meta_json_round_trip() {
        let meta = test_meta("4f2a");
        let json = serde_json::to_string(&meta).expect("serialize meta");
        let back: TemplateMeta = serde_json::from_str(&json).expect("deserialize meta");
        assert_eq!(back.id, meta.id);
        assert_eq!(back.kernel, meta.kernel);
        assert_eq!(back.rootfs, meta.rootfs);
        assert_eq!(back.stamp.layout, meta.stamp.layout);
        assert_eq!(back.stamp.lingcore, meta.stamp.lingcore);
        assert_eq!(
            serde_json::to_string(&back).expect("serialize meta again"),
            json
        );
    }
}
