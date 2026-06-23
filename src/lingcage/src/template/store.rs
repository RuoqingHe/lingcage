// SPDX-FileCopyrightText: 2026 LingCage <opensource@lingcage.com>
//
// SPDX-License-Identifier: Apache-2.0

//! Template store, which registers, lists and removes templates. A
//! flock protocol makes sure a live image is not removed while a
//! sandbox is still using it.

use std::os::fd::AsRawFd;
use std::path::{Path, PathBuf};

use crate::error::{Error, Result};
use crate::template::{Digest, Template, TemplateId, TemplateMeta, TemplateStore, layout_digest};

impl TemplateStore {
    /// Open the store at `root`, create the layout if it is missing.
    pub fn open(root: impl AsRef<Path>) -> Result<Self> {
        let store = TemplateStore {
            root: root.as_ref().to_path_buf(),
        };
        std::fs::create_dir_all(store.aliases_dir()).map_err(Error::Io)?;
        std::fs::create_dir_all(store.run_dir()).map_err(Error::Io)?;
        Ok(store)
    }

    /// Adopt a template directory built elsewhere. Stamp, shape and digest
    /// are verified here, so that a bad template fails at register time
    /// instead of at spawn time.
    pub fn register(&self, dir: impl AsRef<Path>) -> Result<Template> {
        let dir = dir.as_ref();
        let meta = read_meta(dir)?;
        let id = template_id(dir).map_err(|err| match err {
            Error::Io(io) => Error::TemplateBad {
                what: format!("failed to read template files: {io}"),
            },
            other => other,
        })?;
        if id != meta.id {
            return Err(Error::TemplateBad {
                what: format!(
                    "template.json names {}, the files digest to {id}; the template needs \
                     re-baking",
                    meta.id
                ),
            });
        }
        if meta.stamp.lingcore != lingcore::VERSION {
            return Err(Error::TemplateBad {
                what: format!(
                    "template baked by lingcore {} but this build is {}, please re-bake it",
                    meta.stamp.lingcore,
                    lingcore::VERSION
                ),
            });
        }
        let layout = layout_digest(std::env::consts::ARCH, meta.shape.devices);
        if meta.stamp.layout != layout {
            return Err(Error::TemplateBad {
                what: format!(
                    "template baked for layout {} but this build has {layout}, re-bake is needed",
                    meta.stamp.layout
                ),
            });
        }
        let into = self.templates_dir().join(id.as_str());
        std::fs::create_dir_all(&into).map_err(Error::Io)?;
        for name in ["ram.img", "state.json", "kernel.img", "template.json"] {
            place(&dir.join(name), &into.join(name))?;
        }
        self.open_template(into)
    }

    /// Returns the template registered as `id`.
    pub fn get(&self, id: &TemplateId) -> Result<Template> {
        self.open_template(self.resolve(id)?)
    }

    /// List all registered templates.
    pub fn list(&self) -> Result<Vec<TemplateMeta>> {
        let mut metas = Vec::new();
        let mut seen = std::collections::HashSet::new();
        let mut read = |dir: PathBuf| -> Result<()> {
            let meta = read_meta(&dir)?;
            if seen.insert(meta.id.as_str().to_string()) {
                metas.push(meta);
            }
            Ok(())
        };
        for entry in std::fs::read_dir(self.templates_dir()).map_err(Error::Io)? {
            let entry = entry.map_err(Error::Io)?;
            let name = entry.file_name();
            let name = name.to_string_lossy();
            // Skip aliases dir and staging dir left by a crashed build.
            if name == "aliases" || name.starts_with('.') {
                continue;
            }
            if entry.path().is_dir() {
                read(entry.path())?;
            }
        }
        for entry in std::fs::read_dir(self.aliases_dir()).map_err(Error::Io)? {
            let entry = entry.map_err(Error::Io)?;
            // Skip dangling alias.
            let Ok(target) = entry.path().canonicalize() else {
                continue;
            };
            if target.is_dir() {
                read(target)?;
            }
        }
        Ok(metas)
    }

    /// Remove a template. Refused with `Error::TemplateInUse` if any sandbox
    /// is still holding it.
    pub fn remove(&self, id: &TemplateId) -> Result<()> {
        let dir = self.resolve(id)?;
        let ram = std::fs::File::open(dir.join("ram.img")).map_err(Error::Io)?;
        // In-use check. `open_template` holds a shared flock on the image as
        // long as the Template lives, so exclusive lock can only be taken when
        // no Template has the image open.
        if !try_lock_exclusive(&ram)? {
            return Err(Error::TemplateInUse {
                id: id.as_str().to_string(),
            });
        }
        let name = dir.file_name().unwrap_or_default().to_os_string();
        for entry in std::fs::read_dir(self.aliases_dir()).map_err(Error::Io)? {
            let entry = entry.map_err(Error::Io)?;
            let Ok(target) = std::fs::read_link(entry.path()) else {
                continue;
            };
            if target.file_name() == Some(name.as_os_str()) {
                std::fs::remove_file(entry.path()).map_err(Error::Io)?;
            }
        }
        std::fs::remove_dir_all(&dir).map_err(Error::Io)?;
        Ok(())
    }

    /// Open the template in `dir`. Meta is read and RAM image is kept open
    /// with a shared flock as long as the Template lives.
    fn open_template(&self, dir: PathBuf) -> Result<Template> {
        let meta = read_meta(&dir)?;
        let ram = std::fs::File::open(dir.join("ram.img")).map_err(Error::Io)?;
        lock_shared(&ram)?;
        Ok(Template {
            dir,
            meta,
            ram,
            state: std::sync::OnceLock::new(),
        })
    }

    /// Returns the directory of template `id`, either directly or through
    /// an alias.
    fn resolve(&self, id: &TemplateId) -> Result<PathBuf> {
        let direct = self.templates_dir().join(id.as_str());
        if direct.is_dir() {
            return Ok(direct);
        }
        let missing = || Error::TemplateMissing {
            id: id.as_str().to_string(),
        };
        let target =
            std::fs::canonicalize(self.aliases_dir().join(id.as_str())).map_err(|_| missing())?;
        let templates = std::fs::canonicalize(self.templates_dir()).map_err(Error::Io)?;
        if target.is_dir() && target.parent() == Some(templates.as_path()) {
            return Ok(target);
        }
        Err(missing())
    }

    fn templates_dir(&self) -> PathBuf {
        self.root.join("templates")
    }

    fn aliases_dir(&self) -> PathBuf {
        self.templates_dir().join("aliases")
    }

    fn run_dir(&self) -> PathBuf {
        self.root.join("run")
    }
}

/// Content address of a template directory, which is the hex digest
/// over bytes of ram.img, state.json and kernel.img in this order.
fn template_id(dir: &Path) -> Result<TemplateId> {
    use sha2::Digest as _;

    let mut hasher = sha2::Sha256::new();
    for name in ["ram.img", "state.json", "kernel.img"] {
        let mut file = std::fs::File::open(dir.join(name)).map_err(Error::Io)?;
        std::io::copy(&mut file, &mut hasher).map_err(Error::Io)?;
    }
    Ok(TemplateId(Digest(hasher.finalize().into()).to_string()))
}

/// Read template.json under `dir`.
fn read_meta(dir: &Path) -> Result<TemplateMeta> {
    let text =
        std::fs::read_to_string(dir.join("template.json")).map_err(|err| Error::TemplateBad {
            what: format!("failed to read template.json in {}: {err}", dir.display()),
        })?;
    serde_json::from_str(&text).map_err(|err| Error::TemplateBad {
        what: format!(
            "template.json in {} is not a valid template document: {err}",
            dir.display()
        ),
    })
}

/// Link `source` into the store at `at`, fall back to copy across
/// filesystems. Files are content addressed, so an existing one is kept.
fn place(source: &Path, at: &Path) -> Result<()> {
    match std::fs::hard_link(source, at) {
        Ok(()) => Ok(()),
        Err(err) if err.kind() == std::io::ErrorKind::AlreadyExists => Ok(()),
        Err(err) if err.raw_os_error() == Some(libc::EXDEV) => {
            std::fs::copy(source, at).map_err(Error::Io)?;
            Ok(())
        }
        Err(err) => Err(Error::Io(err)),
    }
}

/// Take a shared flock on `file`, held as long as the file is open.
fn lock_shared(file: &std::fs::File) -> Result<()> {
    // SAFETY: the descriptor is valid as long as `file` lives.
    if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_SH) } != 0 {
        return Err(Error::Io(std::io::Error::last_os_error()));
    }
    Ok(())
}

/// Try to take an exclusive flock on `file`, returns `false` if someone
/// else is holding it.
fn try_lock_exclusive(file: &std::fs::File) -> Result<bool> {
    // SAFETY: the descriptor is valid as long as `file` lives.
    if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } == 0 {
        return Ok(true);
    }
    let err = std::io::Error::last_os_error();
    if err.raw_os_error() == Some(libc::EWOULDBLOCK) {
        return Ok(false);
    }
    Err(Error::Io(err))
}

#[cfg(test)]
mod tests {
    use std::os::unix::fs::symlink;

    use crate::error::Error;
    use crate::template::store::*;
    use crate::template::tests::test_meta;
    use crate::template::{TemplateId, TemplateStore};

    fn temp_root(tag: &str) -> PathBuf {
        let root =
            std::env::temp_dir().join(format!("lingcage-store-{tag}-{}", std::process::id()));
        // Leftover of a previous interrupted run would make the writes fail.
        match std::fs::remove_dir_all(&root) {
            Ok(()) => {}
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => {}
            Err(err) => panic!("failed to remove stale temp root: {err}"),
        }
        std::fs::create_dir_all(&root).expect("create the temp root");
        root
    }

    /// Write a template directory under templates dir of the store.
    fn fabricate(store: &TemplateStore, id: &str) {
        let dir = store.templates_dir().join(id);
        std::fs::create_dir_all(&dir).expect("create the template dir");
        std::fs::write(dir.join("ram.img"), b"ram").expect("write ram.img");
        std::fs::write(dir.join("state.json"), b"{}").expect("write state.json");
        std::fs::write(dir.join("kernel.img"), b"kernel").expect("write kernel.img");
        let json = serde_json::to_string(&test_meta(id)).expect("serialize meta");
        std::fs::write(dir.join("template.json"), json).expect("write template.json");
    }

    #[test]
    fn test_template_id_stable() {
        let root = temp_root("id");
        let dir = root.join("t");
        std::fs::create_dir_all(&dir).expect("create the dir");
        std::fs::write(dir.join("ram.img"), b"abc").expect("write ram.img");
        std::fs::write(dir.join("state.json"), b"").expect("write state.json");
        std::fs::write(dir.join("kernel.img"), b"").expect("write kernel.img");
        // sha256("abc") as per FIPS 180-4.
        let want = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";
        assert_eq!(template_id(&dir).expect("digest the dir").as_str(), want);
        assert_eq!(
            template_id(&dir).expect("digest the dir again").as_str(),
            want
        );
        std::fs::remove_dir_all(&root).expect("remove the temp root");
    }

    #[test]
    fn test_alias_resolve() {
        let root = temp_root("alias");
        let store = TemplateStore::open(&root).expect("open the store");
        fabricate(&store, "aa11");
        symlink("../aa11", store.aliases_dir().join("py")).expect("link the alias");
        let template = store
            .get(&TemplateId("py".to_string()))
            .expect("resolve the alias");
        assert_eq!(template.id().as_str(), "aa11");
        drop(template);
        // Name with neither directory nor alias is missing.
        assert!(matches!(
            store.get(&TemplateId("nope".to_string())),
            Err(Error::TemplateMissing { .. })
        ));
        std::fs::remove_dir_all(&root).expect("remove the temp root");
    }

    #[test]
    fn test_list_dedup_aliases() {
        // List follows aliases and reports each template once.
        let root = temp_root("list");
        let store = TemplateStore::open(&root).expect("open the store");
        fabricate(&store, "aa11");
        fabricate(&store, "bb22");
        symlink("../aa11", store.aliases_dir().join("py")).expect("link the alias");
        let mut ids: Vec<String> = store
            .list()
            .expect("list the store")
            .iter()
            .map(|meta| meta.id.as_str().to_string())
            .collect();
        ids.sort();
        assert_eq!(ids, vec!["aa11".to_string(), "bb22".to_string()]);
        std::fs::remove_dir_all(&root).expect("remove the temp root");
    }

    #[test]
    fn test_remove_refused_while_in_use() {
        let root = temp_root("inuse");
        let store = TemplateStore::open(&root).expect("open the store");
        fabricate(&store, "aa11");
        let held = store
            .get(&TemplateId("aa11".to_string()))
            .expect("hold the template");
        assert!(matches!(
            store.remove(&TemplateId("aa11".to_string())),
            Err(Error::TemplateInUse { .. })
        ));
        drop(held);
        store
            .remove(&TemplateId("aa11".to_string()))
            .expect("remove once released");
        assert!(matches!(
            store.get(&TemplateId("aa11".to_string())),
            Err(Error::TemplateMissing { .. })
        ));
        std::fs::remove_dir_all(&root).expect("remove the temp root");
    }

    #[test]
    fn test_register_verified_template() {
        let root = temp_root("register");
        let store = TemplateStore::open(root.join("store")).expect("open the store");
        let baked = root.join("baked");
        std::fs::create_dir_all(&baked).expect("create the baked dir");
        std::fs::write(baked.join("ram.img"), b"ram").expect("write ram.img");
        std::fs::write(baked.join("state.json"), b"{}").expect("write state.json");
        std::fs::write(baked.join("kernel.img"), b"kernel").expect("write kernel.img");
        let id = template_id(&baked).expect("digest the baked dir");
        let json = serde_json::to_string(&test_meta(id.as_str())).expect("serialize meta");
        std::fs::write(baked.join("template.json"), &json).expect("write template.json");

        let template = store.register(&baked).expect("register the template");
        assert_eq!(template.id(), &id);
        drop(template);
        store.get(&id).expect("get the registered template");

        // Stamp from another lingcore version is refused.
        let stale = json.replace(
            &format!("\"lingcore\":\"{}\"", lingcore::VERSION),
            "\"lingcore\":\"0.0.0\"",
        );
        std::fs::write(baked.join("template.json"), stale).expect("write the stale meta");
        assert!(matches!(
            store.register(&baked),
            Err(Error::TemplateBad { .. })
        ));
        std::fs::remove_dir_all(&root).expect("remove the temp root");
    }
}
