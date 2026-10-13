//! The directory a far end serves, held in memory and shared by every
//! session that serves it: files and the directories made in it, each step
//! made whole under one lock, as a file system makes each of its own.
//!
//! Not a file system. What it does keep is what a claim leans on: `MKD` of
//! a name that exists is refused, a rename onto a name that exists is
//! refused, and a rename keeps the file's modification time (RFC 3659's
//! `MDTM` and `MLSD` `modify`), which is the write that last stamped it.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};

/// The files and directories; cloned, the same ones.
#[derive(Clone, Default)]
pub struct Store(Arc<Mutex<Held>>);

#[derive(Default)]
struct Held {
    /// Each file: its bytes, and the write that last stamped it.
    files: BTreeMap<String, (Vec<u8>, u64)>,
    directories: BTreeSet<String>,
    writes: u64,
}

impl Held {
    fn exists(&self, name: &str) -> bool {
        self.files.contains_key(name) || self.directories.contains(name)
    }
}

/// One entry of a listing: its name, whether it is a file, its size and
/// its modification time as `MDTM` writes it.
pub type Listed = (String, bool, usize, String);

impl Store {
    /// A store holding `files`, none of them written since.
    #[must_use]
    pub fn holding(files: BTreeMap<String, Vec<u8>>) -> Self {
        let store = Self::default();
        store.held().files = files
            .into_iter()
            .map(|(name, bytes)| (name, (bytes, 0)))
            .collect();
        store
    }

    fn held(&self) -> MutexGuard<'_, Held> {
        self.0.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// The files, name to bytes.
    #[must_use]
    pub fn files(&self) -> BTreeMap<String, Vec<u8>> {
        self.held()
            .files
            .iter()
            .map(|(name, (bytes, _))| (name.clone(), bytes.clone()))
            .collect()
    }

    /// `name` written whole as `bytes`, replacing what was there.
    pub fn write(&self, name: &str, bytes: Vec<u8>) {
        let mut held = self.held();
        held.writes += 1;
        let written = held.writes;
        held.files.insert(name.to_string(), (bytes, written));
    }

    /// The bytes of `name`.
    #[must_use]
    pub fn read(&self, name: &str) -> Option<Vec<u8>> {
        self.held().files.get(name).map(|(bytes, _)| bytes.clone())
    }

    /// The size and modification time of the file `name`.
    #[must_use]
    pub fn stamp(&self, name: &str) -> Option<(usize, String)> {
        self.held()
            .files
            .get(name)
            .map(|(bytes, written)| (bytes.len(), modified(*written)))
    }

    /// Every entry directly in `directory`, the top where `None`.
    #[must_use]
    pub fn list(&self, directory: Option<&str>) -> Vec<Listed> {
        let held = self.held();
        let within = |name: &str| match directory {
            None => !name.contains('/'),
            Some(dir) => name
                .strip_prefix(dir)
                .and_then(|rest| rest.strip_prefix('/'))
                .is_some_and(|rest| !rest.is_empty() && !rest.contains('/')),
        };
        let files = held
            .files
            .iter()
            .filter(|(name, _)| within(name))
            .map(|(name, (bytes, written))| (name.clone(), true, bytes.len(), modified(*written)));
        let directories = held
            .directories
            .iter()
            .filter(|name| within(name))
            .map(|name| (name.clone(), false, 0, modified(0)));
        files.chain(directories).collect()
    }

    /// Make the directory `name`: `false` where anything of that name
    /// exists, or its parent does not.
    #[must_use]
    pub fn make_directory(&self, name: &str) -> bool {
        let mut held = self.held();
        let parent = name.rsplit_once('/').map(|(parent, _)| parent);
        if held.exists(name) || parent.is_some_and(|parent| !held.directories.contains(parent)) {
            return false;
        }
        held.directories.insert(name.to_string())
    }

    /// Remove the empty directory `name`: `false` where it is not one.
    #[must_use]
    pub fn remove_directory(&self, name: &str) -> bool {
        let mut held = self.held();
        let prefix = format!("{name}/");
        let inside = held.files.keys().any(|one| one.starts_with(&prefix))
            || held.directories.iter().any(|one| one.starts_with(&prefix));
        !inside && held.directories.remove(name)
    }

    /// Rename the file `from` to `to`, its stamp kept: `false` where `from`
    /// is no file or anything lies at `to`.
    #[must_use]
    pub fn rename(&self, from: &str, to: &str) -> bool {
        let mut held = self.held();
        if held.exists(to) {
            return false;
        }
        match held.files.remove(from) {
            Some(file) => {
                held.files.insert(to.to_string(), file);
                true
            }
            None => false,
        }
    }

    /// Whether `name` is a file or a directory here.
    #[must_use]
    pub fn exists(&self, name: &str) -> bool {
        self.held().exists(name)
    }

    /// Delete the file `name`: `false` where there is none.
    #[must_use]
    pub fn delete(&self, name: &str) -> bool {
        self.held().files.remove(name).is_some()
    }
}

/// The modification time of the write numbered `written`, as `MDTM`
/// writes one: the store counts its writes, so a file written again has
/// another time.
fn modified(written: u64) -> String {
    format!("19700101{written:06}")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_directory_is_made_once_and_a_rename_never_lands_on_a_name() {
        let store = Store::default();
        store.write("order.edi", b"ISA".to_vec());
        assert!(store.make_directory("order.edi.xmip-claim"));
        assert!(!store.make_directory("order.edi.xmip-claim"), "once");
        assert!(!store.make_directory("order.edi"), "a file of that name");
        assert!(store.make_directory("order.edi.xmip-claim/node"));
        assert!(!store.remove_directory("order.edi.xmip-claim"), "not empty");
        let before = store.stamp("order.edi");
        assert!(store.rename("order.edi", "order.edi.claimed"));
        assert_eq!(store.stamp("order.edi.claimed"), before, "its stamp kept");
        store.write("order.edi", b"new".to_vec());
        assert!(
            !store.rename("order.edi.claimed", "order.edi"),
            "never over one"
        );
        assert_eq!(store.list(Some("order.edi.xmip-claim")).len(), 1);
        assert_eq!(store.list(None).len(), 3);
    }
}
