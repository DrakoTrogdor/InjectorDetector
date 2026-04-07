//! Helper that builds a real git repository at test time using `gix`,
//! so the gix tree-walker code path in `walk.rs` actually gets exercised.
//!
//! No external `git` binary is required.

#![allow(dead_code)]

use std::path::Path;

use gix::objs::tree::{Entry, EntryKind};
use tempfile::TempDir;

/// A built repo plus its tempdir handle. Drop the struct to clean up.
pub struct BuiltRepo {
    pub dir: TempDir,
}

impl BuiltRepo {
    pub fn path(&self) -> &Path {
        self.dir.path()
    }
}

/// Build a fresh git repo containing the given `(filename, content)` files
/// committed under HEAD.
pub fn build_repo(files: &[(&str, &str)]) -> BuiltRepo {
    let dir = tempfile::Builder::new()
        .prefix("injdet-gittest-")
        .tempdir()
        .expect("tempdir");
    let repo = gix::init(dir.path()).expect("gix init");

    let mut entries: Vec<Entry> = files
        .iter()
        .map(|(name, content)| {
            let oid = repo
                .write_blob(content.as_bytes())
                .expect("write blob")
                .detach();
            Entry {
                mode: EntryKind::Blob.into(),
                filename: (*name).into(),
                oid,
            }
        })
        .collect();
    entries.sort();

    let tree = gix::objs::Tree { entries };
    let tree_id = repo.write_object(&tree).expect("write tree").detach();

    let sig = gix::actor::SignatureRef {
        name: "InjectorDetector Test".into(),
        email: "test@example.invalid".into(),
        time: gix::date::Time::now_utc(),
    };

    let no_parents: Vec<gix::ObjectId> = Vec::new();
    repo.commit_as(sig, sig, "HEAD", "test commit", tree_id, no_parents)
        .expect("commit");

    BuiltRepo { dir }
}
