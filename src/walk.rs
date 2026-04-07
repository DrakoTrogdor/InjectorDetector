//! File walker.
//!
//! Two modes:
//! * If the loaded repo is a real git repo, we resolve `--rev` to a tree
//!   and stream the blobs of that snapshot. This is consistent (no TOCTOU
//!   against the working copy) and respects the committed state only.
//! * If `gix::open` failed (e.g. the user pointed at a plain directory),
//!   we fall back to the `ignore`-crate working-tree walker so the tool
//!   still works on raw file trees.

use std::path::PathBuf;

use anyhow::{Context, Result};
use globset::{Glob, GlobSet, GlobSetBuilder};
use ignore::WalkBuilder;

use crate::config::ScanConfig;
use crate::repo::LoadedRepo;

/// One file the walker has decided is in scope.
#[derive(Debug, Clone)]
pub struct WalkEntry {
    pub path: PathBuf,
    pub bytes: Vec<u8>,
}

/// Walk a loaded repo and yield in-scope files.
pub fn walk(repo: &LoadedRepo, config: &ScanConfig) -> Result<Box<dyn Iterator<Item = Result<WalkEntry>>>> {
    let include = build_globset(&config.include).context("invalid --include glob")?;
    let exclude = build_globset(&config.exclude).context("invalid --exclude glob")?;
    let max_bytes = config.max_binary_bytes;

    if let Ok(git) = gix::open(repo.root()) {
        match walk_git_tree(git, &repo.rev, include.clone(), exclude.clone(), max_bytes) {
            Ok(entries) => return Ok(Box::new(entries.into_iter().map(Ok))),
            Err(e) => {
                tracing::warn!(error = %e, "git tree walk failed; falling back to working tree");
            }
        }
    }

    Ok(Box::new(walk_working_tree(
        repo.root().to_path_buf(),
        include,
        exclude,
        max_bytes,
    )))
}

fn walk_git_tree(
    repo: gix::Repository,
    rev: &str,
    include: Option<GlobSet>,
    exclude: Option<GlobSet>,
    max_bytes: u64,
) -> Result<Vec<WalkEntry>> {
    let object = repo
        .rev_parse_single(rev)
        .with_context(|| format!("failed to resolve revision {rev}"))?
        .object()
        .context("failed to load resolved object")?;

    let tree = object.peel_to_kind(gix::object::Kind::Tree)?.into_tree();

    let mut entries = Vec::new();
    let mut recorder = gix::traverse::tree::Recorder::default();
    tree.traverse().breadthfirst(&mut recorder)?;

    for entry in recorder.records {
        if entry.mode.is_tree() {
            continue;
        }
        let path_str = entry.filepath.to_string();
        let rel = PathBuf::from(&path_str);

        if let Some(set) = include.as_ref()
            && !set.is_match(&rel)
        {
            continue;
        }
        if let Some(set) = exclude.as_ref()
            && set.is_match(&rel)
        {
            continue;
        }

        let blob = match repo.find_object(entry.oid) {
            Ok(o) => o,
            Err(_) => continue,
        };
        if (blob.data.len() as u64) > max_bytes {
            continue;
        }
        entries.push(WalkEntry {
            path: rel,
            bytes: blob.data.clone(),
        });
    }

    Ok(entries)
}

fn walk_working_tree(
    root: PathBuf,
    include: Option<GlobSet>,
    exclude: Option<GlobSet>,
    max_bytes: u64,
) -> impl Iterator<Item = Result<WalkEntry>> {
    let walker = WalkBuilder::new(&root)
        .standard_filters(true)
        .hidden(false)
        .build();

    walker.filter_map(move |result| {
        let dent = match result {
            Ok(d) => d,
            Err(e) => return Some(Err(anyhow::anyhow!(e))),
        };
        if !dent.file_type().map(|t| t.is_file()).unwrap_or(false) {
            return None;
        }
        let path = dent.into_path();
        let rel = path.strip_prefix(&root).unwrap_or(&path).to_path_buf();

        if let Some(set) = include.as_ref()
            && !set.is_match(&rel)
        {
            return None;
        }
        if let Some(set) = exclude.as_ref()
            && set.is_match(&rel)
        {
            return None;
        }

        match std::fs::metadata(&path) {
            Ok(m) if m.len() > max_bytes => return None,
            Ok(_) => {}
            Err(e) => return Some(Err(anyhow::anyhow!(e))),
        }

        match std::fs::read(&path) {
            Ok(bytes) => Some(Ok(WalkEntry { path: rel, bytes })),
            Err(e) => Some(Err(anyhow::anyhow!(e))),
        }
    })
}

fn build_globset(patterns: &[String]) -> Result<Option<GlobSet>> {
    if patterns.is_empty() {
        return Ok(None);
    }
    let mut builder = GlobSetBuilder::new();
    for p in patterns {
        builder.add(Glob::new(p)?);
    }
    Ok(Some(builder.build()?))
}
