//! File walker.
//!
//! Two modes:
//! * If the loaded repo is a real git repo, we resolve `--rev` to a tree
//!   and stream the blobs of that snapshot. This is consistent (no TOCTOU
//!   against the working copy) and respects the committed state only.
//! * If `gix::open` failed (e.g. the user pointed at a plain directory),
//!   we fall back to the `ignore`-crate working-tree walker so the tool
//!   still works on raw file trees.

use std::collections::HashSet;
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

/// Built-in exclusion globs for directories that almost always contain
/// machine-generated content and should never be scanned by default.
///
/// Scoped deliberately to **unambiguous** build / cache / dependency
/// directories. Generic names like `bin/`, `build/`, `dist/`, `out/`
/// are *not* included because legitimate projects put real source or
/// docs in those.
const DEFAULT_EXCLUDE_GLOBS: &[&str] = &[
    // Rust / Maven
    "**/target/**",
    // .NET / MSBuild
    "**/obj/**",
    // Node / web
    "**/node_modules/**",
    "**/.next/**",
    "**/.nuxt/**",
    "**/.parcel-cache/**",
    "**/.turbo/**",
    // Python
    "**/__pycache__/**",
    "**/.venv/**",
    "**/venv/**",
    "**/.tox/**",
    "**/.pytest_cache/**",
    "**/.mypy_cache/**",
    "**/.ruff_cache/**",
    "**/*.egg-info/**",
    // JVM
    "**/.gradle/**",
    // Infra
    "**/.terraform/**",
    "**/.serverless/**",
    // Ruby / CocoaPods
    "**/.bundle/**",
    "**/Pods/**",
    // VCS internals that the ignore crate usually handles but we
    // want to be sure about for the gix-tree walker path.
    "**/.git/**",
];

/// Walk a loaded repo and yield in-scope files.
pub fn walk(repo: &LoadedRepo, config: &ScanConfig) -> Result<Box<dyn Iterator<Item = Result<WalkEntry>>>> {
    let include = build_globset(&config.include).context("invalid --include glob")?;
    // User excludes are merged with the built-in default exclude list
    // unless the user explicitly turned it off.
    let mut exclude_patterns = config.exclude.clone();
    if config.use_default_excludes {
        exclude_patterns.extend(DEFAULT_EXCLUDE_GLOBS.iter().map(|s| (*s).to_string()));
    }
    let exclude = build_globset(&exclude_patterns).context("invalid --exclude glob")?;
    let max_bytes = config.max_binary_bytes;

    // Compute the incremental filter if --since is set.
    let incremental_filter = if let Some(since) = config.since.as_deref() {
        match gix::open(repo.root()) {
            Ok(git) => match changed_paths(&git, since, &repo.rev) {
                Ok(set) => {
                    tracing::info!(
                        since,
                        to = %repo.rev,
                        files = set.len(),
                        "incremental scan restricted to changed files"
                    );
                    Some(set)
                }
                Err(e) => {
                    tracing::warn!(
                        since,
                        error = %e,
                        "failed to compute incremental diff; scanning everything"
                    );
                    None
                }
            },
            Err(e) => {
                tracing::warn!(error = %e, "--since set but target is not a git repo; ignoring");
                None
            }
        }
    } else {
        None
    };

    if let Ok(git) = gix::open(repo.root()) {
        match walk_git_tree(
            git,
            &repo.rev,
            include.clone(),
            exclude.clone(),
            max_bytes,
            incremental_filter.clone(),
        ) {
            Ok(entries) => return Ok(Box::new(entries.into_iter().map(Ok))),
            Err(e) => {
                if repo.rev_explicit {
                    tracing::warn!(
                        rev = %repo.rev,
                        error = %e,
                        "git tree walk failed; --rev will be ignored and the working tree scanned instead"
                    );
                } else {
                    tracing::debug!(error = %e, "git tree walk failed; falling back to working tree");
                }
            }
        }
    } else if repo.rev_explicit {
        tracing::warn!(
            rev = %repo.rev,
            "target is not a git repository; --rev will be ignored and the working tree scanned instead"
        );
    }

    Ok(Box::new(walk_working_tree(
        repo.root().to_path_buf(),
        include,
        exclude,
        max_bytes,
        incremental_filter,
    )))
}

fn walk_git_tree(
    repo: gix::Repository,
    rev: &str,
    include: Option<GlobSet>,
    exclude: Option<GlobSet>,
    max_bytes: u64,
    incremental_filter: Option<HashSet<PathBuf>>,
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
        if let Some(filter) = incremental_filter.as_ref()
            && !filter.contains(&rel)
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
    incremental_filter: Option<HashSet<PathBuf>>,
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
        if let Some(filter) = incremental_filter.as_ref()
            && !filter.contains(&rel)
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

/// Return the set of relative paths that differ between `base_rev` and
/// `to_rev`. Used by `--since` to drive incremental scans. Rather than
/// wrestling with gix's diff API across versions, we simply resolve each
/// side to a tree, collect `(path, oid)` maps, and emit paths that were
/// added, removed, or have a different blob oid. That's equivalent to a
/// name-status diff for our purposes and is stable across gix releases.
fn changed_paths(repo: &gix::Repository, base_rev: &str, to_rev: &str) -> Result<HashSet<PathBuf>> {
    let base = resolve_tree_paths(repo, base_rev)
        .with_context(|| format!("failed to resolve base rev {base_rev}"))?;
    let to = resolve_tree_paths(repo, to_rev)
        .with_context(|| format!("failed to resolve rev {to_rev}"))?;

    let mut out = HashSet::new();
    for (path, oid) in &to {
        match base.get(path) {
            Some(base_oid) if base_oid == oid => {}
            _ => {
                out.insert(path.clone());
            }
        }
    }
    for path in base.keys() {
        if !to.contains_key(path) {
            out.insert(path.clone());
        }
    }
    Ok(out)
}

fn resolve_tree_paths(
    repo: &gix::Repository,
    rev: &str,
) -> Result<std::collections::HashMap<PathBuf, gix::ObjectId>> {
    let tree = repo
        .rev_parse_single(rev)?
        .object()?
        .peel_to_kind(gix::object::Kind::Tree)?
        .into_tree();
    let mut recorder = gix::traverse::tree::Recorder::default();
    tree.traverse().breadthfirst(&mut recorder)?;
    let mut out = std::collections::HashMap::new();
    for entry in recorder.records {
        if entry.mode.is_tree() {
            continue;
        }
        out.insert(PathBuf::from(entry.filepath.to_string()), entry.oid);
    }
    Ok(out)
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
