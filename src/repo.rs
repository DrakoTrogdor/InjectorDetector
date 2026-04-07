//! Repository loader.
//!
//! Resolves a CLI argument to a [`LoadedRepo`]. Local paths are opened in
//! place; remote URLs are shallow-cloned into a tempdir that is removed
//! when the [`LoadedRepo`] is dropped.

use std::path::{Path, PathBuf};
use std::sync::atomic::AtomicBool;

use anyhow::{Context, Result, bail};

use crate::config::ScanConfig;

/// A repository that has been resolved to a local working directory.
pub struct LoadedRepo {
    pub root: PathBuf,
    pub rev: String,
    /// True if the user passed `--rev` (so the walker should warn if it
    /// can't honor it instead of silently dropping the request).
    pub rev_explicit: bool,
    _tempdir: Option<tempfile::TempDir>,
}

impl LoadedRepo {
    pub fn root(&self) -> &Path {
        &self.root
    }
}

/// Resolve `source` to a [`LoadedRepo`].
pub fn load(source: &str, config: &ScanConfig) -> Result<LoadedRepo> {
    let path = Path::new(source);
    if path.exists() {
        return open_local(path, config);
    }

    if config.no_clone {
        bail!("--no-clone set and {source} is not a local path");
    }

    if looks_like_url(source) {
        return clone_remote(source, config);
    }

    bail!("{source} is neither an existing path nor a recognised git URL");
}

fn looks_like_url(source: &str) -> bool {
    source.starts_with("http://")
        || source.starts_with("https://")
        || source.starts_with("git@")
        || source.starts_with("ssh://")
        || source.starts_with("git://")
}

fn open_local(path: &Path, config: &ScanConfig) -> Result<LoadedRepo> {
    let canonical = path
        .canonicalize()
        .with_context(|| format!("failed to canonicalize {}", path.display()))?;

    // Best-effort: confirm it looks like a git repo. Non-git directories
    // are still allowed for now so the walker can be exercised on raw trees.
    let _ = gix::open(&canonical);

    Ok(LoadedRepo {
        root: canonical,
        rev: config.rev.clone(),
        rev_explicit: config.rev != "HEAD",
        _tempdir: None,
    })
}

fn clone_remote(url: &str, config: &ScanConfig) -> Result<LoadedRepo> {
    tracing::info!(url, "cloning remote repository");
    let tempdir = tempfile::Builder::new()
        .prefix("injector-detector-")
        .tempdir()
        .context("failed to create temp dir for clone")?;
    let target = tempdir.path().to_path_buf();

    let interrupt = AtomicBool::new(false);
    let mut prepare = gix::prepare_clone(url, &target)
        .with_context(|| format!("failed to prepare clone of {url}"))?;

    let (mut checkout, _outcome) = prepare
        .fetch_then_checkout(gix::progress::Discard, &interrupt)
        .with_context(|| format!("failed to fetch {url}"))?;

    let (_repo, _outcome) = checkout
        .main_worktree(gix::progress::Discard, &interrupt)
        .with_context(|| format!("failed to checkout worktree for {url}"))?;

    // If --keep was set, we leak the tempdir handle so that its destructor
    // doesn't remove the directory on drop. The path is logged so the
    // user can find it after the scan finishes.
    let tempdir_handle = if config.keep {
        let path = tempdir.path().to_path_buf();
        std::mem::forget(tempdir);
        tracing::info!(path = %path.display(), "--keep set; cloned repo preserved on disk");
        None
    } else {
        Some(tempdir)
    };

    Ok(LoadedRepo {
        root: target,
        rev: config.rev.clone(),
        rev_explicit: config.rev != "HEAD",
        _tempdir: tempdir_handle,
    })
}
