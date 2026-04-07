//! On-demand fetcher for bundled model assets.
//!
//! Gated by the `embeddings` Cargo feature because it transitively pulls
//! in `ureq`. Files are cached under the user's data directory (via the
//! `dirs` crate) so subsequent scans skip the download entirely.

#![cfg(feature = "embeddings")]

use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};

/// The default bundled model: HuggingFace `sentence-transformers/all-MiniLM-L6-v2`.
/// Small (~22 MB fp32 ONNX), fast, and a common baseline for
/// sentence-similarity work. We pin to an exact revision so the cached
/// files stay reproducible.
const REPO: &str = "sentence-transformers/all-MiniLM-L6-v2";
const REVISION: &str = "main";

/// Returns `(model_path, tokenizer_path)`, downloading both into the
/// user cache dir on first use.
pub fn ensure_bundled_model() -> Result<(PathBuf, PathBuf)> {
    let cache_root = cache_root()?;
    let dir = cache_root.join("models").join(REPO.replace('/', "--"));
    std::fs::create_dir_all(&dir)
        .with_context(|| format!("failed to create model cache dir {}", dir.display()))?;

    let model_path = dir.join("model.onnx");
    let tokenizer_path = dir.join("tokenizer.json");

    if !model_path.exists() {
        let url = format!(
            "https://huggingface.co/{REPO}/resolve/{REVISION}/onnx/model.onnx"
        );
        download_to(&url, &model_path)?;
    }
    if !tokenizer_path.exists() {
        let url =
            format!("https://huggingface.co/{REPO}/resolve/{REVISION}/tokenizer.json");
        download_to(&url, &tokenizer_path)?;
    }

    Ok((model_path, tokenizer_path))
}

fn cache_root() -> Result<PathBuf> {
    if let Some(dir) = dirs::cache_dir() {
        Ok(dir.join("injector-detector"))
    } else {
        bail!("no user cache directory available on this platform");
    }
}

fn download_to(url: &str, dest: &Path) -> Result<()> {
    tracing::info!(url, dest = %dest.display(), "downloading model asset");
    let response = ureq::get(url)
        .call()
        .with_context(|| format!("HTTP request failed for {url}"))?;
    let mut reader = response.into_reader();
    let tmp = dest.with_extension("part");
    {
        let mut file = std::fs::File::create(&tmp)
            .with_context(|| format!("failed to create {}", tmp.display()))?;
        std::io::copy(&mut reader, &mut file)
            .with_context(|| format!("failed to stream {url}"))?;
    }
    std::fs::rename(&tmp, dest)
        .with_context(|| format!("failed to rename {} → {}", tmp.display(), dest.display()))?;
    Ok(())
}
