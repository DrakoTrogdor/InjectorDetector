//! Extractors turn raw file bytes into one or more `TextChunk`s tagged
//! with provenance.
//!
//! Format dispatch is by file extension first, then by well-known
//! filename (so e.g. `Cargo.lock` is routed through the TOML extractor
//! even though `.lock` isn't the primary extension for TOML). Unknown
//! extensions fall back to the plain-text extractor.

mod config;
mod markup;
mod notebook;
#[cfg(feature = "pdf")]
mod pdf;
mod source;
mod text;

use anyhow::Result;

use crate::chunk::chunk_text;
use crate::types::{Provenance, TextChunk};
use crate::walk::WalkEntry;

pub fn extract(entry: &WalkEntry) -> Result<Vec<TextChunk>> {
    let ext = entry
        .path
        .extension()
        .and_then(|e| e.to_str())
        .map(|s| s.to_ascii_lowercase());
    let ext_str = ext.as_deref();

    // Well-known structured generated files, dispatched by filename.
    // These would otherwise fall through to the plain-text extractor
    // with `Prose` provenance, which makes the perplexity detector cry.
    let filename = entry
        .path
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("");
    match filename {
        "Cargo.lock" => return Ok(config::extract_toml(&entry.path, &entry.bytes)),
        "package-lock.json" | "composer.lock" | "bun.lockb" => {
            return Ok(config::extract_json(&entry.path, &entry.bytes));
        }
        _ => {}
    }

    match ext_str {
        Some("ipynb") => return Ok(notebook::extract_notebook(&entry.path, &entry.bytes)),
        Some("json") => return Ok(config::extract_json(&entry.path, &entry.bytes)),
        Some("toml") => return Ok(config::extract_toml(&entry.path, &entry.bytes)),
        Some("yaml" | "yml") => return Ok(config::extract_yaml(&entry.path, &entry.bytes)),
        Some("html" | "htm" | "svg" | "xml") => {
            return Ok(markup::extract_markup(&entry.path, &entry.bytes));
        }
        #[cfg(feature = "pdf")]
        Some("pdf") => return Ok(pdf::extract_pdf(&entry.path, &entry.bytes)),
        Some(e) if source::supports(e) => {
            return Ok(source::extract_source(&entry.path, e, &entry.bytes));
        }
        // Generic lockfile / checksum artifacts (yarn.lock, poetry.lock,
        // go.sum, pnpm-lock.yaml-without-extension, …). Their contents
        // are machine-generated and not natural language, so we tag
        // them with ConfigString so the heuristic / encoded / canary
        // / hidden-char detectors still run but perplexity skips them.
        Some("lock" | "sum") => {
            if entry.bytes.contains(&0) {
                return Ok(Vec::new());
            }
            let Ok(text) = std::str::from_utf8(&entry.bytes) else {
                return Ok(Vec::new());
            };
            return Ok(chunk_text(&entry.path, text, Provenance::ConfigString));
        }
        _ => {}
    }

    if entry.bytes.contains(&0) {
        return Ok(Vec::new());
    }
    let Ok(text_str) = std::str::from_utf8(&entry.bytes) else {
        return Ok(Vec::new());
    };
    Ok(text::extract_text(&entry.path, text_str))
}
