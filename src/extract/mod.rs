//! Extractors turn raw file bytes into one or more `TextChunk`s tagged
//! with provenance.
//!
//! Format dispatch is by file extension. Unknown / unspecified extensions
//! fall back to a plain UTF-8 text extractor.

mod config;
mod markup;
mod notebook;
#[cfg(feature = "pdf")]
mod pdf;
mod source;
mod text;

use anyhow::Result;

use crate::types::TextChunk;
use crate::walk::WalkEntry;

pub fn extract(entry: &WalkEntry) -> Result<Vec<TextChunk>> {
    let ext = entry
        .path
        .extension()
        .and_then(|e| e.to_str())
        .map(|s| s.to_ascii_lowercase());
    let ext_str = ext.as_deref();

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
