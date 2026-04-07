//! PDF text extractor (gated by the `pdf` feature).

use std::path::Path;

use crate::chunk::chunk_text;
use crate::types::{Provenance, TextChunk};

pub fn extract_pdf(path: &Path, bytes: &[u8]) -> Vec<TextChunk> {
    let Ok(text) = pdf_extract::extract_text_from_mem(bytes) else {
        return Vec::new();
    };
    if text.is_empty() {
        return Vec::new();
    }
    chunk_text(path, &text, Provenance::PdfText)
}
