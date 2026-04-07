//! Plain-text / markdown extractor.

use std::path::Path;

use crate::chunk::chunk_text;
use crate::types::{Provenance, TextChunk};

pub fn extract_text(path: &Path, text: &str) -> Vec<TextChunk> {
    chunk_text(path, text, Provenance::Prose)
}
