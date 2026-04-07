//! Chunker — normalises and bounds text fed to detectors.

use std::path::Path;

use unicode_normalization::UnicodeNormalization;

use crate::types::{ByteSpan, Provenance, TextChunk};

/// Default window / overlap. The pipeline currently uses these constants;
/// they will be promoted to `ScanConfig` knobs once tuning matters.
const WINDOW: usize = 2048;
const OVERLAP: usize = 256;

/// Split `text` into normalised, bounded chunks for detector consumption.
///
/// We deliberately preserve the *original* byte span (relative to the
/// raw file) so reports can point at the right place even though the
/// chunk text itself has been NFKC-normalised.
pub fn chunk_text(path: &Path, text: &str, provenance: Provenance) -> Vec<TextChunk> {
    if text.is_empty() {
        return Vec::new();
    }

    let mut chunks = Vec::new();
    let bytes = text.as_bytes();
    let mut start = 0usize;

    while start < bytes.len() {
        let end = (start + WINDOW).min(bytes.len());
        let end = floor_char_boundary(text, end);
        if end <= start {
            break;
        }
        let slice = &text[start..end];
        let normalised: String = slice.nfkc().collect();

        chunks.push(TextChunk {
            path: path.to_path_buf(),
            span: ByteSpan::new(start, end),
            text: normalised,
            provenance,
        });

        if end == bytes.len() {
            break;
        }
        start = end.saturating_sub(OVERLAP);
        // Round forward to a char boundary to avoid panics on slicing.
        start = ceil_char_boundary(text, start);
    }

    chunks
}

fn floor_char_boundary(s: &str, mut idx: usize) -> usize {
    while idx > 0 && !s.is_char_boundary(idx) {
        idx -= 1;
    }
    idx
}

fn ceil_char_boundary(s: &str, mut idx: usize) -> usize {
    while idx < s.len() && !s.is_char_boundary(idx) {
        idx += 1;
    }
    idx
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;

    #[test]
    fn empty_input_yields_no_chunks() {
        assert!(chunk_text(Path::new("x"), "", Provenance::Prose).is_empty());
    }

    #[test]
    fn short_input_fits_in_a_single_chunk() {
        let chunks = chunk_text(Path::new("x"), "hello world", Provenance::Prose);
        assert_eq!(chunks.len(), 1);
        assert_eq!(chunks[0].text, "hello world");
        assert_eq!(chunks[0].span.start, 0);
        assert_eq!(chunks[0].span.end, 11);
    }

    #[test]
    fn multibyte_input_does_not_panic() {
        let s: String = "λ".repeat(2000);
        let chunks = chunk_text(Path::new("x"), &s, Provenance::Prose);
        assert!(!chunks.is_empty());
        for c in &chunks {
            assert!(c.span.start <= s.len() && c.span.end <= s.len());
        }
    }

    #[test]
    fn long_input_produces_multiple_overlapping_chunks() {
        let s = "a".repeat(5000);
        let chunks = chunk_text(Path::new("x"), &s, Provenance::Prose);
        assert!(chunks.len() >= 2);
        // Adjacent windows should overlap.
        assert!(chunks[1].span.start < chunks[0].span.end);
    }
}

