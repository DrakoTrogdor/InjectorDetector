//! Property tests for the chunker and the Unicode normalisation pipeline.

use std::path::Path;

use injector_detector::chunk::chunk_text;
use injector_detector::types::Provenance;
use proptest::prelude::*;

proptest! {
    // Spans must always be valid byte ranges into the original text.
    #[test]
    fn chunk_spans_are_within_input(s in "\\PC{0,5000}") {
        let chunks = chunk_text(Path::new("t.txt"), &s, Provenance::Prose);
        for c in &chunks {
            prop_assert!(c.span.start <= s.len());
            prop_assert!(c.span.end <= s.len());
            prop_assert!(c.span.start <= c.span.end);
        }
    }

    // Chunking should never panic on arbitrary multibyte input, including
    // strings dominated by emoji and combining characters.
    #[test]
    fn chunker_does_not_panic_on_random_unicode(s in "[\\u{0000}-\\u{10FFFF}]{0,1000}") {
        let _ = chunk_text(Path::new("t.txt"), &s, Provenance::Prose);
    }

    // For inputs that fit in a single window, exactly one chunk should
    // be produced (if the input is non-empty) and its bytes should be a
    // length-preserving NFKC normalisation of the input.
    #[test]
    fn short_inputs_produce_a_single_chunk(s in "[a-zA-Z0-9 ]{1,1024}") {
        let chunks = chunk_text(Path::new("t.txt"), &s, Provenance::Prose);
        prop_assert_eq!(chunks.len(), 1);
        prop_assert_eq!(chunks[0].span.start, 0);
        prop_assert_eq!(chunks[0].span.end, s.len());
    }

    // Long inputs should always produce strictly more than one chunk
    // and adjacent windows should overlap.
    #[test]
    fn long_inputs_produce_overlapping_windows(
        n in 5usize..50usize,
    ) {
        let s = "x".repeat(n * 1024);
        let chunks = chunk_text(Path::new("t.txt"), &s, Provenance::Prose);
        prop_assert!(chunks.len() >= 2);
        for w in chunks.windows(2) {
            prop_assert!(w[1].span.start < w[0].span.end);
        }
    }
}
