//! Hidden / adversarial character detector (DESIGN.md §4.5.2).
//!
//! Flags zero-width characters, bidi overrides, and tag characters that
//! commonly smuggle payloads past human review.

use super::{Category, Detector};
use crate::types::{ByteSpan, Finding, Severity, TextChunk};

pub struct HiddenCharsDetector;

fn classify(c: char) -> Option<&'static str> {
    match c {
        '\u{200B}' | '\u{200C}' | '\u{200D}' | '\u{FEFF}' => Some("zero-width"),
        '\u{202A}'..='\u{202E}' | '\u{2066}'..='\u{2069}' => Some("bidi-override"),
        '\u{E0000}'..='\u{E007F}' => Some("tag-character"),
        _ => None,
    }
}

impl Detector for HiddenCharsDetector {
    fn id(&self) -> &'static str {
        "hidden_chars"
    }

    fn category(&self) -> Category {
        Category::HiddenChars
    }

    fn analyze(&self, chunk: &TextChunk) -> Vec<Finding> {
        let mut out = Vec::new();
        let mut count_by_kind: std::collections::HashMap<&'static str, usize> =
            std::collections::HashMap::new();

        for (i, c) in chunk.text.char_indices() {
            if let Some(kind) = classify(c) {
                *count_by_kind.entry(kind).or_insert(0) += 1;
                let abs = chunk.span.start + i;
                let len = c.len_utf8();
                let severity = match kind {
                    "bidi-override" => Severity::Critical,
                    "tag-character" => Severity::Critical,
                    _ => Severity::Medium,
                };
                out.push(Finding {
                    detector: "hidden_chars".to_string(),
                    severity,
                    confidence: 0.95,
                    path: chunk.path.clone(),
                    span: ByteSpan::new(abs, abs + len),
                    message: format!("hidden {kind} U+{:04X}", c as u32),
                    evidence: format!("U+{:04X}", c as u32),
                });
            }
        }

        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{ByteSpan, Provenance, TextChunk};
    use std::path::PathBuf;

    fn chunk(text: &str) -> TextChunk {
        TextChunk {
            path: PathBuf::from("t.txt"),
            span: ByteSpan::new(0, text.len()),
            text: text.to_string(),
            provenance: Provenance::Prose,
        }
    }

    #[test]
    fn flags_zero_width_space() {
        let f = HiddenCharsDetector.analyze(&chunk("a\u{200B}b"));
        assert_eq!(f.len(), 1);
        assert_eq!(f[0].severity, Severity::Medium);
    }

    #[test]
    fn flags_bidi_override_as_critical() {
        let f = HiddenCharsDetector.analyze(&chunk("a\u{202E}b"));
        assert_eq!(f.len(), 1);
        assert_eq!(f[0].severity, Severity::Critical);
    }

    #[test]
    fn benign_text_yields_no_findings() {
        let f = HiddenCharsDetector.analyze(&chunk("plain ascii text"));
        assert!(f.is_empty());
    }
}
