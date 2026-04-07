//! Hidden / adversarial character detector (DESIGN.md §4.5.2).
//!
//! Three layers of detection:
//!
//! 1. **Invisible characters** — zero-width characters, bidi overrides,
//!    and Unicode tag characters that smuggle payloads past human review.
//! 2. **Homoglyph clusters** — Cyrillic or Greek code points sitting
//!    inside an otherwise-ASCII Latin word (e.g. Cyrillic `а` U+0430 in
//!    `pаyload`). Used to construct lookalike URLs, identifiers, and
//!    instruction-override phrases that humans skim past.

use super::{Category, Detector};
use crate::types::{ByteSpan, Finding, Severity, TextChunk};

pub struct HiddenCharsDetector;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Script {
    Latin,
    Cyrillic,
    Greek,
    Other,
}

fn classify_invisible(c: char) -> Option<&'static str> {
    match c {
        '\u{200B}' | '\u{200C}' | '\u{200D}' | '\u{FEFF}' => Some("zero-width"),
        '\u{202A}'..='\u{202E}' | '\u{2066}'..='\u{2069}' => Some("bidi-override"),
        '\u{E0000}'..='\u{E007F}' => Some("tag-character"),
        _ => None,
    }
}

fn script_of(c: char) -> Script {
    if c.is_ascii_alphabetic() {
        Script::Latin
    } else if matches!(c, '\u{0400}'..='\u{04FF}' | '\u{0500}'..='\u{052F}') {
        // Cyrillic + Cyrillic Supplement
        Script::Cyrillic
    } else if matches!(c, '\u{0370}'..='\u{03FF}' | '\u{1F00}'..='\u{1FFF}') {
        // Greek + Greek Extended
        Script::Greek
    } else {
        Script::Other
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

        // 1. Invisible characters
        for (i, c) in chunk.text.char_indices() {
            if let Some(kind) = classify_invisible(c) {
                let abs = chunk.span.start + i;
                let len = c.len_utf8();
                let severity = match kind {
                    "bidi-override" | "tag-character" => Severity::Critical,
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

        // 2. Homoglyph clusters — walk word-by-word and report mixed-script
        // Latin words containing Cyrillic / Greek look-alikes.
        let mut word_start: Option<usize> = None;
        let mut latin = 0usize;
        let mut foreign = 0usize;
        let mut foreign_kind: Option<&'static str> = None;

        let bytes_len = chunk.text.len();
        for (i, c) in chunk.text.char_indices() {
            let in_word = c.is_alphabetic() || c == '\u{200C}' || c == '\u{200D}';
            if in_word {
                if word_start.is_none() {
                    word_start = Some(i);
                    latin = 0;
                    foreign = 0;
                    foreign_kind = None;
                }
                match script_of(c) {
                    Script::Latin => latin += 1,
                    Script::Cyrillic => {
                        foreign += 1;
                        foreign_kind = Some("cyrillic");
                    }
                    Script::Greek => {
                        foreign += 1;
                        foreign_kind = Some("greek");
                    }
                    Script::Other => {}
                }
            } else if let Some(start) = word_start.take() {
                emit_homoglyph(
                    &chunk.text,
                    start,
                    i,
                    latin,
                    foreign,
                    foreign_kind,
                    chunk,
                    &mut out,
                );
            }
        }
        // Trailing word that ran to end-of-chunk.
        if let Some(start) = word_start {
            emit_homoglyph(
                &chunk.text,
                start,
                bytes_len,
                latin,
                foreign,
                foreign_kind,
                chunk,
                &mut out,
            );
        }

        out
    }
}

#[allow(clippy::too_many_arguments)]
fn emit_homoglyph(
    text: &str,
    start: usize,
    end: usize,
    latin: usize,
    foreign: usize,
    foreign_kind: Option<&'static str>,
    chunk: &TextChunk,
    out: &mut Vec<Finding>,
) {
    if latin >= 2 && foreign >= 1 {
        let kind = foreign_kind.unwrap_or("foreign");
        let snippet = text.get(start..end).unwrap_or("");
        out.push(Finding {
            detector: "hidden_chars".to_string(),
            severity: Severity::High,
            confidence: 0.85,
            path: chunk.path.clone(),
            span: ByteSpan::new(chunk.span.start + start, chunk.span.start + end),
            message: format!("homoglyph cluster: Latin word with {kind} characters"),
            evidence: Finding::make_evidence(snippet, 60),
        });
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
    fn flags_cyrillic_in_latin_word() {
        // "payload" with Cyrillic 'а' (U+0430) in place of Latin 'a'.
        let f = HiddenCharsDetector.analyze(&chunk("the p\u{0430}yload is harmless"));
        assert!(
            f.iter().any(|x| x.message.contains("cyrillic")),
            "expected cyrillic homoglyph finding, got {f:?}"
        );
    }

    #[test]
    fn flags_greek_in_latin_word() {
        // Greek 'ο' (U+03BF) inside a Latin word.
        let f = HiddenCharsDetector.analyze(&chunk("the c\u{03BF}mmand runs daily"));
        assert!(f.iter().any(|x| x.message.contains("greek")));
    }

    #[test]
    fn pure_cyrillic_word_is_not_flagged() {
        // Russian word "привет" — entirely Cyrillic, not a homoglyph attack.
        let f = HiddenCharsDetector.analyze(&chunk("hello привет world"));
        assert!(
            f.iter().all(|x| !x.message.contains("homoglyph")),
            "expected no homoglyph finding for pure cyrillic word, got {f:?}"
        );
    }

    #[test]
    fn benign_text_yields_no_findings() {
        let f = HiddenCharsDetector.analyze(&chunk("plain ascii text"));
        assert!(f.is_empty());
    }
}
