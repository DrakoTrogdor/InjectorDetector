//! Hidden / adversarial character detector (DESIGN.md §4.5.2).
//!
//! Three layers of detection:
//!
//! 1. **Invisible characters** — zero-width characters, bidi overrides,
//!    and Unicode tag characters that smuggle payloads past human review.
//! 2. **Homoglyph clusters** — Latin words that contain Cyrillic or Greek
//!    characters which are *visually confusable* with a specific Latin
//!    letter (e.g. Cyrillic `а` U+0430 in `pаyload`). Only confusables
//!    fire; math/science notation like `ΔVol`, `Σ(x)`, `π*r²`, `λ-calc`
//!    is explicitly *not* flagged because the Greek letters involved
//!    (Δ, Σ, π, λ, μ, σ, θ, φ, ψ, ω) are not Latin look-alikes.

use super::{Category, Detector};
use crate::types::{ByteSpan, Finding, Severity, TextChunk};

pub struct HiddenCharsDetector;

fn classify_invisible(c: char) -> Option<&'static str> {
    match c {
        '\u{200B}' | '\u{200C}' | '\u{200D}' | '\u{FEFF}' => Some("zero-width"),
        '\u{202A}'..='\u{202E}' | '\u{2066}'..='\u{2069}' => Some("bidi-override"),
        '\u{E0000}'..='\u{E007F}' => Some("tag-character"),
        _ => None,
    }
}

/// U+FEFF at byte offset 0 of a file is the UTF-8 byte-order mark —
/// a standard text-encoding marker written by many Windows tools
/// (notably MSBuild, Visual Studio, and the .NET SDK for generated
/// `.g.props` / `.g.targets` files). It is **not** a smuggling attempt
/// when it appears as the very first character; only mid-file BOMs are
/// suspicious. This helper lets the main loop ignore a leading BOM
/// without relaxing the rule for zero-width characters elsewhere.
fn is_leading_bom(c: char, absolute_offset: usize) -> bool {
    c == '\u{FEFF}' && absolute_offset == 0
}

/// Returns the script kind ("cyrillic" / "greek") if `c` is a non-Latin
/// character that is **visually confusable with a specific Latin letter**.
/// Pure foreign letters (Δ, Σ, π, ф, ш, Ж, …) return `None` — they are
/// unambiguously non-Latin and their presence in a Latin word is almost
/// always legitimate mathematical or linguistic usage, not a homoglyph
/// attack.
fn confusable_kind(c: char) -> Option<&'static str> {
    // Cyrillic lookalikes for Latin letters.
    let cyrillic = matches!(
        c,
        // lowercase: а в е к м н о р с т у х і ј ѕ ԁ ԛ ѡ ѕ ѵ
        '\u{0430}' // а → a
        | '\u{0432}' // в → B / b-ish
        | '\u{0435}' // е → e
        | '\u{043A}' // к → k
        | '\u{043C}' // м → m (M-like)
        | '\u{043D}' // н → H / n-ish
        | '\u{043E}' // о → o
        | '\u{0440}' // р → p
        | '\u{0441}' // с → c
        | '\u{0442}' // т → T (t-ish)
        | '\u{0443}' // у → y
        | '\u{0445}' // х → x
        | '\u{0456}' // і → i
        | '\u{0458}' // ј → j
        | '\u{0455}' // ѕ → s
        | '\u{0501}' // ԁ → d
        | '\u{051B}' // ԛ → q
        | '\u{051D}' // ԝ → w
        | '\u{0461}' // ѡ → w-like
        // uppercase: А В Е Н І Ј К М О Р С Т У Х Ѕ
        | '\u{0410}' // А → A
        | '\u{0412}' // В → B
        | '\u{0415}' // Е → E
        | '\u{041D}' // Н → H
        | '\u{0406}' // І → I
        | '\u{0408}' // Ј → J
        | '\u{041A}' // К → K
        | '\u{041C}' // М → M
        | '\u{041E}' // О → O
        | '\u{0420}' // Р → P
        | '\u{0421}' // С → C
        | '\u{0422}' // Т → T
        | '\u{0423}' // У → Y
        | '\u{0425}' // Х → X
        | '\u{0405}' // Ѕ → S
    );
    if cyrillic {
        return Some("cyrillic");
    }
    // Greek lookalikes for Latin letters. Math-shaped letters like
    // Δ (U+0394) / Σ (U+03A3) / π (U+03C0) / λ (U+03BB) / μ (U+03BC)
    // / σ (U+03C3) / θ (U+03B8) / φ (U+03C6) / ψ (U+03C8) / ω (U+03C9)
    // are deliberately excluded — their presence in code or docs is
    // almost always legitimate scientific notation.
    let greek = matches!(
        c,
        // lowercase letter-shaped
        '\u{03BF}' // ο → o
        | '\u{03B9}' // ι → i
        | '\u{03BA}' // κ → k (letter-like usage in some fonts)
        | '\u{03C1}' // ρ → p
        | '\u{03C7}' // χ → x
        // uppercase letter-shaped (visually identical to Latin)
        | '\u{0391}' // Α → A
        | '\u{0392}' // Β → B
        | '\u{0395}' // Ε → E
        | '\u{0396}' // Ζ → Z
        | '\u{0397}' // Η → H
        | '\u{0399}' // Ι → I
        | '\u{039A}' // Κ → K
        | '\u{039C}' // Μ → M
        | '\u{039D}' // Ν → N
        | '\u{039F}' // Ο → O
        | '\u{03A1}' // Ρ → P
        | '\u{03A4}' // Τ → T
        | '\u{03A5}' // Υ → Y
        | '\u{03A7}' // Χ → X
    );
    if greek {
        return Some("greek");
    }
    None
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
            let abs = chunk.span.start + i;
            if is_leading_bom(c, abs) {
                continue;
            }
            if let Some(kind) = classify_invisible(c) {
                let len = c.len_utf8();
                let severity = match kind {
                    "bidi-override" | "tag-character" => Severity::Critical,
                    _ => Severity::Medium,
                };
                out.push(Finding {
                    detector: "hidden_chars".to_string(),
                    category: Category::HiddenChars,
                    severity,
                    confidence: 0.95,
                    path: chunk.path.clone(),
                    span: ByteSpan::new(abs, abs + len),
                    message: format!("hidden {kind} U+{:04X}", c as u32),
                    evidence: format!("U+{:04X}", c as u32),
                });
            }
        }

        // 2. Homoglyph clusters — walk word-by-word and report Latin words
        // containing at least one Cyrillic/Greek *Latin-confusable* char.
        let mut word_start: Option<usize> = None;
        let mut latin = 0usize;
        let mut confusable = 0usize;
        let mut confusable_kind_seen: Option<&'static str> = None;

        let bytes_len = chunk.text.len();
        for (i, c) in chunk.text.char_indices() {
            let in_word = c.is_alphabetic() || c == '\u{200C}' || c == '\u{200D}';
            if in_word {
                if word_start.is_none() {
                    word_start = Some(i);
                    latin = 0;
                    confusable = 0;
                    confusable_kind_seen = None;
                }
                if c.is_ascii_alphabetic() {
                    latin += 1;
                } else if let Some(kind) = confusable_kind(c) {
                    confusable += 1;
                    confusable_kind_seen = Some(kind);
                }
            } else if let Some(start) = word_start.take() {
                emit_homoglyph(
                    &chunk.text,
                    start,
                    i,
                    latin,
                    confusable,
                    confusable_kind_seen,
                    chunk,
                    &mut out,
                );
            }
        }
        if let Some(start) = word_start {
            emit_homoglyph(
                &chunk.text,
                start,
                bytes_len,
                latin,
                confusable,
                confusable_kind_seen,
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
    confusable: usize,
    confusable_kind_seen: Option<&'static str>,
    chunk: &TextChunk,
    out: &mut Vec<Finding>,
) {
    if latin >= 2 && confusable >= 1 {
        let kind = confusable_kind_seen.unwrap_or("foreign");
        let snippet = text.get(start..end).unwrap_or("");
        out.push(Finding {
            detector: "hidden_chars".to_string(),
            category: Category::HiddenChars,
            severity: Severity::High,
            confidence: 0.85,
            path: chunk.path.clone(),
            span: ByteSpan::new(chunk.span.start + start, chunk.span.start + end),
            message: format!("homoglyph cluster: Latin word with {kind} look-alike character"),
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
    fn leading_bom_is_not_flagged() {
        // U+FEFF at byte 0 of the file (MSBuild `.g.props` / `.g.targets`,
        // Visual Studio auto-generated files, PowerShell scripts from
        // certain tools — all legitimately start with a UTF-8 BOM).
        let f = HiddenCharsDetector.analyze(&chunk(
            "\u{FEFF}<?xml version=\"1.0\" encoding=\"utf-8\"?>",
        ));
        assert!(
            f.is_empty(),
            "leading UTF-8 BOM must not be flagged, got {f:?}"
        );
    }

    #[test]
    fn bom_in_middle_of_file_is_still_flagged() {
        // A BOM after non-zero content is suspicious — real
        // zero-width smuggling.
        let f = HiddenCharsDetector.analyze(&chunk("hello \u{FEFF} world"));
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
    fn flags_cyrillic_lookalike_in_latin_word() {
        // "payload" with Cyrillic 'а' (U+0430, a-lookalike).
        let f = HiddenCharsDetector.analyze(&chunk("the p\u{0430}yload is harmless"));
        assert!(
            f.iter().any(|x| x.message.contains("cyrillic")),
            "expected cyrillic lookalike finding, got {f:?}"
        );
    }

    #[test]
    fn flags_greek_lookalike_omicron_in_latin_word() {
        // Greek 'ο' (U+03BF, o-lookalike) inside a Latin word.
        let f = HiddenCharsDetector.analyze(&chunk("the c\u{03BF}mmand runs daily"));
        assert!(f.iter().any(|x| x.message.contains("greek")));
    }

    #[test]
    fn math_delta_is_not_flagged() {
        // ΔVol = "change in volatility" — legitimate math notation.
        // Δ (U+0394) is a triangle, not a Latin lookalike.
        let f = HiddenCharsDetector.analyze(&chunk("the \u{0394}Vol metric measures change"));
        assert!(
            f.iter().all(|x| !x.message.contains("homoglyph")),
            "Δ must not be flagged as a homoglyph, got {f:?}"
        );
    }

    #[test]
    fn math_sigma_and_pi_are_not_flagged() {
        let f = HiddenCharsDetector.analyze(&chunk(
            "the \u{03A3}(x) summation and \u{03C0}*r\u{00B2} formula",
        ));
        assert!(f.iter().all(|x| !x.message.contains("homoglyph")));
    }

    #[test]
    fn pure_cyrillic_word_is_not_flagged() {
        // Russian word "привет" — entirely Cyrillic, not an attack.
        let f = HiddenCharsDetector.analyze(&chunk("hello \u{043F}\u{0440}\u{0438}\u{0432}\u{0435}\u{0442} world"));
        assert!(f.iter().all(|x| !x.message.contains("homoglyph")));
    }

    #[test]
    fn benign_text_yields_no_findings() {
        let f = HiddenCharsDetector.analyze(&chunk("plain ascii text"));
        assert!(f.is_empty());
    }
}
