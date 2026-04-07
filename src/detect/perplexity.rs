//! Perplexity detector (DESIGN.md §4.5.3).
//!
//! Scores chunks against a character-bigram language model trained from
//! an embedded English corpus (`bigram_corpus.txt`). Chunks whose
//! per-symbol cross-entropy under the model is well above the corpus
//! baseline — **and** which have enough character diversity to look like
//! free-form content rather than structured repetition — are flagged as
//! anomalous. Two gates working together keep both classes of noise at
//! bay:
//!
//! 1. **Bigram cross-entropy** — ordinary English prose scores around
//!    1.8–2.6 nats/symbol, dense technical documentation 3.0–4.0, and
//!    base64 / random garbage 4.5+. Anything below the `HIGH_NATS`
//!    cutoff looks enough like English to be ignored.
//! 2. **Character Shannon entropy** — ASCII art, box drawings, and
//!    tables have legitimately high *bigram* cross-entropy (because
//!    their byte transitions don't appear in the training corpus) but
//!    very *low* character diversity (they only use a handful of
//!    distinct symbols). Requiring a minimum Shannon entropy over the
//!    chunk's character distribution filters them without hurting
//!    detection on genuinely random blobs, which use many distinct
//!    characters and have high Shannon entropy too.
//!
//! # Scope
//!
//! The detector only inspects chunks whose provenance is **natural
//! language** — plain prose, Markdown, docstrings, notebook markdown
//! cells, HTML text nodes, and PDF body text. Structured content
//! (config values, code comments / string literals, HTML attributes,
//! notebook code cells / outputs, `Cargo.lock`-style artefacts,
//! PowerShell / Lua / SQL / etc. scripts routed through the lockfile
//! dispatch) has a legitimately high bigram cross-entropy under an
//! English model, so running perplexity there produces false positives
//! at a rate that drowns out the signal. See
//! `Provenance::is_natural_language`.

use std::collections::HashMap;

use super::bigram_model::BigramModel;
use super::{Category, Detector};
use crate::types::{Finding, Severity, TextChunk};

/// Bigram cross-entropy cutoffs in nats/symbol. The lower bound has to
/// sit comfortably above the natural band for real-world Markdown
/// documentation — dense technical prose in this repo's own `DESIGN.md`
/// and `STATUS.md` scores 3.8–4.2, so anything below 4.5 is treated as
/// "still plausibly English". The upper bound is where we start calling
/// something Critical.
const HIGH_NATS: f64 = 5.0;
const VERY_HIGH_NATS: f64 = 5.6;
/// Character Shannon entropy cutoff in bits. Normal prose sits around
/// 4.3–4.9 bits, ASCII art around 2.5–3.5, and random printable content
/// above 6.0. Requiring ≥ 4.5 bits filters box drawings, tables, and
/// dash-separator lines without rejecting real prose or random blobs.
const MIN_SHANNON_BITS: f64 = 4.5;
/// Don't bother scoring tiny chunks — their statistics are meaningless.
const MIN_BYTES: usize = 256;

pub struct PerplexityDetector;

impl Detector for PerplexityDetector {
    fn id(&self) -> &'static str {
        "perplexity"
    }

    fn category(&self) -> Category {
        Category::Perplexity
    }

    fn analyze(&self, chunk: &TextChunk) -> Vec<Finding> {
        if !chunk.provenance.is_natural_language() {
            return Vec::new();
        }
        if chunk.text.len() < MIN_BYTES {
            return Vec::new();
        }
        if char_shannon_entropy(&chunk.text) < MIN_SHANNON_BITS {
            // Low character diversity — almost certainly ASCII art,
            // box drawings, or a heavily repetitive table. Bigram
            // cross-entropy would fire but the content isn't actually
            // suspicious.
            return Vec::new();
        }

        let model = BigramModel::global();
        let Some(score) = model.score(&chunk.text) else {
            return Vec::new();
        };
        if score < HIGH_NATS {
            return Vec::new();
        }

        let severity = if score >= VERY_HIGH_NATS {
            Severity::High
        } else {
            Severity::Medium
        };
        let confidence = ((score - HIGH_NATS) / (VERY_HIGH_NATS - HIGH_NATS).max(0.001))
            .clamp(0.3, 0.9) as f32;

        vec![Finding {
            detector: "perplexity".to_string(),
            category: Category::Perplexity,
            severity,
            confidence,
            path: chunk.path.clone(),
            span: chunk.span,
            message: format!(
                "anomalous bigram cross-entropy {score:.2} nats/symbol — likely encoded or obfuscated content"
            ),
            evidence: Finding::make_evidence(&chunk.text, 80),
        }]
    }
}

/// Shannon entropy (bits) over the character distribution of `text`.
/// We iterate over `char`s rather than bytes so multi-byte sequences
/// (box drawings, emoji, accented letters) count as a single symbol
/// each — byte-level counting artificially inflates entropy for
/// non-ASCII content.
fn char_shannon_entropy(text: &str) -> f64 {
    let mut counts: HashMap<char, u32> = HashMap::new();
    let mut total = 0u32;
    for c in text.chars() {
        *counts.entry(c).or_insert(0) += 1;
        total += 1;
    }
    if total == 0 {
        return 0.0;
    }
    let total_f = total as f64;
    let mut h = 0.0f64;
    for &c in counts.values() {
        let p = c as f64 / total_f;
        h -= p * p.log2();
    }
    h
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{ByteSpan, Provenance, TextChunk};
    use std::path::PathBuf;

    fn chunk(text: &str) -> TextChunk {
        chunk_with(text, Provenance::Prose)
    }

    fn chunk_with(text: &str, provenance: Provenance) -> TextChunk {
        TextChunk {
            path: PathBuf::from("t.txt"),
            span: ByteSpan::new(0, text.len()),
            text: text.to_string(),
            provenance,
        }
    }

    #[test]
    fn flat_prose_yields_no_finding() {
        let prose = "The quick brown fox jumps over the lazy dog. ".repeat(20);
        assert!(PerplexityDetector.analyze(&chunk(&prose)).is_empty());
    }

    #[test]
    fn high_entropy_blob_yields_finding() {
        // All non-letter printables: every transition maps to the
        // "other" bin in the bigram model, which is heavily penalised
        // against the English-trained distribution — cross-entropy
        // comfortably above HIGH_NATS. 40 distinct characters keep the
        // Shannon-entropy gate happy (log2(40) ≈ 5.3 bits).
        let symbols = "0123456789!@#$%^&*()_+-=[]{}|;:,./<>?`~";
        let mut s = String::new();
        for i in 0..600 {
            s.push(symbols.as_bytes()[i % symbols.len()] as char);
        }
        let f = PerplexityDetector.analyze(&chunk(&s));
        assert!(!f.is_empty(), "expected high-entropy blob to fire");
    }

    #[test]
    fn tiny_input_is_ignored() {
        assert!(PerplexityDetector.analyze(&chunk("xyz")).is_empty());
    }

    #[test]
    fn structured_provenance_is_skipped_even_when_entropy_is_high() {
        // Same kind of high-entropy non-letter blob used above.
        let symbols = "0123456789!@#$%^&*()_+-=[]{}|;:,./<>?`~";
        let mut s = String::new();
        for i in 0..600 {
            s.push(symbols.as_bytes()[i % symbols.len()] as char);
        }
        for p in [
            Provenance::ConfigString,
            Provenance::Comment,
            Provenance::StringLiteral,
            Provenance::HtmlAttribute,
            Provenance::NotebookCodeCell,
        ] {
            assert!(
                PerplexityDetector.analyze(&chunk_with(&s, p)).is_empty(),
                "perplexity should skip {p:?} chunks"
            );
        }
        // Sanity: Prose still fires.
        assert!(!PerplexityDetector.analyze(&chunk_with(&s, Provenance::Prose)).is_empty());
    }

    #[test]
    fn low_diversity_ascii_art_is_skipped() {
        // Box drawings repeated — classic Markdown architecture diagram.
        // This has high bigram cross-entropy under the English model
        // (the transitions don't appear in prose) but very low
        // character diversity (only ~6 distinct chars). The Shannon
        // gate should kick in before scoring happens.
        let mut s = String::new();
        for _ in 0..120 {
            s.push_str("│   │      │    │     │\n");
        }
        assert!(
            PerplexityDetector.analyze(&chunk(&s)).is_empty(),
            "ASCII art with low char diversity must be skipped"
        );
    }

    #[test]
    fn dense_english_prose_stays_below_the_threshold() {
        // A full paragraph of dense technical prose should not fire.
        // Previously this scored ~3.0 and clipped the old 2.9 threshold.
        let prose = "The aggregator component dedupes findings by span and detector, caps \
                     each detector's contribution to the per-file score, and computes the \
                     final verdict against the configured severity threshold. Files are \
                     sorted by their aggregated score so the most suspicious entries appear \
                     at the top of the report without the user having to scroll through \
                     noisier sections first.";
        assert!(PerplexityDetector.analyze(&chunk(prose)).is_empty());
    }
}
