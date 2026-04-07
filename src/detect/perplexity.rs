//! Perplexity detector (DESIGN.md §4.5.3).
//!
//! Scores chunks against a character-bigram language model trained from
//! an embedded English corpus (`bigram_corpus.txt`). Chunks whose
//! per-symbol cross-entropy under the model is well above the corpus
//! baseline are flagged as anomalous — this catches obfuscated, encoded,
//! or otherwise non-natural-language content far more discriminately than
//! pure Shannon entropy because the bigram model rewards real letter
//! transitions ("th", "er", "ing") and penalises adversarial garbage.
//!
//! # Scope
//!
//! The detector only inspects chunks whose provenance is **natural
//! language** — plain prose, Markdown, docstrings, notebook markdown
//! cells, HTML text nodes, and PDF body text. Structured content
//! (config values, code comments / string literals, HTML attributes,
//! notebook code cells / outputs, `Cargo.lock`-style artefacts) has a
//! legitimately high bigram cross-entropy under an English model, so
//! running perplexity there produces false positives at a rate that
//! drowns out the signal. See `Provenance::is_natural_language`.

use super::bigram_model::BigramModel;
use super::{Category, Detector};
use crate::types::{Finding, Severity, TextChunk};

/// Under the bigram model, ordinary English prose scores around 1.8–2.2
/// nats/symbol; dense technical prose up to ~2.6; base64 ≈ 3.0; cyclic
/// random printables ≈ 4.3; truly uniform random ≈ 4.5+. We deliberately
/// set the thresholds well above the natural-prose band so we only flag
/// near-random content — the encoded detector already owns base64/hex
/// payloads, so perplexity is the safety net for content that isn't
/// shaped like either prose or a known encoding.
const HIGH_NATS: f64 = 3.3;
const VERY_HIGH_NATS: f64 = 3.8;
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
        // Random-looking ASCII pushes bigram cross-entropy well above the
        // English baseline.
        let mut s = String::new();
        for i in 0..600u32 {
            s.push((33 + ((i * 7919) % 94)) as u8 as char);
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
        // Same high-entropy blob that fires under Provenance::Prose.
        let mut s = String::new();
        for i in 0..600u32 {
            s.push((33 + ((i * 7919) % 94)) as u8 as char);
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
