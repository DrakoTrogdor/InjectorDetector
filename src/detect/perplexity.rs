//! Perplexity detector (DESIGN.md §4.5.3).
//!
//! Scores chunks against a character-bigram language model trained from
//! an embedded English corpus (`bigram_corpus.txt`). Chunks whose
//! per-symbol cross-entropy under the model is well above the corpus
//! baseline are flagged as anomalous — this catches obfuscated, encoded,
//! or otherwise non-natural-language content far more discriminately than
//! pure Shannon entropy because the bigram model rewards real letter
//! transitions ("th", "er", "ing") and penalises adversarial garbage.

use super::bigram_model::BigramModel;
use super::{Category, Detector};
use crate::types::{Finding, Severity, TextChunk};

/// English prose under the bigram model scores around 2.0 nats/symbol;
/// source code 2.2-2.6; base64 ≈ 3.0; random ≈ 3.3.
const HIGH_NATS: f64 = 2.9;
const VERY_HIGH_NATS: f64 = 3.2;
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
        TextChunk {
            path: PathBuf::from("t.txt"),
            span: ByteSpan::new(0, text.len()),
            text: text.to_string(),
            provenance: Provenance::Prose,
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
}
