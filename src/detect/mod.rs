//! Detector trait and the engine that runs them.

mod bigram_model;
mod canary;
mod embedding;
mod encoded;
mod heuristic;
mod hidden_chars;
mod perplexity;

use crate::config::DetectorConfig;
use crate::types::{Finding, TextChunk};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Category {
    Heuristic,
    HiddenChars,
    Perplexity,
    Encoded,
    Canary,
    Embedding,
}

pub trait Detector: Send + Sync {
    fn id(&self) -> &'static str;
    fn category(&self) -> Category;
    fn analyze(&self, chunk: &TextChunk) -> Vec<Finding>;
}

pub struct Engine {
    detectors: Vec<Box<dyn Detector>>,
}

impl Engine {
    pub fn with_defaults() -> Self {
        Self::from_config(&DetectorConfig::default())
    }

    pub fn from_config(cfg: &DetectorConfig) -> Self {
        let mut detectors: Vec<Box<dyn Detector>> = Vec::new();
        if cfg.heuristic {
            detectors.push(Box::new(heuristic::HeuristicDetector::new(&cfg.extra_rules)));
        }
        if cfg.hidden_chars {
            detectors.push(Box::new(hidden_chars::HiddenCharsDetector));
        }
        if cfg.encoded {
            detectors.push(Box::new(encoded::EncodedDetector::new()));
        }
        if cfg.canary {
            detectors.push(Box::new(canary::CanaryDetector::new(&cfg.extra_canaries)));
        }
        if cfg.perplexity {
            detectors.push(Box::new(perplexity::PerplexityDetector));
        }
        if cfg.embedding {
            detectors.push(Box::new(embedding::EmbeddingDetector::new(
                cfg.embedding_model.as_ref(),
            )));
        }
        Self { detectors }
    }

    pub fn analyze(&self, chunk: &TextChunk) -> Vec<Finding> {
        let mut out = Vec::new();
        for d in &self.detectors {
            out.extend(d.analyze(chunk));
        }
        out
    }
}
