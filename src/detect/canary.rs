//! Canary / prompt-leak detector (DESIGN.md §4.5.5).
//!
//! Flags two things:
//!   1. Known canary token formats committed to the repo (Rebuff-style
//!      `[CANARY:<uuid>]` markers).
//!   2. User-supplied canary strings from the TOML config.
//!
//! A canary appearing in committed source generally means an LLM prompt
//! (possibly containing system instructions) was leaked into the repo.

use aho_corasick::{AhoCorasick, AhoCorasickBuilder, MatchKind};
use regex::Regex;

use super::{Category, Detector};
use crate::types::{ByteSpan, Finding, Severity, TextChunk};

pub struct CanaryDetector {
    rebuff_re: Regex,
    user_matcher: Option<AhoCorasick>,
    user_tokens: Vec<String>,
}

impl CanaryDetector {
    pub fn new(extra_tokens: &[String]) -> Self {
        let user_matcher = if extra_tokens.is_empty() {
            None
        } else {
            Some(
                AhoCorasickBuilder::new()
                    .ascii_case_insensitive(false)
                    .match_kind(MatchKind::LeftmostLongest)
                    .build(extra_tokens)
                    .expect("user-supplied canaries must build"),
            )
        };
        Self {
            rebuff_re: Regex::new(
                r"\[CANARY:[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\]",
            )
            .unwrap(),
            user_matcher,
            user_tokens: extra_tokens.to_vec(),
        }
    }
}

impl Detector for CanaryDetector {
    fn id(&self) -> &'static str {
        "canary"
    }

    fn category(&self) -> Category {
        Category::Canary
    }

    fn analyze(&self, chunk: &TextChunk) -> Vec<Finding> {
        let mut out = Vec::new();
        let text = &chunk.text;

        for m in self.rebuff_re.find_iter(text) {
            let abs_start = chunk.span.start + m.start();
            let abs_end = chunk.span.start + m.end();
            out.push(Finding {
                detector: "canary".to_string(),
                severity: Severity::High,
                confidence: 0.9,
                path: chunk.path.clone(),
                span: ByteSpan::new(abs_start, abs_end),
                message: "Rebuff-style canary token committed to repo".to_string(),
                evidence: Finding::make_evidence(m.as_str(), 120),
            });
        }

        if let Some(matcher) = &self.user_matcher {
            for m in matcher.find_iter(text) {
                let token = &self.user_tokens[m.pattern().as_usize()];
                let abs_start = chunk.span.start + m.start();
                let abs_end = chunk.span.start + m.end();
                out.push(Finding {
                    detector: "canary".to_string(),
                    severity: Severity::High,
                    confidence: 0.95,
                    path: chunk.path.clone(),
                    span: ByteSpan::new(abs_start, abs_end),
                    message: format!("user-defined canary token leaked: {token}"),
                    evidence: Finding::make_evidence(token, 120),
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
    fn detects_rebuff_canary() {
        let d = CanaryDetector::new(&[]);
        let f = d.analyze(&chunk("oh no [CANARY:12345678-1234-1234-1234-123456789abc] leaked"));
        assert_eq!(f.len(), 1);
        assert_eq!(f[0].severity, Severity::High);
    }

    #[test]
    fn detects_user_supplied_token() {
        let d = CanaryDetector::new(&["sk-prod-secret".to_string()]);
        let f = d.analyze(&chunk("oops sk-prod-secret in the open"));
        assert_eq!(f.len(), 1);
    }
}
