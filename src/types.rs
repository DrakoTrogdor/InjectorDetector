//! Core data types shared across the pipeline.

use std::path::PathBuf;

use serde::{Deserialize, Serialize};

/// Severity ranking. Ordered so `>=` comparisons work for `--fail-on`.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize,
)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Low,
    Medium,
    High,
    Critical,
}

impl Severity {
    pub fn weight(self) -> f32 {
        match self {
            Severity::Low => 1.0,
            Severity::Medium => 3.0,
            Severity::High => 7.0,
            Severity::Critical => 15.0,
        }
    }

    /// Lowercase label, matching the serde / SARIF / JSON representation.
    pub fn as_str(self) -> &'static str {
        match self {
            Severity::Low => "low",
            Severity::Medium => "medium",
            Severity::High => "high",
            Severity::Critical => "critical",
        }
    }
}

impl std::fmt::Display for Severity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

impl std::str::FromStr for Severity {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_ascii_lowercase().as_str() {
            "low" => Ok(Severity::Low),
            "medium" | "med" => Ok(Severity::Medium),
            "high" => Ok(Severity::High),
            "critical" | "crit" => Ok(Severity::Critical),
            other => Err(format!("unknown severity: {other}")),
        }
    }
}

/// Where in a file a chunk came from. Detectors can use this to tune
/// sensitivity (a comment is more interesting than a literal config string).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Provenance {
    Prose,
    CodeFence,
    Comment,
    StringLiteral,
    Docstring,
    NotebookMarkdownCell,
    NotebookCodeCell,
    NotebookOutput,
    HtmlText,
    HtmlComment,
    HtmlAttribute,
    ConfigString,
    PdfText,
    Unknown,
}

impl Provenance {
    /// Returns true if chunks of this provenance are expected to be
    /// natural human-readable language. The perplexity detector uses
    /// this to skip structured content (config values, code literals,
    /// HTML attributes, notebook code cells, etc.) that would otherwise
    /// score above the English bigram baseline for purely structural
    /// reasons.
    pub fn is_natural_language(self) -> bool {
        matches!(
            self,
            Self::Prose
                | Self::Docstring
                | Self::NotebookMarkdownCell
                | Self::HtmlText
                | Self::PdfText
        )
    }
}

/// A byte span within the source file the chunk was extracted from.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct ByteSpan {
    pub start: usize,
    pub end: usize,
}

impl ByteSpan {
    pub fn new(start: usize, end: usize) -> Self {
        Self { start, end }
    }

    pub fn len(&self) -> usize {
        self.end.saturating_sub(self.start)
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

/// A normalised piece of text fed to detectors.
#[derive(Debug, Clone)]
pub struct TextChunk {
    pub path: PathBuf,
    pub span: ByteSpan,
    pub text: String,
    pub provenance: Provenance,
}

/// A single detector hit.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Finding {
    pub detector: String,
    /// High-level category the detector belongs to. Populated by the
    /// engine after the detector returns the finding so individual
    /// detectors don't have to set it themselves.
    #[serde(default = "default_category")]
    pub category: crate::detect::Category,
    pub severity: Severity,
    pub confidence: f32,
    pub path: PathBuf,
    pub span: ByteSpan,
    pub message: String,
    pub evidence: String,
}

fn default_category() -> crate::detect::Category {
    crate::detect::Category::Heuristic
}

impl Finding {
    /// Truncate and escape an evidence snippet for safe display.
    pub fn make_evidence(text: &str, max: usize) -> String {
        let mut out = String::with_capacity(text.len().min(max));
        for ch in text.chars().take(max) {
            match ch {
                '\n' => out.push_str("\\n"),
                '\r' => out.push_str("\\r"),
                '\t' => out.push_str("\\t"),
                c if c.is_control() => {
                    out.push_str(&format!("\\u{{{:04x}}}", c as u32));
                }
                c => out.push(c),
            }
        }
        if text.chars().count() > max {
            out.push('…');
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn severity_orders_from_low_to_critical() {
        assert!(Severity::Low < Severity::Medium);
        assert!(Severity::Medium < Severity::High);
        assert!(Severity::High < Severity::Critical);
    }

    #[test]
    fn severity_parses_known_strings() {
        assert_eq!("low".parse::<Severity>().unwrap(), Severity::Low);
        assert_eq!("MED".parse::<Severity>().unwrap(), Severity::Medium);
        assert_eq!("crit".parse::<Severity>().unwrap(), Severity::Critical);
        assert!("nonsense".parse::<Severity>().is_err());
    }

    #[test]
    fn evidence_escapes_control_chars_and_truncates() {
        let evidence = Finding::make_evidence("hello\nworld\u{0007}!", 100);
        assert_eq!(evidence, "hello\\nworld\\u{0007}!");

        let truncated = Finding::make_evidence("abcdefghij", 5);
        assert_eq!(truncated, "abcde…");
    }
}

