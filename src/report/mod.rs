//! Report types and emitters.

mod human;
mod json;
mod sarif;

use std::path::PathBuf;

use serde::{Deserialize, Serialize};

use crate::types::{Finding, Severity};

/// Options that affect how a [`ScanReport`] is rendered. These belong
/// on the renderer, not the report itself, because they don't change
/// the *findings* — only how they're presented.
#[derive(Debug, Clone, Default)]
pub struct RenderOptions {
    /// Sanitize evidence / messages so the rendered output is safe
    /// to display to a large-language-model assistant. Adds a
    /// preamble explaining the [UNTRUSTED:…] markers, escapes
    /// dangerous token pairs (`<|`, `|>`, ` ``` `, `{{`, `}}`), and
    /// renders invisible characters as codepoint notation. See
    /// [`crate::safe_view`].
    pub ai_safe: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Verdict {
    Safe,
    NotSafe,
}

impl Verdict {
    pub fn label(self) -> &'static str {
        match self {
            Verdict::Safe => "SAFE",
            Verdict::NotSafe => "NOT SAFE",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileReport {
    pub path: PathBuf,
    pub findings: Vec<Finding>,
    pub max_severity: Option<Severity>,
    pub score: f32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanReport {
    pub files: Vec<FileReport>,
    pub max_severity: Option<Severity>,
    pub verdict: Verdict,
}

impl ScanReport {
    pub fn max_severity(&self) -> Option<Severity> {
        self.max_severity
    }

    pub fn total_findings(&self) -> usize {
        self.files.iter().map(|f| f.findings.len()).sum()
    }

    pub fn render_human(&self, options: &RenderOptions) -> String {
        human::render(self, options)
    }

    pub fn render_json(&self, options: &RenderOptions) -> Result<String, serde_json::Error> {
        json::render(self, options)
    }

    pub fn render_sarif(&self, options: &RenderOptions) -> Result<String, serde_json::Error> {
        sarif::render(self, options)
    }
}
