//! Report types and emitters.

mod human;
mod json;
mod sarif;

use std::path::PathBuf;

use serde::{Deserialize, Serialize};

use crate::types::{Finding, Severity};

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

    pub fn render_human(&self) -> String {
        human::render(self)
    }

    pub fn render_json(&self) -> Result<String, serde_json::Error> {
        json::render(self)
    }

    pub fn render_sarif(&self) -> Result<String, serde_json::Error> {
        sarif::render(self)
    }
}
