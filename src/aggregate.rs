//! Aggregator — collects findings, dedupes, and computes the verdict.

use std::collections::HashMap;
use std::path::PathBuf;

use crate::config::ScanConfig;
use crate::report::{FileReport, ScanReport, Verdict};
use crate::types::Finding;

pub struct Aggregator {
    by_file: HashMap<PathBuf, Vec<Finding>>,
}

impl Aggregator {
    pub fn new() -> Self {
        Self {
            by_file: HashMap::new(),
        }
    }

    pub fn add(&mut self, finding: Finding) {
        self.by_file
            .entry(finding.path.clone())
            .or_default()
            .push(finding);
    }

    pub fn finalize(mut self, config: &ScanConfig) -> ScanReport {
        let mut files: Vec<FileReport> = self
            .by_file
            .drain()
            .map(|(path, mut findings)| {
                findings.sort_by_key(|f| (f.span.start, f.span.end));
                dedupe(&mut findings);
                let max_severity = findings.iter().map(|f| f.severity).max();
                let score = findings
                    .iter()
                    .map(|f| f.severity.weight() * f.confidence)
                    .sum();
                FileReport {
                    path,
                    findings,
                    max_severity,
                    score,
                }
            })
            .collect();

        files.sort_by(|a, b| b.score.partial_cmp(&a.score).unwrap_or(std::cmp::Ordering::Equal));

        let max_severity = files.iter().filter_map(|f| f.max_severity).max();
        let verdict = match max_severity {
            Some(s) if s >= config.fail_on => Verdict::NotSafe,
            _ => Verdict::Safe,
        };

        ScanReport {
            files,
            max_severity,
            verdict,
        }
    }
}

impl Default for Aggregator {
    fn default() -> Self {
        Self::new()
    }
}

/// Drop exact `(detector, span)` duplicates from a sorted slice.
fn dedupe(findings: &mut Vec<Finding>) {
    findings.dedup_by(|a, b| {
        a.detector == b.detector && a.span.start == b.span.start && a.span.end == b.span.end
    });
}

// Re-export Severity here so callers can be agnostic about modules.
pub use crate::types::Severity as _Severity;
