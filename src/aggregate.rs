//! Aggregator — collects findings, dedupes, and computes the verdict.

use std::collections::HashMap;
use std::path::PathBuf;

use crate::config::ScanConfig;
use crate::report::{FileReport, ScanReport, Verdict};
use crate::types::Finding;

/// Maximum contribution any single detector may make to a file's score.
/// This caps pathological cases where one noisy detector dominates the
/// repo verdict — see DESIGN.md §4.6.
const PER_DETECTOR_SCORE_CAP: f32 = 30.0;

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
                let score = capped_score(&findings);
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

/// Sum severity-weighted confidence per detector, then cap each detector's
/// contribution at [`PER_DETECTOR_SCORE_CAP`] before summing across
/// detectors. This prevents a single high-volume detector from dominating
/// the file's overall score.
fn capped_score(findings: &[Finding]) -> f32 {
    let mut by_detector: HashMap<&str, f32> = HashMap::new();
    for f in findings {
        let entry = by_detector.entry(f.detector.as_str()).or_insert(0.0);
        *entry += f.severity.weight() * f.confidence;
    }
    by_detector
        .into_values()
        .map(|s| s.min(PER_DETECTOR_SCORE_CAP))
        .sum()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{ByteSpan, Severity};
    use std::path::PathBuf;

    fn finding(detector: &str, severity: Severity, confidence: f32, start: usize) -> Finding {
        Finding {
            detector: detector.to_string(),
            category: crate::detect::Category::Heuristic,
            severity,
            confidence,
            path: PathBuf::from("t.txt"),
            span: ByteSpan::new(start, start + 1),
            message: String::new(),
            evidence: String::new(),
        }
    }

    #[test]
    fn cap_limits_a_runaway_detector() {
        // 50 high-confidence Critical findings from one detector would
        // otherwise add up to 50 * 15.0 = 750. The cap holds it at 30.
        let findings: Vec<_> = (0..50)
            .map(|i| finding("noisy", Severity::Critical, 1.0, i))
            .collect();
        assert!((capped_score(&findings) - PER_DETECTOR_SCORE_CAP).abs() < 0.001);
    }

    #[test]
    fn cap_does_not_apply_across_detectors() {
        // Two detectors each contributing < cap should sum normally.
        let findings = vec![
            finding("a", Severity::Medium, 1.0, 0), // 3.0
            finding("b", Severity::High, 1.0, 1),   // 7.0
        ];
        assert!((capped_score(&findings) - 10.0).abs() < 0.001);
    }
}
