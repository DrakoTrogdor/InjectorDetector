//! Auto-quarantine review queue.
//!
//! A project can opt into a review workflow where findings are recorded
//! in a `.injector-detector-ignore` file and subsequent scans skip
//! matching entries. This lets teams accept legacy findings without
//! turning off detectors entirely.
//!
//! File format is TOML so it round-trips through serde cleanly:
//!
//! ```toml
//! version = 1
//! generated_at = "2026-04-07T00:00:00Z"
//!
//! [[ignore]]
//! detector = "heuristic"
//! path = "docs/legacy.md"
//! message = "ChatML role-hijack token (chatml_role_hijack)"
//! evidence_hash = "a3f…"
//! note = "Historical documentation example, reviewed by @alice on 2026-03-15"
//! ```
//!
//! Matching is by `(detector, path, message, evidence_hash)` tuple so
//! edits to the surrounding file don't silently un-ignore findings.

use std::collections::HashSet;
use std::path::Path;

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

use crate::types::Finding;

/// Current on-disk schema version. Bump when the file format changes.
pub const CURRENT_VERSION: u32 = 1;

/// On-disk structure of the ignore file.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct QuarantineFile {
    #[serde(default = "default_version")]
    pub version: u32,
    #[serde(default)]
    pub generated_at: Option<String>,
    #[serde(default, rename = "ignore")]
    pub entries: Vec<QuarantineEntry>,
}

fn default_version() -> u32 {
    CURRENT_VERSION
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub struct QuarantineEntry {
    pub detector: String,
    pub path: String,
    pub message: String,
    pub evidence_hash: String,
    #[serde(default)]
    pub note: Option<String>,
}

impl QuarantineEntry {
    pub fn from_finding(f: &Finding) -> Self {
        Self {
            detector: f.detector.clone(),
            path: f.path.display().to_string().replace('\\', "/"),
            message: f.message.clone(),
            evidence_hash: hash_evidence(&f.evidence),
            note: None,
        }
    }

    pub fn matches_finding(&self, f: &Finding) -> bool {
        self.detector == f.detector
            && self.path == f.path.display().to_string().replace('\\', "/")
            && self.message == f.message
            && self.evidence_hash == hash_evidence(&f.evidence)
    }
}

/// Load a quarantine file from disk. Missing files produce an empty
/// list rather than an error — the common case is "not yet initialised".
pub fn load(path: &Path) -> Result<QuarantineFile> {
    if !path.exists() {
        return Ok(QuarantineFile::default());
    }
    let raw = std::fs::read_to_string(path)
        .with_context(|| format!("failed to read quarantine file {}", path.display()))?;
    let parsed: QuarantineFile = toml::from_str(&raw)
        .with_context(|| format!("failed to parse quarantine file {}", path.display()))?;
    Ok(parsed)
}

/// Write a quarantine file. Creates parent directories if needed.
pub fn save(path: &Path, file: &QuarantineFile) -> Result<()> {
    if let Some(parent) = path.parent()
        && !parent.as_os_str().is_empty()
    {
        std::fs::create_dir_all(parent).ok();
    }
    let toml_text = toml::to_string_pretty(file).context("failed to serialize quarantine file")?;
    std::fs::write(path, toml_text)
        .with_context(|| format!("failed to write quarantine file {}", path.display()))?;
    Ok(())
}

/// Filter a finding list, dropping anything matched by any entry in `file`.
pub fn filter_findings(findings: &mut Vec<Finding>, file: &QuarantineFile) {
    if file.entries.is_empty() {
        return;
    }
    // Index entries by (detector, path) to make the common case fast.
    let mut index: std::collections::HashMap<(String, String), Vec<&QuarantineEntry>> =
        std::collections::HashMap::new();
    for e in &file.entries {
        index
            .entry((e.detector.clone(), e.path.clone()))
            .or_default()
            .push(e);
    }
    findings.retain(|f| {
        let key = (f.detector.clone(), f.path.display().to_string().replace('\\', "/"));
        match index.get(&key) {
            Some(bucket) => !bucket.iter().any(|e| e.matches_finding(f)),
            None => true,
        }
    });
}

/// Append new findings to the file, deduplicating against existing entries.
pub fn append_findings(file: &mut QuarantineFile, findings: &[Finding]) {
    let existing: HashSet<QuarantineEntry> = file.entries.iter().cloned().collect();
    for f in findings {
        let entry = QuarantineEntry::from_finding(f);
        if !existing.contains(&entry) {
            file.entries.push(entry);
        }
    }
    file.version = CURRENT_VERSION;
    file.generated_at = Some(now_rfc3339());
}

/// Lightweight non-cryptographic hash of an evidence string. We don't
/// need collision resistance, just a stable short identifier.
fn hash_evidence(evidence: &str) -> String {
    let mut h: u64 = 0xcbf29ce484222325;
    for &b in evidence.as_bytes() {
        h ^= b as u64;
        h = h.wrapping_mul(0x100000001b3);
    }
    format!("{h:016x}")
}

fn now_rfc3339() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    // Cheap formatted timestamp without chrono: YYYY-MM-DDTHH:MM:SSZ
    // computed from the Unix epoch. Good enough for an audit field.
    let days = secs / 86_400;
    let seconds_of_day = secs % 86_400;
    let (y, m, d) = date_from_days(days as i64);
    let h = seconds_of_day / 3600;
    let mi = (seconds_of_day % 3600) / 60;
    let s = seconds_of_day % 60;
    format!("{y:04}-{m:02}-{d:02}T{h:02}:{mi:02}:{s:02}Z")
}

fn date_from_days(mut days: i64) -> (i32, u32, u32) {
    // Days since 1970-01-01 → (year, month, day). Algorithm from Howard Hinnant.
    days += 719_468;
    let era = if days >= 0 { days } else { days - 146_096 } / 146_097;
    let doe = (days - era * 146_097) as u64;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = (yoe as i64) + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = y + if m <= 2 { 1 } else { 0 };
    (y as i32, m as u32, d as u32)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::detect::Category;
    use crate::types::{ByteSpan, Severity};
    use std::path::PathBuf;

    fn finding(detector: &str, path: &str, message: &str, evidence: &str) -> Finding {
        Finding {
            detector: detector.to_string(),
            category: Category::Heuristic,
            severity: Severity::High,
            confidence: 0.9,
            path: PathBuf::from(path),
            span: ByteSpan::new(0, 1),
            message: message.to_string(),
            evidence: evidence.to_string(),
        }
    }

    #[test]
    fn filter_drops_matching_findings() {
        let mut file = QuarantineFile::default();
        append_findings(
            &mut file,
            &[finding("heuristic", "a.md", "msg", "evidence")],
        );
        let mut findings = vec![
            finding("heuristic", "a.md", "msg", "evidence"),
            finding("heuristic", "a.md", "other", "evidence"),
        ];
        filter_findings(&mut findings, &file);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].message, "other");
    }

    #[test]
    fn append_is_idempotent() {
        let mut file = QuarantineFile::default();
        let f = finding("heuristic", "a.md", "msg", "evidence");
        append_findings(&mut file, std::slice::from_ref(&f));
        append_findings(&mut file, std::slice::from_ref(&f));
        assert_eq!(file.entries.len(), 1);
    }

    #[test]
    fn round_trip_through_toml() {
        let mut file = QuarantineFile::default();
        append_findings(
            &mut file,
            &[finding("heuristic", "a.md", "msg", "evidence")],
        );
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(".injector-detector-ignore");
        save(&path, &file).unwrap();
        let loaded = load(&path).unwrap();
        assert_eq!(loaded.entries.len(), 1);
        assert_eq!(loaded.entries[0].detector, "heuristic");
    }
}
