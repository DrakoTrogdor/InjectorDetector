//! Snapshot tests for the human, JSON, and SARIF reporters.
//!
//! Snapshots are stored under `tests/snapshots/` and reviewed via
//! `cargo insta review` when the rendered output legitimately changes.

use std::path::PathBuf;

use injector_detector::detect::Category;
use injector_detector::report::{FileReport, ScanReport, Verdict};
use injector_detector::types::{ByteSpan, Finding, Severity};

fn fixture_report() -> ScanReport {
    let findings = vec![
        Finding {
            detector: "heuristic".to_string(),
            category: Category::Heuristic,
            severity: Severity::Critical,
            confidence: 0.95,
            path: PathBuf::from("src/foo.md"),
            span: ByteSpan::new(10, 22),
            message: "ChatML role-hijack token (chatml_role_hijack)".to_string(),
            evidence: "<|im_start|>".to_string(),
        },
        Finding {
            detector: "hidden_chars".to_string(),
            category: Category::HiddenChars,
            severity: Severity::Medium,
            confidence: 0.95,
            path: PathBuf::from("src/foo.md"),
            span: ByteSpan::new(40, 43),
            message: "hidden zero-width U+200B".to_string(),
            evidence: "U+200B".to_string(),
        },
    ];
    let file = FileReport {
        path: PathBuf::from("src/foo.md"),
        score: 17.5,
        max_severity: Some(Severity::Critical),
        findings,
    };
    ScanReport {
        files: vec![file],
        max_severity: Some(Severity::Critical),
        verdict: Verdict::NotSafe,
    }
}

#[test]
fn human_report_snapshot() {
    insta::assert_snapshot!("human_report", fixture_report().render_human());
}

#[test]
fn json_report_snapshot() {
    let json = fixture_report().render_json().unwrap();
    insta::assert_snapshot!("json_report", json);
}

#[test]
fn sarif_report_snapshot() {
    let sarif = fixture_report().render_sarif().unwrap();
    // SARIF embeds the package version; redact it so the snapshot is
    // stable across version bumps.
    let redacted = sarif.replace(env!("CARGO_PKG_VERSION"), "<version>");
    insta::assert_snapshot!("sarif_report", redacted);
}
