//! Integration tests that drive the public `scan()` API against the
//! file fixtures under `tests/fixtures/`.

use std::path::PathBuf;

use injector_detector::{
    config::ScanConfig,
    is_unsafe, scan,
    types::Severity,
    report::{ScanReport, Verdict},
};

fn fixture(name: &str) -> String {
    let mut p = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    p.push("tests");
    p.push("fixtures");
    p.push(name);
    p.to_string_lossy().into_owned()
}

fn run(name: &str) -> ScanReport {
    let cfg = ScanConfig::default();
    scan(&fixture(name), &cfg).expect("scan should not error")
}

fn finding_detectors(report: &ScanReport, file_suffix: &str) -> Vec<String> {
    report
        .files
        .iter()
        .filter(|f| f.path.to_string_lossy().ends_with(file_suffix))
        .flat_map(|f| f.findings.iter().map(|x| x.detector.clone()))
        .collect()
}

#[test]
fn clean_fixture_is_safe() {
    let report = run("clean");
    assert_eq!(
        report.verdict,
        Verdict::Safe,
        "expected clean fixture to be SAFE, got {:?} with findings {:#?}",
        report.verdict,
        report.files
    );
    assert!(!is_unsafe(&report, Severity::Medium));
}

#[test]
fn dirty_fixture_is_not_safe() {
    let report = run("dirty");
    assert_eq!(report.verdict, Verdict::NotSafe);
    assert!(is_unsafe(&report, Severity::Medium));
    assert!(report.total_findings() > 0);
}

#[test]
fn heuristic_fires_on_known_phrases() {
    let report = run("dirty");
    let detectors = finding_detectors(&report, "heuristic.md");
    assert!(
        detectors.iter().any(|d| d == "heuristic"),
        "expected heuristic detector to fire on heuristic.md, got {detectors:?}"
    );
}

#[test]
fn hidden_chars_detector_fires() {
    let report = run("dirty");
    let detectors = finding_detectors(&report, "hidden.txt");
    assert!(
        detectors.iter().any(|d| d == "hidden_chars"),
        "expected hidden_chars detector to fire on hidden.txt, got {detectors:?}"
    );
}

#[test]
fn encoded_detector_decodes_base64_payload() {
    let report = run("dirty");
    let detectors = finding_detectors(&report, "encoded.md");
    assert!(
        detectors.iter().any(|d| d == "encoded"),
        "expected encoded detector to fire on encoded.md, got {detectors:?}"
    );
}

#[test]
fn canary_detector_fires_on_rebuff_token() {
    let report = run("dirty");
    let detectors = finding_detectors(&report, "canary.txt");
    assert!(
        detectors.iter().any(|d| d == "canary"),
        "expected canary detector to fire on canary.txt, got {detectors:?}"
    );
}

#[test]
fn notebook_extractor_surfaces_markdown_cells() {
    let report = run("dirty");
    let detectors = finding_detectors(&report, "notebook.ipynb");
    assert!(
        detectors.iter().any(|d| d == "heuristic"),
        "expected heuristic to fire on notebook markdown cell, got {detectors:?}"
    );
}

#[test]
fn source_extractor_surfaces_python_comment() {
    let report = run("dirty");
    let detectors = finding_detectors(&report, "source.py");
    assert!(
        detectors.iter().any(|d| d == "heuristic"),
        "expected heuristic to fire on python comment, got {detectors:?}"
    );
}

#[test]
fn markup_extractor_surfaces_html_comment() {
    let report = run("dirty");
    let detectors = finding_detectors(&report, "markup.html");
    assert!(
        detectors.iter().any(|d| d == "heuristic"),
        "expected heuristic to fire on html comment, got {detectors:?}"
    );
}

#[test]
fn perplexity_detector_fires_on_high_entropy_blob() {
    let report = run("dirty");
    let detectors = finding_detectors(&report, "high_entropy.txt");
    assert!(
        detectors.iter().any(|d| d == "perplexity"),
        "expected perplexity detector to fire on high_entropy.txt, got {detectors:?}"
    );
}

#[test]
fn yaml_extractor_surfaces_run_step() {
    let report = run("dirty");
    let detectors = finding_detectors(&report, "workflow.yaml");
    assert!(
        detectors.iter().any(|d| d == "heuristic"),
        "expected heuristic to fire on yaml run step, got {detectors:?}"
    );
}

#[test]
fn fail_on_threshold_controls_verdict() {
    // With fail_on = Critical, even clean files should remain SAFE; the
    // dirty fixture still has Critical findings (ChatML hijack tokens).
    let mut cfg = ScanConfig::default();
    cfg.fail_on = Severity::Critical;
    let report = scan(&fixture("dirty"), &cfg).unwrap();
    assert_eq!(report.verdict, Verdict::NotSafe);
}

#[test]
fn json_and_sarif_render_without_error() {
    let report = run("dirty");
    let json = report.render_json().expect("json render");
    assert!(json.contains("\"verdict\""));
    let sarif = report.render_sarif().expect("sarif render");
    assert!(sarif.contains("\"version\": \"2.1.0\""));
}
