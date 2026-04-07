//! SARIF 2.1.0 reporter.
//!
//! Emits a minimal but valid SARIF log suitable for `github/codeql-action/upload-sarif`.
//! One rule per detector id encountered, one result per finding.

use std::collections::BTreeMap;

use serde_json::{Value, json};

use super::ScanReport;
use crate::types::Severity;

pub fn render(report: &ScanReport) -> Result<String, serde_json::Error> {
    // Collect unique detector ids in stable order so the rules array is
    // deterministic across runs.
    let mut rule_index: BTreeMap<String, usize> = BTreeMap::new();
    for file in &report.files {
        for f in &file.findings {
            if !rule_index.contains_key(&f.detector) {
                let next = rule_index.len();
                rule_index.insert(f.detector.clone(), next);
            }
        }
    }

    let rules: Vec<Value> = rule_index
        .iter()
        .map(|(id, _)| {
            json!({
                "id": id,
                "name": id,
                "shortDescription": { "text": format!("InjectorDetector {id} detector") },
                "defaultConfiguration": { "level": "warning" }
            })
        })
        .collect();

    let mut results = Vec::new();
    for file in &report.files {
        for f in &file.findings {
            let rule_idx = rule_index[&f.detector];
            results.push(json!({
                "ruleId": f.detector,
                "ruleIndex": rule_idx,
                "level": sarif_level(f.severity),
                "message": { "text": f.message },
                "locations": [{
                    "physicalLocation": {
                        "artifactLocation": { "uri": file.path.display().to_string().replace('\\', "/") },
                        "region": {
                            "byteOffset": f.span.start,
                            "byteLength": f.span.end.saturating_sub(f.span.start)
                        }
                    }
                }],
                "properties": {
                    "confidence": f.confidence,
                    "severity": format!("{:?}", f.severity).to_lowercase(),
                    "evidence": f.evidence
                }
            }));
        }
    }

    let log = json!({
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {
                "driver": {
                    "name": "InjectorDetector",
                    "informationUri": "https://github.com/anthropics/injector-detector",
                    "version": env!("CARGO_PKG_VERSION"),
                    "rules": rules
                }
            },
            "results": results
        }]
    });

    serde_json::to_string_pretty(&log)
}

fn sarif_level(sev: Severity) -> &'static str {
    match sev {
        Severity::Low => "note",
        Severity::Medium => "warning",
        Severity::High | Severity::Critical => "error",
    }
}
