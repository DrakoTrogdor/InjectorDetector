//! SARIF 2.1.0 reporter.
//!
//! Emits a minimal but valid SARIF log suitable for `github/codeql-action/upload-sarif`.
//! One rule per detector id encountered, one result per finding.

use std::collections::BTreeMap;

use serde_json::{Value, json};

use super::{RenderOptions, ScanReport};
use crate::safe_view;
use crate::types::Severity;

pub fn render(
    report: &ScanReport,
    options: &RenderOptions,
) -> Result<String, serde_json::Error> {
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
        .keys()
        .map(|id| {
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
            let uri_raw = file.path.display().to_string().replace('\\', "/");
            let (message, evidence, uri) = if options.ai_safe {
                (
                    safe_view::sanitize_message(&f.message),
                    safe_view::sanitize_evidence(&f.evidence, 120),
                    safe_view::sanitize_path(&uri_raw),
                )
            } else {
                (f.message.clone(), f.evidence.clone(), uri_raw)
            };
            results.push(json!({
                "ruleId": f.detector,
                "ruleIndex": rule_idx,
                "level": sarif_level(f.severity),
                "message": { "text": message },
                "locations": [{
                    "physicalLocation": {
                        "artifactLocation": { "uri": uri },
                        "region": {
                            "byteOffset": f.span.start,
                            "byteLength": f.span.end.saturating_sub(f.span.start)
                        }
                    }
                }],
                "properties": {
                    "category": f.category.as_str(),
                    "confidence": f.confidence,
                    "severity": format!("{:?}", f.severity).to_lowercase(),
                    "evidence": evidence
                }
            }));
        }
    }

    let mut driver = serde_json::Map::new();
    driver.insert("name".to_string(), Value::String("InjectorDetector".into()));
    driver.insert(
        "informationUri".to_string(),
        Value::String("https://github.com/anthropics/injector-detector".into()),
    );
    driver.insert(
        "version".to_string(),
        Value::String(env!("CARGO_PKG_VERSION").to_string()),
    );
    driver.insert("rules".to_string(), Value::Array(rules));
    if options.ai_safe {
        let mut props = serde_json::Map::new();
        props.insert("safeView".to_string(), Value::Bool(true));
        props.insert(
            "aiSafePreamble".to_string(),
            Value::String(safe_view::AI_SAFE_PREAMBLE.to_string()),
        );
        driver.insert("properties".to_string(), Value::Object(props));
    }

    let log = json!({
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": { "driver": driver },
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
