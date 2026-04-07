//! JSON reporter.

use serde_json::Value;

use super::{RenderOptions, ScanReport};
use crate::safe_view;

pub fn render(report: &ScanReport, options: &RenderOptions) -> Result<String, serde_json::Error> {
    if !options.ai_safe {
        return serde_json::to_string_pretty(report);
    }

    // AI-safe mode: serialise the report to a Value, walk the
    // file/finding tree, sanitize the evidence/message fields, and
    // add a top-level flag that tells machine consumers this payload
    // has been rewritten for safe LLM display.
    let mut root = serde_json::to_value(report)?;

    if let Value::Object(ref mut obj) = root {
        obj.insert("safe_view".to_string(), Value::Bool(true));
        obj.insert(
            "ai_safe_preamble".to_string(),
            Value::String(safe_view::AI_SAFE_PREAMBLE.to_string()),
        );
        if let Some(Value::Array(files)) = obj.get_mut("files") {
            for file in files.iter_mut() {
                sanitize_file(file);
            }
        }
    }

    serde_json::to_string_pretty(&root)
}

fn sanitize_file(file: &mut Value) {
    let Value::Object(map) = file else { return };
    if let Some(Value::String(path)) = map.get_mut("path") {
        *path = safe_view::sanitize_path(path);
    }
    if let Some(Value::Array(findings)) = map.get_mut("findings") {
        for f in findings.iter_mut() {
            sanitize_finding(f);
        }
    }
}

fn sanitize_finding(finding: &mut Value) {
    let Value::Object(map) = finding else { return };
    if let Some(Value::String(path)) = map.get_mut("path") {
        *path = safe_view::sanitize_path(path);
    }
    if let Some(Value::String(message)) = map.get_mut("message") {
        *message = safe_view::sanitize_message(message);
    }
    if let Some(Value::String(evidence)) = map.get_mut("evidence") {
        *evidence = safe_view::sanitize_evidence(evidence, 120);
    }
}

