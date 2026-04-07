//! Config-file extractor for JSON / YAML / TOML.
//!
//! Walks the parsed structure and emits a chunk per string value, tagged
//! `ConfigString`. We don't try to preserve byte spans here — config files
//! are small enough that span-level precision is rarely needed and a
//! whole-string chunk is good enough for the heuristic detectors.
//!
//! YAML support is intentionally omitted for now to avoid pulling in
//! `serde_yaml`; the JSON walker handles `.json` and the TOML walker
//! handles `.toml`. YAML can be added behind a feature flag later.

use std::path::Path;

use crate::chunk::chunk_text;
use crate::types::{Provenance, TextChunk};

pub fn extract_json(path: &Path, bytes: &[u8]) -> Vec<TextChunk> {
    let Ok(value): Result<serde_json::Value, _> = serde_json::from_slice(bytes) else {
        return Vec::new();
    };
    let mut out = Vec::new();
    walk_json(&value, path, &mut out);
    out
}

fn walk_json(value: &serde_json::Value, path: &Path, out: &mut Vec<TextChunk>) {
    match value {
        serde_json::Value::String(s) => {
            if !s.is_empty() {
                out.extend(chunk_text(path, s, Provenance::ConfigString));
            }
        }
        serde_json::Value::Array(arr) => {
            for v in arr {
                walk_json(v, path, out);
            }
        }
        serde_json::Value::Object(obj) => {
            for v in obj.values() {
                walk_json(v, path, out);
            }
        }
        _ => {}
    }
}

pub fn extract_yaml(path: &Path, bytes: &[u8]) -> Vec<TextChunk> {
    let Ok(text) = std::str::from_utf8(bytes) else {
        return Vec::new();
    };
    let Ok(value): Result<serde_yml::Value, _> = serde_yml::from_str(text) else {
        return Vec::new();
    };
    let mut out = Vec::new();
    walk_yaml(&value, path, &mut out);
    out
}

fn walk_yaml(value: &serde_yml::Value, path: &Path, out: &mut Vec<TextChunk>) {
    match value {
        serde_yml::Value::String(s) => {
            if !s.is_empty() {
                out.extend(chunk_text(path, s, Provenance::ConfigString));
            }
        }
        serde_yml::Value::Sequence(seq) => {
            for v in seq {
                walk_yaml(v, path, out);
            }
        }
        serde_yml::Value::Mapping(map) => {
            for (_, v) in map {
                walk_yaml(v, path, out);
            }
        }
        _ => {}
    }
}

pub fn extract_toml(path: &Path, bytes: &[u8]) -> Vec<TextChunk> {
    let Ok(text) = std::str::from_utf8(bytes) else {
        return Vec::new();
    };
    let Ok(value): Result<toml::Value, _> = toml::from_str(text) else {
        return Vec::new();
    };
    let mut out = Vec::new();
    walk_toml(&value, path, &mut out);
    out
}

fn walk_toml(value: &toml::Value, path: &Path, out: &mut Vec<TextChunk>) {
    match value {
        toml::Value::String(s) => {
            if !s.is_empty() {
                out.extend(chunk_text(path, s, Provenance::ConfigString));
            }
        }
        toml::Value::Array(arr) => {
            for v in arr {
                walk_toml(v, path, out);
            }
        }
        toml::Value::Table(t) => {
            for v in t.values() {
                walk_toml(v, path, out);
            }
        }
        _ => {}
    }
}
