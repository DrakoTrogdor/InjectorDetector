//! Encoded-payload detector (DESIGN.md §4.5.4).
//!
//! Looks for long base64 / hex / URL-encoded runs in a chunk, decodes them
//! (recursively, bounded depth), and re-runs the heuristic ruleset against
//! the decoded text. Detection of *encoded prompt-injection content* is
//! always a Critical finding because it strongly implies an evasion attempt.

use aho_corasick::{AhoCorasick, AhoCorasickBuilder, MatchKind};
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use percent_encoding::percent_decode_str;
use regex::Regex;

use super::{Category, Detector};
use crate::types::{ByteSpan, Finding, Severity, TextChunk};

const MAX_DEPTH: usize = 2;
const MIN_RUN_LEN: usize = 24;
const MAX_DECODE_BYTES: usize = 64 * 1024;

/// Curated phrases the encoded detector looks for inside *decoded* payloads.
/// We deliberately keep this list focused on the strongest signals so the
/// detector reports false positives at a near-zero rate; the full YARA pack
/// is what catches things in plaintext.
const DECODED_NEEDLES: &[(&str, &str)] = &[
    ("ignore previous instructions", "classic prompt-injection preamble"),
    ("ignore all previous", "classic prompt-injection preamble"),
    ("disregard the above", "instruction-override phrase"),
    ("disregard previous", "instruction-override phrase"),
    ("system prompt:", "system-prompt spoof"),
    ("<|im_start|>", "ChatML role-hijack token"),
    ("<|im_end|>", "ChatML role-hijack token"),
    ("### Instruction:", "Alpaca-style instruction marker"),
    ("DAN mode", "known jailbreak preamble"),
    ("developer mode enabled", "known jailbreak preamble"),
    ("reveal the system prompt", "exfiltration vocabulary"),
];

pub struct EncodedDetector {
    matcher: AhoCorasick,
    base64_re: Regex,
    hex_re: Regex,
    url_re: Regex,
}

impl EncodedDetector {
    pub fn new() -> Self {
        let needles: Vec<&str> = DECODED_NEEDLES.iter().map(|(n, _)| *n).collect();
        let matcher = AhoCorasickBuilder::new()
            .ascii_case_insensitive(true)
            .match_kind(MatchKind::LeftmostLongest)
            .build(&needles)
            .expect("decoded-needle set must build");
        Self {
            matcher,
            base64_re: Regex::new(r"[A-Za-z0-9+/_-]{24,}={0,2}").unwrap(),
            hex_re: Regex::new(r"(?:[0-9A-Fa-f]{2}){12,}").unwrap(),
            url_re: Regex::new(r"(?:%[0-9A-Fa-f]{2}){8,}").unwrap(),
        }
    }

    fn scan_decoded(&self, decoded: &str) -> Option<&'static str> {
        let m = self.matcher.find(decoded)?;
        Some(DECODED_NEEDLES[m.pattern().as_usize()].1)
    }

    fn try_recurse(&self, decoded: &str, depth: usize) -> Option<String> {
        if let Some(msg) = self.scan_decoded(decoded) {
            return Some(msg.to_string());
        }
        if depth >= MAX_DEPTH {
            return None;
        }
        // Re-scan the decoded text for nested encodings.
        for cap in self.base64_re.find_iter(decoded) {
            if let Some(inner) = decode_base64(cap.as_str())
                && let Some(found) = self.try_recurse(&inner, depth + 1)
            {
                return Some(found);
            }
        }
        for cap in self.hex_re.find_iter(decoded) {
            if let Some(inner) = decode_hex(cap.as_str())
                && let Some(found) = self.try_recurse(&inner, depth + 1)
            {
                return Some(found);
            }
        }
        None
    }
}

impl Detector for EncodedDetector {
    fn id(&self) -> &'static str {
        "encoded"
    }

    fn category(&self) -> Category {
        Category::Encoded
    }

    fn analyze(&self, chunk: &TextChunk) -> Vec<Finding> {
        let mut out = Vec::new();
        let text = &chunk.text;

        for (regex, kind, decoder) in [
            (
                &self.base64_re,
                "base64",
                decode_base64 as fn(&str) -> Option<String>,
            ),
            (&self.hex_re, "hex", decode_hex),
            (&self.url_re, "url", decode_url),
        ] {
            for m in regex.find_iter(text) {
                if m.as_str().len() < MIN_RUN_LEN {
                    continue;
                }
                let Some(decoded) = decoder(m.as_str()) else {
                    continue;
                };
                if decoded.len() > MAX_DECODE_BYTES {
                    continue;
                }
                if let Some(msg) = self.try_recurse(&decoded, 0) {
                    let abs_start = chunk.span.start + m.start();
                    let abs_end = chunk.span.start + m.end();
                    out.push(Finding {
                        detector: "encoded".to_string(),
                        severity: Severity::Critical,
                        confidence: 0.9,
                        path: chunk.path.clone(),
                        span: ByteSpan::new(abs_start, abs_end),
                        message: format!("{kind}-encoded injection payload: {msg}"),
                        evidence: Finding::make_evidence(&decoded, 120),
                    });
                }
            }
        }

        out
    }
}

fn decode_base64(s: &str) -> Option<String> {
    let trimmed = s.trim_end_matches('=');
    // Try standard alphabet first; fall back to URL-safe by translating chars.
    let bytes = STANDARD.decode(s).ok().or_else(|| {
        let translated: String = trimmed
            .chars()
            .map(|c| match c {
                '-' => '+',
                '_' => '/',
                other => other,
            })
            .collect();
        STANDARD.decode(translated.as_bytes()).ok()
    })?;
    String::from_utf8(bytes).ok()
}

fn decode_hex(s: &str) -> Option<String> {
    let mut bytes = Vec::with_capacity(s.len() / 2);
    let chars: Vec<char> = s.chars().collect();
    for pair in chars.chunks_exact(2) {
        let hi = pair[0].to_digit(16)?;
        let lo = pair[1].to_digit(16)?;
        bytes.push(((hi << 4) | lo) as u8);
    }
    String::from_utf8(bytes).ok()
}

fn decode_url(s: &str) -> Option<String> {
    percent_decode_str(s).decode_utf8().ok().map(|c| c.into_owned())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{ByteSpan, Provenance, TextChunk};
    use std::path::PathBuf;

    fn chunk(text: &str) -> TextChunk {
        TextChunk {
            path: PathBuf::from("t.txt"),
            span: ByteSpan::new(0, text.len()),
            text: text.to_string(),
            provenance: Provenance::Prose,
        }
    }

    #[test]
    fn detects_base64_encoded_injection() {
        // base64("ignore previous instructions")
        let payload = "aWdub3JlIHByZXZpb3VzIGluc3RydWN0aW9ucw==";
        let f = EncodedDetector::new().analyze(&chunk(payload));
        assert_eq!(f.len(), 1);
        assert_eq!(f[0].severity, Severity::Critical);
    }

    #[test]
    fn benign_base64_is_ignored() {
        // base64("the quick brown fox jumps over the lazy dog twice ")
        let payload = "dGhlIHF1aWNrIGJyb3duIGZveCBqdW1wcyBvdmVyIHRoZSBsYXp5IGRvZyB0d2ljZSA=";
        let f = EncodedDetector::new().analyze(&chunk(payload));
        assert!(f.is_empty());
    }
}
