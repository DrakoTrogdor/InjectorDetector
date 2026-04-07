//! Tree-sitter source-code extractor.
//!
//! Parses source files for a small set of supported languages and yields
//! one chunk per comment, string literal, or docstring node.

use std::path::Path;

use tree_sitter::{Language, Node, Parser, Tree};

use crate::chunk::chunk_text;
use crate::types::{Provenance, TextChunk};

#[derive(Clone, Copy)]
struct LangSpec {
    language: fn() -> Language,
    comment_kinds: &'static [&'static str],
    string_kinds: &'static [&'static str],
}

fn rust_spec() -> LangSpec {
    LangSpec {
        language: || tree_sitter_rust::LANGUAGE.into(),
        comment_kinds: &["line_comment", "block_comment"],
        string_kinds: &["string_literal", "raw_string_literal"],
    }
}

fn python_spec() -> LangSpec {
    LangSpec {
        language: || tree_sitter_python::LANGUAGE.into(),
        comment_kinds: &["comment"],
        string_kinds: &["string"],
    }
}

fn javascript_spec() -> LangSpec {
    LangSpec {
        language: || tree_sitter_javascript::LANGUAGE.into(),
        comment_kinds: &["comment"],
        string_kinds: &["string", "template_string"],
    }
}

fn typescript_spec() -> LangSpec {
    LangSpec {
        language: || tree_sitter_typescript::LANGUAGE_TYPESCRIPT.into(),
        comment_kinds: &["comment"],
        string_kinds: &["string", "template_string"],
    }
}

fn tsx_spec() -> LangSpec {
    LangSpec {
        language: || tree_sitter_typescript::LANGUAGE_TSX.into(),
        comment_kinds: &["comment"],
        string_kinds: &["string", "template_string"],
    }
}

fn go_spec() -> LangSpec {
    LangSpec {
        language: || tree_sitter_go::LANGUAGE.into(),
        comment_kinds: &["comment"],
        string_kinds: &["interpreted_string_literal", "raw_string_literal"],
    }
}

fn spec_for_extension(ext: &str) -> Option<LangSpec> {
    match ext {
        "rs" => Some(rust_spec()),
        "py" | "pyi" => Some(python_spec()),
        "js" | "mjs" | "cjs" | "jsx" => Some(javascript_spec()),
        "ts" | "mts" | "cts" => Some(typescript_spec()),
        "tsx" => Some(tsx_spec()),
        "go" => Some(go_spec()),
        _ => None,
    }
}

pub fn supports(ext: &str) -> bool {
    spec_for_extension(ext).is_some()
}

pub fn extract_source(path: &Path, ext: &str, bytes: &[u8]) -> Vec<TextChunk> {
    let Some(spec) = spec_for_extension(ext) else {
        return Vec::new();
    };
    let Ok(text) = std::str::from_utf8(bytes) else {
        return Vec::new();
    };

    let mut parser = Parser::new();
    if parser.set_language(&(spec.language)()).is_err() {
        return Vec::new();
    }
    let Some(tree): Option<Tree> = parser.parse(text, None) else {
        return Vec::new();
    };

    let mut out = Vec::new();
    walk(tree.root_node(), text, path, &spec, &mut out);
    out
}

fn walk(node: Node, source: &str, path: &Path, spec: &LangSpec, out: &mut Vec<TextChunk>) {
    let kind = node.kind();
    let provenance = if spec.comment_kinds.contains(&kind) {
        Some(Provenance::Comment)
    } else if spec.string_kinds.contains(&kind) {
        Some(Provenance::StringLiteral)
    } else {
        None
    };

    if let Some(provenance) = provenance {
        let start = node.start_byte();
        let end = node.end_byte();
        if let Some(slice) = source.get(start..end) {
            for mut chunk in chunk_text(path, slice, provenance) {
                chunk.span.start += start;
                chunk.span.end += start;
                out.push(chunk);
            }
        }
        return;
    }

    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        walk(child, source, path, spec, out);
    }
}
