//! HTML / SVG / XML extractor.
//!
//! Uses `scraper` to parse the document and walks the resulting node tree
//! to emit text nodes, comments, and a curated set of attribute values
//! (`title`, `alt`, `aria-label`, `placeholder`, `content`).

use std::path::Path;

use scraper::{Html, Node};

use crate::chunk::chunk_text;
use crate::types::{Provenance, TextChunk};

const ATTRS_OF_INTEREST: &[&str] = &["title", "alt", "aria-label", "placeholder", "content"];

pub fn extract_markup(path: &Path, bytes: &[u8]) -> Vec<TextChunk> {
    let Ok(text) = std::str::from_utf8(bytes) else {
        return Vec::new();
    };
    let document = Html::parse_document(text);
    let mut out = Vec::new();

    for node in document.tree.nodes() {
        match node.value() {
            Node::Text(t) => {
                let s = t.text.trim();
                if !s.is_empty() {
                    out.extend(chunk_text(path, s, Provenance::HtmlText));
                }
            }
            Node::Comment(c) => {
                let s = c.comment.trim();
                if !s.is_empty() {
                    out.extend(chunk_text(path, s, Provenance::HtmlComment));
                }
            }
            Node::Element(el) => {
                for (name, value) in el.attrs() {
                    if ATTRS_OF_INTEREST.contains(&name.to_ascii_lowercase().as_str())
                        && !value.is_empty()
                    {
                        out.extend(chunk_text(path, value, Provenance::HtmlAttribute));
                    }
                }
            }
            _ => {}
        }
    }

    out
}
