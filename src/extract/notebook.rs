//! Jupyter `.ipynb` extractor.
//!
//! Walks the JSON structure and emits one chunk per markdown / code / output
//! cell, tagged with the appropriate provenance.

use std::path::Path;

use serde::Deserialize;

use crate::chunk::chunk_text;
use crate::types::{Provenance, TextChunk};

#[derive(Debug, Deserialize)]
struct Notebook {
    #[serde(default)]
    cells: Vec<Cell>,
}

#[derive(Debug, Deserialize)]
struct Cell {
    cell_type: String,
    #[serde(default)]
    source: SourceField,
    #[serde(default)]
    outputs: Vec<Output>,
}

#[derive(Debug, Deserialize, Default)]
#[serde(untagged)]
enum SourceField {
    String(String),
    Lines(Vec<String>),
    #[default]
    None,
}

impl SourceField {
    fn into_string(self) -> String {
        match self {
            SourceField::String(s) => s,
            SourceField::Lines(v) => v.concat(),
            SourceField::None => String::new(),
        }
    }
}

#[derive(Debug, Deserialize)]
struct Output {
    #[serde(default)]
    text: SourceField,
    #[serde(default)]
    data: Option<serde_json::Value>,
}

pub fn extract_notebook(path: &Path, bytes: &[u8]) -> Vec<TextChunk> {
    let Ok(notebook): Result<Notebook, _> = serde_json::from_slice(bytes) else {
        return Vec::new();
    };

    let mut out = Vec::new();
    for cell in notebook.cells {
        let provenance = match cell.cell_type.as_str() {
            "markdown" => Provenance::NotebookMarkdownCell,
            "code" => Provenance::NotebookCodeCell,
            _ => Provenance::Unknown,
        };
        let source = cell.source.into_string();
        if !source.is_empty() {
            out.extend(chunk_text(path, &source, provenance));
        }
        for output in cell.outputs {
            let text = output.text.into_string();
            if !text.is_empty() {
                out.extend(chunk_text(path, &text, Provenance::NotebookOutput));
            }
            if let Some(data) = output.data {
                if let Some(text_plain) = data.get("text/plain").and_then(|v| v.as_str()) {
                    out.extend(chunk_text(
                        path,
                        text_plain,
                        Provenance::NotebookOutput,
                    ));
                }
                if let Some(text_md) = data.get("text/markdown").and_then(|v| v.as_str()) {
                    out.extend(chunk_text(
                        path,
                        text_md,
                        Provenance::NotebookOutput,
                    ));
                }
            }
        }
    }
    out
}
