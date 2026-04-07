//! Extractors turn raw file bytes into one or more `TextChunk`s tagged
//! with provenance.
//!
//! Format dispatch is by file extension first, then by well-known
//! filename (so e.g. `Cargo.lock` is routed through the TOML extractor
//! even though `.lock` isn't the primary extension for TOML). Unknown
//! extensions fall back to the plain-text extractor.

mod config;
mod markup;
mod notebook;
#[cfg(feature = "pdf")]
mod pdf;
mod source;
mod text;

use anyhow::Result;

use crate::chunk::chunk_text;
use crate::types::{Provenance, TextChunk};
use crate::walk::WalkEntry;

pub fn extract(entry: &WalkEntry) -> Result<Vec<TextChunk>> {
    let ext = entry
        .path
        .extension()
        .and_then(|e| e.to_str())
        .map(|s| s.to_ascii_lowercase());
    let ext_str = ext.as_deref();

    // Well-known structured generated files, dispatched by filename.
    // These would otherwise fall through to the plain-text extractor
    // with `Prose` provenance, which makes the perplexity detector cry.
    let filename = entry
        .path
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("");
    match filename {
        "Cargo.lock" => return Ok(config::extract_toml(&entry.path, &entry.bytes)),
        "package-lock.json" | "composer.lock" | "bun.lockb" => {
            return Ok(config::extract_json(&entry.path, &entry.bytes));
        }
        _ => {}
    }

    match ext_str {
        Some("ipynb") => return Ok(notebook::extract_notebook(&entry.path, &entry.bytes)),
        Some("json") => return Ok(config::extract_json(&entry.path, &entry.bytes)),
        Some("toml") => return Ok(config::extract_toml(&entry.path, &entry.bytes)),
        Some("yaml" | "yml") => return Ok(config::extract_yaml(&entry.path, &entry.bytes)),
        Some("html" | "htm" | "svg" | "xml") => {
            return Ok(markup::extract_markup(&entry.path, &entry.bytes));
        }
        #[cfg(feature = "pdf")]
        Some("pdf") => return Ok(pdf::extract_pdf(&entry.path, &entry.bytes)),
        Some(e) if source::supports(e) => {
            return Ok(source::extract_source(&entry.path, e, &entry.bytes));
        }
        // Generic lockfile / checksum artifacts (yarn.lock, poetry.lock,
        // go.sum, pnpm-lock.yaml-without-extension, …). Their contents
        // are machine-generated and not natural language, so we tag
        // them with ConfigString so the heuristic / encoded / canary
        // / hidden-char detectors still run but perplexity skips them.
        Some("lock" | "sum") => return Ok(non_prose(&entry.path, &entry.bytes)),
        // Scripts and source files without a bundled tree-sitter
        // grammar. Treating these as Prose would pipe them straight
        // into the perplexity detector, which fires aggressively on
        // non-English code. We tag them as ConfigString instead so
        // the bigram scorer skips them (via `is_natural_language`)
        // while the other detectors still run normally.
        Some(
            "ps1" | "psm1" | "psd1"        // PowerShell
            | "bat" | "cmd"                 // Windows batch
            | "pl" | "pm"                   // Perl
            | "php" | "phtml" | "phps"      // PHP
            | "lua"                         // Lua
            | "r"                           // R
            | "jl"                          // Julia
            | "ex" | "exs" | "erl" | "hrl"  // Elixir / Erlang
            | "swift"                       // Swift
            | "kt" | "kts"                  // Kotlin
            | "scala" | "sc" | "sbt"        // Scala
            | "dart"                        // Dart
            | "m" | "mm"                    // Objective-C / MATLAB
            | "cs" | "csx"                  // C#
            | "fs" | "fsi" | "fsx"          // F#
            | "hs" | "lhs"                  // Haskell
            | "clj" | "cljc" | "cljs"       // Clojure
            | "ml" | "mli"                  // OCaml
            | "vb" | "vbs"                  // VB / VBScript
            | "pas" | "pp"                  // Pascal
            | "asm" | "s"                   // Assembly
            | "sql"                         // SQL
            | "proto" | "fbs" | "thrift"    // IDLs
            | "ini" | "cfg" | "conf" | "properties" // plain config
            | "tf" | "tfvars" | "hcl"       // Terraform / HCL
            | "nix"                         // Nix
            | "dockerfile" | "containerfile" // containers (rare as ext)
            | "mk" | "mak"                  // Makefiles (as extension)
            | "gradle"                      // Gradle build scripts
            | "cmake"                       // CMake
        ) => return Ok(non_prose(&entry.path, &entry.bytes)),
        _ => {}
    }

    // Well-known filenames that aren't distinguished by extension.
    match filename {
        "Dockerfile" | "Containerfile" | "Makefile" | "makefile" | "GNUmakefile"
        | "CMakeLists.txt" | "Rakefile" | "Gemfile" | "Procfile" | "Vagrantfile" | "Jenkinsfile"
        | "Brewfile" | "Podfile" | "Cartfile" | "Justfile" | "justfile" | ".env" | ".envrc" => {
            return Ok(non_prose(&entry.path, &entry.bytes));
        }
        _ => {}
    }

    if entry.bytes.contains(&0) {
        return Ok(Vec::new());
    }
    let Ok(text_str) = std::str::from_utf8(&entry.bytes) else {
        return Ok(Vec::new());
    };
    Ok(text::extract_text(&entry.path, text_str))
}

/// Chunk the file as plain text but tag the chunks with `ConfigString`
/// provenance so the perplexity detector skips them. Used for script /
/// IDL / build / env files that don't have a tree-sitter grammar.
fn non_prose(path: &std::path::Path, bytes: &[u8]) -> Vec<TextChunk> {
    if bytes.contains(&0) {
        return Vec::new();
    }
    let Ok(text) = std::str::from_utf8(bytes) else {
        return Vec::new();
    };
    chunk_text(path, text, Provenance::ConfigString)
}
