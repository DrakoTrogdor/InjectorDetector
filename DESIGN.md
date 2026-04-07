# InjectorDetector — Design Document

## 1. Overview

`InjectorDetector` is a Rust command-line tool that scans a Git repository for
prompt injection payloads embedded in source files, documentation, configuration,
notebooks, and other repo content. It produces a single binary verdict —
**SAFE** or **NOT SAFE** — alongside a detailed report of findings.

The detection methodology is grounded in the techniques catalogued in
[tldrsec/prompt-injection-defenses](https://github.com/tldrsec/prompt-injection-defenses),
with a focus on the **detective** family of defenses (input overseers, output
overseers, heuristic/YARA matching, perplexity analysis) applied statically to
files at rest rather than to a live LLM request stream.

### 1.1 Goals

- Accept a Git repository (local path or remote URL) as the sole required argument.
- Walk the repository, extract textual content from supported file types, and
  evaluate each chunk against a layered set of detectors.
- Emit a deterministic SAFE / NOT SAFE verdict with a non-zero exit code on
  NOT SAFE, suitable for use in CI pipelines.
- Be fast enough for pre-commit and pull-request gating on real-world repos.

### 1.2 Non-Goals

- Runtime defense of a live LLM (no proxying, no request rewriting).
- Removing or rewriting injection payloads (detection only).
- Semantic understanding of attacker intent beyond what the layered detectors
  can express.

## 2. Usage

```text
injector-detector <REPO> [OPTIONS]

ARGS:
    <REPO>  Path to a local clone or a remote Git URL (https/ssh)

OPTIONS:
    --rev <REV>             Git revision to scan (default: HEAD)
    --config <FILE>         Path to a TOML config file
    --format <FMT>          human | json | sarif (default: human)
    --fail-on <SEVERITY>    low | medium | high | critical (default: medium)
    --include <GLOB>...     Restrict scan to matching paths
    --exclude <GLOB>...     Skip matching paths (in addition to defaults)
    --no-clone              Refuse to clone; require a local path
    --jobs <N>              Worker thread count (default: num_cpus)
```

Exit codes: `0` SAFE, `1` NOT SAFE, `2` scan error.

## 3. High-Level Architecture

```
            +-------------------+
   repo --> |   Repo Loader     |  clone-or-open, checkout rev
            +---------+---------+
                      |
                      v
            +-------------------+
            |   File Walker     |  gitignore-aware, path filters
            +---------+---------+
                      |
                      v
            +-------------------+
            |   Extractors      |  per-format text extraction
            +---------+---------+
                      |
                      v
            +-------------------+
            |    Chunker        |  normalized, bounded segments
            +---------+---------+
                      |
                      v
            +-------------------+
            |  Detector Engine  |  parallel detector pipeline
            +---------+---------+
                      |
                      v
            +-------------------+
            |    Aggregator     |  dedupe, score, severity
            +---------+---------+
                      |
                      v
            +-------------------+
            |    Reporter       |  human / json / sarif
            +-------------------+
```

## 4. Components

### 4.1 Repo Loader (`repo`)

- Uses [`gix`](https://crates.io/crates/gix) (gitoxide) for pure-Rust Git
  access — no external `git` binary required.
- If the argument is a URL, shallow-clones into a temp directory under the OS
  temp dir, and removes it on drop unless `--keep` is set.
- If the argument is a local path, opens it in place and never mutates the
  working tree.
- Resolves `--rev` to a tree object so the scan operates on a consistent
  snapshot, not the working tree, eliminating TOCTOU concerns.

### 4.2 File Walker (`walk`)

- Iterates the resolved tree using `gix` object traversal so that `.gitignore`
  is respected automatically (we only see committed files).
- Applies built-in skip rules:
  - Binary files larger than `max_binary_bytes` (default 1 MiB).
  - Lockfiles, vendored directories, minified JS, generated assets.
- Applies user `--include` / `--exclude` glob filters via the `globset` crate.
- Streams `(path, blob_id, bytes)` tuples downstream; never loads the whole
  repo into memory.

### 4.3 Extractors (`extract`)

Each extractor turns raw bytes into one or more `TextChunk { path, span, text,
provenance }` records. `provenance` records *why* this text is interesting
(e.g. `MarkdownProse`, `PythonStringLiteral`, `NotebookMarkdownCell`,
`HtmlComment`), which downstream detectors can use to tune sensitivity.

Supported formats in v1:

| Format            | Extractor                              | Provenance tags |
|-------------------|----------------------------------------|-----------------|
| Plain text / md   | UTF-8 decode + section split           | `Prose`, `CodeFence` |
| Source code       | `tree-sitter` per language             | `Comment`, `StringLiteral`, `Docstring` |
| Jupyter notebooks | JSON parse                             | `MarkdownCell`, `CodeCell`, `Output` |
| HTML / SVG        | `scraper` walk                         | `Text`, `Comment`, `Attribute` |
| YAML / JSON / TOML| serde traversal of string values       | `ConfigString` |
| PDF (optional)    | `pdf-extract` behind feature flag      | `PdfText` |

Languages with tree-sitter coverage in v1: Rust, Python, JavaScript /
TypeScript, Go, Java, C / C++, Shell, Ruby. Unknown languages fall back to
the plain-text extractor.

### 4.4 Chunker (`chunk`)

- Normalises Unicode using NFKC and strips zero-width / bidi-control
  characters into a separate `hidden_chars` signal that detectors can read.
- Splits long extractions into overlapping windows (default 2 KiB, 256 B
  overlap) so detectors see local context without unbounded inputs.
- Records the original byte span for accurate report locations.

### 4.5 Detector Engine (`detect`)

The engine runs each chunk through a pipeline of `Detector` trait
implementations in parallel via `rayon`. Each detector returns zero or more
`Finding`s:

```rust
pub trait Detector: Sync {
    fn id(&self) -> &'static str;
    fn category(&self) -> Category;
    fn analyze(&self, chunk: &TextChunk) -> Vec<Finding>;
}

pub struct Finding {
    pub detector: &'static str,
    pub severity: Severity,        // Low | Medium | High | Critical
    pub confidence: f32,           // 0.0..=1.0
    pub path: PathBuf,
    pub span: ByteSpan,
    pub message: String,
    pub evidence: String,          // truncated, redacted snippet
}
```

The detectors below map directly to techniques surveyed in
`tldrsec/prompt-injection-defenses`. Detective techniques are applied
statically; preventative techniques (spotlighting, sandwich defense, dual
LLM, etc.) are *not* applicable to a static scanner and are documented in
§7 as out of scope.

#### 4.5.1 Heuristic / YARA Pattern Detector

Implements the **heuristic and YARA-rule matching** input-overseer technique.

- Ships a curated rule pack (`rules/*.yar` and `rules/*.toml`) covering
  well-known injection idioms: "ignore previous instructions", "disregard
  the above", "system prompt:", role-hijack patterns (`<|im_start|>`,
  `### Instruction:`), tool-call spoofs, jailbreak preambles ("DAN",
  "developer mode"), and exfiltration phrasings ("send the contents to").
- Uses [`yara-x`](https://crates.io/crates/yara-x) (pure-Rust YARA engine).
- Rules carry `severity` and `confidence` metadata in their `meta:` block.
- Users can extend the pack via `--config` without recompiling.

#### 4.5.2 Hidden / Adversarial Character Detector

Targets a common smuggling vector that defeats human review.

- Flags zero-width characters (U+200B–U+200D, U+FEFF), bidi overrides
  (U+202A–U+202E, U+2066–U+2069), tag characters (U+E0000–U+E007F), and
  homoglyph clusters (Cyrillic letters mixed into Latin words).
- Severity scales with density: a single ZWSP in prose is Low; a sequence of
  bidi overrides inside a code comment is Critical.

#### 4.5.3 Perplexity Detector

Implements the **perplexity analysis** input-overseer technique.

- Uses a small embedded n-gram language model (KenLM-style binary, loaded
  via `mmap`) trained on natural English plus common code comments.
- Computes per-window perplexity; windows whose perplexity exceeds an
  adaptive threshold relative to the rest of the file are flagged.
- Rationale: many injection payloads (especially obfuscated or
  base64/hex-encoded ones) have anomalous token distributions compared to
  surrounding human-written text.

#### 4.5.4 Encoded-Payload Detector

Catches payloads that try to evade plain-text rules by encoding themselves.

- Scans for long base64, base32, hex, and URL-encoded runs.
- Decodes candidates (bounded by size) and re-feeds the result through the
  Heuristic detector — a recursion depth of 2 covers nearly all observed
  layered encodings while keeping cost predictable.

#### 4.5.5 Canary / Prompt-Leak Detector

Implements the **canary token** output-overseer technique, applied to repo
artifacts that may have been generated by an LLM.

- Looks for known canary token formats (Rebuff-style UUID prefixes, custom
  user-supplied canaries from config) inside committed files. Their
  presence indicates that prompt content (possibly containing system
  instructions) was committed to the repo.

#### 4.5.6 Embedding Similarity Detector (optional, feature-flagged)

Implements a **vector-database matching** approach inspired by Rebuff.

- Off by default; enabled with `--features embeddings`.
- Uses a small ONNX sentence-transformer via `ort` to embed each chunk.
- Compares against a bundled FAISS-style flat index of known injection
  payloads (HuggingFace `deepset/prompt-injections`, Lakera Gandalf
  corpus, plus our own seed set).
- Cosine similarity above a threshold raises a Medium finding.

### 4.6 Aggregator (`aggregate`)

- Deduplicates findings whose `(detector, path, span)` collide.
- Merges overlapping spans from different detectors into a single
  `FindingGroup` and takes the maximum severity.
- Computes a per-file and per-repo score:
  `repo_score = max(file_scores)`, where `file_score` is the sum of
  `severity_weight * confidence` over the file's findings, capped per
  detector to prevent a single noisy file from dominating.

### 4.7 Reporter (`report`)

- `human`: colourised terminal output, grouped by file, with span context.
- `json`: stable schema for downstream tooling.
- `sarif`: SARIF 2.1.0 for GitHub code-scanning integration.

The verdict logic: if any finding's severity is `>= --fail-on`, the verdict
is **NOT SAFE** and the process exits `1`. Otherwise **SAFE**, exit `0`.

## 5. Crate Layout

```
injector-detector/
├── Cargo.toml
├── DESIGN.md
├── rules/                    # bundled YARA + TOML rule packs
├── models/                   # n-gram LM, optional ONNX embedder
└── src/
    ├── main.rs               # CLI entry, arg parsing (clap)
    ├── lib.rs                # public API for library use
    ├── repo.rs               # gix-based loader
    ├── walk.rs               # tree walker + filters
    ├── extract/
    │   ├── mod.rs
    │   ├── text.rs
    │   ├── source.rs         # tree-sitter dispatcher
    │   ├── notebook.rs
    │   ├── markup.rs         # html/svg
    │   └── config.rs         # yaml/json/toml
    ├── chunk.rs
    ├── detect/
    │   ├── mod.rs            # Detector trait + engine
    │   ├── heuristic.rs      # yara-x rules
    │   ├── hidden_chars.rs
    │   ├── perplexity.rs
    │   ├── encoded.rs
    │   ├── canary.rs
    │   └── embedding.rs      # feature = "embeddings"
    ├── aggregate.rs
    ├── report/
    │   ├── mod.rs
    │   ├── human.rs
    │   ├── json.rs
    │   └── sarif.rs
    └── config.rs             # TOML config schema
```

## 6. Key Dependencies

| Crate           | Purpose                                   |
|-----------------|-------------------------------------------|
| `clap`          | CLI parsing                               |
| `gix`           | Git access without shelling out           |
| `ignore`        | gitignore-aware walking helpers           |
| `globset`       | include/exclude glob filters              |
| `rayon`         | parallel detector pipeline                |
| `tree-sitter` + language grammars | source extraction        |
| `yara-x`        | rule engine                               |
| `unicode-normalization`, `unicode-bidi` | hidden-char detection |
| `serde`, `serde_json`, `toml` | config + JSON / notebook parsing |
| `scraper`       | HTML / SVG walking                        |
| `base64`, `hex` | encoded-payload decoding                  |
| `memmap2`       | mmap the n-gram LM and embedding index    |
| `ort`           | ONNX runtime (optional, embeddings)       |
| `tracing`       | structured logging                        |
| `anyhow`, `thiserror` | error handling                      |

## 7. Mapping to tldrsec/prompt-injection-defenses

| Defense (from tldrsec)            | In InjectorDetector                                  |
|-----------------------------------|------------------------------------------------------|
| Heuristic / YARA matching         | §4.5.1 Heuristic detector                            |
| Perplexity analysis               | §4.5.3 Perplexity detector                           |
| Vector-DB / embedding match       | §4.5.6 Embedding detector (feature-flagged)          |
| Canary tokens                     | §4.5.5 Canary detector                               |
| LLM-based input classifier        | Out of v1 scope (would need network or local LLM)    |
| Spotlighting / sandwich / post-prompting | N/A — preventative, applied at request time   |
| Dual LLM / taint tracking         | N/A — preventative, runtime-only                     |
| Paraphrasing / retokenization     | N/A — input pre-processing for live requests         |
| Output overseers (self-defense)   | N/A — no model output to inspect statically          |
| Model hardening / finetuning      | N/A — model-side mitigation                          |

The static-scan posture means InjectorDetector is a **complement** to the
runtime defenses described in tldrsec's catalogue, not a replacement. It
catches payloads that have been *committed* to a repo before they can ever
reach a model.

## 8. Performance Targets

- Cold scan of a 100 kLOC repo on a modern laptop: under 10 seconds with the
  default detector set.
- Memory ceiling: 512 MiB regardless of repo size (streaming walk + bounded
  per-chunk allocations).
- Embedding detector adds roughly 2× latency when enabled.

## 9. Security Considerations

- The tool only *reads* the target repo. Cloning happens into a private
  temp dir with `0700` permissions on Unix.
- All decoded payloads stay in-process; nothing is executed.
- Evidence snippets in reports are length-capped and have control characters
  escaped to avoid terminal-escape-sequence attacks against the user's shell.
- Rule packs and models are loaded read-only via `mmap`; no rule executes
  arbitrary code (yara-x has no `import "console"` equivalent enabled).

## 10. Testing Strategy

- **Unit tests** per detector with curated positive and negative fixtures.
- **Corpus tests** against a vendored mini-corpus of public injection
  payloads (Lakera Gandalf samples, HuggingFace `deepset/prompt-injections`).
- **Repo fixtures** under `tests/fixtures/repos/` are tiny git repos
  (committed as bundle files) exercising each extractor and the verdict
  logic end-to-end.
- **Property tests** (`proptest`) on the chunker and Unicode normaliser.
- **Snapshot tests** (`insta`) on the human/json/sarif reporters.

## 11. Future Work

- Live LLM-based classifier as an opt-in detector.
- Incremental scan mode that only re-evaluates files changed since a base ref.
- Pre-commit hook and GitHub Action wrappers.
- Auto-quarantine mode that writes a `.injector-detector-ignore` review queue
  rather than failing the build outright.
