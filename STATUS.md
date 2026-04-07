# InjectorDetector — Status

Living checklist tracking what's done and what's left against [`DESIGN.md`](DESIGN.md).
Update this file alongside the change that completes (or adds) an item.

## Completed

### Project scaffolding
- [x] `Cargo.toml` with bin + lib targets and feature flags (`embeddings`, `pdf`)
- [x] `DESIGN.md` — full architecture document
- [x] `README.md` — install, usage, CI snippet, configuration
- [x] `LICENSE` — MIT
- [x] `.gitignore` — Rust, IDE, OS, project caches, local config, large model artifacts
- [x] `action.yml` — GitHub Action composite wrapper with cached binary install
- [x] `.pre-commit-hooks.yaml` — pre-commit integration (default + strict hooks)
- [x] Initial commit

### CLI
- [x] `clap`-based CLI with positional `REPO`, `--rev`, `--config`, `--format`, `--fail-on`, `--include`, `--exclude`, `--no-clone`, **`--keep`**, `--jobs`
- [x] Exit codes: `0` SAFE, `1` NOT SAFE, `2` scan error
- [x] `tracing` / `tracing-subscriber` initialised with `RUST_LOG` env filter
- [x] Walker emits `tracing::warn!` when `--rev` is silently dropped during the working-tree fallback

### Repo loader (`src/repo.rs`)
- [x] Local path open via `gix`
- [x] Remote URL shallow clone into a tempdir via `gix::prepare_clone`
- [x] `--no-clone` enforcement
- [x] Tempdir cleanup on drop

### File walker (`src/walk.rs`)
- [x] gix tree walker that resolves `--rev` to a tree and streams blob bytes
- [x] Working-tree fallback via the `ignore` crate for non-git paths and empty repos
- [x] `--include` / `--exclude` glob filters
- [x] `max_binary_bytes` cap

### Extractors (`src/extract/`)
- [x] `text` — UTF-8 / Markdown plain-text fallback
- [x] `source` — tree-sitter dispatcher for **Rust, Python, JavaScript, TypeScript, TSX, Go, Java, C, C++, Bash, Ruby** (comments + string literals with rebased byte spans)
- [x] `notebook` — Jupyter `.ipynb` markdown / code / output cells
- [x] `config` — JSON, TOML, **YAML** string-value walkers
- [x] `markup` — HTML / SVG / XML via `scraper` (text, comments, curated attributes)
- [x] `pdf` — `pdf-extract`-backed extractor behind the `pdf` Cargo feature
- [x] Extension-based dispatcher in `extract/mod.rs`

### Chunker (`src/chunk.rs`)
- [x] NFKC normalisation
- [x] Windowed chunking (2 KiB window, 256 B overlap)
- [x] Multibyte-safe boundary handling
- [x] Original byte spans preserved for reporting

### Detectors (`src/detect/`)
- [x] `Detector` trait + parallel `Engine` (rayon, sized by `--jobs`)
- [x] Per-detector enable toggles via config
- [x] **`heuristic`** — `yara-x` 1.14 backed scanner loading bundled `rules/builtin.yar` (9 rules) plus user `extra_rules` glob patterns
- [x] **`hidden_chars`** — zero-width (Medium), bidi-override + tag-character (Critical), **plus Cyrillic / Greek homoglyph clusters in Latin words (High)**
- [x] **`encoded`** — base64 / hex / URL-encoded recursive decode + needle re-scan
- [x] **`canary`** — Rebuff-style `[CANARY:<uuid>]` regex + user-supplied tokens
- [x] **`perplexity`** — character-bigram language model trained at startup from `bigram_corpus.txt` via `OnceLock`
- [x] **`embedding`** — 64-bit SimHash over normalised tokens vs ~30 canonical injection payloads; **real ONNX backend via `ort` 2.0.0-rc.10 behind the `embeddings` feature**, loading a user-supplied sentence-transformer model and matching by cosine similarity with mean-pooling over the token axis

### Bundled assets
- [x] `rules/builtin.yar` — 9 YARA rules with severity / confidence / message metadata
- [x] `src/detect/bigram_corpus.txt` — embedded English training corpus

### Aggregator (`src/aggregate.rs`)
- [x] Per-file dedupe by `(detector, span)`
- [x] Per-file score = Σ(severity_weight × confidence)
- [x] **Per-detector score cap (30.0) so a single noisy detector cannot dominate the verdict**
- [x] Verdict computation against `--fail-on`
- [x] Files sorted by score in the report

### Reporters (`src/report/`)
- [x] `human` — coloured terminal output, grouped by file
- [x] `json` — `serde_json` pretty
- [x] `sarif` — real SARIF 2.1.0 with rules, results, byte-offset regions, severity-mapped levels
- [x] `Category` exposed via SARIF `properties.category` and JSON `category` field on each finding

### Configuration (`src/config.rs`)
- [x] `ScanConfig` defaults
- [x] TOML config file loading with `[scan]` and `[detectors.*]` sections
- [x] Per-detector enable toggles
- [x] `[detectors.heuristic] extra_rules` glob list
- [x] `[detectors.canary] tokens` user canary list
- [x] `[detectors.embedding] model` ONNX model path

### Tests
- [x] **28 unit tests** across `types`, `chunk`, `aggregate`, `bigram_model`, `heuristic`, `hidden_chars`, `encoded`, `canary`, `perplexity`, `embedding`
- [x] **15 integration tests** in `tests/integration.rs` driving the public `scan()` API
- [x] **4 property tests** (`proptest`) in `tests/properties.rs` for chunker boundary safety, span correctness, multibyte input, overlap invariants
- [x] **3 snapshot tests** (`insta`) in `tests/snapshots.rs` for the human, JSON, and SARIF reporters
- [x] **gix tree walker test** — `tests/common/git_helper.rs` builds a real git repo programmatically via `gix::init` + `write_blob` + `write_object` + `commit_as`; two tests verify the gix snapshot path is taken (committed-content-only finding, working-tree-only-clean negative)
- [x] `tests/fixtures/clean/` — README, Rust source, JSON config (verdict: SAFE)
- [x] `tests/fixtures/dirty/` — one fixture per detector / extractor:
  - `heuristic.md`, `hidden.txt`, `encoded.md`, `canary.txt`
  - `notebook.ipynb`, `source.py`, `markup.html`, `workflow.yaml`
  - `high_entropy.txt`
- [x] Both default and `--features embeddings` build clean
- [x] **Total: 50 tests passing**

## In progress

_(nothing currently in progress)_

## Planned — medium term

- [ ] **Bundle a default ONNX model** — the ONNX backend currently requires the user to point at their own model via `[detectors.embedding] model = "..."`. Shipping a small quantised sentence-transformer (e.g. `all-MiniLM-L6-v2`) would make the backend usable out of the box.
- [ ] **Real tokenizer for the ONNX backend** — the current path uses a placeholder whitespace tokeniser (ids = 1..=N). A bundled model should be paired with its original HuggingFace tokenizer (via the `tokenizers` crate) for accurate embeddings.
- [ ] **Live LLM-based classifier detector** — DESIGN.md §11. Would let the tool consult a hosted or local model at scan time; default off, opt-in.
- [ ] **Incremental scan mode** — only re-evaluate files changed since a base ref (DESIGN.md §11).
- [ ] **Auto-quarantine review queue** — write a `.injector-detector-ignore` file for review instead of failing the build outright (DESIGN.md §11).

## Out of scope

These appear in `tldrsec/prompt-injection-defenses` but are inherently runtime-only and not relevant to a static scanner. Documented in DESIGN.md §7 for completeness.

- Spotlighting / sandwich defense / post-prompting
- Dual-LLM pattern / taint tracking
- Paraphrasing / retokenization input pre-processing
- Output overseers (LLM self-defense)
- Model hardening / finetuning
