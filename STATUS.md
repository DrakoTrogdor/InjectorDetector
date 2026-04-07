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
- [x] `clap`-based CLI with positional `REPO`, `--rev`, `--config`, `--format`, `--fail-on`, `--include`, `--exclude`, `--no-clone`, `--keep`, `--since`, `--quarantine`, `--ignore-file`, **`-q` / `--quiet`**, `--jobs`
- [x] Exit codes: `0` SAFE, `1` NOT SAFE, `2` scan error
- [x] `tracing` / `tracing-subscriber` initialised with `RUST_LOG` env filter
- [x] Walker emits `tracing::warn!` when `--rev` is silently dropped during the working-tree fallback
- [x] **`indicatif` progress bar on stderr** showing pipeline stage (load / walk / scan / aggregate), per-file ticks with the current path, elapsed time, and a final verdict summary. Auto-disables under `--quiet` or when stderr is not a TTY (so redirected output stays clean).

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
- [x] **Lockfile-aware dispatch** — `Cargo.lock` → `extract_toml`; `package-lock.json` / `composer.lock` / `bun.lockb` → `extract_json`; generic `*.lock` / `*.sum` → text with `ConfigString` provenance so perplexity stays off
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
- [x] **`hidden_chars`** — zero-width (Medium), bidi-override + tag-character (Critical), plus Cyrillic / Greek homoglyph clusters in Latin words (High)
- [x] **`encoded`** — base64 / hex / URL-encoded recursive decode + needle re-scan
- [x] **`canary`** — Rebuff-style `[CANARY:<uuid>]` regex + user-supplied tokens
- [x] **`perplexity`** — character-bigram language model trained at startup from `bigram_corpus.txt` via `OnceLock`; thresholds tightened to 3.3 / 3.8 nats/symbol (above the dense-technical-prose band) and limited via `Provenance::is_natural_language` to only fire on prose-shaped chunks (plain text, Markdown, docstrings, notebook markdown cells, HTML body text, PDF text) — structured content like config values, code literals, HTML attributes, and lockfiles is skipped
- [x] **`embedding`** — 64-bit SimHash fallback over ~30 canonical injection payloads; **real ONNX backend via `ort` 2.0.0-rc.10 behind the `embeddings` feature**, with a **real HuggingFace tokenizer via the `tokenizers` crate** and an opt-in **`bundled = true`** mode that fetches `sentence-transformers/all-MiniLM-L6-v2` (ONNX model + `tokenizer.json`) from HuggingFace into the user cache dir on first use
- [x] **`llm_classifier`** — live detector behind the `llm` Cargo feature. Sends chunks to an OpenAI-compatible `chat/completions` endpoint and expects a `{"verdict","confidence","reason"}` JSON response. Configurable base URL, model, and API-key env var. Conservative: API or parse errors are treated as SAFE so the detector can't halt the build on transient outages. Key missing → detector no-ops with a warning.

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
- [x] `[detectors.embedding] model`, `tokenizer`, `bundled`
- [x] `[detectors.llm_classifier] base_url`, `model`, `api_key_env`

### Incremental + quarantine (`src/quarantine.rs`, `src/walk.rs`)
- [x] **Incremental scan** — `--since <REF>` computes the set of paths that differ between `--since` and `--rev` via `gix::traverse` and restricts the walker to just those files. Works on both the gix tree path and the working-tree fallback.
- [x] **Auto-quarantine review queue** — TOML-backed `.injector-detector-ignore` file. `--quarantine` appends current findings to the ignore file and clears the report so the build passes (for human review). Normal scans filter out any finding whose `(detector, path, message, evidence_hash)` matches an entry. Path defaults to `.injector-detector-ignore` and can be overridden with `--ignore-file`.

### Tests
- [x] **33 unit tests** across `types`, `chunk`, `aggregate`, `quarantine`, `bigram_model`, `heuristic`, `hidden_chars`, `encoded`, `canary`, `perplexity`, `embedding`
- [x] **17 integration tests** in `tests/integration.rs` driving the public `scan()` API (adds quarantine round-trip and incremental no-op)
- [x] **4 property tests** (`proptest`) in `tests/properties.rs` for chunker boundary safety, span correctness, multibyte input, overlap invariants
- [x] **3 snapshot tests** (`insta`) in `tests/snapshots.rs` for the human, JSON, and SARIF reporters
- [x] **gix tree walker test** — `tests/common/git_helper.rs` builds a real git repo programmatically via `gix::init` + `write_blob` + `write_object` + `commit_as`; tests verify the gix snapshot path is taken (committed-content-only finding, working-tree-only-clean negative, and incremental HEAD→HEAD no-op)
- [x] `tests/fixtures/clean/` — README, Rust source, JSON config (verdict: SAFE)
- [x] `tests/fixtures/dirty/` — one fixture per detector / extractor:
  - `heuristic.md`, `hidden.txt`, `encoded.md`, `canary.txt`
  - `notebook.ipynb`, `source.py`, `markup.html`, `workflow.yaml`
  - `high_entropy.txt`
- [x] All feature combinations build clean: default, `--features embeddings`, `--features llm`, `--all-features`
- [x] **Total: 57 tests passing under every feature set**

## In progress

_(nothing currently in progress)_

## Planned — medium term

_(nothing currently planned — the DESIGN.md §11 roadmap and all previously-listed follow-ups are shipped)_

## Out of scope

These appear in `tldrsec/prompt-injection-defenses` but are inherently runtime-only and not relevant to a static scanner. Documented in DESIGN.md §7 for completeness.

- Spotlighting / sandwich defense / post-prompting
- Dual-LLM pattern / taint tracking
- Paraphrasing / retokenization input pre-processing
- Output overseers (LLM self-defense)
- Model hardening / finetuning
