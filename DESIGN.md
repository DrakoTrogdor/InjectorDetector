# InjectorDetector — Design Document

## 1. Overview

`InjectorDetector` is a Rust command-line tool that scans a Git
repository for prompt-injection payloads embedded in source files,
documentation, configuration, notebooks, and other repo content. It
produces a single binary verdict — **SAFE** or **NOT SAFE** —
alongside a detailed report of findings.

The detection methodology is grounded in the techniques catalogued in
[tldrsec/prompt-injection-defenses](https://github.com/tldrsec/prompt-injection-defenses),
with a focus on the **detective** family of defenses applied
*statically* to files at rest rather than to a live LLM request stream.
A live LLM-classifier detector is also shipped behind the optional
`llm` Cargo feature for users who want to combine static and runtime
checks.

### 1.1 Goals

- Accept a Git repository (local path or remote URL) as the sole
  required argument.
- Walk the repository, extract textual content from supported file
  types, and evaluate each chunk against a layered set of detectors.
- Emit a deterministic SAFE / NOT SAFE verdict with a non-zero exit
  code on NOT SAFE, suitable for use in CI pipelines and pre-commit
  hooks.
- Be fast enough for pre-commit and pull-request gating on real-world
  repos.
- Produce output that is safe for AI agents to read back into a
  language model when `--ai-safe` is set.

### 1.2 Non-Goals

- Runtime defense of a live LLM (no proxying, no request rewriting).
- Removing or rewriting injection payloads (detection only).
- Semantic understanding of attacker intent beyond what the layered
  detectors can express.

## 2. Usage

```text
injector-detector <REPO> [OPTIONS]

ARGS:
    <REPO>  Local path or remote Git URL (https / ssh / git@)

OPTIONS:
    --rev <REV>             Git revision to scan (default: HEAD)
    --since <REF>           Incremental: only scan files changed
                            between <REF> and --rev
    --config <FILE>         Path to a TOML config file
    --format <FMT>          human | json | sarif (default: human)
    --fail-on <SEVERITY>    low | medium | high | critical
                            (default: medium)
    --include <GLOB>...     Restrict scan to matching paths
    --exclude <GLOB>...     Skip matching paths (added to defaults)
    --no-default-excludes   Disable the built-in build/generated dir
                            exclusion list
    --no-clone              Refuse to clone; require a local path
    --keep                  Preserve cloned tempdirs after the scan
    --quarantine            Append findings to ignore file instead of
                            failing
    --ignore-file <PATH>    Quarantine file path
                            (default: .injector-detector-ignore)
    --ai-safe               Sanitize report so an LLM can read it
    -q, --quiet             Suppress the progress bar / non-error
                            stderr output
    --jobs <N>              Worker thread count (default: num_cpus)
```

Exit codes: `0` SAFE, `1` NOT SAFE, `2` scan error.

`stderr` carries the progress bar and any warnings; the report goes
to `stdout`. JSON / SARIF can be redirected reliably.

## 3. High-Level Architecture

```
                Checking <name>...
            ┌───────────────┐
   repo --> │  Repo Loader  │  gix open / shallow clone, --rev resolution
            └───────┬───────┘
                    │
                    ▼
            ┌───────────────┐
            │  File Walker  │  gix tree walker (or working-tree
            │               │  fallback); default + user excludes;
            │               │  --since incremental filter
            └───────┬───────┘
                    │
                    ▼
            ┌───────────────┐
            │  Extractors   │  format / extension / filename dispatch;
            │               │  per-chunk Provenance tagging
            └───────┬───────┘
                    │
                    ▼
            ┌───────────────┐
            │   Chunker     │  NFKC normalisation, 2 KiB / 256 B
            │               │  windows, multibyte-safe boundaries
            └───────┬───────┘
                    │
                    ▼
            ┌───────────────┐
            │ Detector      │  rayon parallel; 6 always-on detectors
            │ Engine        │  + optional embedding + llm_classifier
            └───────┬───────┘
                    │
                    ▼
            ┌───────────────┐
            │  Aggregator   │  dedupe, per-detector score cap, verdict
            └───────┬───────┘
                    │
                    ▼
            ┌───────────────┐
            │  Quarantine   │  filter (or append) findings vs ignore
            │               │  file
            └───────┬───────┘
                    │
                    ▼
            ┌───────────────┐
            │   Reporter    │  human / json / sarif (with --ai-safe
            │               │  overlay)
            └───────────────┘
```

## 4. Components

### 4.1 Repo Loader (`repo`)

- Uses [`gix`](https://crates.io/crates/gix) (gitoxide) for pure-Rust
  Git access — no external `git` binary required.
- If the argument is a URL, shallow-clones into a temp directory under
  the OS temp dir, and removes it on drop unless `--keep` is set.
- If the argument is a local path, opens it in place and never mutates
  the working tree.
- Resolves `--rev` to a tree object so the scan operates on a
  consistent snapshot, not the working tree, eliminating TOCTOU
  concerns. Tracks `rev_explicit` so the walker can warn if a
  user-supplied `--rev` is silently dropped during the working-tree
  fallback.

### 4.2 File Walker (`walk`)

Two code paths sharing a single `WalkEntry` output stream:

- **gix tree walker** (preferred): resolves `--rev` to a tree via
  `rev_parse_single` + `peel_to_kind(Tree)`, traverses with
  `gix::traverse::tree::Recorder`, and reads each blob via
  `find_object`. Reads only committed content, immune to working-tree
  TOCTOU.
- **Working-tree fallback** (`ignore` crate): used when the directory
  isn't a git repo or the rev can't be resolved. Honors `.gitignore`
  via `WalkBuilder::standard_filters(true)`.

Filters applied in both paths:

- **Built-in default excludes** for machine-generated directories:
  `target/`, `obj/`, `node_modules/`, `__pycache__/`, `.venv/`,
  `venv/`, `.tox/`, `.pytest_cache/`, `.mypy_cache/`, `.ruff_cache/`,
  `*.egg-info/`, `.next/`, `.nuxt/`, `.parcel-cache/`, `.turbo/`,
  `.gradle/`, `.terraform/`, `.serverless/`, `.bundle/`, `Pods/`,
  `.git/`. Disabled with `--no-default-excludes`.
- User `--include` / `--exclude` glob filters via the `globset`
  crate (merged with the default-exclude list).
- Binary file size cap (`max_binary_bytes`, default 1 MiB).
- **Incremental filter**: when `--since <REF>` is set, the walker
  resolves both `since` and `rev` to trees, computes the set of paths
  whose blob oid differs (plus pure adds/removes), and restricts the
  walk to that set.

### 4.3 Extractors (`extract`)

Each extractor turns raw bytes into one or more `TextChunk { path,
span, text, provenance }` records. `Provenance` records *what kind of
text* this is — config string, code comment, HTML attribute, etc. —
which downstream detectors use to tune their sensitivity. Most
importantly, the perplexity detector uses
`Provenance::is_natural_language()` to skip structured content.

| Format / dispatch                              | Extractor                                | Provenance tags                                       |
|------------------------------------------------|------------------------------------------|-------------------------------------------------------|
| Plain text / Markdown                          | UTF-8 decode + window split              | `Prose`                                               |
| Source code (tree-sitter languages)            | `tree-sitter` walk                       | `Comment`, `StringLiteral`                            |
| Jupyter notebooks (`.ipynb`)                   | JSON parse                               | `NotebookMarkdownCell`, `NotebookCodeCell`, `NotebookOutput` |
| HTML / SVG / XML                               | `scraper` walk                           | `HtmlText`, `HtmlComment`, `HtmlAttribute`            |
| JSON / TOML / YAML config                      | serde traversal of string values         | `ConfigString`                                        |
| `Cargo.lock` (filename)                        | TOML extractor                           | `ConfigString`                                        |
| `package-lock.json` / `composer.lock` / `bun.lockb` (filename) | JSON extractor       | `ConfigString`                                        |
| Generic `*.lock` / `*.sum`                     | Plain text fallback                      | `ConfigString`                                        |
| Script extensions without a tree-sitter grammar | Plain text fallback                     | `ConfigString`                                        |
| Well-known build filenames (Dockerfile, Makefile, …) | Plain text fallback                | `ConfigString`                                        |
| PDF (optional)                                 | `pdf-extract` behind `pdf` feature       | `PdfText`                                             |

**Tree-sitter languages**: Rust, Python, JavaScript, TypeScript, TSX,
Go, Java, C, C++, Bash (covers `.sh` / `.bash` / `.zsh`), Ruby. Each
spec lists the comment-node and string-node kinds the walker should
extract.

**Script extensions routed as `ConfigString`** (so they're scanned by
the heuristic / encoded / canary / hidden_chars detectors but skip
perplexity): PowerShell (`ps1` / `psm1` / `psd1`), Windows batch,
Perl, PHP, Lua, R, Julia, Elixir / Erlang, Swift, Kotlin, Scala,
Dart, Objective-C, C#, F#, Haskell, Clojure, OCaml, VB, Pascal,
Assembly, SQL, Protobuf / FlatBuffers / Thrift, Terraform / HCL,
Nix, Gradle, CMake, INI / CFG / CONF / properties, plus filename
fixtures (Dockerfile, Containerfile, Makefile, CMakeLists.txt,
Rakefile, Gemfile, Procfile, Vagrantfile, Jenkinsfile, Brewfile,
Podfile, Cartfile, Justfile, .env, .envrc).

### 4.4 Chunker (`chunk`)

- NFKC-normalises Unicode so visually-equivalent forms are scored
  consistently.
- Splits long extractions into overlapping windows (2 KiB window,
  256 B overlap by default) so detectors see local context without
  unbounded inputs.
- Multibyte-safe boundary handling: window boundaries are rounded to
  valid UTF-8 char boundaries with no panics on emoji / accented
  text / box drawings.
- Records the **original byte span** so reports can point at the
  exact location in the source file even after normalisation and
  windowing.

### 4.5 Detector Engine (`detect`)

The engine runs each chunk through a pipeline of `Detector` trait
implementations in parallel via `rayon`. Each detector returns zero or
more `Finding`s; the engine attaches the detector's `Category` to each
finding before passing it on, so individual detector implementations
don't have to set it.

```rust
pub trait Detector: Send + Sync {
    fn id(&self) -> &'static str;
    fn category(&self) -> Category;
    fn analyze(&self, chunk: &TextChunk) -> Vec<Finding>;
}

pub struct Finding {
    pub detector: String,
    pub category: Category,        // Heuristic | HiddenChars | Perplexity
                                    // Encoded | Canary | Embedding
    pub severity: Severity,        // Low | Medium | High | Critical
    pub confidence: f32,           // 0.0..=1.0
    pub path: PathBuf,
    pub span: ByteSpan,
    pub message: String,
    pub evidence: String,          // truncated, control-char-escaped
}
```

The detectors below map directly to techniques surveyed in
`tldrsec/prompt-injection-defenses`. The static-detective techniques
are always on; preventative techniques (spotlighting, sandwich
defense, dual LLM, etc.) are not applicable to a static scanner and
are documented in §7 as out of scope.

#### 4.5.1 Heuristic / YARA Pattern Detector

Implements the **heuristic and YARA-rule matching** input-overseer
technique.

- Ships a curated rule pack (`rules/builtin.yar`, 9 rules) covering
  classic injection idioms ("ignore previous instructions",
  "disregard the above"), role hijacks (`<|im_start|>`,
  `<|im_end|>`, `<|system|>`, `<|user|>`, `<|assistant|>`), Alpaca
  instruction markers (`### Instruction:`), system-prompt spoofs
  (`system prompt:`, `system message:`, `[system]`), jailbreak
  preambles ("DAN mode", "developer mode enabled"), exfiltration
  vocabulary, and tool-call spoofs (`<tool_call>`, `<function_calls>`).
- Uses [`yara-x`](https://crates.io/crates/yara-x) 1.14 (pure-Rust
  YARA engine).
- Each rule carries `severity`, `confidence`, and `message` metadata
  in its `meta:` block, which the detector reads when constructing
  the `Finding`.
- Users can extend the pack via `[detectors.heuristic] extra_rules`
  glob patterns in the TOML config — no recompile needed.

#### 4.5.2 Hidden / Adversarial Character Detector

Targets common smuggling vectors that defeat human review.

- **Invisible characters** — zero-width (U+200B, U+200C, U+200D,
  U+FEFF), bidi-overrides (U+202A–U+202E, U+2066–U+2069), and
  Unicode tag characters (U+E0000–U+E007F). Zero-width is Medium;
  bidi-override and tag characters are Critical.
- **Homoglyph clusters** — Latin-script words containing one or more
  Cyrillic / Greek characters that are *visually confusable* with a
  specific Latin letter. The confusable set is curated to exclude
  math-shaped Greek letters (Δ, Σ, π, λ, μ, σ, θ, φ, ψ, ω) which are
  unambiguously non-Latin and almost always legitimate scientific
  notation.
- **Leading UTF-8 BOM exception** — U+FEFF at byte 0 of a file is a
  legitimate text-encoding marker (MSBuild `.g.props` /
  `.g.targets`, Visual Studio auto-generated files, PowerShell). It
  is not flagged. Mid-file U+FEFF is still flagged.

#### 4.5.3 Perplexity Detector

Implements the **perplexity analysis** input-overseer technique with
a self-contained character-bigram language model — no model file or
runtime dependency.

- Trains a 27×27 char-bigram model (`a-z` + a single "other" bin)
  with Laplace smoothing at process start from an embedded English
  corpus (`src/detect/bigram_corpus.txt`) via `OnceLock`. The
  trained model lives in memory for the lifetime of the process.
- **Three-gate filtering**:
  1. **Provenance gate** — only fires on `Provenance::is_natural_language()`
     chunks (`Prose`, `Docstring`, `NotebookMarkdownCell`,
     `HtmlText`, `PdfText`). Config values, code literals, HTML
     attributes, lockfiles, and script-extension files are skipped.
  2. **Char Shannon-entropy gate** — requires the chunk's character
     distribution to have ≥ 4.5 bits of Shannon entropy. ASCII art,
     box drawings, and tables have legitimately-high *bigram*
     cross-entropy (because their byte transitions don't appear in
     the English corpus) but very *low* character diversity, so
     this gate filters them.
  3. **Bigram cross-entropy gate** — 5.0 nats/symbol (Medium) /
     5.6 nats/symbol (High). Above the entire natural range of
     English prose, dense technical documentation, and mixed
     Markdown sections.
- Positioned as the last-resort safety net for content the encoded
  and hidden_chars detectors miss — base64 / hex blobs are caught
  earlier by the encoded detector.

#### 4.5.4 Encoded-Payload Detector

Catches payloads that try to evade plain-text rules by encoding
themselves.

- Scans chunks for long base64, hex, and URL-encoded runs (regex
  match with min length 24 / 12 / 8 chars respectively).
- Decodes candidates (bounded by 64 KiB output) and re-runs a
  focused needle list (`DECODED_NEEDLES`, ~11 canonical injection
  phrases) against the decoded text. Recursive decoding is supported
  to depth 2 to handle layered encodings.
- Hits emit **Critical** findings because encoded injection content
  strongly implies an evasion attempt.

#### 4.5.5 Canary / Prompt-Leak Detector

Implements the **canary token** output-overseer technique, applied to
repo artifacts that may have been generated by an LLM.

- Detects Rebuff-style `[CANARY:<uuid>]` tokens via regex.
- User-supplied canary strings can be added via
  `[detectors.canary] tokens = [...]` in the TOML config — useful
  for proprietary canaries that shouldn't appear in committed
  source.

#### 4.5.6 Embedding Similarity Detector (optional)

Implements a **vector-database matching** approach inspired by Rebuff.

Two backends sharing the same `Detector` trait:

- **SimHash backend** (default, always compiled): a 64-bit SimHash
  over normalised word tokens compared by Hamming distance against
  ~30 canonical injection payloads curated from public sources
  (Lakera Gandalf write-ups, HuggingFace `deepset/prompt-injections`,
  LMSYS jailbreak collections). Catches paraphrased or
  lightly-mutated copies of canonical jailbreaks without any model
  file or external runtime.
- **ONNX backend** (`embeddings` Cargo feature): loads a real
  sentence-transformer via `ort` 2.0.0-rc.10 and the `tokenizers`
  crate, embeds each chunk, and matches by cosine similarity
  against the corpus (threshold 0.78). Supports two configuration
  modes:
  - **Explicit paths**: `[detectors.embedding] model = "..."` and
    `tokenizer = "..."` point at a user-supplied ONNX export and
    its HuggingFace tokenizer.
  - **Bundled mode**: `[detectors.embedding] bundled = true` uses
    the `model_cache` module to fetch
    `sentence-transformers/all-MiniLM-L6-v2` (model.onnx +
    tokenizer.json) from HuggingFace into the user cache directory
    on first use, with atomic `.part`→rename writes.

When no model path is supplied or loading fails, the detector
transparently falls back to the SimHash backend.

#### 4.5.7 Live LLM Classifier (optional)

Implements the **LLM-based input classifier** technique surveyed in
tldrsec.

- Behind the `llm` Cargo feature.
- Sends each chunk to an OpenAI-compatible `/chat/completions`
  endpoint and expects a JSON response of the form
  `{"verdict": "safe|unsafe", "confidence": 0-1, "reason": "…"}`.
- Configurable: `base_url` (default `https://api.openai.com/v1`),
  `model` (default `gpt-4o-mini`), `api_key_env` (default
  `OPENAI_API_KEY`).
- **Conservative failure mode**: missing API key, API errors, and
  parse failures all become silent no-ops so the detector can't
  halt the build on transient outages.
- Severity ladders off the model's confidence: ≥ 0.9 Critical,
  ≥ 0.7 High, else Medium.

### 4.6 Aggregator (`aggregate`)

- Deduplicates findings whose `(detector, span)` collide.
- Computes a per-file score: each detector's contribution is
  `Σ(severity_weight × confidence)` over its findings, capped at
  `PER_DETECTOR_SCORE_CAP = 30.0` so a single noisy detector can't
  dominate the file's total. The file score is the sum of capped
  per-detector contributions.
- Files in the report are sorted by score (highest first).
- The repo verdict: **NOT SAFE** if `max_severity >= --fail-on`,
  otherwise **SAFE**.

### 4.7 Quarantine (`quarantine`)

TOML-backed `.injector-detector-ignore` review queue.

- File schema: `version`, `generated_at`, and a list of `[[ignore]]`
  entries each with `detector`, `path`, `message`, `evidence_hash`
  (FNV-1a64), and an optional `note`.
- **`--quarantine`**: appends current findings to the ignore file
  (deduplicating against existing entries) and clears them from the
  report so the build passes. Intended as a one-time
  git-add-and-review workflow for adopting the scanner on a legacy
  codebase.
- **Normal scans**: load the ignore file and drop any finding whose
  `(detector, path, message, evidence_hash)` matches an entry before
  aggregation.
- Path defaults to `.injector-detector-ignore` and can be overridden
  with `--ignore-file`.

### 4.8 Reporter (`report`) and Safe-View (`safe_view`)

Three render formats, all gated through a single `RenderOptions`
struct so `--ai-safe` can be applied uniformly:

- **`human`** — colourised terminal output, grouped by file, with
  span context.
- **`json`** — `serde_json` pretty-printed.
- **`sarif`** — real SARIF 2.1.0 with rules, results, byte-offset
  regions, severity-mapped levels, and a `category` property on
  every result. Ready for upload via
  `github/codeql-action/upload-sarif`.

The verdict logic: if any finding's severity is `>= --fail-on`, the
verdict is **NOT SAFE** and the process exits `1`. Otherwise **SAFE**,
exit `0`.

#### 4.8.1 `--ai-safe` rendering

When an AI agent runs the scanner and reads the output back into a
language model, the findings themselves become a prompt-injection
attack surface — every `evidence` snippet is a literal copy of the
payload that was detected.

`--ai-safe` rewrites the report so it cannot attack a reading LLM:

- The `safe_view` module emits an `AI_SAFE_PREAMBLE` at the top of
  the report. The preamble is addressed to the reading LLM in the
  second person, tells it that anything inside `[UNTRUSTED:…]`
  markers is data, and explains the escaping conventions. The
  preamble itself contains zero literal `<|`, `|>`, ` ``` `, `{{`,
  or `}}` substrings — it describes the transformations in prose.
- Every evidence snippet is wrapped in `[UNTRUSTED:…]`.
- Dangerous token pairs are broken with a backslash-space
  separator (`<|` → `<\ |`, `|>` → `|\ >`, etc.) so that no
  ChatML / Markdown / template parser can find them as substrings.
- Invisible / bidi / tag characters are rendered as `<U+XXXX>`
  codepoint notation — visible to a human reader, inert as glyphs.
- Control characters are escaped (`\n`, `\r`, `\t`, `\u{xxxx}`).
- JSON output gains a top-level `safe_view: true` flag and an
  `ai_safe_preamble` field; SARIF gains the same under
  `runs[].tool.driver.properties`.

### 4.9 Progress reporter (`progress`)

Indicatif-backed progress bar that streams pipeline status to stderr
without polluting the report on stdout.

- A `Checking <name>...` header line at scan start, with `name`
  derived from the source argument (canonical path → last
  component, or remote URL → last segment with `.git` stripped).
- Stage messages: `Loading repository`, `Walking files`, then a
  per-file counted bar during scanning, then `Aggregating findings`,
  then a final summary line replacing the bar.
- Per-file ticks fire from inside the `rayon` parallel loop; a
  small `Mutex<()>` serialises the "current file" suffix so workers
  don't corrupt each other's messages.
- Auto-disable rules:
  - `--quiet` → fully silent
  - non-TTY stderr → no animated bar, but `println()` still flows
    to stderr so quarantine notices and warnings remain visible
  - interactive TTY → full progress bar + messages above it

### 4.10 Configuration (`config`)

`ScanConfig` is the single struct that holds all run-time settings.
TOML files (`--config <FILE>`) are parsed into a section-shaped
`ConfigFile` and merged into `ScanConfig` via `merge_file`. CLI
flags overlay last. All fields are optional; defaults live on
`ScanConfig::default()`.

## 5. Crate Layout

```
injector-detector/
├── Cargo.toml
├── DESIGN.md
├── README.md
├── STATUS.md
├── LICENSE
├── action.yml                       # GitHub Action composite wrapper
├── .pre-commit-hooks.yaml           # pre-commit integration
├── rules/
│   └── builtin.yar                  # bundled YARA rule pack
├── src/
│   ├── main.rs                      # CLI entry, clap parser, examples
│   ├── lib.rs                       # public scan() entry point
│   ├── repo.rs                      # gix-based loader
│   ├── walk.rs                      # gix-tree + working-tree walker
│   ├── chunk.rs                     # NFKC + windowed chunker
│   ├── types.rs                     # Severity, Provenance, ByteSpan,
│   │                                # Finding
│   ├── config.rs                    # ScanConfig + TOML schema
│   ├── progress.rs                  # indicatif progress reporter
│   ├── quarantine.rs                # .injector-detector-ignore
│   ├── safe_view.rs                 # AI-safe sanitizer + preamble
│   ├── extract/
│   │   ├── mod.rs                   # extension/filename dispatcher
│   │   ├── text.rs                  # plain text
│   │   ├── source.rs                # tree-sitter dispatcher
│   │   ├── notebook.rs              # Jupyter .ipynb
│   │   ├── markup.rs                # html / svg / xml
│   │   ├── config.rs                # json / toml / yaml
│   │   └── pdf.rs                   # feature = "pdf"
│   ├── detect/
│   │   ├── mod.rs                   # Detector trait + Engine
│   │   ├── heuristic.rs             # yara-x
│   │   ├── hidden_chars.rs          # invisible + homoglyph
│   │   ├── encoded.rs               # base64/hex/url + recursion
│   │   ├── canary.rs                # Rebuff + user tokens
│   │   ├── perplexity.rs            # bigram model + 3 gates
│   │   ├── bigram_model.rs          # OnceLock-trained model
│   │   ├── bigram_corpus.txt        # embedded English corpus
│   │   ├── embedding.rs             # SimHash + ONNX backends
│   │   ├── model_cache.rs           # feature = "embeddings"
│   │   └── llm_classifier.rs        # feature = "llm"
│   ├── aggregate.rs                 # dedupe, score cap, verdict
│   └── report/
│       ├── mod.rs                   # ScanReport + RenderOptions
│       ├── human.rs
│       ├── json.rs
│       └── sarif.rs
└── tests/
    ├── integration.rs               # public scan() API
    ├── properties.rs                # proptest chunker properties
    ├── snapshots.rs                 # insta reporter snapshots
    ├── snapshots/                   # committed *.snap files
    ├── common/
    │   ├── mod.rs
    │   └── git_helper.rs            # gix-based fixture-repo builder
    └── fixtures/
        ├── clean/                   # SAFE inputs
        └── dirty/                   # one fixture per detector
```

## 6. Key Dependencies

| Crate                     | Purpose                                                 |
|---------------------------|---------------------------------------------------------|
| `clap`                    | CLI parsing (with `derive` feature)                     |
| `gix`                     | Pure-Rust Git access (`worktree-mutation` + `revision` + `blocking-network-client`) |
| `ignore`                  | gitignore-aware working-tree walker fallback            |
| `globset`                 | include / exclude / default-exclude glob filters        |
| `rayon`                   | Parallel detector pipeline                              |
| `tree-sitter` 0.24 + 11 grammars | Source code extraction                           |
| `yara-x` 1.14             | YARA rule engine                                        |
| `scraper`                 | HTML / SVG / XML walking                                |
| `serde` / `serde_json` / `serde_yml` / `toml` | Config + JSON / YAML parsing      |
| `regex`, `aho-corasick`   | Pattern matching                                        |
| `unicode-normalization`   | NFKC chunker normalisation                              |
| `base64`, `percent-encoding` | Encoded-payload decoding                             |
| `tracing` / `tracing-subscriber` | Structured logging                               |
| `indicatif`               | Progress bar                                            |
| `dirs`                    | User cache directory discovery                          |
| `tempfile`                | Temp dirs for clones and tests                          |
| `anyhow`, `thiserror`     | Error handling                                          |
| `once_cell`               | Static initialisation                                   |
| `ort` 2.0.0-rc.10 (optional) | ONNX runtime for embedding backend (`embeddings`)    |
| `tokenizers` (optional)   | HuggingFace tokenizer for ONNX embedding (`embeddings`) |
| `ndarray` (optional)      | Tensor shapes for ONNX (`embeddings`)                   |
| `ureq` (optional)         | HTTP client for model fetch + LLM classifier (`embeddings`, `llm`) |
| `pdf-extract` (optional)  | PDF text extraction (`pdf`)                             |
| `proptest` (dev)          | Property tests for chunker / Unicode normaliser         |
| `insta` (dev)             | Snapshot tests for reporters                            |

## 7. Mapping to tldrsec/prompt-injection-defenses

| Defense (from tldrsec)                   | In InjectorDetector                                       |
|------------------------------------------|-----------------------------------------------------------|
| Heuristic / YARA matching                | §4.5.1 Heuristic detector                                 |
| Perplexity analysis                      | §4.5.3 Perplexity detector                                |
| Vector-DB / embedding match              | §4.5.6 Embedding detector (SimHash + optional ONNX)       |
| Canary tokens                            | §4.5.5 Canary detector                                    |
| LLM-based input classifier               | §4.5.7 LLM classifier (optional, `llm` feature)           |
| Spotlighting                             | §4.8.1 `--ai-safe` mode (applied to *output*, not input)  |
| Sandwich defense / post-prompting        | N/A — preventative, applied at request time              |
| Dual LLM / taint tracking                | N/A — preventative, runtime-only                          |
| Paraphrasing / retokenization            | N/A — input pre-processing for live requests              |
| Output overseers (LLM self-defense)      | N/A — no model output to inspect statically               |
| Model hardening / finetuning             | N/A — model-side mitigation                               |

The static-scan posture means InjectorDetector is a **complement** to
the runtime defenses described in tldrsec's catalogue, not a
replacement. It catches payloads that have been *committed* to a repo
before they can ever reach a model. The `--ai-safe` mode adds a
spotlighting-style defense in the *output* direction so that AI agents
running the scanner can read the findings safely.

## 8. Performance Targets

- Cold scan of a 100 kLOC repo on a modern laptop: under 10 seconds
  with the default detector set.
- Memory ceiling: a few hundred MiB regardless of repo size
  (streaming walk + bounded per-chunk allocations).
- Embedding (ONNX) and LLM-classifier detectors add roughly 2–10×
  latency when enabled, depending on model and network conditions.

## 9. Security Considerations

- The tool only *reads* the target repo. Cloning happens into a
  private temp dir; with `--keep` the path is preserved and logged.
- All decoded payloads stay in-process; nothing is executed.
- Evidence snippets in the default human/JSON/SARIF reports have
  control characters escaped to avoid terminal-escape-sequence
  attacks against the user's shell.
- `--ai-safe` mode goes further (see §4.8.1): it neutralises
  ChatML / Markdown / template tokens so the report is safe to feed
  to a language model.
- Rule packs are compiled by `yara-x`, which has no `import "console"`
  equivalent and cannot execute arbitrary code.
- The bundled-model fetch path uses HTTPS via `ureq` to a pinned
  HuggingFace repo and writes via `.part`→rename so partial
  downloads are not treated as cached.

## 10. Testing Strategy

- **76 tests** total, split across:
  - **50 unit tests** (in-module `#[cfg(test)]` blocks) covering
    severity ordering, evidence escaping, chunker boundary safety,
    aggregator score capping, quarantine round-trips, safe-view
    sanitization, bigram model training, and per-detector positive +
    negative cases.
  - **17 integration tests** in `tests/integration.rs` driving the
    public `scan()` API against on-disk fixtures.
  - **4 property tests** (`proptest`) in `tests/properties.rs` for
    chunker span correctness, multibyte safety, and overlap
    invariants on arbitrary `[U+0000–U+10FFFF]` input.
  - **5 snapshot tests** (`insta`) in `tests/snapshots.rs` for the
    human, JSON, and SARIF reporters in both default and AI-safe
    modes.
- **Repo fixtures** under `tests/fixtures/clean/` (verdict: SAFE)
  and `tests/fixtures/dirty/` (one file per detector, verdict: NOT
  SAFE), exercising every extractor end-to-end.
- **Programmatic git fixtures** via `tests/common/git_helper.rs`,
  which uses `gix::init` + `write_blob` + `write_object` +
  `commit_as` to build real git repos at test time. No external
  `git` binary is required, and the gix-tree walker code path
  is exercised end-to-end (committed-content vs working-tree
  divergence + `--since HEAD` no-op).
- **All feature combinations build clean**: default,
  `--features embeddings`, `--features llm`, `--all-features`.

## 11. Future Work

The original v1 roadmap is shipped (live LLM classifier, incremental
scan, GitHub Action + pre-commit hook, auto-quarantine). Open
follow-ups:

- **Bundled tokenizer / model variants** beyond `all-MiniLM-L6-v2` —
  e.g. quantised int8 builds for smaller cache footprint.
- **Fence-aware Markdown extraction** — parse fenced code blocks out
  of `.md` files into a non-Prose provenance so perplexity sees only
  prose sections, not embedded code.
- **More tree-sitter languages** — Zig, Nim, Crystal, Solidity,
  GraphQL, Elixir (currently script-extension fallback).
- **Pre-compiled binary releases** + a Homebrew tap so users don't
  need a Rust toolchain installed.
