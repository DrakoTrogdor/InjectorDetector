# InjectorDetector

A Rust command-line tool that scans a Git repository for **prompt
injection payloads** and returns a single **SAFE** or **NOT SAFE**
verdict, suitable for use as a CI gate or pre-commit hook.

InjectorDetector applies the *detective* family of techniques surveyed
in [tldrsec/prompt-injection-defenses](https://github.com/tldrsec/prompt-injection-defenses)
— heuristic / YARA rule matching, hidden-character scanning, encoded
payload decoding, perplexity analysis, canary detection, embedding
similarity, and an optional live LLM classifier — to files at rest in
a repo, before they ever reach a live LLM.

## Why

Prompt-injection payloads increasingly arrive *through* code, docs,
READMEs, notebooks, issue templates, and config files that downstream
agents and copilots later read. Runtime defenses (spotlighting,
dual-LLM, sandwiching) only help if the payload reaches the model
boundary. InjectorDetector catches payloads earlier — at commit time —
and complements those runtime defenses rather than replacing them.

## Features

- **Single-argument CLI**: point it at a local clone, an absolute path,
  or a remote Git URL.
- **Deterministic verdict**: exit code `0` on SAFE, `1` on NOT SAFE,
  `2` on scan error — drops cleanly into any CI pipeline.
- **Layered detectors**:
  - **Heuristic** — `yara-x` 1.14 backed scanner over a bundled rule
    pack (`rules/builtin.yar`, 14 rules) plus user-supplied rule
    files. Catches "ignore previous instructions", role hijacks for
    **OpenAI ChatML** (`<|im_start|>`), **Llama 2 / Mistral**
    (`[INST]`, `<<SYS>>`), **Llama 3** (`<|start_header_id|>`,
    `<|eot_id|>`), **GPT** (`<|endoftext|>`, FIM tokens), **Claude**
    (`\n\nHuman:` / `\n\nAssistant:`), and **Gemini / Gemma**
    (`<start_of_turn>` / `<end_of_turn>`); Alpaca instruction markers;
    jailbreak preambles; exfiltration vocabulary; and tool-call
    spoofs. The scanner runs three passes — primary, **denoise**
    (strips zalgo / strikethrough / underline combining marks before
    re-scanning), and **deconfuse** (rewrites Cyrillic / Greek
    confusables to Latin before re-scanning) — so obfuscated copies
    of the same payloads still match.
  - **Hidden characters** — five categories of invisible smuggling:
    zero-width (incl. Word Joiner U+2060), bidi-override (Trojan
    Source), Unicode tag characters, **variation selectors VS1–VS16**,
    and **Variation Selectors Supplement VS17–VS256** (the Paul Butler
    "smuggling arbitrary data through an emoji" channel). Plus
    **stacked combining marks** (zalgo glyphs) and **strikethrough /
    underline overlay marks** (Parseltongue-style obfuscation), and
    Cyrillic / Greek **homoglyph clusters** that are visually
    confusable with Latin letters. Math notation like `ΔVol`, `Σ(x)`,
    `π*r²` is correctly *not* flagged. Precomposed accented text
    (café, résumé, Hà Nội) is *not* flagged as combining-mark
    obfuscation. Leading UTF-8 BOMs are recognised as legitimate
    text-encoding markers.
  - **Encoded payloads** — recursive base64 / hex / URL decoding
    (depth ≤ 2) with re-scanning of the decoded text against a
    focused needle list.
  - **Canary tokens** — Rebuff-style `[CANARY:<uuid>]` plus
    user-supplied tokens.
  - **Perplexity** — character-bigram language model trained at
    startup from an embedded English corpus, with three gates
    (provenance, char Shannon entropy, bigram cross-entropy) that
    keep false positives near zero on real-world Markdown and code.
  - **Embedding similarity** — 64-bit SimHash fallback over ~30
    canonical injection payloads, plus an optional ONNX
    sentence-transformer backend behind the `embeddings` Cargo
    feature.
  - **Live LLM classifier** — opt-in detector behind the `llm` Cargo
    feature that sends each chunk to an OpenAI-compatible
    `/chat/completions` endpoint.
- **Format-aware extraction**:
  - Tree-sitter grammars for **Rust, Python, JavaScript, TypeScript,
    TSX, Go, Java, C, C++, Bash, Ruby** (yields `Comment` and
    `StringLiteral` chunks with rebased byte spans).
  - Dedicated extractors for Markdown plain text, Jupyter notebooks
    (`.ipynb`), HTML / SVG / XML, JSON / TOML / YAML config files,
    and PDFs (behind the `pdf` feature).
  - Filename-aware dispatch for `Cargo.lock`, `package-lock.json`,
    `Dockerfile`, `Makefile`, `Rakefile`, `Gemfile`, etc.
  - Extension dispatch for ~30 script / IDL / build languages
    without a tree-sitter grammar (PowerShell, Lua, SQL, Terraform,
    Swift, Kotlin, etc.) so they're scanned by the heuristic /
    encoded / canary / hidden_chars detectors but skip perplexity.
- **Default-excludes** common build / generated directories
  (`target/`, `obj/`, `node_modules/`, `__pycache__/`, `.venv/`,
  `.terraform/`, …) so you can point the tool at any repo and get
  signal, not noise.
- **Three report formats**: human, JSON, and a real **SARIF 2.1.0**
  emitter for GitHub code scanning upload.
- **Live progress bar** on stderr (auto-disables under `--quiet` or
  on non-TTY stderr) so the report on stdout pipes cleanly.
- **Pure-Rust Git access** via `gix` — no external `git` binary
  required, and remote repos are shallow-cloned into a tempdir.
- **Quarantine workflow** — `--quarantine` accepts current findings
  as a baseline written to `.injector-detector-ignore`; subsequent
  scans pass while still detecting new findings.
- **Incremental scans** — `--since <REF>` restricts the scan to
  files that differ between the base ref and `--rev`.
- **AI-safe rendering** — `--ai-safe` rewrites the report so AI
  agents (Claude Code, Cursor, Copilot, autonomous agents) can read
  the findings without being attacked by the payloads they describe.

## Installation

Requires Rust 1.85+ (edition 2024).

```bash
git clone https://github.com/DrakoTrogdor/InjectorDetector
cd InjectorDetector
cargo install --path .
```

Or build a local binary without installing:

```bash
cargo build --release
./target/release/injector-detector --help
```

### Platform notes

The default-feature build is pure Rust apart from a few small C
dependencies (tree-sitter grammars, `zstd-sys` via `yara-x`) that
compile against the system C compiler. On Linux you need a C
toolchain (`build-essential` on Debian / Ubuntu, the `gcc` group on
Fedora / Arch); macOS already ships one with the Xcode command-line
tools; on Windows the MSVC build tools work out of the box.

The optional **`embeddings`** feature additionally requires
`pkg-config` and the OpenSSL development headers, because the
`ort-sys` crate's build script downloads the ONNX Runtime native
library via a `ureq` build that links `native-tls` → `openssl-sys`.
On Debian / Ubuntu / WSL:

```bash
sudo apt-get install -y pkg-config libssl-dev
```

On Fedora / RHEL: `sudo dnf install -y pkgconf-pkg-config openssl-devel`.
On Arch: `sudo pacman -S pkgconf openssl`. On macOS the Homebrew
`pkg-config` and `openssl` formulas cover it. The `pdf` and `llm`
features have no extra system requirements beyond a C compiler.

## Usage

```text
injector-detector <REPO> [OPTIONS]
```

Scan the current directory:

```bash
injector-detector .
```

Scan a remote GitHub repository at a specific tag and emit SARIF:

```bash
injector-detector https://github.com/example/project \
  --rev v1.2.3 \
  --format sarif > results.sarif
```

Fail the build only on high-severity findings:

```bash
injector-detector . --fail-on high
```

Incremental scan — only re-evaluate files that changed since `main`:

```bash
injector-detector . --since main
```

One-time baseline of current findings (review workflow):

```bash
injector-detector . --quarantine
# review the generated .injector-detector-ignore, then commit it.
# subsequent normal scans will skip the quarantined findings.
injector-detector .
```

For an AI agent invoking the tool:

```bash
injector-detector . --ai-safe
```

### Options

| Flag                       | Description                                            |
|----------------------------|--------------------------------------------------------|
| `--rev <REV>`              | Git revision to scan (default: `HEAD`)                 |
| `--config <FILE>`          | TOML config file with custom rules and thresholds      |
| `--format <FMT>`           | `human` \| `json` \| `sarif` (default: `human`)        |
| `--fail-on <SEVERITY>`     | `low` \| `medium` \| `high` \| `critical`              |
| `--include <GLOB>...`      | Restrict scan to matching paths                        |
| `--exclude <GLOB>...`      | Skip matching paths (in addition to defaults)          |
| `--no-clone`               | Refuse to clone; require a local path                  |
| `--keep`                   | Preserve cloned tempdirs after the scan completes      |
| `--since <REF>`            | Incremental: only scan files changed since this ref    |
| `--quarantine`             | Append findings to ignore file instead of failing      |
| `--ignore-file <PATH>`     | Path to the quarantine file (default: `.injector-detector-ignore`) |
| `-q`, `--quiet`            | Suppress the progress bar and non-error stderr         |
| `--no-default-excludes`    | Disable the built-in build/generated dir exclusions    |
| `--ai-safe`                | Sanitize the report so an LLM can read it safely       |
| `--jobs <N>`               | Worker thread count (default: number of CPUs)          |

Run `injector-detector --help` for the full description and worked
examples.

### Exit codes

| Code | Meaning      |
|------|--------------|
| `0`  | SAFE         |
| `1`  | NOT SAFE     |
| `2`  | Scan error   |

## CI integration

### GitHub Actions

The repository ships with a [`action.yml`](action.yml) composite action
that installs the binary, caches it across runs, and executes the scan.

```yaml
- name: Scan for prompt injections
  uses: DrakoTrogdor/InjectorDetector@main
  with:
    path: .
    fail-on: medium
    format: sarif
    output-file: results.sarif

- uses: github/codeql-action/upload-sarif@v3
  if: always()
  with:
    sarif_file: results.sarif
```

### Pre-commit

The repository also ships with a [`.pre-commit-hooks.yaml`](.pre-commit-hooks.yaml)
manifest. Add this to your project's `.pre-commit-config.yaml`:

```yaml
- repo: https://github.com/DrakoTrogdor/InjectorDetector
  rev: main
  hooks:
    - id: injector-detector
```

## How it works

```
              Checking <name>...
        ┌───────────────┐
 repo → │  Repo Loader  │  gix open / shallow clone, --rev resolution
        └───────┬───────┘
                ▼
        ┌───────────────┐
        │  File Walker  │  gix tree walker (or working-tree fallback);
        │               │  default + user excludes; incremental --since
        └───────┬───────┘
                ▼
        ┌───────────────┐
        │  Extractors   │  format / extension / filename dispatch;
        │               │  per-chunk Provenance tagging
        └───────┬───────┘
                ▼
        ┌───────────────┐
        │   Chunker     │  NFKC normalisation, 2 KiB windows, 256 B
        │               │  overlap, multibyte-safe boundaries
        └───────┬───────┘
                ▼
        ┌───────────────┐
        │ Detector      │  rayon parallel; 6 always-on detectors plus
        │ Engine        │  optional embedding (--features embeddings)
        │               │  and llm_classifier (--features llm)
        └───────┬───────┘
                ▼
        ┌───────────────┐
        │  Aggregator   │  dedupe, per-detector score cap, verdict
        └───────┬───────┘
                ▼
        ┌───────────────┐
        │  Quarantine   │  filter (or append) findings vs ignore file
        └───────┬───────┘
                ▼
        ┌───────────────┐
        │   Reporter    │  human / json / sarif (with --ai-safe overlay)
        └───────────────┘
```

See [`DESIGN.md`](DESIGN.md) for the full component breakdown and the
mapping from each tldrsec defense technique to its implementation.

## Configuration

A `injector-detector.toml` (or any file passed via `--config`) can
override defaults:

```toml
[scan]
fail_on          = "medium"
max_binary_bytes = 1048576
jobs             = 8
include          = ["src/**", "docs/**"]
exclude          = ["**/generated/**"]

[detectors.heuristic]
enabled     = true
extra_rules = ["./my-rules/*.yar"]

[detectors.hidden_chars]
enabled = true

[detectors.encoded]
enabled = true

[detectors.canary]
enabled = true
tokens  = ["sk-prod-secret-marker"]

[detectors.perplexity]
enabled = true

[detectors.embedding]
enabled   = false  # default
bundled   = false  # set true to fetch all-MiniLM-L6-v2 on first use
model     = "/path/to/model.onnx"     # alternative: explicit ONNX path
tokenizer = "/path/to/tokenizer.json" # required when `model` is set

[detectors.llm_classifier]
enabled     = false  # default
base_url    = "https://api.openai.com/v1"
model       = "gpt-4o-mini"
api_key_env = "OPENAI_API_KEY"
```

All fields are optional; CLI flags and config merge into a single
`ScanConfig` at startup.

## Using the optional features

The three optional features (`embeddings`, `llm`, `pdf`) are opt-in
at **build time** via `--features`, and `embeddings` and `llm` also
need a small bit of **runtime config** in `injector-detector.toml`
to actually turn the detector on. The default-feature build is
fully usable on its own — every always-on detector still runs, and
the embedding detector silently falls back to a 64-bit SimHash
backend that needs no model file.

### `embeddings` — real ONNX sentence-transformer backend

Replaces the SimHash fallback with a real semantic-similarity match
against canonical injection payloads.

Build (Linux requires `pkg-config` + `libssl-dev` first — see
[Platform notes](#platform-notes)):

```bash
cargo install --path . --features embeddings
# or, without installing:
cargo build --release --features embeddings
```

Runtime config — bundled mode fetches `all-MiniLM-L6-v2` from
HuggingFace into your user cache dir on first use:

```toml
[detectors.embedding]
enabled = true
bundled = true
```

Or point at a model you already have on disk:

```toml
[detectors.embedding]
enabled   = true
model     = "/path/to/model.onnx"
tokenizer = "/path/to/tokenizer.json"
```

If `enabled = false` (the default) or the binary was built without
the feature, the detector silently falls back to the SimHash
backend — no model file, no network.

### `llm` — live LLM-classifier detector

Sends each chunk to an OpenAI-compatible `/chat/completions`
endpoint for a verdict.

```bash
cargo install --path . --features llm
```

Runtime config:

```toml
[detectors.llm_classifier]
enabled     = true
base_url    = "https://api.openai.com/v1"   # or any OpenAI-compatible endpoint
model       = "gpt-4o-mini"
api_key_env = "OPENAI_API_KEY"              # name of the env var to read
```

Run:

```bash
export OPENAI_API_KEY=sk-...
injector-detector .
```

If the env var is missing, the detector logs a warning and no-ops
rather than failing the build. API errors and parse failures are
also treated as SAFE so transient outages can't break CI.

### `pdf` — PDF text extraction

Adds `.pdf` files to the extractor dispatch table. No runtime
config needed — once built in, PDFs are scanned automatically by
all the always-on detectors.

```bash
cargo install --path . --features pdf
```

### Combining features

```bash
cargo install --path . --features "embeddings llm pdf"
# or, equivalently:
cargo install --path . --all-features
```

You can also install directly from git with features baked in:

```bash
cargo install --git https://github.com/DrakoTrogdor/InjectorDetector \
  --features "embeddings llm pdf" --locked injector-detector
```

## AI agent usage

If you are running this tool from inside an AI assistant (Claude Code,
Cursor, Copilot CLI, an autonomous agent, …) you should pass
**`--ai-safe`**. The flag rewrites the report so the findings cannot
attack you when you read them back:

- A preamble at the top of the output addresses the reading model
  directly and tells it that the contents of `[UNTRUSTED:…]` markers
  are literal data, not instructions.
- Every evidence snippet is wrapped in `[UNTRUSTED:…]`.
- Dangerous token pairs (`<|`, `|>`, ` ``` `, `{{`, `}}`) are
  textually broken with a backslash-space separator so ChatML
  role markers, Markdown code fences, and template delimiters
  cannot parse.
- Invisible / bidi / tag characters are rendered as `<U+XXXX>`
  codepoint notation.
- JSON output gains a top-level `safe_view: true` flag and an
  `ai_safe_preamble` field; SARIF gains the same under
  `runs[].tool.driver.properties`.

The verdict (`SAFE` / `NOT SAFE`), file paths, severity levels, and
summary counts remain authoritative — those are the parts of the
report an AI should rely on for decisions.

## Cargo features

| Feature       | Default | Description                                                |
|---------------|---------|------------------------------------------------------------|
| `embeddings`  | off     | Pulls in `ort` 2.0, `tokenizers`, and `ureq` to enable the ONNX sentence-transformer backend for the embedding detector (with optional bundled-model fetch). |
| `llm`         | off     | Pulls in `ureq` to enable the live LLM-classifier detector that calls an OpenAI-compatible `/chat/completions` endpoint. |
| `pdf`         | off     | Pulls in `pdf-extract` to enable the PDF text extractor.   |

## Development

```bash
cargo build
cargo test
cargo test --features embeddings
cargo test --features llm
cargo clippy --all-targets -- -D warnings
cargo fmt
```

Test inventory: 64 unit tests, 17 integration tests, 4 property tests
(`proptest`), 5 snapshot tests (`insta`). All 90 pass under default,
`--features embeddings`, `--features llm`, and `--all-features`.

The repo layout is documented in [`DESIGN.md`](DESIGN.md) §5, and the
end-to-end status of every shipped feature is tracked in
[`STATUS.md`](STATUS.md).

## License

MIT — see [`LICENSE`](LICENSE).

## Acknowledgements

- [tldrsec/prompt-injection-defenses](https://github.com/tldrsec/prompt-injection-defenses)
  for the taxonomy of techniques this tool draws from.
- The `gix`, `tree-sitter`, `yara-x`, `tokenizers`, `ort`, and
  `indicatif` projects for the building blocks that make a fast,
  pure-Rust static scanner possible.
