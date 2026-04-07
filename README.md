# InjectorDetector

A Rust command-line tool that scans a Git repository for **prompt injection
payloads** and returns a single **SAFE** or **NOT SAFE** verdict, suitable for
use as a CI gate.

InjectorDetector applies the *detective* family of techniques surveyed in
[tldrsec/prompt-injection-defenses](https://github.com/tldrsec/prompt-injection-defenses)
— heuristic / YARA rule matching, perplexity analysis, canary detection, and
optional embedding-similarity matching — to files at rest in a repo, before
they ever reach a live LLM.

> Status: early development. See [`DESIGN.md`](DESIGN.md) for the full
> architecture.

## Why

Prompt injection payloads increasingly arrive *through* code, docs, READMEs,
notebooks, issue templates, and config files that downstream agents and
copilots later read. Runtime defenses (spotlighting, dual-LLM, sandwiching)
only help if the payload reaches the model boundary. InjectorDetector catches
payloads earlier — at commit time — and complements those runtime defenses
rather than replacing them.

## Features

- **Single-argument CLI**: point it at a local clone or a remote Git URL.
- **Deterministic verdict**: exit code `0` on SAFE, `1` on NOT SAFE — drop it
  into any CI pipeline.
- **Layered detectors**:
  - YARA rule pack for known injection idioms (role hijacks, jailbreak
    preambles, "ignore previous instructions", tool-call spoofs).
  - Hidden-character detector for zero-width, bidi-override, tag, and
    homoglyph smuggling.
  - Perplexity analysis to flag anomalous text inside otherwise normal files.
  - Encoded-payload detector that recursively decodes base64 / hex / URL runs.
  - Canary / prompt-leak detector for committed Rebuff-style tokens.
  - Optional embedding-similarity detector against a known-payload corpus.
- **Format-aware extraction** via `tree-sitter` for source code, plus
  dedicated extractors for Markdown, Jupyter notebooks, HTML/SVG, and
  YAML/JSON/TOML config.
- **Reports** in human, JSON, or SARIF 2.1.0 (for GitHub code scanning).
- **Pure-Rust Git access** via `gix` — no external `git` binary required.

## Installation

Requires Rust 1.85+ (edition 2024).

```bash
# from source
git clone https://github.com/<you>/InjectorDetector
cd InjectorDetector
cargo install --path .
```

Or build a local binary:

```bash
cargo build --release
./target/release/injector-detector --help
```

## Usage

```text
injector-detector <REPO> [OPTIONS]
```

Scan a local clone:

```bash
injector-detector ./path/to/repo
```

Scan a remote repo at a specific revision and emit SARIF:

```bash
injector-detector https://github.com/example/project \
  --rev v1.2.3 \
  --format sarif > results.sarif
```

Fail the build only on high-severity findings:

```bash
injector-detector . --fail-on high
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
| `--jobs <N>`               | Worker thread count (default: number of CPUs)          |

### Exit codes

| Code | Meaning      |
|------|--------------|
| `0`  | SAFE         |
| `1`  | NOT SAFE     |
| `2`  | Scan error   |

## CI integration

GitHub Actions example:

```yaml
- name: Scan for prompt injections
  run: |
    cargo install injector-detector
    injector-detector . --format sarif --fail-on medium > results.sarif
- uses: github/codeql-action/upload-sarif@v3
  if: always()
  with:
    sarif_file: results.sarif
```

## How it works

1. **Load** the repo with `gix` (clone if remote, open in place if local) and
   resolve `--rev` to a tree.
2. **Walk** the tree, applying gitignore-aware filters and skipping vendored
   or generated content.
3. **Extract** text from each file using a format-appropriate extractor that
   tags chunks with provenance (e.g. `Comment`, `Docstring`,
   `NotebookMarkdownCell`).
4. **Chunk** with Unicode normalisation and bounded windows.
5. **Detect** by running every chunk through the detector pipeline in
   parallel via `rayon`.
6. **Aggregate** findings, dedupe overlaps, and compute per-file scores.
7. **Report** in the requested format and exit with the appropriate code.

See [`DESIGN.md`](DESIGN.md) for the full component breakdown and the
mapping from each tldrsec defense technique to its implementation here.

## Configuration

A `injector-detector.toml` (or any file passed via `--config`) can override
defaults:

```toml
[scan]
max_binary_bytes = 1048576
jobs = 8

[detectors.heuristic]
enabled = true
extra_rules = ["./my-rules/*.yar"]

[detectors.perplexity]
enabled = true
threshold_z = 3.0

[detectors.embedding]
enabled = false   # requires the `embeddings` cargo feature
```

## Cargo features

| Feature       | Default | Description                                    |
|---------------|---------|------------------------------------------------|
| `embeddings`  | off     | Enables the ONNX-backed similarity detector    |
| `pdf`         | off     | Enables PDF text extraction                    |

## Development

```bash
cargo build
cargo test
cargo clippy --all-targets -- -D warnings
cargo fmt
```

The repo layout is documented in [`DESIGN.md`](DESIGN.md) §5.

## License

MIT — see [`LICENSE`](LICENSE).

## Acknowledgements

- [tldrsec/prompt-injection-defenses](https://github.com/tldrsec/prompt-injection-defenses)
  for the taxonomy of techniques this tool draws from.
- The `gix`, `tree-sitter`, and `yara-x` projects for the building blocks
  that make a fast, dependency-light static scanner possible.
