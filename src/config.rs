//! Scan configuration. Loaded from CLI flags and an optional TOML file.

use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

use crate::types::Severity;

/// User-tunable scan configuration. CLI flags and the TOML config file
/// both populate this struct.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanConfig {
    pub rev: String,
    pub fail_on: Severity,
    pub include: Vec<String>,
    pub exclude: Vec<String>,
    pub no_clone: bool,
    pub keep: bool,
    pub jobs: usize,
    /// Optional base revision for incremental scans. When set, only
    /// files that changed between `since` and `rev` are scanned.
    pub since: Option<String>,
    /// Path to the quarantine file. Findings listed here are suppressed
    /// from normal scans and verdict computation.
    pub ignore_file: PathBuf,
    /// When true, the scan appends new findings to `ignore_file` instead
    /// of returning NOT SAFE.
    pub quarantine: bool,
    pub max_binary_bytes: u64,
    pub max_chunk_bytes: usize,
    pub chunk_overlap_bytes: usize,
    pub config_file: Option<PathBuf>,
    pub detectors: DetectorConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct DetectorConfig {
    #[serde(default = "default_true")]
    pub heuristic: bool,
    #[serde(default = "default_true")]
    pub hidden_chars: bool,
    #[serde(default = "default_true")]
    pub encoded: bool,
    #[serde(default = "default_true")]
    pub canary: bool,
    #[serde(default = "default_true")]
    pub perplexity: bool,
    #[serde(default)]
    pub embedding: bool,
    /// Extra canary tokens to flag if found in repo content.
    #[serde(default)]
    pub extra_canaries: Vec<String>,
    /// Glob patterns pointing at additional YARA rule files to load.
    #[serde(default)]
    pub extra_rules: Vec<String>,
    /// Optional path to an ONNX sentence-transformer model for the
    /// embedding detector. When unset, the embedding detector falls back
    /// to its built-in SimHash near-duplicate matcher.
    #[serde(default)]
    pub embedding_model: Option<PathBuf>,
    /// Optional path to the HuggingFace tokenizer.json for the ONNX
    /// model. When unset and `embedding_bundled` is true, the default
    /// `all-MiniLM-L6-v2` tokenizer is downloaded alongside the model.
    #[serde(default)]
    pub embedding_tokenizer: Option<PathBuf>,
    /// Fetch the default bundled model (`sentence-transformers/all-MiniLM-L6-v2`)
    /// on first use. The files are cached in the user's data directory.
    #[serde(default)]
    pub embedding_bundled: bool,

    // --- LLM classifier ---
    #[serde(default)]
    pub llm_classifier: bool,
    #[serde(default)]
    pub llm_classifier_base_url: Option<String>,
    #[serde(default)]
    pub llm_classifier_model: Option<String>,
    #[serde(default)]
    pub llm_classifier_api_key_env: Option<String>,
}

fn default_true() -> bool {
    true
}

impl Default for ScanConfig {
    fn default() -> Self {
        Self {
            rev: "HEAD".to_string(),
            fail_on: Severity::Medium,
            include: Vec::new(),
            exclude: Vec::new(),
            no_clone: false,
            keep: false,
            jobs: num_cpus_or_one(),
            since: None,
            ignore_file: PathBuf::from(".injector-detector-ignore"),
            quarantine: false,
            max_binary_bytes: 1024 * 1024,
            max_chunk_bytes: 2048,
            chunk_overlap_bytes: 256,
            config_file: None,
            detectors: DetectorConfig {
                heuristic: true,
                hidden_chars: true,
                encoded: true,
                canary: true,
                perplexity: true,
                embedding: false,
                extra_canaries: Vec::new(),
                extra_rules: Vec::new(),
                embedding_model: None,
                embedding_tokenizer: None,
                embedding_bundled: false,
                llm_classifier: false,
                llm_classifier_base_url: None,
                llm_classifier_model: None,
                llm_classifier_api_key_env: None,
            },
        }
    }
}

/// Mirror of the on-disk TOML schema. Every field is optional so users
/// only need to specify what they want to override.
#[derive(Debug, Clone, Default, Deserialize)]
struct ConfigFile {
    #[serde(default)]
    scan: ScanSection,
    #[serde(default)]
    detectors: DetectorSection,
}

#[derive(Debug, Clone, Default, Deserialize)]
struct ScanSection {
    max_binary_bytes: Option<u64>,
    jobs: Option<usize>,
    fail_on: Option<Severity>,
    include: Option<Vec<String>>,
    exclude: Option<Vec<String>>,
}

#[derive(Debug, Clone, Default, Deserialize)]
struct DetectorSection {
    #[serde(default)]
    heuristic: HeuristicSection,
    #[serde(default)]
    hidden_chars: TogglableSection,
    #[serde(default)]
    encoded: TogglableSection,
    #[serde(default)]
    canary: CanarySection,
    #[serde(default)]
    perplexity: TogglableSection,
    #[serde(default)]
    embedding: EmbeddingSection,
    #[serde(default)]
    llm_classifier: LlmClassifierSection,
}

#[derive(Debug, Clone, Default, Deserialize)]
struct EmbeddingSection {
    enabled: Option<bool>,
    #[serde(default)]
    model: Option<PathBuf>,
    #[serde(default)]
    tokenizer: Option<PathBuf>,
    #[serde(default)]
    bundled: Option<bool>,
}

#[derive(Debug, Clone, Default, Deserialize)]
struct LlmClassifierSection {
    enabled: Option<bool>,
    #[serde(default)]
    base_url: Option<String>,
    #[serde(default)]
    model: Option<String>,
    #[serde(default)]
    api_key_env: Option<String>,
}

#[derive(Debug, Clone, Default, Deserialize)]
struct TogglableSection {
    enabled: Option<bool>,
}

#[derive(Debug, Clone, Default, Deserialize)]
struct CanarySection {
    enabled: Option<bool>,
    #[serde(default)]
    tokens: Vec<String>,
}

#[derive(Debug, Clone, Default, Deserialize)]
struct HeuristicSection {
    enabled: Option<bool>,
    #[serde(default)]
    extra_rules: Vec<String>,
}

impl ScanConfig {
    /// Load a TOML file from disk and overlay it onto `self`.
    pub fn merge_file(&mut self, path: &Path) -> Result<()> {
        let raw = std::fs::read_to_string(path)
            .with_context(|| format!("failed to read config file {}", path.display()))?;
        let parsed: ConfigFile = toml::from_str(&raw)
            .with_context(|| format!("failed to parse config file {}", path.display()))?;

        if let Some(v) = parsed.scan.max_binary_bytes {
            self.max_binary_bytes = v;
        }
        if let Some(v) = parsed.scan.jobs {
            self.jobs = v;
        }
        if let Some(v) = parsed.scan.fail_on {
            self.fail_on = v;
        }
        if let Some(v) = parsed.scan.include {
            self.include.extend(v);
        }
        if let Some(v) = parsed.scan.exclude {
            self.exclude.extend(v);
        }

        if let Some(v) = parsed.detectors.heuristic.enabled {
            self.detectors.heuristic = v;
        }
        self.detectors
            .extra_rules
            .extend(parsed.detectors.heuristic.extra_rules);
        if let Some(v) = parsed.detectors.hidden_chars.enabled {
            self.detectors.hidden_chars = v;
        }
        if let Some(v) = parsed.detectors.encoded.enabled {
            self.detectors.encoded = v;
        }
        if let Some(v) = parsed.detectors.canary.enabled {
            self.detectors.canary = v;
        }
        if let Some(v) = parsed.detectors.perplexity.enabled {
            self.detectors.perplexity = v;
        }
        if let Some(v) = parsed.detectors.embedding.enabled {
            self.detectors.embedding = v;
        }
        if let Some(v) = parsed.detectors.embedding.model {
            self.detectors.embedding_model = Some(v);
        }
        if let Some(v) = parsed.detectors.embedding.tokenizer {
            self.detectors.embedding_tokenizer = Some(v);
        }
        if let Some(v) = parsed.detectors.embedding.bundled {
            self.detectors.embedding_bundled = v;
        }

        if let Some(v) = parsed.detectors.llm_classifier.enabled {
            self.detectors.llm_classifier = v;
        }
        if let Some(v) = parsed.detectors.llm_classifier.base_url {
            self.detectors.llm_classifier_base_url = Some(v);
        }
        if let Some(v) = parsed.detectors.llm_classifier.model {
            self.detectors.llm_classifier_model = Some(v);
        }
        if let Some(v) = parsed.detectors.llm_classifier.api_key_env {
            self.detectors.llm_classifier_api_key_env = Some(v);
        }
        self.detectors.extra_canaries.extend(parsed.detectors.canary.tokens);

        Ok(())
    }
}

fn num_cpus_or_one() -> usize {
    std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(1)
}
