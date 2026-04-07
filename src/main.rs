use std::process::ExitCode;

use anyhow::Result;
use clap::{Parser, ValueEnum};

use injector_detector::{
    config::ScanConfig,
    is_unsafe, scan,
    types::Severity,
};

#[derive(Debug, Clone, Copy, ValueEnum)]
enum Format {
    Human,
    Json,
    Sarif,
}

#[derive(Debug, Clone, Copy, ValueEnum)]
enum SeverityArg {
    Low,
    Medium,
    High,
    Critical,
}

impl From<SeverityArg> for Severity {
    fn from(s: SeverityArg) -> Self {
        match s {
            SeverityArg::Low => Severity::Low,
            SeverityArg::Medium => Severity::Medium,
            SeverityArg::High => Severity::High,
            SeverityArg::Critical => Severity::Critical,
        }
    }
}

/// Static prompt-injection scanner for Git repositories.
#[derive(Debug, Parser)]
#[command(name = "injector-detector", version, about)]
struct Cli {
    /// Local path or remote Git URL to scan.
    repo: String,

    /// Git revision to scan.
    #[arg(long, default_value = "HEAD")]
    rev: String,

    /// Path to a TOML config file.
    #[arg(long)]
    config: Option<std::path::PathBuf>,

    /// Output format.
    #[arg(long, value_enum, default_value_t = Format::Human)]
    format: Format,

    /// Minimum severity that fails the scan.
    #[arg(long, value_enum, default_value_t = SeverityArg::Medium)]
    fail_on: SeverityArg,

    /// Restrict scan to matching paths (repeatable).
    #[arg(long)]
    include: Vec<String>,

    /// Skip matching paths (repeatable).
    #[arg(long)]
    exclude: Vec<String>,

    /// Refuse to clone; require a local path.
    #[arg(long)]
    no_clone: bool,

    /// Preserve cloned tempdirs on disk after the scan completes.
    /// The path is printed via tracing.
    #[arg(long)]
    keep: bool,

    /// Incremental scan: only evaluate files changed between this base
    /// revision and --rev.
    #[arg(long)]
    since: Option<String>,

    /// Append new findings to the ignore file instead of failing the
    /// build. Intended for review workflows; the file should be committed
    /// and inspected by a human before future scans pass.
    #[arg(long)]
    quarantine: bool,

    /// Path to the ignore file read by both normal and quarantine scans.
    #[arg(long, default_value = ".injector-detector-ignore")]
    ignore_file: std::path::PathBuf,

    /// Worker thread count.
    #[arg(long)]
    jobs: Option<usize>,
}

fn main() -> ExitCode {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("warn")),
        )
        .init();

    match run() {
        Ok(code) => code,
        Err(e) => {
            eprintln!("error: {e:#}");
            ExitCode::from(2)
        }
    }
}

fn run() -> Result<ExitCode> {
    let cli = Cli::parse();

    let mut config = ScanConfig::default();
    config.rev = cli.rev;
    config.fail_on = cli.fail_on.into();
    config.include = cli.include;
    config.exclude = cli.exclude;
    config.no_clone = cli.no_clone;
    config.keep = cli.keep;
    config.since = cli.since;
    config.quarantine = cli.quarantine;
    config.ignore_file = cli.ignore_file;
    if let Some(j) = cli.jobs {
        config.jobs = j;
    }
    config.config_file = cli.config.clone();
    if let Some(path) = &cli.config {
        config.merge_file(path)?;
    }

    let report = scan(&cli.repo, &config)?;

    let rendered = match cli.format {
        Format::Human => report.render_human(),
        Format::Json => report.render_json()?,
        Format::Sarif => report.render_sarif()?,
    };
    println!("{rendered}");

    if is_unsafe(&report, config.fail_on) {
        Ok(ExitCode::from(1))
    } else {
        Ok(ExitCode::from(0))
    }
}
