//! InjectorDetector — static prompt-injection scanner for Git repositories.
//!
//! See `DESIGN.md` at the repo root for the architecture this crate
//! implements.

pub mod aggregate;
pub mod chunk;
pub mod config;
pub mod detect;
pub mod extract;
pub mod progress;
pub mod quarantine;
pub mod report;
pub mod repo;
pub mod types;
pub mod walk;

use anyhow::Result;
use rayon::prelude::*;

use crate::aggregate::Aggregator;
use crate::config::ScanConfig;
use crate::detect::Engine;
use crate::progress::ProgressReporter;
use crate::report::ScanReport;
use crate::types::Severity;

/// Run a full scan against the given repository source.
pub fn scan(source: &str, config: &ScanConfig) -> Result<ScanReport> {
    let progress = ProgressReporter::new(config.quiet);

    progress.stage("Loading repository");
    let loaded = repo::load(source, config)?;
    let engine = Engine::from_config(&config.detectors);

    // Load the quarantine file up front so we can filter / append to it.
    let ignore_path = if config.ignore_file.is_absolute() {
        config.ignore_file.clone()
    } else {
        loaded.root().join(&config.ignore_file)
    };
    let mut quarantine_file = quarantine::load(&ignore_path).unwrap_or_default();

    progress.stage("Walking files");
    let entries: Vec<_> = walk::walk(&loaded, config)?.collect::<Result<Vec<_>>>()?;
    progress.begin_scanning(entries.len() as u64);

    let pool = rayon::ThreadPoolBuilder::new()
        .num_threads(config.jobs.max(1))
        .build()
        .map_err(|e| anyhow::anyhow!(e))?;

    let mut findings: Vec<_> = pool.install(|| {
        entries
            .par_iter()
            .flat_map_iter(|entry| {
                progress.on_file(&entry.path);
                let chunks = extract::extract(entry).unwrap_or_default();
                let result: Vec<_> = chunks
                    .into_iter()
                    .flat_map(|chunk| engine.analyze(&chunk))
                    .collect();
                progress.inc_file();
                result
            })
            .collect()
    });

    progress.stage("Aggregating findings");
    if config.quarantine {
        // In quarantine mode, append every new finding to the ignore file
        // and then drop them so the report comes back SAFE. The user is
        // expected to `git add` the ignore file and review it.
        quarantine::append_findings(&mut quarantine_file, &findings);
        quarantine::save(&ignore_path, &quarantine_file)?;
        progress.println(format!(
            "quarantined {} finding(s) → {}",
            findings.len(),
            ignore_path.display()
        ));
        findings.clear();
    } else {
        quarantine::filter_findings(&mut findings, &quarantine_file);
    }

    let mut aggregator = Aggregator::new();
    for f in findings {
        aggregator.add(f);
    }
    let report = aggregator.finalize(config);

    progress.finish(&format!(
        "Scanned {} file(s) — verdict: {}",
        entries.len(),
        report.verdict.label()
    ));

    Ok(report)
}

/// Returns `true` if the report's worst severity meets or exceeds `fail_on`.
pub fn is_unsafe(report: &ScanReport, fail_on: Severity) -> bool {
    report
        .max_severity()
        .map(|s| s >= fail_on)
        .unwrap_or(false)
}
