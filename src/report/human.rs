//! Human-readable text reporter.

use std::fmt::Write;

use super::ScanReport;

pub fn render(report: &ScanReport) -> String {
    let mut out = String::new();
    let total = report.total_findings();

    let _ = writeln!(
        out,
        "InjectorDetector — verdict: {} ({} finding(s) across {} file(s))",
        report.verdict.label(),
        total,
        report.files.len()
    );

    if let Some(sev) = report.max_severity {
        let _ = writeln!(out, "max severity: {sev:?}");
    }

    for file in &report.files {
        let _ = writeln!(out, "\n{}", file.path.display());
        let _ = writeln!(
            out,
            "  score {:.2}, max {:?}",
            file.score, file.max_severity
        );
        for f in &file.findings {
            let _ = writeln!(
                out,
                "  [{:?}] {} @ {}..{}: {}",
                f.severity, f.detector, f.span.start, f.span.end, f.message
            );
            let _ = writeln!(out, "    evidence: {}", f.evidence);
        }
    }

    out
}
