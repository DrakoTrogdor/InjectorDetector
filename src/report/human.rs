//! Human-readable text reporter.

use std::fmt::Write;

use super::{RenderOptions, ScanReport};
use crate::safe_view;

pub fn render(report: &ScanReport, options: &RenderOptions) -> String {
    let mut out = String::new();

    if options.ai_safe {
        out.push_str(safe_view::AI_SAFE_PREAMBLE);
        out.push('\n');
    }

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
        let path = if options.ai_safe {
            safe_view::sanitize_path(&file.path.display().to_string())
        } else {
            file.path.display().to_string()
        };
        let _ = writeln!(out, "\n{path}");
        let _ = writeln!(
            out,
            "  score {:.2}, max {:?}",
            file.score, file.max_severity
        );
        for f in &file.findings {
            let message = if options.ai_safe {
                safe_view::sanitize_message(&f.message)
            } else {
                f.message.clone()
            };
            let _ = writeln!(
                out,
                "  [{:?}] {} @ {}..{}: {}",
                f.severity, f.detector, f.span.start, f.span.end, message
            );
            let evidence = if options.ai_safe {
                safe_view::sanitize_evidence(&f.evidence, 120)
            } else {
                f.evidence.clone()
            };
            let _ = writeln!(out, "    evidence: {evidence}");
        }
    }

    out
}
