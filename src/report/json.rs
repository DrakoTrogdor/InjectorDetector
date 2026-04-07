//! JSON reporter.

use super::ScanReport;

pub fn render(report: &ScanReport) -> Result<String, serde_json::Error> {
    serde_json::to_string_pretty(report)
}
