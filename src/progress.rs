//! Command-line progress reporting.
//!
//! Wraps `indicatif` so the scan pipeline can stream status updates
//! without every caller worrying about TTY detection or whether the
//! progress bar has been initialised. Output always goes to stderr, so
//! it never mixes with the JSON/SARIF report emitted on stdout.
//!
//! When `--quiet` is set or stderr is not a terminal, the reporter
//! becomes a no-op — this keeps CI logs and redirected output clean.

use std::io::IsTerminal;
use std::sync::Mutex;

use indicatif::{ProgressBar, ProgressDrawTarget, ProgressStyle};

/// Thread-safe progress reporter. Cloneable so multiple workers can
/// increment the same bar concurrently via `Arc` internally.
pub struct ProgressReporter {
    inner: Option<Inner>,
}

struct Inner {
    bar: ProgressBar,
    /// Protects the "current file" suffix so concurrent workers don't
    /// clobber each other. The bar itself is already thread-safe, but
    /// `set_message` takes a full string so we serialise formatting.
    suffix: Mutex<()>,
}

impl ProgressReporter {
    /// Construct a reporter. Returns a no-op reporter when `quiet` is
    /// set or stderr isn't a terminal.
    pub fn new(quiet: bool) -> Self {
        if quiet || !std::io::stderr().is_terminal() {
            return Self { inner: None };
        }
        let bar = ProgressBar::with_draw_target(Some(0), ProgressDrawTarget::stderr());
        bar.set_style(
            ProgressStyle::with_template(
                "{spinner:.cyan} [{elapsed_precise}] {wide_msg}",
            )
            .unwrap()
            .tick_strings(&["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏", ""]),
        );
        bar.enable_steady_tick(std::time::Duration::from_millis(100));
        Self {
            inner: Some(Inner {
                bar,
                suffix: Mutex::new(()),
            }),
        }
    }

    /// Announce the start of a new pipeline stage.
    pub fn stage(&self, msg: &str) {
        if let Some(inner) = &self.inner {
            inner.bar.set_message(msg.to_string());
        }
    }

    /// Switch the bar into counted mode once the total number of files
    /// to scan is known.
    pub fn begin_scanning(&self, total: u64) {
        if let Some(inner) = &self.inner {
            inner.bar.set_length(total);
            inner.bar.set_position(0);
            inner.bar.set_style(
                ProgressStyle::with_template(
                    "{spinner:.cyan} [{elapsed_precise}] [{bar:40.cyan/blue}] {pos}/{len} {wide_msg}",
                )
                .unwrap()
                .progress_chars("=>-"),
            );
        }
    }

    /// Called by each worker just before analysing a file. Updates the
    /// trailing message so the user can see which file is in flight.
    pub fn on_file(&self, path: &std::path::Path) {
        if let Some(inner) = &self.inner {
            let _lock = inner.suffix.lock();
            let display = path.display().to_string();
            let truncated = if display.len() > 60 {
                format!("…{}", &display[display.len() - 59..])
            } else {
                display
            };
            inner.bar.set_message(truncated);
        }
    }

    /// Called after a file has been analysed. Increments the bar.
    pub fn inc_file(&self) {
        if let Some(inner) = &self.inner {
            inner.bar.inc(1);
        }
    }

    /// Finalise the bar with a summary line.
    pub fn finish(&self, msg: &str) {
        if let Some(inner) = &self.inner {
            inner.bar.set_style(
                ProgressStyle::with_template("{spinner:.green} [{elapsed_precise}] {msg}")
                    .unwrap(),
            );
            inner.bar.finish_with_message(msg.to_string());
        }
    }

    /// Emit a message above the progress bar without consuming the bar
    /// itself. Useful for tracing-style notices that should still appear
    /// even while the bar is drawn.
    pub fn println(&self, msg: impl AsRef<str>) {
        if let Some(inner) = &self.inner {
            inner.bar.println(msg.as_ref());
        } else {
            // No bar — dump straight to stderr so the user still sees it.
            eprintln!("{}", msg.as_ref());
        }
    }
}

impl Default for ProgressReporter {
    fn default() -> Self {
        Self { inner: None }
    }
}
