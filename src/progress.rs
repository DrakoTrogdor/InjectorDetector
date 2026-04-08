//! Command-line progress reporting.
//!
//! Wraps `indicatif` so the scan pipeline can stream status updates
//! without every caller worrying about TTY detection or whether the
//! progress bar has been initialised. Output always goes to stderr, so
//! it never mixes with the JSON/SARIF report emitted on stdout.
//!
//! Behaviour by mode:
//!   * `--quiet` → everything suppressed.
//!   * interactive terminal → animated progress bar + header lines.
//!   * non-interactive stderr (CI logs, redirected output) → plain
//!     `eprintln!` for header lines, no progress bar (drops cleanly
//!     into logs without ANSI spam).

use std::io::IsTerminal;
use std::path::Path;
use std::sync::Mutex;

use indicatif::{ProgressBar, ProgressDrawTarget, ProgressStyle};

/// Thread-safe progress reporter. Cloneable so multiple workers can
/// increment the same bar concurrently via `Arc` internally.
#[derive(Default)]
pub struct ProgressReporter {
    quiet: bool,
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
    /// Construct a reporter. When `quiet` is set, the reporter is fully
    /// silent. When stderr isn't a terminal, header/println lines still
    /// go to stderr but no animated progress bar is drawn.
    pub fn new(quiet: bool) -> Self {
        if quiet {
            return Self {
                quiet: true,
                inner: None,
            };
        }
        if !std::io::stderr().is_terminal() {
            return Self {
                quiet: false,
                inner: None,
            };
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
            quiet: false,
            inner: Some(Inner {
                bar,
                suffix: Mutex::new(()),
            }),
        }
    }

    /// Print the "Checking &lt;name&gt;..." header that announces the scan
    /// target. `source` is the CLI argument the user passed (a local
    /// path or a git URL); this helper canonicalises and shortens it
    /// down to a friendly single-word name.
    pub fn checking(&self, source: &str) {
        if self.quiet {
            return;
        }
        let name = display_name(source);
        self.println(format!("Checking {name}..."));
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
                // Walk forward to the nearest char boundary so we never
                // panic on a path containing multi-byte UTF-8 characters.
                let mut start = display.len() - 59;
                while start < display.len() && !display.is_char_boundary(start) {
                    start += 1;
                }
                format!("…{}", &display[start..])
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
    /// itself. Respects `--quiet`; falls through to plain `eprintln!`
    /// when running without a bar (non-TTY output).
    pub fn println(&self, msg: impl AsRef<str>) {
        if self.quiet {
            return;
        }
        if let Some(inner) = &self.inner {
            inner.bar.println(msg.as_ref());
        } else {
            eprintln!("{}", msg.as_ref());
        }
    }
}

/// Derive a short, user-friendly name for the scan target.
///
/// * Local path: canonicalise (if possible) and return the last path
///   component — e.g. `D:\Code\dual-encrypt` → `dual-encrypt`, `.` →
///   the current directory's name.
/// * Remote URL: strip trailing slashes and a `.git` suffix, return
///   the last path segment — e.g.
///   `https://github.com/foo/bar.git` → `bar`,
///   `git@github.com:foo/bar.git` → `bar`.
/// * Fallback: the raw `source` string.
fn display_name(source: &str) -> String {
    let path = Path::new(source);
    if path.exists() {
        if let Ok(canonical) = path.canonicalize()
            && let Some(name) = canonical.file_name().and_then(|n| n.to_str())
        {
            return name.to_string();
        }
        if let Some(name) = path.file_name().and_then(|n| n.to_str()) {
            return name.to_string();
        }
    }
    let trimmed = source.trim_end_matches('/').trim_end_matches('\\');
    let last = trimmed
        .rsplit(['/', '\\', ':'])
        .find(|s| !s.is_empty())
        .unwrap_or(trimmed);
    let last = last.trim_end_matches(".git");
    if last.is_empty() {
        source.to_string()
    } else {
        last.to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::display_name;

    #[test]
    fn local_path_returns_last_component() {
        // Use a tempdir so the expected name is exactly what we created.
        let dir = tempfile::Builder::new()
            .prefix("injdet-display-name-test-")
            .tempdir()
            .unwrap();
        let expected = dir.path().file_name().unwrap().to_str().unwrap().to_string();
        let resolved = display_name(dir.path().to_str().unwrap());
        assert_eq!(resolved, expected);
    }

    #[test]
    fn url_returns_last_segment_stripped_of_git_suffix() {
        assert_eq!(
            display_name("https://github.com/example/my-cool-repo.git"),
            "my-cool-repo"
        );
        assert_eq!(
            display_name("https://github.com/example/my-cool-repo"),
            "my-cool-repo"
        );
        assert_eq!(
            display_name("git@github.com:example/my-cool-repo.git"),
            "my-cool-repo"
        );
    }

    #[test]
    fn trailing_slashes_are_handled() {
        assert_eq!(
            display_name("https://example.com/foo/bar.git/"),
            "bar"
        );
    }

    #[test]
    fn nonexistent_path_falls_back_to_last_component() {
        let name = display_name("/nonexistent/path/to/my-project");
        assert_eq!(name, "my-project");
    }
}

