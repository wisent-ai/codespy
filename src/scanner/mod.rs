//! Collect scannable files and evaluate the rule table against their contents.

mod files;

use std::cmp::Reverse;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::time::Instant;

use crate::model::{Finding, ScanResult, Severity};
use crate::rules::{rules, Rule};

pub use files::{collect_files, detect_language, scanned_suffixes};

/// Milliseconds in a second, for the duration the report states.
const MILLISECONDS_PER_SECOND: f64 = 1000.0;

/// Why a scan could not finish.
#[derive(Debug)]
pub enum ScanError {
    /// A directory or file of the scan path could not be opened or measured.
    Walk { path: PathBuf, error: io::Error },
    /// A file the scan selected could not be read, so it was not scanned.
    Read { file: PathBuf, error: io::Error },
    /// A rule's pattern gave up on a file (the matcher's backtracking bound).
    Pattern { rule: String, file: PathBuf, detail: String },
}

impl std::fmt::Display for ScanError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ScanError::Walk { path, error } => write!(formatter, "cannot walk {}: {error}", path.display()),
            ScanError::Read { file, error } => write!(formatter, "cannot read {}: {error}", file.display()),
            ScanError::Pattern { rule, file, detail } => {
                write!(formatter, "rule {rule} could not be evaluated on {}: {detail}", file.display())
            }
        }
    }
}

impl std::error::Error for ScanError {}

/// Scan one file: every finding of every rule that applies to `language` at
/// or above `min_severity`, in rule order, and the file's line count. A file
/// that cannot be read is an error: reporting it as clean would pass a gate
/// over code nobody looked at.
pub fn scan_file(
    file_path: &Path,
    language: &str,
    rules: &[Rule],
    min_severity: Severity,
) -> Result<(Vec<Finding>, usize), ScanError> {
    let bytes = fs::read(file_path).map_err(|error| ScanError::Read { file: file_path.to_path_buf(), error })?;
    let content = String::from_utf8_lossy(&bytes);
    let lines: Vec<&str> = content.split('\n').collect();
    let mut findings = Vec::new();
    for rule in rules {
        if !rule.applies_to(language) || rule.severity < min_severity {
            continue;
        }
        for found in rule.pattern.find_iter(&content) {
            let found = found.map_err(|error| ScanError::Pattern {
                rule: rule.id.clone(),
                file: file_path.to_path_buf(),
                detail: error.to_string(),
            })?;
            let line_number = content[..found.start()].matches('\n').count() + 1;
            let line_content = lines[(line_number - 1).min(lines.len() - 1)];
            findings.push(Finding {
                rule_id: rule.id.clone(),
                title: rule.title.clone(),
                description: rule.description.clone(),
                severity: rule.severity,
                category: rule.category,
                file_path: file_path.to_string_lossy().into_owned(),
                line_number,
                line_content: line_content.to_owned(),
                suggestion: rule.suggestion.clone(),
                cwe_id: rule.cwe_id.clone(),
                confidence: rule.confidence,
            });
        }
    }
    Ok((findings, lines.len()))
}

/// `file` relative to the scan root, or `.` when the root is the file.
fn relative(file: &Path, root: &Path) -> String {
    match file.strip_prefix(root) {
        Ok(rest) if rest.as_os_str().is_empty() => ".".to_owned(),
        Ok(rest) => rest.to_string_lossy().into_owned(),
        Err(_) => file.to_string_lossy().into_owned(),
    }
}

/// Scan `path` with every released rule at or above `min_severity`.
/// Findings come most severe first, then by file and line; equal ones keep
/// rule order.
pub fn run_scan(path: &Path, min_severity: Severity) -> Result<ScanResult, ScanError> {
    let started = Instant::now();
    let root = std::path::absolute(path)
        .map_err(|error| ScanError::Walk { path: path.to_path_buf(), error })?;
    let mut result = ScanResult { path: root.to_string_lossy().into_owned(), ..ScanResult::default() };
    for (file, language) in collect_files(&root)? {
        let (mut findings, line_count) = scan_file(&file, language, rules(), min_severity)?;
        let shown = relative(&file, &root);
        for finding in &mut findings {
            finding.file_path.clone_from(&shown);
        }
        result.findings.append(&mut findings);
        result.files_scanned += 1;
        result.lines_scanned += line_count;
        let stats = result.language_stats.entry(language.to_owned()).or_default();
        stats.files += 1;
        stats.lines += line_count;
    }
    result.scan_duration_ms = started.elapsed().as_secs_f64() * MILLISECONDS_PER_SECOND;
    result.findings.sort_by(|left, right| {
        (Reverse(left.severity), &left.file_path, left.line_number)
            .cmp(&(Reverse(right.severity), &right.file_path, right.line_number))
    });
    Ok(result)
}
