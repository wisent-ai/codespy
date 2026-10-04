//! Report rendering for the terminal, JSON, SARIF, and Markdown output
//! formats.

mod markdown;
mod scoring;
mod structured;
mod terminal;

use std::collections::BTreeMap;

use crate::model::{Finding, ScanResult, Severity};

pub use markdown::format_markdown;
pub use scoring::{ScoringPolicy, ScoringReport};
pub use structured::{format_json, format_sarif};
pub use terminal::format_terminal;

/// Digits per group in a number written with thousands separators.
const DIGITS_PER_GROUP: usize = 3;

/// The severities a summary lists, most severe first.
fn summary_order() -> impl Iterator<Item = Severity> {
    Severity::ALL.into_iter().rev()
}

/// `value` with a comma between every three digits, as `{:,}` writes it.
fn thousands(value: usize) -> String {
    let digits = value.to_string();
    let mut grouped = String::with_capacity(digits.len() + digits.len() / DIGITS_PER_GROUP);
    for (index, digit) in digits.chars().enumerate() {
        if index > 0 && (digits.len() - index) % DIGITS_PER_GROUP == 0 {
            grouped.push(',');
        }
        grouped.push(digit);
    }
    grouped
}

/// The findings grouped by file, files in path order, each file's findings in
/// report order.
fn by_file(result: &ScanResult) -> BTreeMap<&str, Vec<&Finding>> {
    let mut files: BTreeMap<&str, Vec<&Finding>> = BTreeMap::new();
    for finding in &result.findings {
        files.entry(finding.file_path.as_str()).or_default().push(finding);
    }
    files
}
