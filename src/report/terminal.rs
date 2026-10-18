//! Human-readable terminal report, with optional colour.

use crate::identity::VERSION;
use crate::model::{ScanResult, Severity};

use super::{by_file, summary_order, thousands, ScoringReport};

const RESET: &str = "\x1b[0m";
const BOLD: &str = "\x1b[1m";
const DIM: &str = "\x1b[2m";
const CYAN: &str = "\x1b[36m";
const YELLOW: &str = "\x1b[33m";
const RED: &str = "\x1b[31m";

/// The width a column needs to hold every value it shows: its widest one.
fn column_width<'a>(values: impl Iterator<Item = &'a str>) -> usize {
    values
        .map(|value| value.chars().count())
        .max()
        .into_iter()
        .sum()
}

fn severity_color(severity: Severity) -> &'static str {
    match severity {
        Severity::Critical => "\x1b[1;31m",
        Severity::High => RED,
        Severity::Medium => YELLOW,
        Severity::Low => CYAN,
        Severity::Info => "\x1b[37m",
    }
}

/// The scan as the terminal report writes it; with `use_color` it carries
/// ANSI colours, with `show_fix` each finding's suggestion.
pub fn format_terminal(
    result: &ScanResult,
    scoring: &ScoringReport<'_>,
    show_fix: bool,
    use_color: bool,
) -> String {
    let paint = |code: &'static str| if use_color { code } else { "" };
    let (bold, dim, reset) = (paint(BOLD), paint(DIM), paint(RESET));
    let title = format!("codespy v{VERSION} — Code Security Scanner");
    // The rules between sections are as wide as the report's title.
    let rule = "─".repeat(title.chars().count());
    let mut lines = vec![
        format!("\n{bold}{title}{reset}"),
        format!("{dim}{rule}{reset}"),
        format!("  Path:    {}", result.path),
        format!(
            "  Files:   {} scanned, {} skipped",
            result.files_scanned, result.files_skipped
        ),
        format!("  Lines:   {}", thousands(result.lines_scanned)),
        format!("  Time:    {:.0}ms", result.scan_duration_ms),
        String::new(),
    ];
    lines.push(format!("{bold}{}{reset}", scoring.summary()));
    if scoring.policy.is_some() {
        lines.push(format!("Scoring policy: {}", scoring.policy_json()));
    }
    lines.push(String::new());

    if !result.language_stats.is_empty() {
        lines.push(format!("{bold}Languages:{reset}"));
        let mut languages: Vec<_> = result
            .language_stats
            .iter()
            .map(|(language, stats)| {
                (
                    language.as_str(),
                    stats.files.to_string(),
                    thousands(stats.lines),
                    stats.lines,
                )
            })
            .collect();
        languages.sort_by(|left, right| right.3.cmp(&left.3));
        let language_width = column_width(languages.iter().map(|row| row.0));
        let files_width = column_width(languages.iter().map(|row| row.1.as_str()));
        let lines_width = column_width(languages.iter().map(|row| row.2.as_str()));
        for (language, files, line_count, _) in &languages {
            lines.push(format!(
                "  {language:<language_width$} {files:>files_width$} files  {line_count:>lines_width$} lines"
            ));
        }
        lines.push(String::new());
    }

    let counts = result.severity_counts();
    lines.push(format!(
        "{bold}Findings:{reset} {} total",
        result.finding_count()
    ));
    // A severity is listed when a finding has it.
    let present: Vec<Severity> = summary_order()
        .into_iter()
        .filter(|severity| {
            result
                .findings
                .iter()
                .any(|finding| finding.severity == *severity)
        })
        .collect();
    let names: Vec<String> = present
        .iter()
        .map(|severity| severity.as_str().to_uppercase())
        .collect();
    let summary_width = column_width(names.iter().map(String::as_str));
    for (severity, name) in present.iter().zip(&names) {
        let count = counts[severity.as_str()];
        let color = paint(severity_color(*severity));
        lines.push(format!("  {color}{name:<summary_width$}{reset} {count}"));
    }
    lines.push(String::new());

    if result.findings.is_empty() {
        lines.push(format!(
            "  {bold}No issues found.{reset} Your code looks clean!"
        ));
        lines.push(String::new());
        return lines.join("\n");
    }

    let finding_names: Vec<String> = result
        .findings
        .iter()
        .map(|finding| finding.severity.as_str().to_uppercase())
        .collect();
    let finding_width = column_width(finding_names.iter().map(String::as_str));
    let line_numbers: Vec<String> = result
        .findings
        .iter()
        .map(|finding| finding.line_number.to_string())
        .collect();
    let line_number_width = column_width(line_numbers.iter().map(String::as_str));
    lines.push(format!("{dim}{rule}{reset}"));
    for (file_path, findings) in by_file(result) {
        lines.push(format!("\n{bold}{file_path}{reset}"));
        for finding in findings {
            let name = finding.severity.as_str().to_uppercase();
            let color = paint(severity_color(finding.severity));
            lines.push(format!(
                "  {color}{name:<finding_width$}{reset}  L{:<line_number_width$} [{}] {}",
                finding.line_number, finding.rule_id, finding.title,
            ));
            let shown = finding.line_content.trim();
            lines.push(format!("           {dim}{shown}{reset}"));
            if show_fix && !finding.suggestion.is_empty() {
                lines.push(format!("           💡 {}", finding.suggestion));
            }
        }
    }
    lines.push(format!("\n{dim}{rule}{reset}"));

    lines.push(String::new());
    lines.join("\n")
}
