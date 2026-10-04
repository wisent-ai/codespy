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
/// Width of the horizontal rules between report sections.
const RULE_WIDTH: usize = 60;
/// Column widths of the language table and the finding lines.
const LANGUAGE_WIDTH: usize = 15;
const FILE_COUNT_WIDTH: usize = 4;
const LINE_COUNT_WIDTH: usize = 8;
const SUMMARY_SEVERITY_WIDTH: usize = 10;
const FINDING_SEVERITY_WIDTH: usize = 8;
const LINE_NUMBER_WIDTH: usize = 5;

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
pub fn format_terminal(result: &ScanResult, scoring: &ScoringReport<'_>, show_fix: bool, use_color: bool) -> String {
    let paint = |code: &'static str| if use_color { code } else { "" };
    let (bold, dim, reset) = (paint(BOLD), paint(DIM), paint(RESET));
    let rule = "─".repeat(RULE_WIDTH);
    let mut lines = vec![
        format!("\n{bold}codespy v{VERSION}{reset} — Code Security Scanner"),
        format!("{dim}{rule}{reset}"),
        format!("  Path:    {}", result.path),
        format!("  Files:   {} scanned, {} skipped", result.files_scanned, result.files_skipped),
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
        let mut languages: Vec<_> = result.language_stats.iter().collect();
        languages.sort_by(|left, right| right.1.lines.cmp(&left.1.lines));
        for (language, stats) in languages {
            lines.push(format!(
                "  {language:<LANGUAGE_WIDTH$} {:>FILE_COUNT_WIDTH$} files  {:>LINE_COUNT_WIDTH$} lines",
                stats.files,
                thousands(stats.lines),
            ));
        }
        lines.push(String::new());
    }

    let counts = result.severity_counts();
    lines.push(format!("{bold}Findings:{reset} {} total", result.finding_count()));
    for severity in summary_order() {
        let count = counts[severity.as_str()];
        if count > 0 {
            let name = severity.as_str().to_uppercase();
            let color = paint(severity_color(severity));
            lines.push(format!("  {color}{name:<SUMMARY_SEVERITY_WIDTH$}{reset} {count}"));
        }
    }
    lines.push(String::new());

    if result.findings.is_empty() {
        lines.push(format!("  {bold}No issues found.{reset} Your code looks clean!"));
        lines.push(String::new());
        return lines.join("\n");
    }

    lines.push(format!("{dim}{rule}{reset}"));
    for (file_path, findings) in by_file(result) {
        lines.push(format!("\n{bold}{file_path}{reset}"));
        for finding in findings {
            let name = finding.severity.as_str().to_uppercase();
            let color = paint(severity_color(finding.severity));
            lines.push(format!(
                "  {color}{name:<FINDING_SEVERITY_WIDTH$}{reset}  L{:<LINE_NUMBER_WIDTH$} [{}] {}",
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
