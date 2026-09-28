//! The scanner-local score and grade summarising one set of findings.

use crate::model::{ScanResult, Severity};

/// A clean codebase scores the top score; each finding takes its severity's
/// deduction off it.
pub const TOP_SCORE: i64 = 100;
/// Larger codebases get some leniency: one size unit per this many scanned
/// lines, and each unit softens the deduction by this fraction.
const LINES_PER_SIZE_UNIT: f64 = 1000.0;
const LENIENCY_PER_SIZE_UNIT: f64 = 0.1;
/// The smallest size factor: a codebase under one unit is treated as one.
const MINIMUM_SIZE_FACTOR: f64 = 1.0;
/// The lowest score that still earns each letter grade, best first; anything
/// below the last is an F.
const GRADE_FLOORS: [(i64, &str); 6] = [(95, "A+"), (90, "A"), (80, "B+"), (70, "B"), (60, "C"), (50, "D")];
const FAILING_GRADE: &str = "F";

/// What one finding of `severity` takes off the score.
fn deduction(severity: Severity) -> f64 {
    match severity {
        Severity::Critical => 20.0,
        Severity::High => 10.0,
        Severity::Medium => 5.0,
        Severity::Low => 2.0,
        Severity::Info => 0.0,
    }
}

/// Half to even, as the score has always been rounded.
fn round_half_even(value: f64) -> f64 {
    let floor = value.floor();
    if value - floor != 0.5 {
        return value.round();
    }
    if floor % 2.0 == 0.0 { floor } else { floor + 1.0 }
}

/// A security score from 0 to 100 for the findings of one scan.
pub fn compute_score(result: &ScanResult) -> i64 {
    if result.files_scanned == 0 {
        return TOP_SCORE;
    }
    let total: f64 = result.findings.iter().map(|finding| deduction(finding.severity)).sum();
    let size_factor = (result.lines_scanned as f64 / LINES_PER_SIZE_UNIT).max(MINIMUM_SIZE_FACTOR);
    let adjusted = total / (1.0 + size_factor * LENIENCY_PER_SIZE_UNIT);
    (round_half_even(TOP_SCORE as f64 - adjusted) as i64).clamp(0, TOP_SCORE)
}

/// The letter grade a score earns.
pub fn score_to_grade(score: i64) -> &'static str {
    GRADE_FLOORS
        .iter()
        .find(|(floor, _)| score >= *floor)
        .map_or(FAILING_GRADE, |(_, grade)| grade)
}
