//! Optional, explicitly supplied scoring policy. Findings never need a score.

use std::path::Path;

use serde::{Deserialize, Serialize};

use crate::model::{ScanResult, Severity};

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ScoringPolicy {
    top_score: f64,
    lines_per_size_unit: f64,
    leniency_per_size_unit: f64,
    minimum_size_factor: f64,
    deductions: Deductions,
    grades: Vec<Grade>,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Deductions {
    critical: f64,
    high: f64,
    medium: f64,
    low: f64,
    info: f64,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Grade {
    floor: f64,
    label: String,
}

impl ScoringPolicy {
    pub fn load(path: &Path) -> Result<Self, String> {
        let text = std::fs::read_to_string(path)
            .map_err(|error| format!("cannot read scoring policy {}: {error}", path.display()))?;
        let policy: Self = serde_json::from_str(&text)
            .map_err(|error| format!("invalid scoring policy {}: {error}", path.display()))?;
        policy
            .validate()
            .map_err(|error| format!("invalid scoring policy {}: {error}", path.display()))?;
        Ok(policy)
    }

    fn validate(&self) -> Result<(), String> {
        for (name, value) in [
            ("top_score", self.top_score),
            ("lines_per_size_unit", self.lines_per_size_unit),
        ] {
            if !value.is_finite() || value <= 0.0 {
                return Err(format!("{name} must be finite and greater than zero"));
            }
        }
        for (name, value) in [
            ("leniency_per_size_unit", self.leniency_per_size_unit),
            ("minimum_size_factor", self.minimum_size_factor),
            ("deductions.critical", self.deductions.critical),
            ("deductions.high", self.deductions.high),
            ("deductions.medium", self.deductions.medium),
            ("deductions.low", self.deductions.low),
            ("deductions.info", self.deductions.info),
        ] {
            if !value.is_finite() || value < 0.0 {
                return Err(format!("{name} must be finite and nonnegative"));
            }
        }
        if self.grades.last().map(|grade| grade.floor) != Some(0.0) {
            return Err("grades must end with a zero floor to cover every possible score".into());
        }
        let mut previous = None;
        for grade in &self.grades {
            if !grade.floor.is_finite() || grade.floor < 0.0 || grade.floor > self.top_score {
                return Err("every grade floor must be between zero and top_score".into());
            }
            if previous.is_some_and(|floor| grade.floor >= floor) {
                return Err("grade floors must be strictly descending".into());
            }
            if grade.label.trim().is_empty() || grade.label.chars().any(char::is_control) {
                return Err(
                    "grade labels must be nonempty single-line text without control characters"
                        .into(),
                );
            }
            previous = Some(grade.floor);
        }
        Ok(())
    }

    fn deduction(&self, severity: Severity) -> f64 {
        match severity {
            Severity::Critical => self.deductions.critical,
            Severity::High => self.deductions.high,
            Severity::Medium => self.deductions.medium,
            Severity::Low => self.deductions.low,
            Severity::Info => self.deductions.info,
        }
    }
}

/// The complete policy travels with every report, not just its file name.
#[derive(Debug, Serialize)]
pub struct ScoringReport<'a> {
    pub policy: Option<&'a ScoringPolicy>,
    pub score: Option<f64>,
    pub grade: Option<&'a str>,
    pub reason: Option<&'static str>,
}

impl<'a> ScoringReport<'a> {
    pub fn new(result: &ScanResult, policy: Option<&'a ScoringPolicy>) -> Result<Self, String> {
        let mut report = Self {
            policy,
            score: None,
            grade: None,
            reason: None,
        };
        let Some(policy) = policy else {
            report.reason =
                Some("No scoring policy supplied; use --scoring-policy PATH to request a score");
            return Ok(report);
        };
        policy.validate()?;
        if result.files_scanned == 0 {
            report.reason = Some("No supported source files were scanned");
            return Ok(report);
        }
        let total: f64 = result
            .findings
            .iter()
            .map(|finding| policy.deduction(finding.severity))
            .sum();
        let size_factor = (result.lines_scanned as f64 / policy.lines_per_size_unit)
            .max(policy.minimum_size_factor);
        let divisor = 1.0 + size_factor * policy.leniency_per_size_unit;
        if !total.is_finite() || !size_factor.is_finite() || !divisor.is_finite() {
            return Err(
                "scoring policy calculation overflowed for this scan; no score was produced".into(),
            );
        }
        let score =
            round_half_even(policy.top_score - total / divisor).clamp(0.0, policy.top_score);
        report.score = Some(score);
        report.grade = policy
            .grades
            .iter()
            .find(|grade| score >= grade.floor)
            .map(|grade| grade.label.as_str());
        Ok(report)
    }

    pub fn summary(&self) -> String {
        match (self.score, self.grade, self.policy) {
            (Some(score), Some(grade), Some(policy)) => format!(
                "Security score: {score}/{} (Grade: {grade})",
                policy.top_score
            ),
            _ => format!(
                "Security score unavailable: {}",
                self.reason.unwrap_or("no assessment")
            ),
        }
    }

    pub fn policy_json(&self) -> String {
        serde_json::to_string(&self.policy).expect("validated scoring policy serializes")
    }
}

/// Half to even is a rounding operation, not a policy weight.
fn round_half_even(value: f64) -> f64 {
    let floor = value.floor();
    if value - floor != 0.5 {
        return value.round();
    }
    if floor % 2.0 == 0.0 {
        floor
    } else {
        floor + 1.0
    }
}
