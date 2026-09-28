//! What one scan found and measured, and the JSON and SARIF documents it is
//! written as.

use indexmap::IndexMap;
use serde_json::{json, Map, Value};

use super::{Finding, Severity};
use crate::identity::{INFORMATION_URI, NAME, SARIF_SCHEMA, SARIF_VERSION, VERSION};

/// Decimal places the JSON report keeps on the scan duration.
const DURATION_DIGITS: i32 = 2;

/// Everything one scan of one path produced.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct ScanResult {
    pub path: String,
    pub files_scanned: usize,
    pub files_skipped: usize,
    pub lines_scanned: usize,
    pub scan_duration_ms: f64,
    pub findings: Vec<Finding>,
    /// Files scanned per language, in the order languages were first met.
    pub language_stats: IndexMap<String, usize>,
}

/// `value` rounded to `digits` decimals, halves to the even neighbour, as the
/// reports have always rounded.
fn round_half_even(value: f64, digits: i32) -> f64 {
    let scale = 10f64.powi(digits);
    let scaled = value * scale;
    let floor = scaled.floor();
    let whole = if scaled - floor == 0.5 {
        if floor % 2.0 == 0.0 { floor } else { floor + 1.0 }
    } else {
        scaled.round()
    };
    whole / scale
}

impl ScanResult {
    pub fn finding_count(&self) -> usize {
        self.findings.len()
    }

    /// Every severity, present or not, so a report never has to guess a
    /// missing one; least severe first.
    pub fn severity_counts(&self) -> IndexMap<&'static str, usize> {
        let mut counts: IndexMap<&'static str, usize> =
            Severity::ALL.iter().map(|severity| (severity.as_str(), 0)).collect();
        for finding in &self.findings {
            *counts.entry(finding.severity.as_str()).or_default() += 1;
        }
        counts
    }

    /// Findings per category, in the order categories were first found.
    pub fn category_counts(&self) -> IndexMap<&'static str, usize> {
        let mut counts: IndexMap<&'static str, usize> = IndexMap::new();
        for finding in &self.findings {
            *counts.entry(finding.category.as_str()).or_default() += 1;
        }
        counts
    }

    /// The scan as the JSON report writes it.
    pub fn to_json(&self) -> Value {
        json!({
            "version": VERSION,
            "path": self.path,
            "files_scanned": self.files_scanned,
            "files_skipped": self.files_skipped,
            "lines_scanned": self.lines_scanned,
            "scan_duration_ms": round_half_even(self.scan_duration_ms, DURATION_DIGITS),
            "total_findings": self.finding_count(),
            "severity_counts": self.severity_counts(),
            "category_counts": self.category_counts(),
            "language_stats": self.language_stats,
            "findings": self.findings.iter().map(Finding::to_json).collect::<Vec<_>>(),
        })
    }

    /// The scan as a SARIF 2.1.0 log for CI systems: one rule per rule id,
    /// described by the first finding that carries it, and one result per
    /// finding.
    pub fn to_sarif(&self) -> Value {
        let mut rules: IndexMap<&str, Value> = IndexMap::new();
        let mut results = Vec::with_capacity(self.findings.len());
        for finding in &self.findings {
            rules.entry(finding.rule_id.as_str()).or_insert_with(|| {
                let mut rule = Map::new();
                rule.insert("id".into(), json!(finding.rule_id));
                rule.insert("name".into(), json!(finding.title));
                rule.insert("shortDescription".into(), json!({ "text": finding.title }));
                rule.insert("fullDescription".into(), json!({ "text": finding.description }));
                rule.insert(
                    "defaultConfiguration".into(),
                    json!({ "level": finding.severity.sarif_level() }),
                );
                if !finding.cwe_id.is_empty() {
                    rule.insert("properties".into(), json!({ "cwe": finding.cwe_id }));
                }
                Value::Object(rule)
            });
            results.push(finding.to_sarif_result());
        }
        json!({
            "$schema": SARIF_SCHEMA,
            "version": SARIF_VERSION,
            "runs": [{
                "tool": {
                    "driver": {
                        "name": NAME,
                        "version": VERSION,
                        "informationUri": INFORMATION_URI,
                        "rules": rules.into_values().collect::<Vec<_>>(),
                    }
                },
                "results": results,
            }]
        })
    }
}
