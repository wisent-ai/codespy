//! One problem found on one line, and the two ways a report writes it.

use serde_json::{json, Map, Value};

use super::{Category, Severity};

/// How sure the rule is that the line is a real problem.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Confidence {
    High,
    Medium,
    Low,
}

impl Confidence {
    pub fn as_str(self) -> &'static str {
        match self {
            Confidence::High => "high",
            Confidence::Medium => "medium",
            Confidence::Low => "low",
        }
    }
}

/// One problem a rule found, at one line of one file.
#[derive(Clone, Debug, PartialEq)]
pub struct Finding {
    pub rule_id: String,
    pub title: String,
    pub description: String,
    pub severity: Severity,
    pub category: Category,
    pub file_path: String,
    pub line_number: usize,
    pub line_content: String,
    /// How to fix it; empty when the rule gives no advice.
    pub suggestion: String,
    /// The CWE the problem is an instance of; empty when none applies.
    pub cwe_id: String,
    pub confidence: Confidence,
}

impl Finding {
    /// The finding as the JSON report writes it. `cwe_id` appears only when
    /// the rule names one, and the line is written without its indentation.
    pub fn to_json(&self) -> Value {
        let mut map = Map::new();
        map.insert("rule_id".into(), json!(self.rule_id));
        map.insert("title".into(), json!(self.title));
        map.insert("description".into(), json!(self.description));
        map.insert("severity".into(), json!(self.severity.as_str()));
        map.insert("category".into(), json!(self.category.as_str()));
        map.insert("file_path".into(), json!(self.file_path));
        map.insert("line_number".into(), json!(self.line_number));
        map.insert("line_content".into(), json!(self.line_content.trim()));
        map.insert("suggestion".into(), json!(self.suggestion));
        map.insert("confidence".into(), json!(self.confidence.as_str()));
        if !self.cwe_id.is_empty() {
            map.insert("cwe_id".into(), json!(self.cwe_id));
        }
        Value::Object(map)
    }

    /// The finding as one SARIF 2.1.0 result. A suggestion becomes the
    /// result's fix description.
    pub fn to_sarif_result(&self) -> Value {
        let mut result = Map::new();
        result.insert("ruleId".into(), json!(self.rule_id));
        result.insert("level".into(), json!(self.severity.sarif_level()));
        result.insert("message".into(), json!({ "text": self.description }));
        result.insert(
            "locations".into(),
            json!([{
                "physicalLocation": {
                    "artifactLocation": { "uri": self.file_path },
                    "region": { "startLine": self.line_number }
                }
            }]),
        );
        if !self.suggestion.is_empty() {
            result.insert(
                "fixes".into(),
                json!([{ "description": { "text": self.suggestion } }]),
            );
        }
        Value::Object(result)
    }
}
