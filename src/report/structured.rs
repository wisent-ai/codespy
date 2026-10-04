//! JSON and SARIF reports for other tools to read.

use std::fmt::Write;

use serde_json::Value;

use crate::model::ScanResult;

use super::ScoringReport;

/// The first code point JSON writes as an escape rather than as itself.
const FIRST_NON_ASCII: u32 = 0x80;

/// Format findings with the supplied policy and assessment, or the reason
/// no score was produced. The Action preserves unavailable scores as null.
pub fn format_json(result: &ScanResult, scoring: &ScoringReport<'_>) -> String {
    let mut document = result.to_json();
    document["security_score"] = serde_json::json!(scoring.score);
    document["security_grade"] = serde_json::json!(scoring.grade);
    document["scoring"] = serde_json::json!(scoring);
    pretty_ascii(&document)
}

/// Format scan results as SARIF 2.1.0.
pub fn format_sarif(result: &ScanResult, scoring: &ScoringReport<'_>) -> String {
    let mut document = result.to_sarif();
    document["runs"][0]["properties"] = serde_json::json!({ "scoring": scoring });
    pretty_ascii(&document)
}

/// Two-space indented JSON with every character outside ASCII escaped as
/// `\uXXXX`, the byte form every published report has had, so a report
/// consumer that compares bytes sees the same file.
fn pretty_ascii(value: &Value) -> String {
    let pretty = serde_json::to_string_pretty(value).expect("a JSON value always serializes");
    // Outside ASCII a character can only occur inside a string literal, where
    // its escape means the same text.
    let mut escaped = String::with_capacity(pretty.len());
    let mut units = [0u16; 2];
    for character in pretty.chars() {
        if (character as u32) < FIRST_NON_ASCII {
            escaped.push(character);
            continue;
        }
        for unit in character.encode_utf16(&mut units) {
            write!(escaped, "\\u{unit:04x}").expect("writing to a String cannot fail");
        }
    }
    escaped
}
