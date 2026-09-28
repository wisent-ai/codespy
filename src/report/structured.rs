//! JSON and SARIF reports for other tools to read.

use std::fmt::Write;

use serde_json::Value;

use crate::model::ScanResult;

use super::{compute_score, score_to_grade};

/// The first code point JSON writes as an escape rather than as itself.
const FIRST_NON_ASCII: u32 = 0x80;

/// Format scan results as JSON. The score and grade close the document: the
/// GitHub Action reads them for its `security-score` and `security-grade`
/// outputs, which had no source before and always read 100 and A+.
pub fn format_json(result: &ScanResult) -> String {
    let mut document = result.to_json();
    let score = compute_score(result);
    document["security_score"] = score.into();
    document["security_grade"] = score_to_grade(score).into();
    pretty_ascii(&document)
}

/// Format scan results as SARIF 2.1.0.
pub fn format_sarif(result: &ScanResult) -> String {
    pretty_ascii(&result.to_sarif())
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
