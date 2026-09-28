//! The detection rules: one table of data, in the released order.
//!
//! Rule order is part of what the tool promises: findings of equal severity,
//! file and line keep it, so reports stay stable between runs. The table is
//! data (`table.json`), read once; each pattern is matched case-insensitively
//! with `^` and `$` at line boundaries, as the rules were written for.

use std::sync::LazyLock;

use fancy_regex::Regex;
use serde::Deserialize;

use crate::model::{Category, Confidence, Severity};

/// The released rule table.
const TABLE: &str = include_str!("table.json");
/// Case-insensitive, and `^`/`$` match at every line.
const MATCH_FLAGS: &str = "(?im)";

/// One rule as the table declares it.
#[derive(Debug, Deserialize)]
struct Declared {
    id: String,
    title: String,
    pattern: String,
    severity: Severity,
    category: Category,
    description: String,
    suggestion: String,
    cwe: String,
    languages: Option<Vec<String>>,
    confidence: Confidence,
}

/// One rule, its pattern compiled.
#[derive(Debug)]
pub struct Rule {
    pub id: String,
    pub title: String,
    pub pattern: Regex,
    pub severity: Severity,
    pub category: Category,
    pub description: String,
    pub suggestion: String,
    pub cwe_id: String,
    /// The languages the rule reads; `None` reads every language.
    pub languages: Option<Vec<String>>,
    pub confidence: Confidence,
}

impl Rule {
    /// Whether the rule reads files of `language`.
    pub fn applies_to(&self, language: &str) -> bool {
        self.languages
            .as_ref()
            .is_none_or(|languages| languages.iter().any(|name| name == language))
    }
}

fn load() -> Vec<Rule> {
    let declared: Vec<Declared> =
        serde_json::from_str(TABLE).expect("the released rule table is valid JSON");
    declared
        .into_iter()
        .map(|rule| {
            let pattern = Regex::new(&format!("{MATCH_FLAGS}{}", rule.pattern))
                .unwrap_or_else(|error| panic!("rule {} does not compile: {error}", rule.id));
            Rule {
                id: rule.id,
                title: rule.title,
                pattern,
                severity: rule.severity,
                category: rule.category,
                description: rule.description,
                suggestion: rule.suggestion,
                cwe_id: rule.cwe,
                languages: rule.languages,
                confidence: rule.confidence,
            }
        })
        .collect()
}

/// Every released rule, in released order.
pub fn rules() -> &'static [Rule] {
    &RULES
}

static RULES: LazyLock<Vec<Rule>> = LazyLock::new(load);
