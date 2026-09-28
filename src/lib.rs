//! codespy: an offline code security scanner and quality analyzer.
//!
//! The Rust port of `codespy_core`. Ported so far: the finding and scan
//! result model, the rule table, the scanner, and the JSON and SARIF reports.
//! The terminal and Markdown reports, scoring and the command line still run
//! from `codespy_core` until their ports land here.

pub mod identity;
pub mod model;
pub mod report;
pub mod rules;
pub mod scanner;
