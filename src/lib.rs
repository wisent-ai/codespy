//! codespy: an offline code security scanner and quality analyzer.
//!
//! The finding and scan-result model, the rule table, the scanner and the
//! terminal, JSON, SARIF and Markdown reports with the score and grade. The
//! `codespy` binary (`src/main.rs`) is the command line.

pub mod identity;
pub mod model;
pub mod report;
pub mod rules;
pub mod scanner;
