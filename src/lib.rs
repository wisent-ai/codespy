//! codespy: an offline code security scanner and quality analyzer.
//!
//! The Rust port of `codespy_core`. Ported so far: the finding and scan
//! result model and the JSON and SARIF reports. The rules, the scanner, the
//! terminal and Markdown reports and the command line still run from
//! `codespy_core` until their ports land here.

pub mod identity;
pub mod model;
pub mod report;
