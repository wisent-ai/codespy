//! What the scanner calls itself in the reports it writes.

/// The released version, from Cargo.toml, the one place it is set.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");
/// The tool name SARIF consumers show beside each result.
pub const NAME: &str = "codespy";
/// Where a SARIF consumer sends a reader who wants to know the tool.
pub const INFORMATION_URI: &str = "https://github.com/wisent-ai/codespy";
/// The SARIF format the log follows.
pub const SARIF_VERSION: &str = "2.1.0";
pub const SARIF_SCHEMA: &str =
    "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json";
