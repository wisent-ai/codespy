//! Severities, categories, findings, and the scan result reports are written
//! from.

mod finding;
mod scan_result;

pub use finding::{Confidence, Finding};
pub use scan_result::{LanguageStats, ScanResult};

/// How much a finding matters, least first: the declaration order is the
/// order a threshold compares against.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, serde::Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

impl Severity {
    /// Every severity, least first, as a report lists them.
    pub const ALL: [Severity; 5] = [
        Severity::Info,
        Severity::Low,
        Severity::Medium,
        Severity::High,
        Severity::Critical,
    ];

    /// The name reports and configuration files use.
    pub fn as_str(self) -> &'static str {
        match self {
            Severity::Info => "info",
            Severity::Low => "low",
            Severity::Medium => "medium",
            Severity::High => "high",
            Severity::Critical => "critical",
        }
    }

    /// The SARIF level a CI system reads: critical and high fail a build,
    /// medium warns, the rest are notes.
    pub fn sarif_level(self) -> &'static str {
        match self {
            Severity::Critical | Severity::High => "error",
            Severity::Medium => "warning",
            Severity::Low | Severity::Info => "note",
        }
    }
}

/// What kind of problem a finding is.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, serde::Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Category {
    Security,
    Secret,
    Injection,
    Quality,
    Performance,
    Deprecation,
    Configuration,
    SupplyChain,
}

impl Category {
    /// The name reports use.
    pub fn as_str(self) -> &'static str {
        match self {
            Category::Security => "security",
            Category::Secret => "secret",
            Category::Injection => "injection",
            Category::Quality => "quality",
            Category::Performance => "performance",
            Category::Deprecation => "deprecation",
            Category::Configuration => "configuration",
            Category::SupplyChain => "supply-chain",
        }
    }
}
