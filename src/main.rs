//! `codespy`: command-line arguments, output selection, and the scan exit
//! status.

mod surface;

use std::io::IsTerminal;
use std::path::PathBuf;
use std::process::ExitCode;

use clap::{ArgAction, CommandFactory, Parser, ValueEnum};

use codespy::model::Severity;
use codespy::report::{format_json, format_markdown, format_sarif, format_terminal};
use codespy::scanner::run_scan;

// The exit statuses, each with one meaning (cli.md rule 10): 0 the scan is
// clean at high and above, 1 it found something at high or above, and these.
/// The invocation is wrong: a path that does not exist, an unknown severity.
const USAGE_EXIT: u8 = 2;
/// The scan could not read everything it selected, so it cannot say clean.
const INCOMPLETE_SCAN_EXIT: u8 = 3;
/// The scan ran but its report could not be written to `--output`.
const REPORT_UNWRITTEN_EXIT: u8 = 4;

#[derive(Clone, Copy, PartialEq, Eq, ValueEnum)]
enum Format {
    Terminal,
    Json,
    Sarif,
    Markdown,
}

#[derive(Parser)]
#[command(
    name = "codespy",
    version,
    disable_version_flag = true,
    about = "Fast offline code security scanner & quality analyzer.",
    after_help = "Exit status: 0 clean at high and above; 1 a high or critical finding; 2 the invocation is wrong; 3 the scan is incomplete; 4 the report could not be written.\nBuilt by Adam (ADAM) — https://github.com/wisent-ai/codespy"
)]
struct Arguments {
    /// Path to scan (file or directory, default: current directory)
    #[arg(default_value = ".")]
    path: PathBuf,
    /// Output format (default: terminal)
    #[arg(long, short = 'f', value_enum, default_value = "terminal")]
    format: Format,
    /// Minimum severity to report: info, low, medium, high, critical
    #[arg(long, short = 's', default_value = "info")]
    severity: String,
    /// Show suggested fixes for each finding
    #[arg(long)]
    fix: bool,
    /// Disable colored output
    #[arg(long)]
    no_color: bool,
    /// Write output to file instead of stdout
    #[arg(long, short = 'o')]
    output: Option<PathBuf>,
    /// Print the version
    #[arg(long, short = 'v', action = ArgAction::Version)]
    version: Option<bool>,
    /// Print the public surface, read against this action manifest, as JSON
    /// for the version gate; nothing is scanned.
    #[arg(long, hide = true, value_name = "ACTION_YML")]
    surface: Option<PathBuf>,
}

/// Print the public surface for the version gate.
fn print_surface(action_manifest: &std::path::Path) -> ExitCode {
    match surface::surface::<Format>(&Arguments::command(), action_manifest) {
        Ok(names) => {
            let document = serde_json::json!({ "surface": names });
            println!("{}", serde_json::to_string_pretty(&document).expect("a JSON value always serializes"));
            ExitCode::SUCCESS
        }
        Err(error) => {
            eprintln!("Error: cannot read {}: {error}", action_manifest.display());
            ExitCode::FAILURE
        }
    }
}

/// The minimum severity a `--severity` value names.
fn parse_severity(value: &str) -> Result<Severity, String> {
    let wanted = value.trim().to_lowercase();
    Severity::ALL.into_iter().find(|severity| severity.as_str() == wanted).ok_or_else(|| {
        let names: Vec<&str> = Severity::ALL.iter().map(|severity| severity.as_str()).collect();
        format!("Invalid severity: {wanted}. Choose from: {}", names.join(", "))
    })
}

fn main() -> ExitCode {
    let arguments = Arguments::parse();
    if let Some(action_manifest) = &arguments.surface {
        return print_surface(action_manifest);
    }
    if !arguments.path.exists() {
        eprintln!("Error: Path '{}' does not exist.", arguments.path.display());
        return ExitCode::from(USAGE_EXIT);
    }
    let min_severity = match parse_severity(&arguments.severity) {
        Ok(severity) => severity,
        Err(message) => {
            eprintln!("Error: {message}");
            return ExitCode::from(USAGE_EXIT);
        }
    };
    let result = match run_scan(&arguments.path, min_severity) {
        Ok(result) => result,
        Err(error) => {
            // Not 1: that status means "findings at high or above", and a scan
            // that could not read part of the tree has not found that it is clean.
            eprintln!("Error: the scan is incomplete: {error}");
            return ExitCode::from(INCOMPLETE_SCAN_EXIT);
        }
    };

    let use_color = !arguments.no_color
        && arguments.format == Format::Terminal
        && std::io::stdout().is_terminal();
    let output = match arguments.format {
        Format::Json => format_json(&result),
        Format::Sarif => format_sarif(&result),
        Format::Markdown => format_markdown(&result, arguments.fix),
        Format::Terminal => format_terminal(&result, arguments.fix, use_color),
    };

    match &arguments.output {
        Some(file) => {
            if let Err(error) = std::fs::write(file, &output) {
                eprintln!("Error: cannot write {}: {error}", file.display());
                return ExitCode::from(REPORT_UNWRITTEN_EXIT);
            }
            println!("Report written to {}", file.display());
        }
        None => println!("{output}"),
    }

    // A critical or high finding fails the run, which is what a CI step reads.
    let blocking = result.findings.iter().any(|finding| finding.severity >= Severity::High);
    if blocking { ExitCode::FAILURE } else { ExitCode::SUCCESS }
}
