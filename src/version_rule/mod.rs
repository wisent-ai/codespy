//! `codespy --version-rule …`: the fleet's versioning rule, carried by the
//! released binary so the release gate asks the build it is judging instead of
//! installing a separate program. Every answer is JSON on stdout; a refusal
//! names the rule's refusal on stderr and exits 1.
//!
//! * `decide --current V --published-surface F --candidate-surface F
//!   [--breaking]` — the change class and the next version.
//! * `order --older V --newer V` — whether the second sorts after the first.
//! * `conformance --fixtures F` — every case of AutoVersion's FIXTURES.md.

mod rule;

use std::path::{Path, PathBuf};
use std::process::ExitCode;

use clap::{Parser, Subcommand};
use serde_json::{json, Value};

/// The flag that selects this command; the scan's own arguments follow clap.
pub(crate) const FLAG: &str = "--version-rule";

#[derive(Parser)]
#[command(name = "codespy --version-rule", about = "The fleet's versioning rule (AutoVersion SPEC v0.1.0).")]
struct RuleArguments {
    #[command(subcommand)]
    command: RuleCommand,
}

#[derive(Subcommand)]
enum RuleCommand {
    /// Classify the change between two surface documents and name the next version
    Decide {
        /// The published version
        #[arg(long)]
        current: String,
        /// `{"surface": [...]}` as released
        #[arg(long)]
        published_surface: PathBuf,
        /// `{"surface": [...]}` as proposed
        #[arg(long)]
        candidate_surface: PathBuf,
        /// Declare breakage the surface cannot show; escalates only
        #[arg(long)]
        breaking: bool,
    },
    /// Whether NEWER sorts strictly after OLDER
    Order {
        #[arg(long)]
        older: String,
        #[arg(long)]
        newer: String,
    },
    /// Reproduce every case of AutoVersion's FIXTURES.md with this port
    Conformance {
        #[arg(long)]
        fixtures: PathBuf,
    },
}

fn read_surface(path: &Path) -> Result<Vec<String>, String> {
    let text = std::fs::read_to_string(path).map_err(|error| format!("{}: {error}", path.display()))?;
    let document: Value =
        serde_json::from_str(&text).map_err(|error| format!("{}: not JSON: {error}", path.display()))?;
    let names = document["surface"].as_array().ok_or(format!(
        "{}: no \"surface\" list. A surface document is {{\"surface\": [\"name\", ...]}}",
        path.display()
    ))?;
    names
        .iter()
        .map(|name| {
            name.as_str()
                .map(str::to_owned)
                .ok_or(format!("{}: a surface name is not a string: {name}", path.display()))
        })
        .collect()
}

fn names(value: &Value) -> Vec<String> {
    value
        .as_array()
        .map(|items| items.iter().filter_map(Value::as_str).map(str::to_owned).collect())
        .unwrap_or_default()
}

/// The JSON between the first pair of ``` fences of FIXTURES.md, or the whole
/// text when it is already JSON.
fn cases(text: &str) -> Result<Value, String> {
    if let Ok(value) = serde_json::from_str(text) {
        return Ok(value);
    }
    let block = text
        .split("```")
        .nth(1)
        .ok_or("the fixtures file has no fenced block")?;
    let body = block.split_once('\n').map_or(block, |(_, rest)| rest);
    serde_json::from_str(body).map_err(|error| format!("the fenced fixtures are not JSON: {error}"))
}

fn group<'a>(fixtures: &'a Value, name: &str) -> Result<&'a Vec<Value>, String> {
    fixtures[name]
        .as_array()
        .ok_or(format!("the fixtures declare no `{name}` list"))
}

/// Every case of the four groups; one line per disagreement, then a count.
fn conformance(text: &str) -> Result<bool, String> {
    let fixtures = cases(text)?;
    let mut failures = Vec::new();
    let mut total = 0usize;
    for (name, expect_refusal) in [("classify", false), ("refuse", true)] {
        for case in group(&fixtures, name)? {
            total += 1;
            let observed = match rule::decide(
                case["current"].as_str().unwrap_or_default(),
                &names(&case["published"]),
                &names(&case["candidate"]),
                case["declared_breaking"].as_bool().unwrap_or_default() && !expect_refusal,
            ) {
                Ok(answer) => json!({
                    "class": answer.change.name(), "next": answer.next,
                    "removed": answer.removed, "added": answer.added,
                }),
                Err(refusal) => json!({ "refusal": refusal.name }),
            };
            if observed != case["expect"] {
                failures.push(format!("{name} {}: expected {}, observed {observed}", case["name"], case["expect"]));
            }
        }
    }
    for case in group(&fixtures, "order")? {
        total += 1;
        let (older, newer) = (case["older"].as_str().unwrap_or_default(), case["newer"].as_str().unwrap_or_default());
        if !rule::newer(older, newer) || rule::newer(newer, older) {
            failures.push(format!("order {}: {newer:?} is not strictly after {older:?}", case["name"]));
        }
    }
    for case in group(&fixtures, "order_equal")? {
        total += 1;
        let (left, right) = (case["left"].as_str().unwrap_or_default(), case["right"].as_str().unwrap_or_default());
        if rule::newer(left, right) {
            failures.push(format!("order_equal {}: a version outranked itself", case["name"]));
        }
    }
    for failure in &failures {
        println!("FAIL {failure}");
    }
    println!("{} of {total} fixture case(s) reproduced", total - failures.len());
    Ok(failures.is_empty())
}

fn dispatch(command: RuleCommand) -> Result<bool, String> {
    match command {
        RuleCommand::Decide { current, published_surface, candidate_surface, breaking } => {
            let published = read_surface(&published_surface)?;
            let candidate = read_surface(&candidate_surface)?;
            let answer = rule::decide(&current, &published, &candidate, breaking).map_err(|refusal| refusal.to_string())?;
            println!(
                "{}",
                json!({
                    "current": answer.current, "change": answer.change.name(), "next": answer.next,
                    "removed": answer.removed, "added": answer.added,
                })
            );
            Ok(true)
        }
        RuleCommand::Order { older, newer } => {
            let is_newer = rule::newer(&older, &newer);
            println!("{}", json!({ "older": older, "newer": newer, "is_newer": is_newer }));
            Ok(true)
        }
        RuleCommand::Conformance { fixtures } => {
            let text = std::fs::read_to_string(&fixtures).map_err(|error| format!("{}: {error}", fixtures.display()))?;
            conformance(&text)
        }
    }
}

/// Run `codespy --version-rule <arguments>`.
pub(crate) fn run(arguments: impl Iterator<Item = std::ffi::OsString>) -> ExitCode {
    let parsed = RuleArguments::parse_from(std::iter::once(FLAG.into()).chain(arguments));
    match dispatch(parsed.command) {
        Ok(true) => ExitCode::SUCCESS,
        Ok(false) => ExitCode::FAILURE,
        Err(message) => {
            eprintln!("codespy --version-rule: {message}");
            ExitCode::FAILURE
        }
    }
}
