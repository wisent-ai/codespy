//! The public surface: what a codespy user would notice disappearing, printed
//! for the version gate to compare against `released-surface.json`.
//!
//! Nine things are observable, each written down somewhere outside this
//! repository: rule ids (`rule:`), the categories rules emit (`category:`),
//! severities (`severity:`), `language_stats` keys (`language:`), the file
//! suffixes that get opened at all (`ext:`), `--format` choices (`format:`),
//! every option string and positional of the command line (`cli:`), and the
//! inputs and outputs of `action.yml` (`action-input:`, `action-output:`).
//! Patterns, suggestions, CWE ids and per-rule language scoping change what a
//! rule finds, not what it promises, and are left out.
//!
//! Everything comes from the running program itself: its rule table, its
//! file-type table and its own argument declaration; only the action manifest
//! is read from disk.

use std::collections::BTreeSet;
use std::io;
use std::path::Path;

use clap::{Command, ValueEnum};

use codespy::model::Severity;
use codespy::rules::rules;
use codespy::scanner::scanned_suffixes;

/// The two manifest sections callers address, and the prefix each is named by.
const ACTION_SECTIONS: [(&str, &str); 2] = [("inputs:", "action-input"), ("outputs:", "action-output")];
/// The indentation of a key directly under a top-level manifest section.
const SECTION_KEY_INDENT: &str = "  ";

/// The keys declared directly under each of `action.yml`'s `inputs:` and
/// `outputs:` sections.
fn action_keys(manifest: &str) -> Vec<String> {
    let mut keys = Vec::new();
    let mut section: Option<&str> = None;
    for line in manifest.lines() {
        if !line.starts_with(' ') && !line.trim().is_empty() {
            section = ACTION_SECTIONS.iter().find(|(heading, _)| line.trim_end() == *heading).map(|(_, prefix)| *prefix);
            continue;
        }
        let Some(prefix) = section else { continue };
        let Some(rest) = line.strip_prefix(SECTION_KEY_INDENT) else { continue };
        if rest.starts_with(' ') {
            continue;
        }
        if let Some(key) = rest.trim_end().strip_suffix(':') {
            keys.push(format!("{prefix}:{key}"));
        }
    }
    keys
}

/// Every option string and positional a script can invoke, hidden ones left
/// out; the help flag is clap's own and not part of the vocabulary.
fn cli_vocabulary(command: &Command) -> Vec<String> {
    let mut words = Vec::new();
    for argument in command.get_arguments() {
        if argument.is_hide_set() || argument.get_id() == "help" {
            continue;
        }
        if argument.is_positional() {
            words.push(format!("cli:{}", argument.get_id()));
            continue;
        }
        if let Some(long) = argument.get_long() {
            words.push(format!("cli:--{long}"));
        }
        if let Some(short) = argument.get_short() {
            words.push(format!("cli:-{short}"));
        }
    }
    words
}

/// The whole surface, namespaced and sorted, for a program whose arguments
/// are `command`, whose formats are `F`, and whose action manifest is at
/// `action_manifest`.
pub fn surface<F: ValueEnum>(command: &Command, action_manifest: &Path) -> io::Result<Vec<String>> {
    let manifest = std::fs::read_to_string(action_manifest)?;
    let mut names = BTreeSet::new();
    for rule in rules() {
        names.insert(format!("rule:{}", rule.id));
        names.insert(format!("category:{}", rule.category.as_str()));
    }
    names.extend(Severity::ALL.iter().map(|severity| format!("severity:{}", severity.as_str())));
    for (language, suffixes) in scanned_suffixes() {
        names.insert(format!("language:{language}"));
        names.extend(suffixes.iter().map(|suffix| format!("ext:{suffix}")));
    }
    for format in F::value_variants() {
        if let Some(value) = format.to_possible_value() {
            names.insert(format!("format:{}", value.get_name()));
        }
    }
    names.extend(cli_vocabulary(command));
    names.extend(action_keys(&manifest));
    Ok(names.into_iter().collect())
}
