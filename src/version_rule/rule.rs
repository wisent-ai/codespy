//! The fleet's versioning rule (github.com/lbartoszcze/AutoVersion, SPEC.md at
//! v0.1.0): given the published version, the published surface and the
//! candidate surface, what kind of change this is and what the next version
//! is. The SPEC keeps one small implementation per consumer, held identical by
//! its shared fixtures (brama, jeden and oko carry theirs); `codespy
//! --version-rule conformance` runs those fixtures against this port, and the
//! release gate runs it before it trusts a verdict from it.

use std::cmp::Ordering;
use std::collections::BTreeSet;
use std::fmt;

/// The value a version slot resets to when a higher slot advances, and the
/// value of an unstable major (SPEC.md, "What moves").
const SLOT_RESET: u64 = 0;
/// How far one change advances one slot (SPEC.md, "What moves").
const SLOT_STEP: u64 = 1;

/// A refusal, named the way the rule's fixtures name it.
#[derive(Debug)]
pub(crate) struct Refusal {
    pub(crate) name: &'static str,
    pub(crate) message: String,
}

impl fmt::Display for Refusal {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "refused ({}): {}", self.name, self.message)
    }
}

fn refuse(name: &'static str, message: String) -> Refusal {
    Refusal { name, message }
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum Change {
    Breaking,
    Additive,
    Internal,
}

impl Change {
    pub(crate) fn name(self) -> &'static str {
        match self {
            Self::Breaking => "breaking",
            Self::Additive => "additive",
            Self::Internal => "internal",
        }
    }
}

struct Version {
    major: u64,
    minor: u64,
    patch: u64,
}

impl fmt::Display for Version {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}.{}.{}", self.major, self.minor, self.patch)
    }
}

/// A segment that survives a URL path and a filesystem key unchanged.
fn canonical(value: &str) -> bool {
    !value.is_empty()
        && value.trim() == value
        && value
            .chars()
            .all(|character| character.is_ascii_alphanumeric() || "._-".contains(character))
}

impl Version {
    fn parse(value: &str) -> Result<Self, Refusal> {
        if !canonical(value) {
            return Err(refuse(
                "not-canonical",
                format!("{value:?} is not a canonical coordinate: expected a non-empty segment of alphanumerics, '.', '_' and '-', with no surrounding whitespace"),
            ));
        }
        let slots = value.split('.').collect::<Vec<_>>();
        let [major, minor, patch] = slots.as_slice() else {
            return Err(refuse(
                "not-a-triple",
                format!("{value:?} is not a major.minor.patch triple, so there is no slot to advance; name the next version explicitly"),
            ));
        };
        let numeric = |slot: &str| {
            (!slot.is_empty() && slot.bytes().all(|byte| byte.is_ascii_digit()))
                .then(|| slot.parse::<u64>().ok())
                .flatten()
        };
        match (numeric(major), numeric(minor), numeric(patch)) {
            (Some(major), Some(minor), Some(patch)) => Ok(Self { major, minor, patch }),
            _ => Err(refuse(
                "not-numeric",
                format!("{value:?} has a non-numeric slot, so advancing it would invent an ordering; name the next version explicitly"),
            )),
        }
    }

    /// The version this change produces. While the major slot is zero, the
    /// minor slot carries compatibility.
    fn advance(&self, change: Change) -> Self {
        let (major, minor, patch) = match (change, self.major == SLOT_RESET) {
            (Change::Breaking, true) => (self.major, self.minor + SLOT_STEP, SLOT_RESET),
            (Change::Breaking, false) => (self.major + SLOT_STEP, SLOT_RESET, SLOT_RESET),
            (Change::Additive, false) => (self.major, self.minor + SLOT_STEP, SLOT_RESET),
            _ => (self.major, self.minor, self.patch + SLOT_STEP),
        };
        Self {
            major,
            minor,
            patch,
        }
    }
}

pub(crate) struct Decision {
    pub(crate) current: String,
    pub(crate) change: Change,
    pub(crate) next: String,
    pub(crate) removed: Vec<String>,
    pub(crate) added: Vec<String>,
}

fn surface(names: &[String], side: &str) -> Result<BTreeSet<String>, Refusal> {
    let collected = names.iter().cloned().collect::<BTreeSet<_>>();
    if collected.is_empty() {
        return Err(refuse(
            "empty-surface",
            format!("the {side} surface is empty, which is far more likely to be a broken extractor than a product that promises nothing"),
        ));
    }
    Ok(collected)
}

/// The whole answer. A declared break may only escalate the class.
pub(crate) fn decide(
    current: &str,
    published: &[String],
    candidate: &[String],
    declared_breaking: bool,
) -> Result<Decision, Refusal> {
    let version = Version::parse(current)?;
    let before = surface(published, "published")?;
    let after = surface(candidate, "candidate")?;
    let removed = before.difference(&after).cloned().collect::<Vec<_>>();
    let added = after.difference(&before).cloned().collect::<Vec<_>>();
    let change = if declared_breaking || !removed.is_empty() {
        Change::Breaking
    } else if !added.is_empty() {
        Change::Additive
    } else {
        Change::Internal
    };
    Ok(Decision {
        current: version.to_string(),
        change,
        next: version.advance(change).to_string(),
        removed,
        added,
    })
}

/// One token of a coordinate being ordered: numbers sort before words, and
/// numbers compare as numbers.
#[derive(PartialEq, Eq, PartialOrd, Ord)]
enum Token<'a> {
    Number(u128),
    Word(&'a str),
}

/// Split on '.' and '-'. Ordering works on coordinates that are not triples,
/// because a version that can never be advanced can still be compared.
fn tokens(value: &str) -> Vec<Token<'_>> {
    value
        .split(['.', '-'])
        .map(|token| {
            token
                .parse::<u128>()
                .map_or(Token::Word(token), Token::Number)
        })
        .collect()
}

/// True when `newer` sorts strictly after `older`.
pub(crate) fn newer(older: &str, newer: &str) -> bool {
    tokens(older).cmp(&tokens(newer)) == Ordering::Less
}
