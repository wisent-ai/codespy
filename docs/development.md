# Development

`codespy` is one Rust program. The GitHub Action builds it from the pinned ref
with `cargo install --path`, and the fleet release reads its version from
`Cargo.toml`.

```text
src/
  main.rs                arguments, output selection, exit status
  surface.rs             the public surface the version gate compares (--surface)
  identity.rs            name, version, SARIF identity
  model/                 severities, categories, findings, scan result
  rules/table.json       the rule catalogue, in released order
  rules/mod.rs           loads the table and compiles each pattern
  scanner/               file collection, the file-type table, rule evaluation
  report/                terminal, JSON, SARIF, Markdown, score and grade
release/gate.sh          the version gate, run by the release after its build
release/version-check/rule/      asking the rule: prove-rule.sh, compare.sh, newer.sh
release/version-check/baseline/  the baseline and its provenance checks
```

Rule order is part of the contract, because findings of equal severity, file and
line keep it. `src/rules/table.json` lists the rules in that order, and the
scanner evaluates them in the order they are listed. Patterns are matched
case-insensitively with `^` and `$` at line boundaries, with lookaround
available, as the rules were written for.

`codespy --surface action.yml` prints the public contract that the version gate
compares against `released-surface.json`: rule ids, the categories rules emit,
severities, languages, scanned suffixes, formats, the command line and the
action's inputs and outputs. It reads them from the program itself, so the
surface is the one the binary actually has.

The version gate runs in the release, not per push: `.wisent-release.json`
builds `codespy` once and then runs `release/gate.sh`, which reads that built
binary's `--surface` and asks Stado's one port of the fleet's versioning rule
(`stado release version-gate decide|conformance|semver-at-least`, AutoVersion
SPEC v0.1.0); codespy carries no copy of the rule. `prove-rule.sh` first
requires that port to reproduce every case of the SPEC's pinned FIXTURES.md
and to answer `internal` for the committed surface against itself and
`breaking` with one name removed; `compare.sh` then checks the declared
version against the change, and `newer.sh` answers every ordering question.
The steps live in `release/version-check/rule/` (`prove-rule.sh`,
`compare.sh`, `newer.sh`) and `release/version-check/baseline/`
(`verify-baseline.sh`, `verify-provenance.sh`, `baseline.sh`), with scratch in
`target/version-gate`.
Where the baseline's provenance is checked depends on where the gate runs. In a
checkout, `verify-baseline.sh` reads tags and history itself. A release worker
runs the gate in an unpacked archive without `.git`; there
`verify-provenance.sh` reads `.wisent-provenance/baseline.json`, which
`stado release build submit` writes after checking the baseline tag against
origin. It refuses when the record is missing, describes another revision
than `WISENT_SOURCE_COMMIT`, names another marker than `released-surface.json`,
or lists a full-version tag newer than the baseline. No second checkout is made.
`baseline.sh` regenerates `released-surface.json` from the
best published artifact; releases from before the Rust port (the `codespy.py`
tags) are read from the surface the baseline already records for them. In every
report, `severity_counts` names all five severities, with `0` for the ones no
finding carries. JSON `security_score` and `security_grade` are nullable; the
Action preserves unavailable values as `null` rather than reporting a clean
score. The `scoring` object contains the exact supplied policy and any reason
that scoring was unavailable; SARIF includes it in `runs[].properties`.

## Scoring policy

Scanning has no file-size exclusion. Known directory exclusions and supported
language selection still apply. Reading a selected file can fail with exit 3;
it is never silently excluded because it exceeds a byte limit.

Scoring is optional and never changes the finding-based exit status.
`codespy . --format json --scoring-policy policy.json --output report.json`
reads the supplied policy before scanning. Without that flag, reports contain
findings and explain that no scoring policy was supplied. An empty scan has no
score even when a policy is supplied. No default policy file is installed.

The JSON object requires all of these fields; unknown fields are refused:

| Field | Meaning and constraint |
|---|---|
| `top_score` | positive finite maximum score |
| `lines_per_size_unit` | positive finite number of scanned lines per size unit |
| `leniency_per_size_unit` | finite nonnegative reduction factor; zero disables size leniency |
| `minimum_size_factor` | finite nonnegative floor on size units |
| `deductions` | finite nonnegative weights for each of `critical`, `high`, `medium`, `low`, `info` |
| `grades` | descending `{ "floor": number, "label": text }` entries covering the score range; the final floor is zero |

The formula is `top_score - sum(deductions) / (1 + size * leniency)`, where
`size = max(lines_scanned / lines_per_size_unit, minimum_size_factor)`.
The result is rounded to the nearest integer, halves to even, then clamped
between zero and `top_score`. The first grade whose floor the score meets wins.
Grade floors cannot repeat or exceed the maximum. Labels must be nonempty
single-line text without control characters.

This example is an input illustration, **not a recommended security policy**:

```json
{
  "top_score": 20,
  "lines_per_size_unit": 1,
  "leniency_per_size_unit": 0,
  "minimum_size_factor": 0,
  "deductions": {"critical": 10, "high": 4, "medium": 2, "low": 1, "info": 0},
  "grades": [{"floor": 16, "label": "review"}, {"floor": 0, "label": "investigate"}]
}
```

With that policy, one high finding scores 16 and receives `review`, regardless
of repository size. Its process exit status is still 1. Every report records
all policy values so that the score is interpretable without the input file.
Terminal and Markdown reports display them; the Action summary does too.
The Action's optional `scoring-policy` input passes the same file to both its
machine report and the selected report format.

An unreadable file, malformed JSON, missing field, invalid bound or invalid
grade sequence is an invocation error (exit 2) naming the policy file and the
cause. Arithmetic overflow refuses scoring with exit 2 instead of emitting an
invented score. The Action retains those diagnostics and fails without a
successful report. It never substitutes zero or the maximum for an absent score.

## Scan-policy regression journeys

`cargo test --test scan-policy` runs the real CLI on isolated source files under
`target/scan-policy/`. It covers a finding beyond the former byte ceiling,
operator-weighted scores and grade boundaries, unavailable scores, policy
refusals, and each report format. Input files are removed after each case;
commands, exit statuses, stdout, stderr, reports and the source revision remain
in that run's evidence directory. This is a local offline scanner: the actual
dependencies are its filesystem and compiled rule catalogue, not a provider
simulation. A source change without this run is not a passed qualification.
