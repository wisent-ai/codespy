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
finding carries; the JSON report also states `security_score` and
`security_grade`, which the Action publishes as outputs.
