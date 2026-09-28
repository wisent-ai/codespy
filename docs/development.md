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
.github/version-check/   the version gate's steps as scripts a laptop can run
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

The gate's own steps live in `.github/version-check/` (`install-rule.sh`,
`prove-refusal.sh`, `compare.sh`, `verify-baseline.sh`, `baseline.sh`) and take
`RUNNER_TEMP` from the environment, so
`RUNNER_TEMP=build/tmp bash .github/version-check/compare.sh` runs the same
comparison locally. `baseline.sh` regenerates `released-surface.json` from the
best published artifact; releases from before the Rust port (the `codespy.py`
tags) are read from the surface the baseline already records for them. In every
report, `severity_counts` names all five severities, with `0` for the ones no
finding carries; the JSON report also states `security_score` and
`security_grade`, which the Action publishes as outputs.
