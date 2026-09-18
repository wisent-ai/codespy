# Development

`codespy.py` is the release: one file to download, read, and run. It is rendered
from the package rather than edited by hand, so the source stays readable:

```text
codespy_core/            scanner source
  configuration.py       version, scanned file types, size limit
  models.py              severities, categories, findings, scan result
  rules/                 detection families; rules/__init__.py fixes their order
  scanner.py             file collection and rule evaluation
  reporting/             terminal, JSON, SARIF, Markdown, score
  cli.py                 arguments, output selection, exit status
tools/build_codespy.py   renders codespy.py from codespy_core
tests/                   run.py plus one folder per area
.github/version-check/   the version gate's steps as scripts a laptop can run
```

```bash
python3 tools/build_codespy.py          # rewrite codespy.py after editing the package
python3 tools/build_codespy.py --check  # what CI runs; fails when codespy.py is stale
python3 tests/run.py                    # every area
python3 tests/run.py cli/commands       # one area
```

Rule order is part of the contract, because findings of equal severity, file and
line keep it. `codespy_core/rules/__init__.py` declares that order once, and both
the package and the rendered release read it from there.

The `cli/commands` area runs the released file as a separate process and reads
the reports it writes, so exit statuses and refusals are covered by tests rather
than by description. `tests/surface.py` prints the public contract that the
version gate compares against `released-surface.json`. The gate's own steps
live in `.github/version-check/` (`install-rule.sh`, `prove-refusal.sh`,
`compare.sh`, `verify-baseline.sh`) and take `RUNNER_TEMP` from the
environment, so `RUNNER_TEMP=build/tmp bash .github/version-check/compare.sh`
runs the same comparison locally. In every report, `severity_counts` names all
five severities, with `0` for the ones no finding carries.
