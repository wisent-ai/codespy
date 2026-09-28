#!/usr/bin/env bash
# The rule is the fleet's AutoVersion SPEC, answered by Stado's one port of it
# (`stado release version-gate`), which every release worker carries; codespy
# keeps no copy. Before any verdict below is trusted, that port must reproduce
# every case of the SPEC's pinned FIXTURES.md, and then give two DIFFERENT
# known answers on the committed baseline: one answer cannot be enough,
# because a rule that always says `internal` passes a single-answer probe AND
# the comparison, since with the declared version equal to the released one
# `internal` IS the passing branch.
set -euo pipefail
: "${RUNNER_TEMP:?the gate sets its scratch directory}"
fixtures_url="https://raw.githubusercontent.com/lbartoszcze/AutoVersion/v0.1.0/FIXTURES.md"
curl -sSf --output "$RUNNER_TEMP/autoversion-fixtures.md" "$fixtures_url"
stado release version-gate conformance --fixtures "$RUNNER_TEMP/autoversion-fixtures.md"

# Both sides are built from the COMMITTED baseline rather than a synthetic
# pair, so this step also proves the frozen file parses and that it is the file
# reaching the decision. An empty candidate would be no use as the breaking
# case -- the rule rejects it outright as a far more likely broken extractor.
shrunk="$RUNNER_TEMP/shrunk.json"
jq '{surface: (.surface - [(.surface | sort | first)])}' \
  released-surface.json > "$shrunk"
current="$(jq -r .version released-surface.json)"
unchanged="$(stado release version-gate decide --json --current "$current" \
  --published-surface released-surface.json \
  --candidate-surface released-surface.json | jq -r .change)"
removed="$(stado release version-gate decide --json --current "$current" \
  --published-surface released-surface.json \
  --candidate-surface "$shrunk" | jq -r .change)"
if [ "$unchanged" != internal ] || [ "$removed" != breaking ]; then
  echo "::error::the rule does not answer as the rule: the committed surface" \
    "against itself read '$unchanged', and with one name removed it read" \
    "'$removed', so no verdict below means anything."
  false
fi
