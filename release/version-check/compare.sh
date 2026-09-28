#!/usr/bin/env bash
set -euo pipefail
released="$(jq -r .version released-surface.json)"
declared="$(bash release/version-check/baseline.sh --declared HEAD)"
echo "released: $released"
echo "declared: $declared"

verdict="$("$CODESPY_BIN" --version-rule decide \
  --current "$released" \
  --published-surface released-surface.json \
  --candidate-surface "$RUNNER_TEMP/candidate.json")"
echo "$verdict"

change="$(printf '%s' "$verdict" | jq -r .change)"
required="$(printf '%s' "$verdict" | jq -r .next)"

if [ "$declared" = "$released" ]; then
  if [ "$change" != "internal" ]; then
    echo "::error::The public contract changed ($change) but Cargo.toml still" \
      "declares the released version $released. The next version must be $required."
    false
  fi
  echo "Nothing new released and the contract is unchanged."
elif [ "$declared" != "$required" ]; then
  echo "::error::Cargo.toml declares $declared, but a $change change to" \
    "$released requires $required."
  false
else
  echo "Declared version matches the $change change."
fi
