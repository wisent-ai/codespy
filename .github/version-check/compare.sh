#!/usr/bin/env bash
set -euo pipefail
released="$(jq -r .version released-surface.json)"
declared="$(awk -F'"' '/^__version__/{print $2; exit}' codespy.py)"
echo "released: $released"
echo "declared: $declared"

verdict="$(autoversion decide \
  --current "$released" \
  --published-surface released-surface.json \
  --candidate-surface "$RUNNER_TEMP/candidate.json" \
  --json)"
echo "$verdict"

change="$(printf '%s' "$verdict" | jq -r .change)"
required="$(printf '%s' "$verdict" | jq -r .next)"

if [ "$declared" = "$released" ]; then
  if [ "$change" != "internal" ]; then
    echo "::error::The public contract changed ($change) but codespy.py still" \
      "declares the released version $released. The next version must be $required."
    false
  fi
  echo "Nothing new released and the contract is unchanged."
elif [ "$declared" != "$required" ]; then
  echo "::error::codespy.py declares $declared, but a $change change to" \
    "$released requires $required."
  false
else
  echo "Declared version matches the $change change."
fi
