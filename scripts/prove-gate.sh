#!/usr/bin/env sh
# Prove the version gate can both pass and refuse, using the same shared rule the
# workflow installs. Run from the repository root:
#
#     scripts/prove-gate.sh [path-to-autoversion]
#
# Three comparisons against released-surface.json:
#   HEAD            — should be `internal`, since nothing observable changed
#   one name added   — should be `additive`
#   one name removed — should be `breaking`
#
# The mutated surfaces are built with jq from the baseline, so they exercise the real
# rule rather than a story about it.

set -eu

autoversion="${1:-autoversion}"
released="$(jq -r .version released-surface.json)"
declared="$(awk -F'"' '/^__version__/{print $2; exit}' codespy.py)"
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

echo "released: $released"
echo "declared: $declared"
echo

python3 scripts/surface.py > "$work/head.json"

# One rule id removed. A suppression list keyed on it stops matching: breaking.
victim="$(jq -r '.surface | map(select(startswith("rule:"))) | first' released-surface.json)"
jq --arg drop "$victim" '{surface: (.surface - [$drop])}' released-surface.json > "$work/removed.json"

# One rule id added, nothing removed: additive.
jq '{surface: (.surface + ["rule:SEC999"]) | sort}' released-surface.json > "$work/added.json"

# One removed and one added at once. The rule must weigh the removal, not average it.
jq --arg drop "$victim" \
  '{surface: ((.surface - [$drop]) + ["rule:SEC999"]) | sort}' released-surface.json \
  > "$work/mixed.json"

for case in head added removed mixed; do
  printf '%s: ' "$case"
  "$autoversion" decide \
    --current "$released" \
    --published-surface released-surface.json \
    --candidate-surface "$work/$case.json" \
    --json
done

echo
echo "removed name was $victim"
