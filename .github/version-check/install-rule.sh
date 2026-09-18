#!/usr/bin/env bash
# Never `pip install` into the system interpreter. `ubuntu-latest` resolves to an
# Ubuntu whose python3 carries the externally-managed marker, so that spelling
# dies with `error: externally-managed-environment` before any check runs -- a
# permanently red gate, which by this fleet's own standard is worth exactly what a
# sleeping one is worth and trains people to ignore a red build. Invisible from a
# laptop, and invisible here too while Actions is billing-locked, because this step
# has never once run on a runner.
#
# A venv sidesteps the marker without --break-system-packages, and appending its
# bin to GITHUB_PATH leaves every later `autoversion` call spelled exactly as it
# was. RUNNER_TEMP and GITHUB_PATH exist only on a runner, hence the defaults --
# which are also what let this body be extracted and run locally, the only
# technique available here that can falsify a claim about CI.
set -euo pipefail
: "${RUNNER_TEMP:=$(mktemp -d)}"
: "${GITHUB_PATH:=$(mktemp)}"
python3 -m venv "$RUNNER_TEMP/rule"
"$RUNNER_TEMP/rule/bin/python" -m pip install --quiet \
  "git+https://github.com/lbartoszcze/AutoVersion@v0.1.0"
echo "$RUNNER_TEMP/rule/bin" >> "$GITHUB_PATH"
# GITHUB_PATH takes effect on the NEXT step only, so without this export the
# assertion below would consult whatever `autoversion` was already on PATH --
# including a stranger's, which would exit zero and vouch for a rule nobody
# asked. Prepending after the install is what makes the venv win, and it is
# load-bearing separately from the GITHUB_PATH line.
export PATH="$RUNNER_TEMP/rule/bin:$PATH"

# Which `autoversion` is about to answer? Establish that BEFORE asking it
# anything. `--help` is satisfied by any executable that exits zero, so a
# stranger earlier on PATH passes a liveness probe and then supplies every
# verdict below -- and if the export above is ever dropped in an edit, the
# symptom is a green step rather than a red one. Naming the resolved path is
# what makes that failure visible instead of invisible.
resolved="$(command -v autoversion || true)"
case "$resolved" in
  "$RUNNER_TEMP/rule/bin/"*) ;;
  *)
    echo "::error::autoversion resolves to '${resolved:-nothing}', outside the" \
      "venv this step just built, so a stranger would answer for the rule and" \
      "every verdict below would be its word rather than the rule's."
    false
    ;;
esac

# Then two DIFFERENT known answers, because one cannot be enough: a saboteur
# that always says `internal` passes a single-answer probe AND the gate's own
# steps, since with the declared version equal to the released one `internal`
# IS the passing branch. Identical surfaces must read `internal`; a surface
# with one name removed must read `breaking`. That second arm is the only
# thing here that requires the gate to be ABLE TO REFUSE.
#
# Both sides are built from the COMMITTED baseline rather than a synthetic
# pair, so this same step also proves the frozen file parses and that it is
# the file reaching the decision. The name is dropped without a bare index,
# which this workspace refuses. An empty candidate would be no use as the
# breaking case -- the rule rejects it outright as a far more likely broken
# extractor.
shrunk="$RUNNER_TEMP/shrunk.json"
jq '{surface: (.surface - [(.surface | sort | first)])}' \
  released-surface.json > "$shrunk"
current="$(jq -r .version released-surface.json)"
unchanged="$(autoversion decide --current "$current" \
  --published-surface released-surface.json \
  --candidate-surface released-surface.json --json | jq -r .change)"
removed="$(autoversion decide --current "$current" \
  --published-surface released-surface.json \
  --candidate-surface "$shrunk" --json | jq -r .change)"
if [ "$unchanged" != internal ] || [ "$removed" != breaking ]; then
  echo "::error::the rule does not answer as the rule: the committed surface" \
    "against itself read '$unchanged', and with one name removed it read" \
    "'$removed'. Something other than AutoVersion is answering, so no verdict" \
    "below means anything."
  false
fi
