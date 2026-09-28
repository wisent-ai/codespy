#!/usr/bin/env bash
set -euo pipefail
# The version gate, run by the release after its build, against the binary that
# build made: refuse a release whose declared version disagrees with what it did
# to the public contract. Nothing is compiled here, and nothing runs per push.
#
# The contract of this tool is what a caller can observe: the rule ids it stamps
# findings with, the categories and severities it reports, the files it agrees
# to open, its output formats, its command line and the Action's inputs and
# outputs. The rule itself lives once for the whole fleet
# (https://github.com/lbartoszcze/AutoVersion); this repository supplies its
# surface and the version it declares.
#
# Where the baseline's provenance comes from depends on where the gate runs. In
# a checkout it reads tags and history itself (verify-baseline.sh). A release
# worker runs it in an unpacked archive with no .git; there Stado's build submit
# has already checked the baseline tag against origin and archived the result
# at .wisent-provenance/baseline.json, which verify-provenance.sh reads. No
# second checkout is ever made.
root="$(pwd)"
export CODESPY_BIN="${CODESPY_BIN:-$root/target/release/codespy}"
if [ ! -x "$CODESPY_BIN" ]; then
  echo "::error::no built codespy at $CODESPY_BIN; the gate reads the release's own binary." >&2
  exit 1
fi
# Scratch lives in this tree's ignored build directory.
export RUNNER_TEMP="$root/target/version-gate"
rm -rf "$RUNNER_TEMP"
mkdir -p "$RUNNER_TEMP"

bash release/version-check/prove-rule.sh
"$CODESPY_BIN" --surface action.yml > "$RUNNER_TEMP/candidate.json"
bash release/version-check/compare.sh

if git rev-parse --is-inside-work-tree >/dev/null 2>&1; then
  # Tags and full history, which every later read of a ref depends on.
  if [ "$(git rev-parse --is-shallow-repository)" = "true" ]; then
    git fetch --force --tags --unshallow
  else
    git fetch --force --tags
  fi
  bash release/version-check/verify-baseline.sh
else
  bash release/version-check/verify-provenance.sh
fi
