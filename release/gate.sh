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

root="$(git rev-parse --show-toplevel 2>/dev/null)" || {
  echo "::error::the version gate reads tags and history, and this release runs" \
    "outside a git work tree, so the gate cannot decide; refusing." >&2
  exit 1
}
cd "$root"
export CODESPY_BIN="${CODESPY_BIN:-$root/target/release/codespy}"
if [ ! -x "$CODESPY_BIN" ]; then
  echo "::error::no built codespy at $CODESPY_BIN; the gate reads the release's own binary." >&2
  exit 1
fi
# Scratch lives in this checkout's ignored build directory.
export RUNNER_TEMP="$root/target/version-gate"
rm -rf "$RUNNER_TEMP"
mkdir -p "$RUNNER_TEMP"
export GITHUB_PATH="$RUNNER_TEMP/path"

# Tags and full history, which every later read of a ref depends on.
if [ "$(git rev-parse --is-shallow-repository)" = "true" ]; then
  git fetch --force --tags --unshallow
else
  git fetch --force --tags
fi

bash release/version-check/install-rule.sh
export PATH="$RUNNER_TEMP/rule/bin:$PATH"
"$CODESPY_BIN" --surface action.yml > "$RUNNER_TEMP/candidate.json"
bash release/version-check/prove-refusal.sh
bash release/version-check/compare.sh
bash release/version-check/verify-baseline.sh
