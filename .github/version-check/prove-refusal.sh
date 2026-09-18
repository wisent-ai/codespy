#!/usr/bin/env bash
set -euo pipefail
# A gate that has never refused is decoration, and the install step's probe does
# not cover the step below. That probe interrogated an `autoversion` it had put
# on PATH with an `export` in its OWN shell; every later step, including the one
# that consumes the real verdict, resolves the name through GITHUB_PATH instead.
# Those are two different resolutions, and only one of them was proved. Drop,
# misspell or reorder the GITHUB_PATH line and the install step still passes
# while a stranger answers from here on -- and a stranger that always answers
# `internal` sails through the comparison below, because while codespy.py
# declares the released version `internal` IS the passing branch. So the ability
# to refuse is demanded again, from the same resolution the verdict below is read
# from, immediately before it is read.
#
# Built out of the COMMITTED baseline rather than a synthetic pair, so this also
# proves the frozen file parses, carries a surface, and is really what reaches a
# decision. One name is dropped with `- [first]` rather than a bare subscript,
# which this workspace refuses. All but one of the baseline's names survive, so
# the candidate is never the empty surface the rule rejects outright as the far
# likelier broken extractor.
dropped="$(jq -r '.surface | sort | first' released-surface.json)"
jq '{surface: (.surface - [(.surface | sort | first)])}' \
  released-surface.json > "$RUNNER_TEMP/refusal.json"
released="$(jq -r .version released-surface.json)"
# `|| true` so an `autoversion` that crashes or prints no verdict is reported by
# the message below, naming the removal it was asked about, instead of killing
# the step with a stack trace. Safe only because nothing but the literal
# `breaking` passes: an empty answer falls through to the refusal.
verdict="$(autoversion decide --current "$released" \
  --published-surface released-surface.json \
  --candidate-surface "$RUNNER_TEMP/refusal.json" \
  --json | jq -r .change || true)"
if [ "$verdict" != breaking ]; then
  echo "::error::removing '$dropped' from the released contract $released read" \
    "'${verdict:-<nothing>}' instead of breaking, so this gate cannot refuse a" \
    "removal and the verdict consumed by the next step is worth nothing. Fix the" \
    "check; do not touch the baseline."
  false
fi
echo "Removing '$dropped' is refused as breaking, so this gate can refuse."
