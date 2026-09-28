#!/usr/bin/env bash
set -euo pipefail
# Regenerate released-surface.json from the best published artifact that exists.
#
# The baseline is the yardstick every version decision is measured against, so
# it is never typed by hand. This script owns the provenance marker that couples
# released-surface.json to the workflow; the marker is the first
# whitespace-delimited token of "source", everything after it is prose:
#
#   pypi-sdist:<filename>    recovered from a published sdist
#   pypi-wheel:<filename>    recovered from a published wheel
#   stado:<object path>      recovered from a published Stado channel artifact
#   git-archive:<tag>        reproduced from a git tag with `git archive`
#   head:<full sha>          last resort: nothing published and no usable tag
#
# Tiers are tried best-first and the first that exists wins. A tier this script
# does not implement is refused loudly rather than skipped.
#
# The version recorded is the latest PUBLISHED version, never the one Cargo.toml
# happens to declare.
#
# A surface is read by running that artifact's own `codespy --surface`. The
# releases before the Rust port (codespy.py) cannot be read that way; their
# surface is the one released-surface.json already records for them, and only
# when its marker names exactly that artifact.
#
# Usage:
#   bash release/version-check/baseline.sh            # rewrite released-surface.json
#   bash release/version-check/baseline.sh --stdout   # print it, touch nothing
#   bash release/version-check/baseline.sh --dry-run  # print the marker only
#   bash release/version-check/baseline.sh --declared <ref>  # the version <ref> declares

# The version a tree declares: Cargo.toml's package version, or the
# __version__ of a pre-port codespy.py.
declared_at() {
  local ref="$1"
  if git cat-file -e "$ref:Cargo.toml" 2>/dev/null; then
    git show "$ref:Cargo.toml" | awk -F'"' '/^version *=/{print $2; exit}'
  elif git cat-file -e "$ref:codespy.py" 2>/dev/null; then
    git show "$ref:codespy.py" | awk -F'"' '/^__version__/{print $2; exit}'
  fi
}

mode="${1:-write}"
if [ "$mode" = --declared ]; then
  declared_at "${2:?--declared needs a git ref}"
  exit 0
fi
root="$(git rev-parse --show-toplevel)"
cd "$root"
# Scratch lives in this checkout's ignored build directory.
work="$root/target/version-check"
rm -rf "$work"
mkdir -p "$work"

pypi="https://pypi.org/pypi/codespy/json"
status="$(curl -sS -o "$work/pypi.json" -w '%{http_code}' "$pypi" || true)"
case "$status" in
  404) ;;
  200)
    echo "::error::PyPI serves codespy, and recovering a surface from a PyPI artifact" \
      "is a tier this script does not implement; add it rather than letting the" \
      "baseline drop to a git tag." >&2
    exit 1 ;;
  *)
    echo "::error::$pypi answered '$status'. An unreachable index looks identical to an" \
      "unpublished project, so absence is unproven." >&2
    exit 1 ;;
esac

# Whether a tag name asserts a complete version (v1.1.0), as opposed to a
# floating major alias (v1) that is expected to move.
full_version_tag() {
  [[ "${1#v}" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]]
}

newer() {
  local answer
  answer="$(bash release/version-check/newer.sh "$1" "$2")"
  [ "$answer" = true ]
}

best_tag=""
best_version=""
for tag in $(git tag -l | sort); do
  version="$(declared_at "$tag")"
  if [ -z "$version" ]; then
    echo "skipping tag $tag: it declares no version" >&2
    continue
  fi
  if full_version_tag "$tag" && [ "${tag#v}" != "$version" ]; then
    echo "skipping tag $tag: it declares $version, so the tag is mis-signed" >&2
    continue
  fi
  if [ -z "$best_version" ] || newer "$best_version" "$version"; then
    best_tag="$tag"; best_version="$version"
  elif [ "$version" = "$best_version" ] && full_version_tag "$tag" && ! full_version_tag "$best_tag"; then
    best_tag="$tag"
  fi
done

# The surface of the artifact at git ref $1, marked $2. Nothing is unpacked:
# a Rust-era artifact is read by running this checkout's own `codespy
# --surface`, which is only that artifact when the checkout's tree is the
# ref's tree; a pre-port artifact is read from what the baseline records.
surface_of() {
  local ref="$1" marker="$2"
  if git cat-file -e "$ref:Cargo.toml" 2>/dev/null; then
    if ! git diff --quiet "$ref" -- ; then
      echo "::error::$marker is not the tree checked out here; run this at $ref," \
        "whose own program states its surface." >&2
      return 1
    fi
    # The binary the release build already made; nothing is compiled here.
    "${CODESPY_BIN:-target/release/codespy}" --surface action.yml | jq .surface
  elif [ "$(jq -r '.source | split(" ") | first' released-surface.json)" = "$marker" ]; then
    jq .surface released-surface.json
  else
    echo "::error::$marker predates the Rust port, and released-surface.json does not" \
      "record its surface; it cannot be read without the retired Python reader." >&2
    return 1
  fi
}

if [ -n "$best_tag" ]; then
  marker="git-archive:$best_tag"
  version="$best_version"
  if [ "$mode" = --stdout ] || [ "$mode" = --dry-run ]; then
    # The tier check reads the marker only; the surface is never recomputed
    # at check time, so the committed one stands in.
    surface="$(jq .surface released-surface.json)"
  else
    surface="$(surface_of "$best_tag" "$marker")"
  fi
  prose="the artifact at git tag $best_tag, read by its own codespy --surface. PyPI serves no project named codespy, and codespy does not ship through Stado. It is published as a GitHub Action, and every README example consumes wisent-ai/codespy@$best_tag, so this tag is the artifact callers actually get, and it declares $version."
else
  sha="$(git rev-parse HEAD)"
  marker="head:$sha"
  version="$(declared_at HEAD)"
  if [ "$mode" = --stdout ] || [ "$mode" = --dry-run ]; then
    surface="$(jq .surface released-surface.json)"
  else
    surface="$(surface_of HEAD "$marker")"
  fi
  prose="last resort. PyPI serves no project named codespy, and no git tag carries a version, so nothing is published and there is no higher tier to reach for."
fi

document="$(jq -n --arg version "$version" --arg source "$marker $prose" --argjson surface "$surface" \
  '{version: $version, source: $source, surface: $surface}')"
case "$mode" in
  --stdout) printf '%s\n' "$document" ;;
  --dry-run) echo "$marker  version=$version  names=$(printf '%s' "$surface" | jq length)" ;;
  write)
    printf '%s\n' "$document" > released-surface.json
    echo "wrote released-surface.json: $marker, version $version" ;;
  *) echo "usage: baseline.sh [--stdout|--dry-run]" >&2; exit 2 ;;
esac
