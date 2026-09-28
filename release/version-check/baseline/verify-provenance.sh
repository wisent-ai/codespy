#!/usr/bin/env bash
set -euo pipefail
# The baseline check for a release worker's archive, which has no .git.
# Stado's build submit reads the committed released-surface.json, requires a
# git-archive:<tag> baseline's tag to be served by origin at the commit the
# checkout resolves it to, and archives the result at
# .wisent-provenance/baseline.json, together with origin_tag_versions: every
# tag origin serves, its commit, and the version that commit's Cargo.toml
# declares (null when that tree has none). This step believes nothing else:
# the record must exist, must describe this source revision and the marker the
# committed baseline carries, the marker tag's declared version must be the
# released one, and no tag origin serves may declare a newer version (a stale
# baseline measures against a superseded artifact). Versions come from the
# tagged trees, never from tag spelling: a floating tag such as v1 names no
# version, and a moved one would name another tree's. A head: baseline is
# refused while any tag declares a version, because a tag is what callers of
# the Action pin.
record=".wisent-provenance/baseline.json"
if [ ! -f "$record" ]; then
  echo "::error::this archive carries no $record, so nobody verified where" \
    "released-surface.json came from; submit the release through stado release" \
    "build submit, which writes it." >&2
  exit 1
fi

released="$(jq -r .version released-surface.json)"
marker="$(jq -r '.source | split(" ") | first' released-surface.json)"
recorded="$(jq -r .marker "$record")"
if [ "$recorded" != "$marker" ]; then
  echo "::error::released-surface.json names '$marker', but Stado verified" \
    "'$recorded'; the archive's baseline is not the one that was checked." >&2
  exit 1
fi
source_commit="$(jq -r .source_commit "$record")"
if [ -n "${WISENT_SOURCE_COMMIT:-}" ] && [ "$source_commit" != "$WISENT_SOURCE_COMMIT" ]; then
  echo "::error::$record describes $source_commit, but this build is" \
    "$WISENT_SOURCE_COMMIT." >&2
  exit 1
fi

case "$marker" in
  git-archive:*)
    tag="${marker#git-archive:}"
    if [ "$(jq -r .tag "$record")" != "$tag" ]; then
      echo "::error::Stado's record does not name the baseline tag $tag as verified." >&2
      exit 1
    fi
    declared="$(jq -r --arg tag "$tag" '.origin_tag_versions[$tag].version // empty' "$record")"
    if [ -n "$declared" ] && [ "$declared" != "$released" ]; then
      echo "::error::baseline tag $tag's tree declares $declared, not the released" \
        "version $released. Run release/version-check/baseline/baseline.sh." >&2
      exit 1
    fi
    if [ -z "$declared" ]; then
      # Pre-port tags (codespy.py) carry no Cargo.toml, so Stado could not
      # read their version; say so rather than let the tag name stand in.
      echo "note: $tag's tree declares no Cargo.toml version; released-surface.json" \
        "records $released for it, read from codespy.py when the baseline was made."
    fi
    ;;
  head:*) ;;
  *)
    echo "::error::baseline marker '$marker' is a tier this gate does not read." >&2
    exit 1
    ;;
esac

newest=""
for version in $(jq -r '.origin_tag_versions // {} | .[] | .version // empty' "$record"); do
  if [ -z "$newest" ]; then
    newest="$version"
    continue
  fi
  later="$(bash release/version-check/rule/newer.sh "$newest" "$version")"
  if [ "$later" = true ]; then
    newest="$version"
  fi
done
if [ -n "$newest" ]; then
  if [ "${marker%%:*}" = head ]; then
    echo "::error::baseline claims $marker, but a tag origin serves declares $newest;" \
      "head is the last resort only. Run release/version-check/baseline/baseline.sh." >&2
    exit 1
  fi
  superseded="$(bash release/version-check/rule/newer.sh "$released" "$newest")"
  if [ "$superseded" = true ]; then
    echo "::error::a tag origin serves declares $newest, newer than the baseline" \
      "$released. Run release/version-check/baseline/baseline.sh." >&2
    exit 1
  fi
fi
echo "Baseline $released at '$marker' matches Stado's verified provenance."
