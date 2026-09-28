#!/usr/bin/env bash
set -euo pipefail
# The baseline check for a release worker's archive, which has no .git.
# Stado's build submit reads the committed released-surface.json, requires a
# git-archive:<tag> baseline's tag to be served by origin at the commit the
# checkout resolves it to, and archives the result together with every tag
# origin serves at .wisent-provenance/baseline.json. This step believes nothing
# else: the record must exist, must describe this source revision, must name
# the same marker the committed baseline carries, and no full-version tag origin
# serves may be newer than the baseline (a stale baseline measures against a
# superseded artifact). A head: baseline is refused while any full-version tag
# exists, because the tag is what callers of the Action pin.
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
    # A full-version tag must name the released version; a floating major
    # alias (v1, what the README pins) names none, and Stado has already
    # verified that origin serves it at the recorded commit.
    if [[ "${tag#v}" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] && [ "${tag#v}" != "$released" ]; then
      echo "::error::baseline tag $tag does not name the released version $released." >&2
      exit 1
    fi
    ;;
  head:*) ;;
  *)
    echo "::error::baseline marker '$marker' is a tier this gate does not read." >&2
    exit 1
    ;;
esac

newest=""
for tag in $(jq -r '.origin_tags[]' "$record"); do
  version="${tag#v}"
  [[ "$version" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] || continue
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
    echo "::error::baseline claims $marker, but origin serves tag v$newest;" \
      "head is the last resort only. Run release/version-check/baseline/baseline.sh." >&2
    exit 1
  fi
  superseded="$(bash release/version-check/rule/newer.sh "$released" "$newest")"
  if [ "$superseded" = true ]; then
    echo "::error::origin serves v$newest, newer than the baseline $released." \
      "Run release/version-check/baseline/baseline.sh." >&2
    exit 1
  fi
fi
echo "Baseline $released at '$marker' matches Stado's verified provenance."
