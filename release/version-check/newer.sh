#!/usr/bin/env bash
# Print `true` when $2 is a strictly newer version than $1 and `false`
# otherwise, asking Stado's port of the fleet versioning rule
# (stado release version-gate), which every release worker carries. A version
# Stado refuses as invalid stops the caller: it exits nonzero with Stado's
# words instead of answering, so a garbled coordinate is never read as "not
# newer".
set -euo pipefail
older="${1:?newer.sh OLDER NEWER}"
newer="${2:?newer.sh OLDER NEWER}"
if [ "$older" = "$newer" ]; then
  echo false
  exit 0
fi
status=0
stado release version-gate semver-at-least "$newer" "$older" || status=$?
case "$status" in
  0) echo true ;;
  1) echo false ;;
  *)
    echo "::error::stado refused to order '$older' and '$newer' (status $status)." >&2
    exit "$status"
    ;;
esac
