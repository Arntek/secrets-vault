#!/usr/bin/env bash
# Run every Go fuzz target in the module for a fixed time each.
# Usage: scripts/fuzz.sh [fuzztime]   (default 30s)
# Crashers are written to <package>/testdata/fuzz/<Target>/ by go test.
set -euo pipefail

fuzztime="${1:-30s}"
status=0
count=0

for pkg in $(go list ./...); do
  targets=$(go test -list '^Fuzz' "$pkg" | grep '^Fuzz' || true)
  for target in $targets; do
    count=$((count + 1))
    echo "==> $pkg $target ($fuzztime)"
    if ! go test -run='^$' -fuzz="^${target}\$" -fuzztime="$fuzztime" "$pkg"; then
      status=1
    fi
  done
done

if [ "$count" -eq 0 ]; then
  echo "no fuzz targets found" >&2
  exit 1
fi
echo "ran $count fuzz target(s)"
exit "$status"
