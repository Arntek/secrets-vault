#!/bin/sh
# Fills the version, download base and sha256 lines of the Homebrew formula
# from a GoReleaser checksums.txt.
#   render-formula.sh FORMULA VERSION CHECKSUMS_FILE [BASE_URL]
# VERSION has no leading "v". BASE_URL defaults to the GitHub release folder
# (the formula builds it from the version); pass file:///folder to test locally.
set -eu
formula=$1 version=$2 sums=$3 base=${4:-}
tmp="$(mktemp)"
trap 'rm -f "$tmp"' EXIT
cp "$formula" "$tmp"
sed -i.bak "s|version \"[^\"]*\" # render-formula:version|version \"$version\" # render-formula:version|" "$tmp"
if [ -n "$base" ]; then
  sed -i.bak "s|base = \"[^\"]*\" # render-formula:base|base = \"$base\" # render-formula:base|" "$tmp"
fi
for t in darwin_arm64 darwin_amd64 linux_arm64 linux_amd64; do
  sha="$(awk -v f="secrets-vault_${version}_${t}.tar.gz" '$2==f {print $1}' "$sums")"
  case "$sha" in
    [0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f]*) ;;
    *) echo "no checksum for $t in $sums" >&2; exit 1 ;;
  esac
  sed -i.bak "s|sha256 \"[0-9a-f]*\" # render-formula:$t|sha256 \"$sha\" # render-formula:$t|" "$tmp"
done
rm -f "$tmp.bak"
cp "$tmp" "$formula"
