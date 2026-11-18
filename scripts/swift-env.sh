#!/bin/sh
# Prints the Swift SDK and toolchain library paths the macOS release build
# links against, as KEY=VALUE lines. The release workflow appends them to
# $GITHUB_ENV; `make snapshot` evals them. Needs Xcode or Command Line Tools.
set -eu
sdk="$(xcrun --show-sdk-path)"
tc="$(cd "$(dirname "$(xcrun -f swiftc)")/../lib/swift/macosx" && pwd)"
echo "SWIFT_SDK=$sdk"
echo "SWIFT_TCLIB=$tc"
