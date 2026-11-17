# Phase 0: Touch ID spike (17 Nov 2026) — PASSED

Proves an unsigned (ad-hoc, linker-signed, no Apple Team ID) CLI can:
1. create a Secure Enclave P-256 key requiring Touch ID (`.biometryCurrentSet`) with no entitlements,
2. store it as a CryptoKit `dataRepresentation` blob in a normal file (no Keychain),
3. unwrap a vault key after a Touch ID prompt, from a non-TTY process (agent shell),
4. keep working after a rebuild (different binary hash/CDHash, different path).

Build on this Mac (Command Line Tools ship a duplicate `bridging.modulemap`; the overlay hides it without touching system files):

    mkdir -p build && : > build/empty.modulemap
    # build/overlay.yaml maps /Library/Developer/CommandLineTools/usr/include/swift/bridging.modulemap -> build/empty.modulemap
    swiftc -O main.swift -o touchid-spike -vfsoverlay build/overlay.yaml -Xcc -ivfsoverlay -Xcc build/overlay.yaml

    ./touchid-spike enroll ./testvault
    ./touchid-spike unlock ./testvault   # Touch ID prompt
