#!/bin/sh
# Builds the macOS stub (per guest architecture), embedded by the sandbox darwin
# backend. Cross-compiles from Linux with the pinned Zig toolchain; the result is
# ad-hoc codesigned at runtime by the supervisor before exec (macOS refuses an
# unsigned freshly written binary). The stub's architecture matches the guest's:
# an arm64 guest runs in the arm64 stub, an x86-64 guest in the x86-64 stub (on
# Apple Silicon the latter runs under Rosetta).
set -e
cd "$(dirname "$0")"
ZIG=${ZIG:-/tmp/zig-linux-x86_64-0.13.0/zig}
"$ZIG" build-exe -target aarch64-macos -lc -O ReleaseSmall \
	-femit-bin=stub-arm64.bin stub.zig
"$ZIG" build-exe -target x86_64-macos -lc -O ReleaseSmall \
	-femit-bin=stub-amd64.bin stub.zig
rm -f stub-arm64.bin.o stub-amd64.bin.o
