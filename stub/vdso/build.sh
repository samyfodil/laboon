#!/bin/sh
# Builds the guest vDSO images for hosts without a Linux kernel, one per guest
# architecture, with the pinned Zig toolchain. Each is linked as the kernel
# links its vDSO: one read-execute segment, the kernel's symbols and versions.
set -e
cd "$(dirname "$0")"
ZIG=${ZIG:-/tmp/zig-linux-x86_64-0.13.0/zig}
for a in amd64:x86_64 arm64:aarch64; do
	"$ZIG" build-lib -dynamic -target "${a#*:}-linux-none" -O ReleaseSmall -fstrip \
		-fsoname=linux-vdso.so.1 --version-script "vdso-${a%%:*}.map" -T vdso.lds \
		-z max-page-size=4096 -femit-bin="vdso-${a%%:*}.so" vdso.zig
	rm -f "vdso-${a%%:*}.so.o"
done
