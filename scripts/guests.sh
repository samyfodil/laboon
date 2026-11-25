#!/bin/sh
# Stage the Linux test guests for the sandbox suite on a host that cannot build
# them itself (macOS, Windows, or a Linux host of the other arch):
#
#	scripts/guests.sh OUTDIR
#
# Run it on a Linux host of the target arch with gcc and glibc's static libc, or
# set CC to a glibc cross gcc. Every testdata/*.c and internal/sandbox/testdata/*.c
# for that arch is built into OUTDIR (static-PIE, unless the source names its
# flags on a "// build:" line; with zig, also against musl as <name>+musl when
# it has a "// libc: musl" line, and for x86-64 as <name>+x64 when it has a
# "// cross: x64" line), every testdata Go program for linux/<arch>,
# a dynamic glibc program with its libraries (dynroot), and the dynamic musl
# programs and libraries alpine_test.go adds to Alpine (zig); then run
# the suite with LC_GUEST_DIR=OUTDIR. A guest that does not build fails the
# script, as a guest missing from OUTDIR fails its test.
#
# PARTS picks what to build, of "glibc musl go" (all by default), so the parts
# can come from different hosts into one OUTDIR: glibc from a native gcc, musl
# and Go from any host, since zig and Go cross-compile. ARCH (amd64 or arm64)
# names the target when gcc is not building: by default it is gcc's.
set -eu
out=${1:?usage: scripts/guests.sh OUTDIR}
cc=${CC:-gcc}
parts=${PARTS:-glibc musl go}
has() { case " $parts " in *" $1 "*) return 0 ;; esac; return 1; }
case ${ARCH:-$($cc -dumpmachine)} in
amd64 | x86_64-*) arch=amd64 bb=x86_64 ;;
arm64 | aarch64-*) arch=arm64 bb=aarch64 ;;
*) echo "guests.sh: neither x86_64 nor aarch64: set ARCH or CC" >&2; exit 2 ;;
esac
cd "$(dirname "$0")/.."
mkdir -p "$out"
failed=
for src in testdata/*.c internal/sandbox/testdata/*.c; do
	name=$(basename "$src" .c)
	case $name in
	btilib | btimain) continue ;; # a shared-library pair sandbox_linux_arm64_test.go builds itself
	libm5 | libm5b | m5dyn | m5dlopen) continue ;; # dynamic musl, built below
	*_amd64) [ $arch = amd64 ] || continue ;;
	*_arm64) [ $arch = arm64 ] || continue ;;
	esac
	flags=$(sed -n 's|^// build: ||p' "$src" | head -n 1)
	flags=${flags:--static-pie}
	if has glibc; then
		# shellcheck disable=SC2086 # flags is a word list
		$cc -O2 -pthread -w -I internal/sandbox/testdata $flags -o "$out/$name" "$src" || failed="$failed $name"
	fi
	if has musl && grep -q '^// libc: musl' "$src"; then
		case $flags in *-static-pie*) flags="$flags -fPIE" ;; esac
		# shellcheck disable=SC2086
		"${ZIG:-zig}" cc -target "$bb-linux-musl" -O2 -pthread -w $flags -o "$out/$name+musl" "$src" || failed="$failed $name+musl"
	fi
	# A "// cross: x64" program is also built for x86-64 (static musl), which
	# an arm64 macOS supervisor runs under Rosetta beside its own guests.
	if has musl && grep -q '^// cross: x64' "$src"; then
		"${ZIG:-zig}" cc -target x86_64-linux-musl -O2 -w -static-pie -fPIE -o "$out/$name+x64" "$src" || failed="$failed $name+x64"
	fi
done
# A dynamic glibc program with its loader and libraries, each at its own path.
if has glibc; then
	rm -rf "$out/dynroot"
	mkdir -p "$out/dynroot"
	if $cc -O2 -o "$out/dynroot/hello" testdata/hello.c; then
		for lib in $(ldd "$out/dynroot/hello" | sed -n 's|.*=> \(/[^ ]*\).*|\1|p; s|^[[:space:]]*\(/[^ ]*\).*|\1|p'); do
			mkdir -p "$out/dynroot$(dirname "$lib")"
			cp -L "$lib" "$out/dynroot$lib"
		done
	else
		failed="$failed dynroot"
	fi
fi
# Dynamic musl programs and their libraries, for Alpine's ld-musl.
zcc() { "${ZIG:-zig}" cc -target "$bb-linux-musl" -O2 "$@"; }
if has musl; then
	zcc -shared -fPIC -Wl,-soname,libm5.so -o "$out/libm5.so" testdata/libm5.c &&
		zcc -shared -fPIC -Wl,-soname,libm5b.so -o "$out/libm5b.so" testdata/libm5b.c &&
		zcc -pthread -o "$out/m5dyn" testdata/m5dyn.c -L"$out" -lm5 &&
		zcc -o "$out/m5dlopen" testdata/m5dlopen.c -L"$out" -lm5b || failed="$failed m5"
fi
has go && for src in testdata/*.go testdata/*/main.go; do
	name=$(basename "$src" .go)
	[ "$name" = main ] && { src=$(dirname "$src"); name=$(basename "$src"); }
	for mode in exe pie; do
		GOOS=linux GOARCH=$arch CGO_ENABLED=0 go build -buildmode=$mode -o "$out/go-$name-$mode" "./$src" || failed="$failed go-$name-$mode"
	done
done

if [ -n "$failed" ]; then
	echo "guests.sh: did not build:$failed" >&2
	exit 1
fi
