#!/bin/sh
# container-sweep.sh: run the language runtimes and databases laboon is expected
# to handle, each as an OCI image, and report which start and execute. A proof
# command per image (print a version or run a one-liner) is enough to show the
# runtime loads and runs under the sandbox; it is not a full test suite.
#
#   scripts/container-sweep.sh [laboon-binary]   (default: ./laboon, else `go run ./cmd/laboon`)
#
# LABOON       the laboon binary to use
# PLATFORM     linux/amd64 or linux/arm64 (default: the host architecture)
# SWEEP_NET    pass -net to every run (databases need it less, runtimes not at all)
# Exit status is the number of non-deferred images that failed.
set -u

LABOON=${LABOON:-${1:-./laboon}}
if [ ! -x "$LABOON" ]; then
	LABOON="go run ./cmd/laboon"
fi
PLAT=""
[ -n "${PLATFORM:-}" ] && PLAT="-platform $PLATFORM"
NET=""
[ -n "${SWEEP_NET:-}" ] && NET="-net"

# A per-image wall-clock cap, if the host has a timeout command (macOS has
# neither by default; then runs are uncapped).
TO=""
for t in timeout gtimeout; do
	if command -v "$t" >/dev/null 2>&1; then TO="$t 600"; break; fi
done

pass=0
fail=0
fails=""

# run NAME MARKER IMAGE CMD...: run IMAGE's CMD under laboon, expect MARKER in
# the output. A leading "?" on NAME marks a known-deferred image: a miss is
# reported but does not fail the sweep. A failure's whole output is kept in
# sweep-fail-NAME.txt.
run() {
	name=$1 marker=$2 image=$3
	shift 3
	defer=no
	case $name in \?*) defer=yes; name=${name#\?} ;; esac
	out=$($TO $LABOON $PLAT $NET -image "$image" "$@" 2>&1)
	rc=$?
	if [ "$rc" = 0 ] && printf '%s' "$out" | grep -q "$marker"; then
		echo "PASS  $name ($image)"
		pass=$((pass + 1))
	elif [ "$defer" = yes ]; then
		echo "DEFER $name ($image): rc=$rc (known)"
	else
		echo "FAIL  $name ($image): rc=$rc | $(printf '%s' "$out" | tail -1 | cut -c1-120)"
		printf '%s\n' "$out" > "sweep-fail-$name.txt"
		fail=$((fail + 1))
		fails="$fails $name"
	fi
}

echo "== container sweep: $LABOON ${PLATFORM:+platform=$PLATFORM} $(date)"

# Interpreted / compiled language runtimes. A version command starts the full
# runtime (interpreter, JVM, ...) and exits; quote-free so it passes cleanly
# through every host shell.
run python  Python   python:3.12-alpine        python3 --version
run node    v22      node:22-alpine            node --version
run ruby    ruby     ruby:3.3-alpine           ruby --version
run perl    perl     perl:5.40                 perl --version
run php     PHP      php:8.3-cli-alpine        php --version
run go      go       golang:1.23-alpine        go version
run rust    rustc    rust:1.82-alpine          rustc --version
run java    version  eclipse-temurin:21        java -version
run gcc     gcc      gcc:14                     gcc --version
run busybox Linux    busybox:1.36              busybox uname -s

# Databases: the server binary prints its version without opening sockets, which
# shows the (often large, threaded) image loads and runs.
run redis    Redis    redis:7-alpine           redis-server --version
run postgres postgres postgres:16-alpine       postgres --version
run mariadb  mariadb  mariadb:11               mariadbd --version

# .NET hangs under laboon in futex/poll threading (runtime bring-up deferred).
run dotnet   dotnet   mcr.microsoft.com/dotnet/runtime:8.0  dotnet --info

echo "== sweep done: $pass passed, $fail failed${fails:+ ($fails)}"
exit $fail
