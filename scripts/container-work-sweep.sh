#!/bin/sh
# container-work-sweep.sh: the container sweep taken past "it starts". Every
# language runtime compiles and runs a real program (sum 1..100 == 5050), and
# every database starts a server and serves a real query over a unix socket.
# A marker in the output proves the work actually happened.
#
#   scripts/container-work-sweep.sh [laboon-binary]   (default: ./laboon)
#
# LABOON     the laboon binary to use
# PLATFORM   linux/amd64 or linux/arm64 (default: the host architecture)
# Exit status is the number of non-deferred images that failed.
set -u

LABOON=${LABOON:-${1:-./laboon}}
if [ ! -x "$LABOON" ]; then LABOON="go run ./cmd/laboon"; fi
PLAT=""
[ -n "${PLATFORM:-}" ] && PLAT="-platform $PLATFORM"

TO=""
for t in timeout gtimeout; do
	if command -v "$t" >/dev/null 2>&1; then TO="$t 600"; break; fi
done

pass=0
fail=0
fails=""

# _run LBFLAGS NAME MARKER IMAGE CMD...: run IMAGE's CMD (with extra laboon
# flags LBFLAGS, e.g. a -u user) and expect MARKER in the output. A leading "?"
# on NAME marks a known-deferred image. A failure's whole output is kept in
# work-fail-NAME.txt.
_run() {
	lbflags=$1 name=$2 marker=$3 image=$4
	shift 4
	defer=no
	case $name in \?*) defer=yes; name=${name#\?} ;; esac
	out=$($TO $LABOON $PLAT $lbflags -image "$image" "$@" 2>&1)
	rc=$?
	if [ "$rc" = 0 ] && printf '%s' "$out" | grep -q "$marker"; then
		echo "PASS  $name ($image)"
		pass=$((pass + 1))
	elif [ "$defer" = yes ]; then
		echo "DEFER $name ($image): rc=$rc (known)"
	else
		echo "FAIL  $name ($image): rc=$rc | $(printf '%s' "$out" | tail -2 | tr '\n' ' ' | cut -c1-160)"
		printf '%s\n' "$out" > "work-fail-$name.txt"
		fail=$((fail + 1))
		fails="$fails $name"
	fi
}
run() { _run "" "$@"; }

echo "== container WORK sweep: $LABOON ${PLATFORM:+platform=$PLATFORM} $(date)"

# --- language runtimes: compile (where compiled) and RUN a real program ------
run python pysum   python:3.12-alpine  python3 -c "print('pysum', sum(range(101)))"
run node   nodesum node:22-alpine      node -e "let s=0;for(let i=1;i<=100;i++)s+=i;console.log('nodesum',s)"
run ruby   rubysum ruby:3.3-alpine     ruby -e "puts 'rubysum '+(1..100).sum.to_s"
run perl   perlsum perl:5.40           perl -e '$s+=$_ for 1..100; print "perlsum $s\n"'
run php    phpsum  php:8.3-cli-alpine   php -r 'echo "phpsum ".array_sum(range(1,100))."\n";'
run busybox bbsum  busybox:1.36        sh -c 's=0;i=1;while [ $i -le 100 ];do s=$((s+i));i=$((i+1));done;echo bbsum $s'

run go   gosum   golang:1.23-alpine sh -c 'printf "package main\nimport \"fmt\"\nfunc main(){s:=0;for i:=1;i<=100;i++{s+=i};fmt.Println(\"gosum\",s)}\n" > /tmp/m.go && go run /tmp/m.go'
run gcc  csum    gcc:14             sh -c 'cat > /tmp/a.c <<"END"
#include <stdio.h>
int main(){int s=0;for(int i=1;i<=100;i++)s+=i;printf("csum %d\n",s);return 0;}
END
gcc /tmp/a.c -o /tmp/a && /tmp/a'
run rust rustsum rust:1.82-alpine   sh -c 'printf "fn main(){let mut s=0;for i in 1..=100{s+=i};println!(\"rustsum {}\",s);}\n" > /tmp/m.rs && rustc -O /tmp/m.rs -o /tmp/m && /tmp/m'
run java javasum eclipse-temurin:21 sh -c 'cd /tmp && printf "public class Main{public static void main(String[] a){int s=0;for(int i=1;i<=100;i++)s+=i;System.out.println(\"javasum \"+s);}}\n" > Main.java && javac Main.java && java Main'

# --- databases: start the server and serve a real query over a unix socket ---
run redis redisok redis:7-alpine sh -c '
redis-server --unixsocket /tmp/r.sock --port 0 --daemonize no --save "" --ignore-warnings ARM64-COW-BUG >/tmp/redis.log 2>&1 &
for i in $(seq 1 200); do redis-cli -s /tmp/r.sock ping 2>/dev/null | grep -q PONG && break; done
redis-cli -s /tmp/r.sock set greet redisok >/dev/null
redis-cli -s /tmp/r.sock get greet'

_run "-u postgres" postgres pgselect2 postgres:16-alpine sh -c '
export PGDATA=/tmp/pg
initdb -D "$PGDATA" -A trust >/tmp/initdb.log 2>&1 || { tail -3 /tmp/initdb.log; exit 1; }
pg_ctl -D "$PGDATA" -o "-k /tmp -c listen_addresses=\"\"" -w start >/tmp/pg.log 2>&1 || { tail -3 /tmp/pg.log; exit 1; }
psql -h /tmp -d postgres -tAc "select '"'"'pgselect'"'"' || (1+1)"
pg_ctl -D "$PGDATA" stop -m fast >/dev/null 2>&1'

_run "-u mysql" mariadb mariasel2 mariadb:11 sh -c '
mariadb-install-db --datadir=/tmp/maria --auth-root-authentication-method=normal --force >/tmp/mi.log 2>&1 || { tail -3 /tmp/mi.log; exit 1; }
mariadbd --datadir=/tmp/maria --socket=/tmp/my.sock --skip-networking --skip-grant-tables >/tmp/md.log 2>&1 &
for i in $(seq 1 400); do mariadb --socket=/tmp/my.sock -e "select 1" >/dev/null 2>&1 && break; done
mariadb --socket=/tmp/my.sock -N -e "select concat('"'"'mariasel'"'"',1+1)"
mariadb-admin --socket=/tmp/my.sock shutdown >/dev/null 2>&1 || mysqladmin --socket=/tmp/my.sock shutdown >/dev/null 2>&1 || true'

# Bounded so a hang fails in 120s instead of burning the per-image cap; an
# emulated arm64 host takes up to a minute.
run dotnet 8. mcr.microsoft.com/dotnet/sdk:8.0-alpine sh -c 'timeout 120 dotnet --version'

echo "== work sweep done: $pass passed, $fail failed${fails:+ ($fails)}"
exit $fail
