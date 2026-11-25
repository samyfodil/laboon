package sandbox

import (
	"bytes"
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/samyfodil/laboon/oci"
)

// Alpine's minirootfs and busybox-extras (for httpd), pinned per arch.
var alpinePins = map[string][2]pin{
	"amd64": {
		{"https://dl-cdn.alpinelinux.org/alpine/v3.20/releases/x86_64/alpine-minirootfs-3.20.10-x86_64.tar.gz", "0d44a414245f043ae56872a23762e6c9bee585da2cbe4aa81cbd0331eaf53223"},
		{"https://dl-cdn.alpinelinux.org/alpine/v3.20/main/x86_64/busybox-extras-1.36.1-r31.apk", "cd02c0d70bf3c80738afabc4ef78fc0893db6b07be48c826bcca1446a67def20"},
	},
	"arm64": {
		{"https://dl-cdn.alpinelinux.org/alpine/v3.20/releases/aarch64/alpine-minirootfs-3.20.10-aarch64.tar.gz", "61ac877fdbcee6914731bc22a4ed5668ea3470f201f97a7078931c48b71bbeec"},
		{"https://dl-cdn.alpinelinux.org/alpine/v3.20/main/aarch64/busybox-extras-1.36.1-r31.apk", "af03dbd202eddb4bb1d4794a8bce21befc186e610fd990db798bc8d9436a56ef"},
	},
}

var alpine struct {
	sync.Mutex
	root string
}

// alpineRoot is an Alpine 3.20 rootfs, unpacked once per test binary, with
// the test programs added: m4proc, m6net and m7tty, and the dynamic-linking
// probes m5dyn and m5dlopen with their libraries built against its musl.
func alpineRoot(t *testing.T) string {
	t.Helper()
	alpine.Lock()
	defer alpine.Unlock()
	if alpine.root != "" {
		return alpine.root
	}
	pins := alpinePins[runtime.GOARCH]
	f, err := os.Open(fetchPinned(t, pins[0]))
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	dir, err := os.MkdirTemp("", "lc-alpine-")
	if err != nil {
		t.Fatal(err)
	}
	root := filepath.Join(dir, "rootfs")
	if err := os.Mkdir(root, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := oci.Unpack(gunzip(t, f), root, 1<<30); err != nil {
		t.Fatal(err)
	}
	put := func(at string, b []byte) {
		if err := os.WriteFile(filepath.Join(root, at), b, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	put("bin/busybox-extras", apkFile(t, pins[1], "bin/busybox-extras"))
	for _, n := range []string{"m4proc", "m6net", "m7tty"} {
		copyGuest(t, filepath.Join(root, "bin", n), n+"+musl")
	}
	for at, b := range m5Guests(t) {
		put(at, b)
	}
	alpine.root = root
	return root
}

// m5Guests returns, by their path in the root, the dynamic musl programs
// m5dyn and m5dlopen and the libraries they load: staged in LC_GUEST_DIR,
// else built here with zig.
func m5Guests(t *testing.T) map[string][]byte {
	t.Helper()
	files := map[string]string{"usr/lib/libm5.so": "libm5.so", "usr/lib/libm5b.so": "libm5b.so", "bin/m5dyn": "m5dyn", "bin/m5dlopen": "m5dlopen"}
	dir := os.Getenv("LC_GUEST_DIR")
	if dir == "" {
		if runtime.GOOS != "linux" {
			t.Fatalf("Linux guests are not built on %s: stage them with scripts/guests.sh and set LC_GUEST_DIR", runtime.GOOS)
		}
		z := zigCC()
		if z == "" {
			t.Fatal("m5dyn needs zig to build against musl (set ZIG)")
		}
		dir = t.TempDir()
		src := func(n string) string { return filepath.Join("..", "..", "testdata", n+".c") }
		cc := []string{"cc", "-target", map[string]string{"amd64": "x86_64", "arm64": "aarch64"}[runtime.GOARCH] + "-linux-musl", "-O2"}
		for _, args := range [][]string{
			{"-shared", "-fPIC", "-Wl,-soname,libm5.so", "-o", filepath.Join(dir, "libm5.so"), src("libm5")},
			{"-shared", "-fPIC", "-Wl,-soname,libm5b.so", "-o", filepath.Join(dir, "libm5b.so"), src("libm5b")},
			{"-pthread", "-o", filepath.Join(dir, "m5dyn"), src("m5dyn"), "-L" + dir, "-lm5"},
			{"-o", filepath.Join(dir, "m5dlopen"), src("m5dlopen"), "-L" + dir, "-lm5b"},
		} {
			if b, err := exec.Command(z, append(cc, args...)...).CombinedOutput(); err != nil {
				t.Fatalf("zig %v: %v\n%s", args, err, b)
			}
		}
	}
	out := map[string][]byte{}
	for at, n := range files {
		b, err := os.ReadFile(filepath.Join(dir, n))
		if err != nil {
			t.Fatalf("%s is not staged (scripts/guests.sh): %v", n, err)
		}
		out[at] = b
	}
	return out
}

func runIn(t *testing.T, root, prog string, args ...string) (int, string, string) {
	t.Helper()
	return runCfg(t, root, nil, prog, args...)
}

// runCfg is runIn with the Config adjusted by mod (networking, egress).
func runCfg(t *testing.T, root string, mod func(*Config), prog string, args ...string) (int, string, string) {
	t.Helper()
	var out, errb bytes.Buffer
	cfg := Config{
		RootFS: HostRoot(root),
		Args:   args,
		Env:    []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin", "HOME=/root"},
		Stdin:  strings.NewReader(""),
		Stdout: &out,
		Stderr: &errb,
	}
	if mod != nil {
		mod(&cfg)
	}
	if testing.Verbose() && os.Getenv("LC_TRACE") != "" {
		cfg.Trace = os.Stderr
	}
	code, err := Run(context.Background(), prog, cfg)
	if err != nil {
		t.Fatalf("%s %v: Run: %v (stdout %q stderr %q)", prog, args, err, out.String(), errb.String())
	}
	return code, out.String(), errb.String()
}

// TestAlpine runs a real Alpine rootfs: dynamic
// programs start in ld-musl, which maps their libraries; each executable
// mapping is rewritten as it is mapped.
func TestAlpine(t *testing.T) {
	root := alpineRoot(t)
	cases := []struct {
		prog string
		args []string
		code int
		want []string
	}{
		{"/sbin/apk", []string{"apk", "--version"}, 0, []string{"apk-tools 2.14", "compiled for " + map[string]string{"amd64": "x86_64", "arm64": "aarch64"}[runtime.GOARCH]}},
		{"/bin/busybox", []string{"sh", "-c", "echo hi; x=$((6*7)); echo $x; exit 3"}, 3, []string{"hi\n42\n"}},
		{"/bin/sh", []string{"sh", "-c", "read v; echo got:$v"}, 0, []string{"got:\n"}},
		{"/bin/busybox", []string{"ls", "-l", "/"}, 0, []string{"drwxr-xr-x", " root ", " etc\n", " usr\n", "drwxrwxrwt"}},
		{"/bin/ls", []string{"ls", "-l", "/bin/sh"}, 0, []string{"lrwxrwxrwx", "/bin/sh -> /bin/busybox"}},
		{"/bin/busybox", []string{"cat", "/etc/os-release"}, 0, []string{"Alpine Linux v3.20"}},
		{"/bin/m5dyn", []string{"m5dyn"}, 0, []string{"v=9 len=5", "m5dyn OK"}},
		{"/bin/m5dlopen", []string{"m5dlopen"}, 0, []string{"zlib 1.", "m5dlopen OK"}},
	}
	for _, c := range cases {
		t.Run(strings.Join(c.args, " "), func(t *testing.T) {
			code, out, errs := runIn(t, root, c.prog, c.args...)
			ok := code == c.code
			for _, w := range c.want {
				ok = ok && strings.Contains(out, w)
			}
			if !ok {
				t.Fatalf("exit %d stdout %q stderr %q; want %d and %q", code, out, errs, c.code, c.want)
			}
		})
	}
}

// TestImageLookPath finds programs the way -image does, through the
// extracted rootfs's stored modes and symlinks.
func TestImageLookPath(t *testing.T) {
	root := alpineRoot(t)
	env := []string{"PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"}
	for name, want := range map[string]string{"apk": "/sbin/apk", "sh": "/bin/sh", "cat": "/bin/cat", "m5dyn": "/bin/m5dyn"} {
		if p, err := oci.LookPath(root, name, env); err != nil || p != want {
			t.Errorf("LookPath(%s) = %q, %v; want %q", name, p, err, want)
		}
	}
	if p, err := oci.LookPath(root, "os-release", []string{"PATH=/etc"}); err == nil {
		t.Errorf("LookPath(os-release) = %q, want not executable", p)
	}
}

// TestShell runs busybox sh scripts
// with subshells, command substitution, background jobs, exit statuses and
// traps, and pipelines through xargs, over Alpine's dynamic busybox.
func TestShell(t *testing.T) {
	root := alpineRoot(t)
	cases := []struct {
		name, script string
		code         int
		want         string
	}{
		{"subshell", "(exit 3); echo $?; (cd /etc && pwd); pwd", 0, "3\n/etc\n/\n"},
		{"substitution", "echo $(echo a $(echo b)) $(( $(echo 6) * 7 ))", 0, "a b 42\n"},
		{"background", "sleep 0.2 & p=$!; (exit 5) & q=$!; wait $q; echo q=$?; wait $p; echo p=$?", 0, "q=5\np=0\n"},
		{"status", "false; echo $?; ! true; echo $?; sh -c 'exit 9'; echo $?", 0, "1\n1\n9\n"},
		{"trap-term", "trap 'echo term; exit 4' TERM; kill -TERM $$; sleep 1; echo missed", 4, "term\n"},
		{"trap-chld", "trap 'echo chld' CHLD; sleep 0.1 & wait; echo end", 0, "chld\nend\n"},
		{"kill-bg", "sleep 5 & p=$!; kill $p; wait $p; echo $?", 0, "143\n"},
		{"pipe-grep", "ls / | grep b | wc -l", 0, "3\n"},
		{"xargs", "seq 1 1000 | xargs -n 10 echo | wc -l", 0, "100\n"},
		{"find-cat", "a=$(find /etc -type f | xargs cat | wc -c); b=$(cat $(find /etc -type f) | wc -c); [ $a -gt 1000 ] && [ $a = $b ] && echo same", 0, "same\n"},
		{"sigpipe", "yes | head -n 1000 | wc -l; yes | head -n 1", 0, "1000\ny\n"},
		{"sigpipe-status", "sh -c 'yes | (head -n 1 >/dev/null; sleep 0.2); echo done'", 0, "done\n"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			code, out, errs := runIn(t, root, "/bin/sh", "sh", "-c", c.script)
			if code != c.code || out != c.want {
				t.Fatalf("exit %d stdout %q stderr %q; want %d and %q", code, out, errs, c.code, c.want)
			}
		})
	}
}

// TestProcesses runs m4proc: fork, execve of a dynamic program,
// posix_spawn, system, vfork, waitpid with WNOHANG and the status macros,
// kill of a process group, fork from a multithreaded parent (only the caller
// survives), MAP_SHARED memory and a futex shared across fork; then fork+exec
// timing.
func TestProcesses(t *testing.T) {
	root := alpineRoot(t)
	for _, c := range []string{"fork", "exec", "spawn", "pgrp", "mt", "shm", "killread", "killwrite", "abortpipe", "abortsleep", "jit", "bench"} {
		t.Run(c, func(t *testing.T) {
			code, out, errs := runIn(t, root, "/bin/m4proc", "m4proc", c)
			if code != 0 || !strings.Contains(out, c+" OK") {
				t.Fatalf("exit %d stdout %q stderr %q", code, out, errs)
			}
			if c == "bench" || c == "jit" {
				t.Log(strings.TrimSpace(out))
			}
		})
	}
}

// TestNet: sockets served by the supervisor. m6net runs a local TCP server
// and client (nonblocking connect, poll, epoll edge- and level-triggered,
// shutdown, a bulk transfer), signals interrupting each kind of network wait,
// AF_UNIX stream sockets with SCM_RIGHTS, socketpairs across fork, UDP and
// eventfd; busybox nc and httpd
// serve a request; DNS resolves through the supervisor's proxy; busybox wget
// fetches an HTTP page; and the egress allowlist refuses the rest.
func TestNet(t *testing.T) {
	root := alpineRoot(t)
	netOn := func(c *Config) { c.Net = true }
	allow := func(c *Config) { c.Net, c.AllowDomains = true, []string{"example.com"} }
	type tc struct {
		name string
		mod  func(*Config)
		prog string
		args []string
		code int // -1: any non-zero
		want []string
	}
	page := os.Getenv("LC_NET_URL")
	if page == "" {
		page = "http://example.com/"
	}
	cases := []tc{
		{"tcp", netOn, "/bin/m6net", []string{"m6net", "tcp"}, 0, []string{"tcp OK"}},
		{"eintr", netOn, "/bin/m6net", []string{"m6net", "eintr"}, 0, []string{"eintr OK"}},
		{"unix", nil, "/bin/m6net", []string{"m6net", "unix"}, 0, []string{"unix OK"}},
		{"pair", nil, "/bin/m6net", []string{"m6net", "pair"}, 0, []string{"pair OK"}},
		{"udp", netOn, "/bin/m6net", []string{"m6net", "udp"}, 0, []string{"udp OK"}},
		{"eventfd", nil, "/bin/m6net", []string{"m6net", "eventfd"}, 0, []string{"eventfd OK"}},
		{"ifaddrs", nil, "/bin/m6net", []string{"m6net", "ifaddrs"}, 0, []string{"ifaddrs OK"}},
		{"ifaddrs-net", netOn, "/bin/m6net", []string{"m6net", "ifaddrs", "net"}, 0, []string{"ifaddrs OK"}},
		{"ip", nil, "/bin/busybox", []string{"ip", "addr"}, 0, []string{"lo", "127.0.0.1"}},
		{"nonet", nil, "/bin/sh", []string{"sh", "-c", "wget -q -O - http://127.0.0.1:1/ 2>&1; echo rc=$?"}, 0, []string{"rc=1"}},
		{"nc", netOn, "/bin/sh", []string{"sh", "-c", "nc -l -p 9000 > /tmp/nc.out & sleep 1; echo hi-nc | nc 127.0.0.1 9000; wait; cat /tmp/nc.out"}, 0, []string{"hi-nc"}},
		{"httpd", netOn, "/bin/sh", []string{"sh", "-c", "mkdir -p /www && echo served > /www/index.html && busybox-extras httpd -p 127.0.0.1:8080 -h /www && wget -q -O - http://127.0.0.1:8080/index.html"}, 0, []string{"served"}},
		{"dns", netOn, "/bin/m6net", []string{"m6net", "dns", "example.com"}, 0, []string{"example.com -> ", "dns OK"}},
		{"nslookup", netOn, "/bin/busybox", []string{"nslookup", "example.com"}, 0, []string{"Name:", "example.com", "Address"}},
		{"wget", netOn, "/bin/busybox", []string{"wget", "-q", "-O", "-", page}, 0, []string{"Example Domain"}},
		{"allowed", allow, "/bin/busybox", []string{"wget", "-q", "-O", "-", page}, 0, []string{"Example Domain"}},
		{"denied-dns", allow, "/bin/m6net", []string{"m6net", "dns", "example.org", "denied"}, 0, []string{"dns OK"}},
		{"denied-wget", allow, "/bin/busybox", []string{"wget", "-q", "-O", "-", "http://example.org/"}, -1, nil},
		{"denied-ip", allow, "/bin/busybox", []string{"wget", "-q", "-T", "10", "-O", "-", "http://1.1.1.1/"}, -1, nil},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			code, out, errs := runCfg(t, root, c.mod, c.prog, c.args...)
			ok := code == c.code || c.code == -1 && code != 0
			for _, w := range c.want {
				ok = ok && strings.Contains(out, w)
			}
			if !ok {
				t.Fatalf("exit %d stdout %q stderr %q; want %d and %q", code, out, errs, c.code, c.want)
			}
			if c.name == "dns" || strings.HasPrefix(c.name, "denied") {
				t.Logf("exit %d: %s%s", code, strings.TrimSpace(out), strings.TrimSpace(errs))
			}
		})
	}
}

// TestTTY drives guest ptys: m7tty
// drives each case through /dev/ptmx as script and expect do. pty: the line
// discipline across a pair; termios: every flag round-tripped on a
// controlling terminal; tty: isatty, ttyname, TIOCGWINSZ and SIGWINCH;
// ttin: background reads and writes stop with SIGTTIN and SIGTTOU; wait:
// WUNTRACED and WCONTINUED; sh: an interactive busybox sh with line editing,
// ^C, ^Z, jobs, bg and fg; vi and less.
func TestTTY(t *testing.T) {
	root := alpineRoot(t)
	for _, c := range []string{"pty", "termios", "tty", "ttin", "wait", "sh", "vi", "less"} {
		t.Run(c, func(t *testing.T) {
			start := time.Now()
			code, out, errs := runIn(t, root, "/bin/m7tty", "m7tty", c)
			if code != 0 || !strings.Contains(out, c+" OK") {
				t.Fatalf("exit %d stdout %q stderr %q", code, out, errs)
			}
			t.Logf("%s in %v", c, time.Since(start).Round(time.Millisecond))
		})
	}
}
