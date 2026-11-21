//go:build linux

package sandbox

import (
	"bytes"
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

func TestVforkLifecycle(t *testing.T) {
	for _, name := range []string{"execspawn", "vforkhold"} {
		t.Run(name, func(t *testing.T) {
			exe := filepath.Join(t.TempDir(), name)
			if b, err := exec.Command("gcc", "-O2", "-static", "-pthread", "-o", exe, "../../testdata/"+name+".c").CombinedOutput(); err != nil {
				t.Skipf("static gcc unavailable: %v\n%s", err, b)
			}
			ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
			defer cancel()
			var out bytes.Buffer
			code, err := Run(ctx, exe, Config{Args: []string{exe}, RootFS: HostRoot("/"), Stdout: &out, Stderr: &out})
			if err != nil || code != 0 || !strings.HasSuffix(out.String(), "OK\n") {
				t.Fatalf("code=%d err=%v out=%q", code, err, out.String())
			}
		})
	}
}

// posix_spawn from glibc and musl: clone(CLONE_VM|CLONE_VFORK) on a stack of
// the child's own.
func TestPosixSpawn(t *testing.T) {
	dir := t.TempDir()
	hello := filepath.Join(dir, "hello")
	builds := map[string][]string{
		hello:                             {"gcc", "-O2", "-static", "-o", hello, "../../testdata/hello.c"},
		filepath.Join(dir, "spawn-glibc"): {"gcc", "-O2", "-static", "-o", filepath.Join(dir, "spawn-glibc"), "../../testdata/spawn.c"},
	}
	if z := zigCC(); z != "" {
		musl := filepath.Join(dir, "spawn-musl")
		target := map[string]string{"amd64": "x86_64", "arm64": "aarch64"}[runtime.GOARCH] + "-linux-musl"
		builds[musl] = []string{z, "cc", "-target", target, "-O2", "-static", "-o", musl, "../../testdata/spawn.c"}
	}
	for _, c := range builds {
		if b, err := exec.Command(c[0], c[1:]...).CombinedOutput(); err != nil {
			t.Skipf("build: %v\n%s", err, b)
		}
	}
	for exe := range builds {
		if exe == hello {
			continue
		}
		var o bytes.Buffer
		prog := "/" + filepath.Base(exe)
		code, err := Run(context.Background(), prog, Config{Args: []string{"spawn", "/hello"}, RootFS: HostRoot(dir), Stdout: &o, Stderr: &o})
		want := "argv[1]=spawned\nchild exit 7\nmissing: No such file or directory\n"
		if err != nil || code != 0 || !strings.HasSuffix(o.String(), want) {
			t.Errorf("%s: code=%d err=%v out=%q", filepath.Base(exe), code, err, o.String())
		}
	}
}

func TestPythonSubprocess(t *testing.T) {
	if _, err := os.Stat("/usr/bin/python3"); err != nil {
		t.Skip("no python3")
	}
	script := `import os, subprocess
print(subprocess.run(["/bin/echo", "sub-ok"], capture_output=True).stdout.decode().strip())
try:
    subprocess.run(["/nonexistent"])
except FileNotFoundError:
    print("missing-ok")
pid = os.posix_spawn("/bin/sh", ["sh", "-c", "exit 3"], os.environ)
print("spawn", os.waitstatus_to_exitcode(os.waitpid(pid, 0)[1]))
`
	var o bytes.Buffer
	code, err := Run(context.Background(), "/usr/bin/python3", Config{Args: []string{"python3", "-c", script}, Stdout: &o, Stderr: &o, RootFS: HostRoot("/")})
	if err != nil || code != 0 || o.String() != "sub-ok\nmissing-ok\nspawn 3\n" {
		t.Fatalf("code=%d err=%v out=%q", code, err, o.String())
	}
}
