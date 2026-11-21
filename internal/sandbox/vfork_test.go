package sandbox

import (
	"bytes"
	"context"
	"strings"
	"testing"
	"time"
)

func TestVforkLifecycle(t *testing.T) {
	for _, name := range []string{"execspawn", "vforkhold"} {
		t.Run(name, func(t *testing.T) {
			root, exe := guestRoot(t, name)
			ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
			defer cancel()
			var out bytes.Buffer
			code, err := Run(ctx, exe, Config{Args: []string{exe}, RootFS: HostRoot(root), Stdout: &out, Stderr: &out})
			if err != nil || code != 0 || !strings.HasSuffix(out.String(), "OK\n") {
				t.Fatalf("code=%d err=%v out=%q", code, err, out.String())
			}
		})
	}
}

// posix_spawn from glibc and musl: clone(CLONE_VM|CLONE_VFORK) on a stack of
// the child's own.
func TestPosixSpawn(t *testing.T) {
	for _, name := range []string{"spawn", "spawn+musl"} {
		root, prog := guestRoot(t, name)
		addGuest(t, root, "hello")
		var o bytes.Buffer
		code, err := Run(context.Background(), prog, Config{Args: []string{"spawn", "/hello"}, RootFS: HostRoot(root), Stdout: &o, Stderr: &o})
		want := "argv[1]=spawned\nchild exit 7\nmissing: No such file or directory\n"
		if err != nil || code != 0 || !strings.HasSuffix(o.String(), want) {
			t.Errorf("%s: code=%d err=%v out=%q", name, code, err, o.String())
		}
	}
}
