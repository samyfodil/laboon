//go:build linux

package sandbox

import (
	"bytes"
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// TestCreateRace: a file another process of the same non-root user creates is
// never seen owned by anyone else, in an image's overlay or on the host root
// (testdata/createrace.c).
func TestCreateRace(t *testing.T) {
	dir := t.TempDir()
	lower := filepath.Join(dir, "lower")
	upper := filepath.Join(dir, "upper")
	for _, d := range []string{lower, upper} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	bin := filepath.Join(lower, "createrace")
	if b, err := exec.Command("gcc", "-O2", "-static", "-o", bin, "../../testdata/createrace.c").CombinedOutput(); err != nil {
		t.Skipf("static gcc unavailable: %v\n%s", err, b)
	}
	for _, c := range []struct {
		name string
		cfg  Config
		prog string
	}{
		{"overlay", Config{Args: []string{"createrace", "/work"}, RootFS: HostRoot(lower), Upper: upper}, "/createrace"},
		{"host", Config{Args: []string{"createrace", filepath.Join(dir, "work")}, RootFS: HostRoot("/")}, bin},
	} {
		t.Run(c.name, func(t *testing.T) {
			var o bytes.Buffer
			c.cfg.Stdout, c.cfg.Stderr = &o, &o
			code, err := Run(context.Background(), c.prog, c.cfg)
			if err != nil || code != 0 || !strings.Contains(o.String(), "createrace fails=0") {
				t.Fatalf("code = %d, err = %v, out:\n%s", code, err, o.String())
			}
		})
	}
}
