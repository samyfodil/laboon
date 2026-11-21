package sandbox

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// With no root filesystem the guest sees nothing of the host's: not a host file,
// not a host directory to write into (testdata/noroot.c).
func TestNoRootNoHostView(t *testing.T) {
	bin := guestPath(t, "noroot")
	dir := t.TempDir()
	secret := filepath.Join(dir, "secret")
	if err := os.WriteFile(secret, []byte("host"), 0o644); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()
	var o bytes.Buffer
	code, err := Run(ctx, bin, Config{Args: []string{bin, secret, dir}, Stdout: &o, Stderr: &o})
	t.Log(strings.TrimSpace(o.String()))
	if _, serr := os.Stat(filepath.Join(dir, "made-by-guest")); serr == nil {
		t.Errorf("the guest created a file in the host directory %s", dir)
	}
	if err != nil || code != 0 || !strings.Contains(o.String(), "done fails=0") {
		t.Fatalf("code=%d err=%v\n%s", code, err, o.String())
	}
}
