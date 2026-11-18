//go:build linux

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

// TestGetdentsDirIdentity checks that a directory fd keeps enumerating the
// directory it was opened on: an impostor renamed onto the path is not listed
// (even after rewind), a rename of the opened directory is followed, and a
// copy-up triggered by a write does not make the directory look replaced.
func TestGetdentsDirIdentity(t *testing.T) {
	dir := t.TempDir()
	lower := filepath.Join(dir, "lower")
	upper := filepath.Join(dir, "upper")
	for _, d := range []string{lower, upper, filepath.Join(lower, "pre")} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	// A lower-layer entry so opening /pre and then writing into it copies the
	// directory up while the fd is held (Case C in the guest).
	if err := os.WriteFile(filepath.Join(lower, "pre", "lo"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}

	bin := buildGuest(t, lower, "getdentsdir")
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	var out bytes.Buffer
	code, err := Run(ctx, "/"+filepath.Base(bin), Config{
		Args: []string{"/" + filepath.Base(bin)}, RootFS: HostRoot(lower), Upper: upper,
		Stdout: &out, Stderr: &out,
	})
	s := out.String()
	if err != nil || code != 0 || !strings.Contains(s, "GETDENTS-DONE") {
		t.Fatalf("code=%d err=%v out=%q", code, err, s)
	}
	t.Logf("getdentsdir output:\n%s", s)
	for _, want := range []string{
		"replaceHidesImpostor=1", // a different dir renamed onto the path is not listed
		"moveFollows=1",          // the opened dir's own rename is followed
		"copyUpStable=1",         // copy-up does not look like a replacement
	} {
		if !strings.Contains(s, want) {
			t.Errorf("missing %q in guest output:\n%s", want, s)
		}
	}
}
