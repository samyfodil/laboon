package sandbox

import (
	"bytes"
	"context"
	"testing"

	"github.com/samyfodil/laboon/internal/rewrite"
)

// TestTextWrite: a program makes its own text writable, writes it (a byte
// back, then a syscall over a padding function) and runs it again: the
// written syscall is served as the guest's. The second run maps the program
// from the image the first saved, where a host keeps one (Windows).
func TestTextWrite(t *testing.T) {
	root, prog := guestRoot(t, "textwrite")
	cache := rewrite.NewCache(t.TempDir())
	for i := range 2 {
		var o bytes.Buffer
		code, err := Run(context.Background(), prog, Config{RootFS: HostRoot(root), Args: []string{"textwrite"}, Cache: cache, Stdout: &o, Stderr: &o})
		if err != nil || code != 0 || o.String() != "text written, seven()=7, written getpid ok\n" {
			t.Fatalf("run %d: code=%d err=%v\n%s", i+1, code, err, o.String())
		}
	}
}
