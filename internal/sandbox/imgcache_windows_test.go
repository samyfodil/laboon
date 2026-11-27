package sandbox

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/samyfodil/laboon/internal/rewrite"
)

// TestImgCacheReused: a program in the root's lower layer is saved to the
// cache directory's img store on its first run and mapped from it on the next.
func TestImgCacheReused(t *testing.T) {
	root, prog := guestRoot(t, "hello")
	dir := t.TempDir()
	run := func() {
		var o bytes.Buffer
		code, err := Run(context.Background(), prog, Config{RootFS: HostRoot(root), Args: []string{"hello"}, Cache: rewrite.NewCache(dir), Stdout: &o, Stderr: &o})
		if err != nil || code != 7 {
			t.Fatalf("code=%d err=%v\n%s", code, err, o.String())
		}
	}
	entries := func() []string {
		ents, err := os.ReadDir(filepath.Join(dir, "img"))
		if err != nil && !os.IsNotExist(err) {
			t.Fatal(err)
		}
		var names []string
		for _, e := range ents {
			names = append(names, e.Name())
		}
		return names
	}
	run()
	first := entries()
	if len(first) == 0 {
		t.Fatal("the first run saved no image")
	}
	run()
	if second := entries(); strings.Join(second, ",") != strings.Join(first, ",") {
		t.Fatalf("the second run changed the store: %v, then %v", first, second)
	}
}
