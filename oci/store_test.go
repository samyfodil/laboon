package oci

import (
	"os"
	"path/filepath"
	"sync"
	"testing"

	"github.com/google/go-containerregistry/pkg/v1/random"
)

// Stores of one image at once all end with the same whole rootfs: the image's
// lock lets one unpack it and the rest find it done.
func TestStoreConcurrent(t *testing.T) {
	img, err := random.Image(4096, 3)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	var wg sync.WaitGroup
	roots := make([]string, 8)
	errs := make([]error, 8)
	for i := range roots {
		wg.Add(1)
		go func() {
			defer wg.Done()
			out, err := Store(img, "example.com/img:1", Options{CacheDir: dir})
			if err == nil {
				roots[i] = out.Root
			}
			errs[i] = err
		}()
	}
	wg.Wait()
	for i, err := range errs {
		if err != nil {
			t.Fatalf("store %d: %v", i, err)
		}
		if roots[i] != roots[0] {
			t.Fatalf("store %d at %s, store 0 at %s", i, roots[i], roots[0])
		}
	}
	if n := countFiles(t, roots[0]); n == 0 {
		t.Fatal("empty rootfs")
	}
	if _, err := os.Stat(filepath.Join(filepath.Dir(roots[0]), "config.json")); err != nil {
		t.Fatal(err)
	}
}

// A rootfs without its config is one an unpack or a removal left half done:
// the next store unpacks it afresh.
func TestStoreRedoesHalfUnpack(t *testing.T) {
	img, err := random.Image(4096, 2)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	out, err := Store(img, "example.com/img:1", Options{CacheDir: dir})
	if err != nil {
		t.Fatal(err)
	}
	want := countFiles(t, out.Root)
	cfg := filepath.Join(filepath.Dir(out.Root), "config.json")
	if err := os.Remove(cfg); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(out.Root, "left-behind"), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Store(img, "example.com/img:1", Options{CacheDir: dir}); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(out.Root, "left-behind")); err == nil {
		t.Fatal("the half-done rootfs was kept")
	}
	if got := countFiles(t, out.Root); got != want {
		t.Fatalf("%d files, want %d", got, want)
	}
	if _, err := os.Stat(cfg); err != nil {
		t.Fatal(err)
	}
}

func countFiles(t *testing.T, root string) int {
	t.Helper()
	n := 0
	err := filepath.WalkDir(root, func(p string, d os.DirEntry, err error) error {
		if err == nil && !d.IsDir() {
			n++
		}
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	return n
}
