package oci

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/google/go-containerregistry/pkg/name"
)

// mkImage lays down an unpacked image dir/<hex> with a rootfs holding a file of
// the given size and a minimal config.
func mkImage(t *testing.T, dir, hex string, size int) {
	t.Helper()
	root := filepath.Join(dir, hex, "rootfs")
	if err := os.MkdirAll(root, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "data"), make([]byte, size), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, hex, "config.json"), []byte(`{}`), 0o600); err != nil {
		t.Fatal(err)
	}
}

// mkRef points ref at image hex, as remember does.
func mkRef(t *testing.T, dir, ref, hex string) {
	t.Helper()
	r, err := name.ParseReference(ref)
	if err != nil {
		t.Fatal(err)
	}
	p := refFileFor(dir, r, runtime.GOARCH)
	if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(hex+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
}

func exists(dir, hex string) bool {
	_, err := os.Stat(filepath.Join(dir, hex))
	return err == nil
}

func TestLocalRemoveSweep(t *testing.T) {
	dir := t.TempDir()
	opt := Options{CacheDir: dir}
	h1 := strings.Repeat("a", 64)
	h2 := strings.Repeat("b", 64)
	h3 := strings.Repeat("c", 64) // an orphan: no ref names it
	mkImage(t, dir, h1, 1000)
	mkImage(t, dir, h2, 2000)
	mkImage(t, dir, h3, 500)
	mkRef(t, dir, "img-a", h1)
	mkRef(t, dir, "img-b", h1) // a second ref to the same image
	mkRef(t, dir, "img-c", h2)

	// Local: a cached ref resolves to its digest; an unknown one is an error.
	im, err := Local("img-a", opt)
	if err != nil {
		t.Fatalf("Local(img-a): %v", err)
	}
	if im.Digest != "sha256:"+h1 {
		t.Fatalf("digest = %q, want sha256:%s", im.Digest, h1)
	}
	if _, err := Local("img-x", opt); err == nil {
		t.Fatal("Local of an uncached ref should error")
	}

	// Remove drops a ref but keeps the image while another ref names it.
	if err := Remove("img-a", opt); err != nil {
		t.Fatal(err)
	}
	if !exists(dir, h1) {
		t.Fatal("image removed while img-b still names it")
	}
	if err := Remove("img-b", opt); err != nil {
		t.Fatal(err)
	}
	if exists(dir, h1) {
		t.Fatal("image kept after its last ref went")
	}
	if err := Remove("img-a", opt); err != nil { // already gone: not an error
		t.Fatalf("Remove of a gone ref: %v", err)
	}

	// Sweep with no budget removes only the orphan; a named image stays.
	if _, err := Sweep(opt, 0); err != nil {
		t.Fatal(err)
	}
	if exists(dir, h3) {
		t.Fatal("orphan not swept")
	}
	if !exists(dir, h2) {
		t.Fatal("a referenced image was swept with no budget")
	}

	// Sweep under a tiny budget removes the referenced image and its ref too.
	if _, err := Sweep(opt, 1); err != nil {
		t.Fatal(err)
	}
	if exists(dir, h2) {
		t.Fatal("over-budget image not swept")
	}
	if _, err := Local("img-c", opt); err == nil {
		t.Fatal("ref of a swept image should be gone")
	}
}
