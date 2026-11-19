//go:build linux || darwin

package laboon

import (
	"bytes"
	"context"
	"io"
	"os"
	"strings"
	"testing"
	"time"
)

// TestComposedRootOverImage composes a guest root from an unpacked OCI image as
// the lower layer and an in-memory FileSystem as the writable upper, and runs a
// real guest on it through the public API alone. The guest loads and execs a
// binary that exists only in the image layer, then writes a file that must land
// in the in-memory upper -- never touching the host image directory. It proves a
// composed filesystem is a real guest root and can be layered over an image.
func TestComposedRootOverImage(t *testing.T) {
	root := os.Getenv("LC_IMAGE_ROOT") // an unpacked image rootfs, as oci.Pull's Image.Root
	if root == "" {
		t.Skip("set LC_IMAGE_ROOT to an unpacked rootfs with /bin/busybox")
	}
	upper := NewMemFS()
	composed := Overlay(NewDirFS(root), upper) // image lower + in-memory upper, copy-on-write

	var out bytes.Buffer
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()
	code, err := Run(ctx, "/bin/busybox",
		WithArgs("sh", "-c", "test -x /bin/busybox && echo FROM-IMAGE=ok; echo COMPOSED-UPPER > /over.txt; cat /over.txt"),
		WithFS("/", composed),
		WithStdout(&out), WithStderr(&out))
	if err != nil || code != 0 {
		t.Fatalf("code=%d err=%v out=%q", code, err, out.String())
	}
	o := out.String()
	if !strings.Contains(o, "FROM-IMAGE=ok") { // a read served from the image layer
		t.Fatalf("did not read from the image layer: out=%q", o)
	}
	if !strings.Contains(o, "COMPOSED-UPPER") {
		t.Fatalf("overlay write/read failed: out=%q", o)
	}
	// The write landed in the in-memory upper...
	if b := readUpper(t, upper, "over.txt"); strings.TrimSpace(string(b)) != "COMPOSED-UPPER" {
		t.Fatalf("upper /over.txt = %q, want COMPOSED-UPPER", b)
	}
	// ...and never reached the host image directory.
	if _, err := os.Stat(root + "/over.txt"); !os.IsNotExist(err) {
		t.Fatal("overlay write leaked into the host image directory")
	}
}

func readUpper(t *testing.T, fsys FileSystem, name string) []byte {
	t.Helper()
	n, err := fsys.Lookup(fsys.Root(), name)
	if err != nil {
		t.Fatal(err)
	}
	f, err := n.Open(0)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	b := make([]byte, 256)
	k, err := f.ReadAt(b, 0)
	if err != nil && err != io.EOF {
		t.Fatal(err)
	}
	return b[:k]
}
