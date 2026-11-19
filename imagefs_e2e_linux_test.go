//go:build linux

package laboon

import (
	"archive/tar"
	"bytes"
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/google/go-containerregistry/pkg/v1/empty"
	"github.com/google/go-containerregistry/pkg/v1/mutate"
	"github.com/google/go-containerregistry/pkg/v1/tarball"

	"github.com/samyfodil/laboon/oci"
)

// TestImageFSRunEndToEnd proves the whole no-unpack path: a real binary, placed
// in an image layer tar and reached through a layer symlink, runs under laboon
// from a filesystem composed with oci.ImageFS (lazy TarFS layers + an on-disk
// writable upper) -- never extracted to a directory tree.
func TestImageFSRunEndToEnd(t *testing.T) {
	gcc, err := exec.LookPath("gcc")
	if err != nil {
		t.Skip("gcc not available")
	}
	dir := t.TempDir()
	src := filepath.Join(dir, "g.c")
	if err := os.WriteFile(src, []byte("#include <unistd.h>\nint main(){write(1,\"LABOON-OK\\n\",10);_exit(0);}\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	bin := filepath.Join(dir, "g")
	if out, err := exec.Command(gcc, "-static", "-O2", "-o", bin, src).CombinedOutput(); err != nil {
		t.Skipf("static gcc build unavailable: %v %s", err, out)
	}
	data, err := os.ReadFile(bin)
	if err != nil {
		t.Fatal(err)
	}

	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	tw.WriteHeader(&tar.Header{Name: "app", Typeflag: tar.TypeReg, Mode: 0o755, Size: int64(len(data)), ModTime: time.Unix(1700000000, 0)})
	tw.Write(data)
	tw.WriteHeader(&tar.Header{Name: "run", Typeflag: tar.TypeSymlink, Linkname: "app", ModTime: time.Unix(1700000000, 0)})
	tw.Close()
	layer, err := tarball.LayerFromReader(bytes.NewReader(buf.Bytes()))
	if err != nil {
		t.Fatal(err)
	}
	img, err := mutate.AppendLayers(empty.Image, layer)
	if err != nil {
		t.Fatal(err)
	}

	upper := t.TempDir()
	fsys, closeFS, err := oci.ImageFS(img, upper)
	if err != nil {
		t.Fatal(err)
	}
	defer closeFS()

	var out bytes.Buffer
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	code, err := Run(ctx, "/run", WithArgs("run"), WithRootFS(fsys), WithStdout(&out), WithStderr(&out))
	if err != nil || code != 0 {
		t.Fatalf("code=%d err=%v out=%q", code, err, out.String())
	}
	if !strings.Contains(out.String(), "LABOON-OK") {
		t.Fatalf("missing output, got %q", out.String())
	}
}
