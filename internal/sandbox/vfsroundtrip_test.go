//go:build linux

package sandbox

import (
	"bytes"
	"context"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/samyfodil/laboon/filesystems/hostfs"
	"github.com/samyfodil/laboon/oci"
)

// TestVFSRoundTrip is the overlay serialization gate: a guest writes a rich
// change set over a known lower (vfsmutate), its kept upper is serialized to an
// OCI tar, reloaded and materialized onto a fresh copy of the lower, and a
// second guest (vfscheck) runs over the result and asserts every change — new
// files, a sub-0600 mode, a nested dir, a symlink, a whiteout and two copied-up
// lower files — survived the run -> serialize -> reload -> run round trip.
func TestVFSRoundTrip(t *testing.T) {
	dir := t.TempDir()
	lower := filepath.Join(dir, "lower")
	upper1 := filepath.Join(dir, "upper1")
	merged := filepath.Join(dir, "merged")
	upper2 := filepath.Join(dir, "upper2")
	for _, d := range []string{lower, upper1, upper2} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	for name, body := range map[string]string{
		"keep.txt": "keep", "gone.txt": "x", "mod.txt": "orig",
	} {
		if err := os.WriteFile(filepath.Join(lower, name), []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}

	mutate := buildGuest(t, lower, "vfsmutate")
	check := buildGuest(t, lower, "vfscheck")

	// Run 1: produce the change set in upper1.
	var out bytes.Buffer
	code, err := Run(context.Background(), "/"+filepath.Base(mutate), Config{
		Args: []string{"/" + filepath.Base(mutate)}, RootFS: HostRoot(lower), Upper: upper1,
		Stdout: &out, Stderr: &out,
	})
	if err != nil || code != 0 {
		t.Fatalf("vfsmutate code %d err %v\n%s", code, err, out.String())
	}

	// Serialize upper1 to an OCI tar and reload it — the heart of the round trip.
	l1, err := hostfs.LayerFromDir(upper1)
	if err != nil {
		t.Fatal(err)
	}
	var tarBuf bytes.Buffer
	if err := oci.WriteTar(l1.ChangeSet(), &tarBuf); err != nil {
		t.Fatalf("WriteTar: %v", err)
	}
	l2, err := oci.ReadTar(&tarBuf, filepath.Join(dir, "reload"))
	if err != nil {
		t.Fatalf("ReadTar: %v", err)
	}

	// Materialize the reloaded layer over a fresh copy of the lower: the merged
	// view becomes the read-only lower of run 2.
	if err := copyDir(lower, merged); err != nil {
		t.Fatal(err)
	}
	if err := l2.ApplyTo(merged); err != nil {
		t.Fatalf("ApplyTo: %v", err)
	}

	// Run 2: vfscheck asserts the merged lower reflects run 1 exactly.
	out.Reset()
	code, err = Run(context.Background(), "/"+filepath.Base(check), Config{
		Args: []string{"/" + filepath.Base(check)}, RootFS: HostRoot(merged), Upper: upper2,
		Stdout: &out, Stderr: &out,
	})
	if err != nil || code != 0 {
		t.Fatalf("vfscheck code %d err %v\n%s", code, err, out.String())
	}
}

// buildGuest compiles testdata/<name>.c statically into the lower as /<name>.
func buildGuest(t *testing.T, lower, name string) string {
	t.Helper()
	bin := filepath.Join(lower, name)
	if b, err := exec.Command("gcc", "-O2", "-static", "-w", "-o", bin, "../../testdata/"+name+".c").CombinedOutput(); err != nil {
		t.Skipf("build %s: %v\n%s", name, err, b)
	}
	return bin
}

func copyDir(src, dst string) error {
	return filepath.WalkDir(src, func(p string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(src, p)
		if err != nil {
			return err
		}
		target := filepath.Join(dst, rel)
		if d.IsDir() {
			return os.MkdirAll(target, 0o755)
		}
		in, err := os.Open(p)
		if err != nil {
			return err
		}
		defer in.Close()
		fi, err := d.Info()
		if err != nil {
			return err
		}
		o, err := os.OpenFile(target, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, fi.Mode().Perm())
		if err != nil {
			return err
		}
		if _, err := io.Copy(o, in); err != nil {
			o.Close()
			return err
		}
		return o.Close()
	})
}
