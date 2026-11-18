package oci

import (
	"archive/tar"
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func layer(t *testing.T, entries ...tar.Header) *bytes.Buffer {
	t.Helper()
	var b bytes.Buffer
	tw := tar.NewWriter(&b)
	for _, h := range entries {
		body := []byte("x")
		if h.Typeflag == tar.TypeReg {
			h.Size = int64(len(body))
		}
		if err := tw.WriteHeader(&h); err != nil {
			t.Fatal(err)
		}
		if h.Typeflag == tar.TypeReg {
			tw.Write(body)
		}
	}
	tw.Close()
	return &b
}

func TestUnpackStaysInRoot(t *testing.T) {
	parent := t.TempDir()
	dir := filepath.Join(parent, "rootfs")
	os.Mkdir(dir, 0o755)
	tr := layer(t,
		tar.Header{Name: "../escape", Typeflag: tar.TypeReg, Mode: 0o644},
		tar.Header{Name: "evil", Typeflag: tar.TypeSymlink, Linkname: parent},
		tar.Header{Name: "evil/through-symlink", Typeflag: tar.TypeReg, Mode: 0o644},
		tar.Header{Name: "bin/suid", Typeflag: tar.TypeReg, Mode: 0o4755},
		tar.Header{Name: "dev/sda", Typeflag: tar.TypeBlock, Mode: 0o600},
	)
	// The symlinked write must fail rather than land outside.
	if err := Unpack(tr, dir, 1<<20); err == nil {
		t.Fatal("write through an escaping symlink succeeded")
	}
	if _, err := os.Stat(filepath.Join(parent, "escape")); err == nil {
		t.Fatal("../escape was written outside the rootfs")
	}
	if _, err := os.Stat(filepath.Join(parent, "through-symlink")); err == nil {
		t.Fatal("file written through symlink outside the rootfs")
	}
}

func TestUnpackModesAndDevices(t *testing.T) {
	dir := t.TempDir()
	tr := layer(t,
		tar.Header{Name: "escape-attempt/../../ok", Typeflag: tar.TypeReg, Mode: 0o644},
		tar.Header{Name: "bin/suid", Typeflag: tar.TypeReg, Mode: 0o4755},
		tar.Header{Name: "dev/sda", Typeflag: tar.TypeBlock, Mode: 0o600},
		tar.Header{Name: "bin/hard", Typeflag: tar.TypeLink, Linkname: "bin/suid"},
	)
	if err := Unpack(tr, dir, 1<<20); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(dir, "ok")); err != nil {
		t.Fatal("cleaned path not written inside the rootfs")
	}
	st, err := os.Stat(filepath.Join(dir, "bin/suid"))
	if err != nil {
		t.Fatal(err)
	}
	if st.Mode()&os.ModeSetuid != 0 || st.Mode().Perm() != 0o755 {
		t.Fatalf("mode = %v, want 0755 without setuid", st.Mode())
	}
	if _, err := os.Lstat(filepath.Join(dir, "dev/sda")); err == nil {
		t.Fatal("device node created")
	}
	if _, err := os.Stat(filepath.Join(dir, "bin/hard")); err != nil {
		t.Fatal("hard link missing")
	}
}

func TestUnpackSizeLimit(t *testing.T) {
	tr := layer(t, tar.Header{Name: "a", Typeflag: tar.TypeReg, Mode: 0o644})
	if err := Unpack(tr, t.TempDir(), 0); err != errTooLarge {
		t.Fatalf("err = %v, want errTooLarge", err)
	}
}

// TestPullArch refuses an architecture the sandbox does not run before it
// touches the network.
func TestPullArch(t *testing.T) {
	_, err := Pull(context.Background(), "alpine:3.20", Options{CacheDir: t.TempDir(), Arch: "riscv64"})
	if err == nil || !strings.Contains(err.Error(), "linux/riscv64") {
		t.Fatalf("err = %v", err)
	}
}
