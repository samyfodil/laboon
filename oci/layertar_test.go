package oci

import (
	"archive/tar"
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"github.com/samyfodil/laboon/core"
	"github.com/samyfodil/laboon/internal/vfs/hostfs"
)

// TestLayerTarRoundTrip builds a vfs layer, serializes it to an OCI tar and
// reads it back, checking files, a symlink, a hardlink, a whiteout, an opaque
// directory and a mode/owner the host file need not hold all survive.
func TestLayerTarRoundTrip(t *testing.T) {
	l, err := hostfs.NewLayer(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	must := func(err error) {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
	}
	must(l.Mkdir("etc", 0o755))
	must(l.Put("etc/hello", 0o644, []byte("hi there")))
	must(l.Put("run.sh", 0o4755, []byte("#!/bin/sh\n"))) // setuid
	must(l.SetOwner("etc/hello", 1000, 1000))
	must(l.Symlink("link", "etc/hello", 0o777))
	must(l.Hardlink("etc/hello2", "etc/hello"))
	must(l.Mkdir("var", 0o755))
	must(l.SetOpaque("var"))
	must(l.Mkdir("opt", 0o755))
	must(l.Whiteout("opt/old"))

	var buf bytes.Buffer
	if err := WriteTar(l.ChangeSet(), &buf); err != nil {
		t.Fatalf("WriteTar: %v", err)
	}
	got, err := ReadTar(&buf, t.TempDir())
	if err != nil {
		t.Fatalf("ReadTar: %v", err)
	}

	if b, err := got.ReadFile("etc/hello"); err != nil || string(b) != "hi there" {
		t.Fatalf("etc/hello = %q, %v", b, err)
	}
	if a, ok := got.Stat("link"); !ok || a.Kind != core.Symlink || a.Target != "etc/hello" {
		t.Fatalf("link = %+v, %v", a, ok)
	}
	if a, ok := got.Stat("run.sh"); !ok || a.Mode != 0o4755 {
		t.Fatalf("run.sh mode = %+v, %v", a, ok)
	}
	if a, ok := got.Stat("etc/hello"); !ok || a.Uid != 1000 || a.Gid != 1000 {
		t.Fatalf("etc/hello owner = %+v, %v", a, ok)
	}
	a1, e1 := os.Stat(filepath.Join(got.Dir(), "etc/hello"))
	a2, e2 := os.Stat(filepath.Join(got.Dir(), "etc/hello2"))
	if e1 != nil || e2 != nil || !os.SameFile(a1, a2) {
		t.Fatalf("hardlink not preserved: %v %v same=%v", e1, e2, os.SameFile(a1, a2))
	}
	if a, ok := got.Stat("opt/old"); !ok || !a.Whiteout {
		t.Fatalf("opt/old whiteout = %+v, %v", a, ok)
	}
	if a, ok := got.Stat("var"); !ok || !a.Opaque {
		t.Fatalf("var opaque = %+v, %v", a, ok)
	}
}

// TestReadTarConfined checks a symlink in the archive cannot redirect a later
// entry's write outside the layer store.
func TestReadTarConfined(t *testing.T) {
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	tw.WriteHeader(&tar.Header{Typeflag: tar.TypeSymlink, Name: "evil", Linkname: "../escape", Mode: 0o777})
	tw.WriteHeader(&tar.Header{Typeflag: tar.TypeReg, Name: "evil/pwned", Mode: 0o644, Size: 3})
	tw.Write([]byte("bad"))
	tw.Close()

	store := t.TempDir()
	// Extraction is confined to store: "evil/pwned" cannot traverse the symlink,
	// so nothing is written outside.
	ReadTar(&buf, store)
	if _, err := os.Stat(filepath.Join(filepath.Dir(store), "escape")); err == nil {
		t.Fatal("write escaped the layer store")
	}
}
