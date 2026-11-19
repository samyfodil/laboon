package vfs

import (
	"archive/tar"
	"bytes"
	"testing"
	"time"
)

type tarEnt struct {
	name     string
	tf       byte
	mode     int64
	uid, gid int
	link     string
	data     string
}

func buildTar(t *testing.T, ents []tarEnt) *bytes.Reader {
	t.Helper()
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	for _, e := range ents {
		h := &tar.Header{
			Name: e.name, Typeflag: e.tf, Mode: e.mode, Uid: e.uid, Gid: e.gid,
			Linkname: e.link, Size: int64(len(e.data)), ModTime: time.Unix(1700000000, 0),
		}
		if err := tw.WriteHeader(h); err != nil {
			t.Fatal(err)
		}
		if e.data != "" {
			if _, err := tw.Write([]byte(e.data)); err != nil {
				t.Fatal(err)
			}
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	return bytes.NewReader(buf.Bytes())
}

func lookupPath(t *testing.T, f FileSystem, p string) Node {
	t.Helper()
	n := f.Root()
	for _, name := range bytes.Split([]byte(p), []byte("/")) {
		if len(name) == 0 {
			continue
		}
		c, err := f.Lookup(n, string(name))
		if err != nil {
			t.Fatalf("lookup %q under %q: %v", name, p, err)
		}
		n = c
	}
	return n
}

func readAll(t *testing.T, n Node) string {
	t.Helper()
	a, err := n.Stat()
	if err != nil {
		t.Fatal(err)
	}
	fh, err := n.Open(0)
	if err != nil {
		t.Fatal(err)
	}
	defer fh.Close()
	b := make([]byte, a.Size)
	if a.Size == 0 {
		return ""
	}
	k, err := fh.ReadAt(b, 0)
	if err != nil && err.Error() != "EOF" {
		t.Fatalf("readAt: %v", err)
	}
	return string(b[:k])
}

func TestTarFS(t *testing.T) {
	ra := buildTar(t, []tarEnt{
		{name: "a.txt", tf: tar.TypeReg, mode: 0o644, uid: 1000, gid: 1000, data: "AAAA"},
		{name: "sub/", tf: tar.TypeDir, mode: 0o750},
		{name: "sub/b.txt", tf: tar.TypeReg, mode: 0o600, data: "BBBBBB"},
		{name: "link", tf: tar.TypeSymlink, link: "a.txt"},
		{name: "bin/tool", tf: tar.TypeReg, mode: 0o755, data: "TOOL"},
		{name: "bin/alias", tf: tar.TypeLink, link: "bin/tool"},
		{name: ".wh.gone", tf: tar.TypeReg, mode: 0o644},
	})
	f, err := TarFS(ra, ra.Size())
	if err != nil {
		t.Fatal(err)
	}

	// Content served lazily; a file whose data is not first proves offset tracking.
	if got := readAll(t, lookupPath(t, f, "a.txt")); got != "AAAA" {
		t.Fatalf("a.txt = %q, want AAAA", got)
	}
	if got := readAll(t, lookupPath(t, f, "sub/b.txt")); got != "BBBBBB" {
		t.Fatalf("sub/b.txt = %q, want BBBBBB", got)
	}

	// Metadata from the header.
	if a, _ := lookupPath(t, f, "a.txt").Stat(); a.Mode != 0o644 || a.Uid != 1000 || a.Gid != 1000 {
		t.Fatalf("a.txt attr = %+v", a)
	}
	if a, _ := lookupPath(t, f, "sub").Stat(); a.Kind != Dir || a.Mode != 0o750 {
		t.Fatalf("sub attr = %+v", a)
	}

	// Symlink.
	if tgt, err := lookupPath(t, f, "link").Readlink(); err != nil || tgt != "a.txt" {
		t.Fatalf("link -> %q (%v)", tgt, err)
	}

	// Hardlink shares identity and content with its target.
	tool, alias := lookupPath(t, f, "bin/tool"), lookupPath(t, f, "bin/alias")
	if tool.ID() != alias.ID() {
		t.Fatalf("hardlink ids differ: %v vs %v", tool.ID(), alias.ID())
	}
	if got := readAll(t, alias); got != "TOOL" {
		t.Fatalf("bin/alias = %q, want TOOL", got)
	}

	// Whiteout markers are kept verbatim as ordinary files.
	if wh := lookupPath(t, f, ".wh.gone"); wh.Kind() != Reg {
		t.Fatalf(".wh.gone kind = %v", wh.Kind())
	}

	// Read-only.
	if _, err := f.Create(f.Root(), "x", CreateSpec{Kind: Reg}); err == nil {
		t.Fatal("Create on TarFS should fail")
	}
}
