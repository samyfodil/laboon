package vfs

import (
	"os"
	"testing"
)

func writeInto(t *testing.T, f FileSystem, dir Node, name, data string, spec CreateSpec) Node {
	t.Helper()
	spec.Kind = Reg
	n, err := f.(WriteFileSystem).WriteFile(dir, name, spec, []byte(data))
	if err != nil {
		t.Fatalf("writeInto %s: %v", name, err)
	}
	return n
}

func TestOverlayUnionAndCopyUp(t *testing.T) {
	lower, top := NewMemFS(), NewMemFS()
	// lower: /a="low" (mode 0640, uid 1000), /keep="L"
	writeInto(t, lower, lower.Root(), "a", "low", CreateSpec{Mode: 0o640, Uid: 1000, Gid: 1000})
	writeInto(t, lower, lower.Root(), "keep", "L", CreateSpec{Mode: 0o644})
	ov := OverlayFS(lower, top)

	// Union read from the lower.
	if got := readAll(t, lookupPath(t, ov, "a")); got != "low" {
		t.Fatalf("read /a = %q, want low", got)
	}

	// Writing /a copies it up: content changes, metadata is preserved, the lower
	// is untouched, and the write lands in the top.
	an := lookupPath(t, ov, "a")
	fh, err := an.Open(os.O_WRONLY | os.O_TRUNC)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := fh.WriteAt([]byte("HIGH"), 0); err != nil {
		t.Fatal(err)
	}
	fh.Close()
	if got := readAll(t, lookupPath(t, ov, "a")); got != "HIGH" {
		t.Fatalf("after copy-up read /a = %q, want HIGH", got)
	}
	if a, _ := lookupPath(t, ov, "a").Stat(); a.Mode != 0o640 || a.Uid != 1000 || a.Gid != 1000 {
		t.Fatalf("copy-up lost metadata: %+v", a)
	}
	if got := readAll(t, lookupPath(t, lower, "a")); got != "low" {
		t.Fatalf("lower /a mutated: %q", got)
	}
	if _, err := top.Lookup(top.Root(), "a"); err != nil {
		t.Fatalf("copy-up did not land in top: %v", err)
	}
}

func TestOverlayWhiteoutAndOpaque(t *testing.T) {
	lower, top := NewMemFS(), NewMemFS()
	dn, _ := lower.Create(lower.Root(), "d", CreateSpec{Kind: Dir, Mode: 0o755})
	writeInto(t, lower, dn, "x", "X", CreateSpec{Mode: 0o644})
	writeInto(t, lower, dn, "y", "Y", CreateSpec{Mode: 0o644})
	writeInto(t, lower, lower.Root(), "top-level", "T", CreateSpec{Mode: 0o644})
	ov := OverlayFS(lower, top)

	// Remove a file in a lower dir: it is whiteouted, a sibling still shows. A
	// mutation invalidates in-hand nodes, so callers re-resolve (the namespace
	// does this via the generation); re-look up /d after the Remove.
	dov, _ := ov.Lookup(ov.Root(), "d")
	if err := ov.Remove(dov, "x", false); err != nil {
		t.Fatal(err)
	}
	dov, _ = ov.Lookup(ov.Root(), "d")
	if _, err := ov.Lookup(dov, "x"); err == nil {
		t.Fatal("removed /d/x still resolves")
	}
	if _, err := ov.Lookup(dov, "y"); err != nil {
		t.Fatalf("sibling /d/y lost: %v", err)
	}
	names := map[string]bool{}
	ents, _ := ov.ReadDir(dov)
	for _, e := range ents {
		names[e.Name] = true
	}
	if names["x"] || !names["y"] {
		t.Fatalf("readdir /d = %v, want y without x", names)
	}

	// Remove the whole dir then recreate it: the recreated dir is opaque, hiding
	// the lower entries.
	if err := ov.Remove(ov.Root(), "d", true); err != nil {
		t.Fatal(err)
	}
	if _, err := ov.Create(ov.Root(), "d", CreateSpec{Kind: Dir, Mode: 0o755}); err != nil {
		t.Fatal(err)
	}
	dov2, _ := ov.Lookup(ov.Root(), "d")
	if _, err := ov.Lookup(dov2, "y"); err == nil {
		t.Fatal("opaque dir did not hide lower /d/y")
	}
}

func TestOverlayRenameAndCreateMetadata(t *testing.T) {
	lower, top := NewMemFS(), NewMemFS()
	writeInto(t, lower, lower.Root(), "src", "DATA", CreateSpec{Mode: 0o600})
	ov := OverlayFS(lower, top)

	// Create carries metadata into a faithful top.
	if _, err := ov.Create(ov.Root(), "made", CreateSpec{Kind: Dir, Mode: 0o750, Uid: 7, Gid: 9}); err != nil {
		t.Fatal(err)
	}
	if a, _ := lookupPath(t, ov, "made").Stat(); a.Mode != 0o750 || a.Uid != 7 || a.Gid != 9 {
		t.Fatalf("created dir metadata = %+v", a)
	}

	// Rename a lower file: it copies up, moves, and the old name is whiteouted.
	if err := ov.Rename(ov.Root(), "src", ov.Root(), "dst"); err != nil {
		t.Fatal(err)
	}
	if got := readAll(t, lookupPath(t, ov, "dst")); got != "DATA" {
		t.Fatalf("renamed /dst = %q, want DATA", got)
	}
	if _, err := ov.Lookup(ov.Root(), "src"); err == nil {
		t.Fatal("old name /src still resolves after rename")
	}
}
