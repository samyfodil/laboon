package hostfs

import "testing"

func TestEscapeName(t *testing.T) {
	for in, want := range map[string]string{
		"plain":   "plain",
		"a:b*c?":  "abc",
		"dot.":    "dot",
		"CON":     "ON",
		"con.txt": "on.txt",
		"..":      "..",
	} {
		got := EscapeName(in)
		if got != want {
			t.Errorf("EscapeName(%q) = %q, want %q", in, got, want)
		}
		if back := UnescapeName(got); back != in {
			t.Errorf("UnescapeName(%q) = %q, want %q", got, back, in)
		}
	}
}

func TestEntry(t *testing.T) {
	for _, e := range []Entry{
		{Mode: 0o100755, Path: "bin/busybox"},
		{Mode: 0o120777, Path: "bin/sh"},
		{Mode: 0o40755, Uid: 100, Gid: 101, Path: "home/a b"},
	} {
		line := e.String()
		got, ok := ParseEntry(line)
		if !ok || got != e {
			t.Errorf("ParseEntry(%q) = %+v, %v; want %+v", line, got, ok, e)
		}
	}
	if e, ok := ParseEntry("100644 etc/hostname"); !ok || e.Mode != 0o100644 || e.Path != "etc/hostname" || e.Uid != 0 {
		t.Errorf("old format: %+v %v", e, ok)
	}
	for _, bad := range []string{"", "755", "x bin", "755,1 bin", "755,a,b bin"} {
		if _, ok := ParseEntry(bad); ok {
			t.Errorf("ParseEntry(%q) accepted", bad)
		}
	}
	if (Entry{Mode: 0o100644, Path: "a\nb"}).Valid() {
		t.Error("a newline in a path is valid")
	}
}
