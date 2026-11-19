package core

import "testing"

// TestMetaCodec round-trips the override sidecar's binary form across the field
// combinations it must carry, including a path with bytes a line format could not
// (a space, a tab, a newline) and a path with no recorded override (dropped).
func TestMetaCodec(t *testing.T) {
	in := map[string]*Override{
		"etc/passwd":           {Uid: 1000, Gid: 1000, HasOwner: true},
		"bin/ro":               {Mode: 0o400, HasMode: true},
		"root/setuid":          {Uid: 0, Gid: 0, HasOwner: true, Mode: 0o4755, HasMode: true},
		"dev/initctl":          {Special: true, Kind: Fifo, Rdev: 0, Mode: 0o600, HasMode: true},
		"weird path\twith\nnl": {Uid: 7, Gid: 8, HasOwner: true},
		"nothing":              {}, // no flags set -> omitted
	}
	got := map[string]Override{}
	DecodeMeta(EncodeMeta(in), func(p string, o Override) { got[p] = o })

	if _, ok := got["nothing"]; ok {
		t.Error("empty override should be omitted")
	}
	if len(got) != 5 {
		t.Fatalf("got %d entries, want 5: %+v", len(got), got)
	}
	for p, want := range in {
		if p == "nothing" {
			continue
		}
		g := got[p]
		if g.HasOwner != want.HasOwner || g.Uid != want.Uid || g.Gid != want.Gid ||
			g.HasMode != want.HasMode || g.Mode != want.Mode ||
			g.Special != want.Special || g.Kind != want.Kind || g.Rdev != want.Rdev {
			t.Errorf("%q: got %+v, want %+v", p, g, *want)
		}
	}

	// A truncated stream must not panic.
	full := EncodeMeta(in)
	for i := 0; i < len(full); i++ {
		DecodeMeta(full[:i], func(string, Override) {})
	}
}
