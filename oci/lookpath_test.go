package oci

import (
	"testing"

	"github.com/samyfodil/laboon/core"
	"github.com/samyfodil/laboon/filesystems/memfs"
)

func TestLookPathFS(t *testing.T) {
	m := memfs.NewMemFS()
	bin, _ := m.Create(m.Root(), "bin", core.CreateSpec{Kind: core.Dir, Mode: 0o755})
	m.(core.WriteFileSystem).WriteFile(bin, "sh", core.CreateSpec{Kind: core.Reg, Mode: 0o755}, []byte("x"))
	m.Create(bin, "echo", core.CreateSpec{Kind: core.Symlink, Target: "sh"}) // /bin/echo -> sh

	cases := []struct {
		file, env, want string
		ok              bool
	}{
		{"sh", "PATH=/bin", "/bin/sh", true}, // PATH search
		{"echo", "", "/bin/echo", true},      // symlink to a regular file, default PATH
		{"/bin/sh", "", "/bin/sh", true},     // absolute
		{"nope", "", "", false},              // missing
		{"/bin/missing", "", "", false},      // absolute missing
	}
	for _, c := range cases {
		var env []string
		if c.env != "" {
			env = []string{c.env}
		}
		got, err := LookPathFS(m, c.file, env)
		if c.ok && (err != nil || got != c.want) {
			t.Errorf("LookPathFS(%q) = %q, %v; want %q", c.file, got, err, c.want)
		}
		if !c.ok && err == nil {
			t.Errorf("LookPathFS(%q) = %q, want error", c.file, got)
		}
	}
}
