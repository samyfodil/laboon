package hostfs

import (
	"testing"

	"github.com/samyfodil/laboon/core"
)

func TestDiskFSFaithfulMetadata(t *testing.T) {
	root := t.TempDir()
	d := NewDiskFS(root)

	// A file the guest owns as 1000:1000 with a sub-floor mode 0400.
	n, err := d.WriteFile(d.Root(), "secret", core.CreateSpec{Kind: core.Reg, Mode: 0o400, Uid: 1000, Gid: 1000}, []byte("x"))
	if err != nil {
		t.Fatal(err)
	}
	if a, _ := n.Stat(); a.Mode != 0o400 || a.Uid != 1000 || a.Gid != 1000 {
		t.Fatalf("secret stat = %+v, want mode 0400 uid/gid 1000", a)
	}
	// The host file must stay writable to the unprivileged host owner despite the
	// guest 0400, or copy-up could not write it.
	if fh, err := n.Open(1 /*O_WRONLY*/); err != nil {
		t.Fatalf("sub-floor file not host-writable: %v", err)
	} else {
		fh.Close()
	}

	// A device node the host cannot really create.
	dev, err := d.Create(d.Root(), "null", core.CreateSpec{Kind: core.Chardev, Rdev: 259, Mode: 0o666})
	if err != nil {
		t.Fatal(err)
	}
	if a, _ := dev.Stat(); a.Kind != core.Chardev || a.Rdev != 259 {
		t.Fatalf("device stat = %+v, want Chardev rdev 259", a)
	}

	// Persist and reload: the sidecar must restore owner, sub-floor mode and the
	// special-node kind.
	if err := d.Save(); err != nil {
		t.Fatal(err)
	}
	d2 := NewDiskFS(root)
	s2, err := d2.Lookup(d2.Root(), "secret")
	if err != nil {
		t.Fatal(err)
	}
	if a, _ := s2.Stat(); a.Uid != 1000 || a.Mode != 0o400 {
		t.Fatalf("reloaded secret = %+v, want uid 1000 mode 0400", a)
	}
	n2, err := d2.Lookup(d2.Root(), "null")
	if err != nil {
		t.Fatal(err)
	}
	if n2.Kind() != core.Chardev {
		t.Fatalf("reloaded device kind = %v, want Chardev", n2.Kind())
	}
}
