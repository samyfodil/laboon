//go:build linux || darwin

package sandbox

import (
	"testing"

	"github.com/samyfodil/laboon/internal/vfs"
)

// The guest root is always a vfs.FileSystem. A plain backend (in-memory, custom)
// is the root directly, with no host path; a host directory arrives wrapped in a
// HostRoot carrier, which the sandbox unwraps to run its confined host-overlay
// machinery. This checks both paths wire up as intended.
func TestRootFSWiring(t *testing.T) {
	// A memFS root: no host path, and the namespace roots at it directly.
	mem := vfs.NewMemFS()
	if _, ok := HostRootPath(mem); ok {
		t.Fatalf("a memFS is not a host root")
	}
	fs, err := newDfs(mem, "", nil, nil, t.TempDir())
	if err != nil {
		t.Fatalf("newDfs(memFS): %v", err)
	}
	if fs.rootFS != mem {
		t.Fatalf("rootFS = %v, want the memFS", fs.rootFS)
	}
	if fs.overlay != mem {
		t.Fatalf("overlay = %T, want the memFS used as the root directly", fs.overlay)
	}
	if fs.rootAbs != "" {
		t.Fatalf("a pure-FS root must have no host path, got rootAbs=%q", fs.rootAbs)
	}

	// A host directory via HostRoot: the carrier yields its path, and newDfs routes
	// it through the host-overlay path (rootAbs set, rootFS cleared).
	dir := t.TempDir()
	hr := HostRoot(dir)
	if p, ok := HostRootPath(hr); !ok || p != dir {
		t.Fatalf("HostRootPath(HostRoot(%q)) = %q, %v", dir, p, ok)
	}
	hfs, err := newDfs(hr, "", nil, nil, t.TempDir())
	if err != nil {
		t.Fatalf("newDfs(HostRoot): %v", err)
	}
	if hfs.rootFS != nil {
		t.Fatalf("a host root must run the host-overlay path, not keep rootFS")
	}
	if hfs.rootAbs == "" {
		t.Fatalf("a host root must set rootAbs")
	}
}
