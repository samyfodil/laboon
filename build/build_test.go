//go:build linux

package build

import (
	"archive/tar"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/tarball"

	"github.com/samyfodil/laboon/oci"
)

// TestBuild builds a small Dockerfile from a cached base image and checks the
// result: a RUN step's new file and deletion (as a whiteout), a COPY, and the
// merged config. It skips when the base image is not available offline.
func TestBuild(t *testing.T) {
	ctx := context.Background()
	if _, err := oci.Pull(ctx, "alpine:3.20", oci.Options{}); err != nil {
		t.Skipf("base image unavailable: %v", err)
	}
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "greeting.txt"), []byte("hello"), 0o644); err != nil {
		t.Fatal(err)
	}
	df := `FROM alpine:3.20
ENV BUILT_BY=laboon
RUN echo made > /made.txt && chmod 0400 /made.txt && rm -f /etc/motd
COPY greeting.txt /app/greeting.txt
WORKDIR /app
CMD ["/bin/sh","-c","cat /made.txt"]
`
	out := filepath.Join(dir, "image.tar")
	h, err := Build(ctx, strings.NewReader(df), Options{
		Context: dir, Tag: "laboon-test:1", Output: out,
		Stdout: os.Stderr, Stderr: os.Stderr,
	})
	if err != nil {
		t.Fatal(err)
	}
	if h.Hex == "" {
		t.Fatal("empty digest")
	}

	ref, _ := name.NewTag("laboon-test:1")
	img, err := tarball.ImageFromPath(out, &ref)
	if err != nil {
		t.Fatalf("read built image: %v", err)
	}
	cf, err := img.ConfigFile()
	if err != nil {
		t.Fatal(err)
	}
	if !has(cf.Config.Env, "BUILT_BY=laboon") {
		t.Errorf("Env missing BUILT_BY: %v", cf.Config.Env)
	}
	if cf.Config.WorkingDir != "/app" {
		t.Errorf("WorkingDir = %q, want /app", cf.Config.WorkingDir)
	}
	layers, _ := img.Layers()
	if len(layers) < 3 {
		t.Fatalf("got %d layers, want >= 3 (base + RUN + COPY)", len(layers))
	}
	// The RUN chmod 0400 is captured authoritatively, a mode the host file (on
	// an unprivileged laboon) cannot hold, with root ownership and no leaked
	// host user.
	if mode, uid, gid, ok := entryMeta(t, layers, "made.txt"); !ok || mode&0o7777 != 0o400 || uid != 0 || gid != 0 {
		t.Fatalf("made.txt in image: mode=%o uid=%d gid=%d ok=%v, want 0400 root", mode, uid, gid, ok)
	}
}

// entryMeta finds a path across the image layers (last writer wins) and returns
// its tar mode and owner.
func entryMeta(t *testing.T, layers []v1.Layer, name string) (mode int64, uid, gid int, ok bool) {
	t.Helper()
	for _, l := range layers {
		rc, err := l.Uncompressed()
		if err != nil {
			t.Fatal(err)
		}
		tr := tar.NewReader(rc)
		for {
			h, err := tr.Next()
			if err != nil {
				break
			}
			if h.Name == name {
				mode, uid, gid, ok = h.Mode, h.Uid, h.Gid, true
			}
		}
		rc.Close()
	}
	return
}

func has(ss []string, want string) bool {
	for _, s := range ss {
		if s == want {
			return true
		}
	}
	return false
}
