package oci

import (
	"bytes"
	"context"
	"os"
	"strings"
	"testing"

	"github.com/samyfodil/laboon/internal/sandbox"
)

// TestPullAndRun needs the network: LABOON_NET_TESTS=1 go test ./oci
func TestPullAndRun(t *testing.T) {
	if os.Getenv("LABOON_NET_TESTS") == "" {
		t.Skip("set LABOON_NET_TESTS=1 to pull from Docker Hub")
	}
	img, err := Pull(context.Background(), "alpine:3.20", Options{CacheDir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	prog, err := LookPath(img.Root, "cat", img.Config.Env)
	if err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	code, err := sandbox.Run(context.Background(), prog, sandbox.Config{
		Args:   []string{"cat", "/etc/os-release"},
		Env:    img.Config.Env,
		RootFS: sandbox.HostRoot(img.Root),
		Stdout: &out,
		Stderr: &out,
	})
	if err != nil || code != 0 {
		t.Fatalf("code = %d, err = %v, output = %q", code, err, out.String())
	}
	if !strings.Contains(out.String(), `ID=alpine`) {
		t.Fatalf("output = %q", out.String())
	}
}
