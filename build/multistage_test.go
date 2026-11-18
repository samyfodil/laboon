//go:build linux

package build

import (
	"archive/tar"
	"context"
	"io"
	"strings"
	"testing"

	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/tarball"

	"github.com/samyfodil/laboon/oci"
)

// TestMultiStage builds a two-stage Dockerfile: a builder stage produces a file,
// and a scratch final stage copies it out with COPY --from. The final image must
// contain the artifact and nothing from the builder's base, proving stages are
// isolated and COPY --from reads a prior stage's filesystem.
func TestMultiStage(t *testing.T) {
	ctx := context.Background()
	if _, err := oci.Pull(ctx, "alpine:3.20", oci.Options{}); err != nil {
		t.Skipf("base image unavailable: %v", err)
	}
	df := `FROM alpine:3.20 AS builder
RUN mkdir -p /out && echo artifact > /out/app && chmod 0755 /out/app
FROM scratch
COPY --from=builder /out/app /app
CMD ["/app"]
`
	h, err := Build(ctx, strings.NewReader(df), Options{Tag: "laboon-ms:1"})
	if err != nil {
		t.Fatal(err)
	}
	if h.Hex == "" {
		t.Fatal("empty digest")
	}

	img := buildImage(t, ctx, df, "laboon-ms:1")
	names := layerNames(t, img)
	if !names["app"] {
		t.Errorf("final image missing /app (have %v)", names)
	}
	// The scratch final stage must not carry alpine's rootfs (e.g. /etc/alpine-release).
	if names["etc/alpine-release"] || names["bin/sh"] {
		t.Errorf("scratch final stage leaked the builder's base rootfs: %v", names)
	}
	if body := fileBody(t, img, "app"); strings.TrimSpace(body) != "artifact" {
		t.Errorf("/app body = %q, want artifact", body)
	}

	// --target builds only the builder stage, whose base is alpine.
	ht, err := Build(ctx, strings.NewReader(df), Options{Tag: "laboon-ms-b:1", Target: "builder"})
	if err != nil {
		t.Fatalf("target build: %v", err)
	}
	if ht == h {
		t.Error("target=builder produced the same image as the final stage")
	}
}

func buildImage(t *testing.T, ctx context.Context, df, tag string) v1.Image {
	t.Helper()
	out := t.TempDir() + "/image.tar"
	if _, err := Build(ctx, strings.NewReader(df), Options{Tag: tag, Output: out}); err != nil {
		t.Fatal(err)
	}
	ref, err := name.NewTag(tag)
	if err != nil {
		t.Fatal(err)
	}
	img, err := tarball.ImageFromPath(out, &ref)
	if err != nil {
		t.Fatal(err)
	}
	return img
}

func layerNames(t *testing.T, img v1.Image) map[string]bool {
	t.Helper()
	names := map[string]bool{}
	layers, _ := img.Layers()
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
			names[strings.TrimPrefix(h.Name, "./")] = true
		}
		rc.Close()
	}
	return names
}

func fileBody(t *testing.T, img v1.Image, name string) string {
	t.Helper()
	layers, _ := img.Layers()
	body := ""
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
			if strings.TrimPrefix(h.Name, "./") == name {
				b, _ := io.ReadAll(tr)
				body = string(b)
			}
		}
		rc.Close()
	}
	return body
}
