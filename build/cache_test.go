//go:build linux

package build

import (
	"context"
	"strings"
	"testing"

	v1 "github.com/google/go-containerregistry/pkg/v1"

	"github.com/samyfodil/laboon/oci"
)

// countCache wraps a real Cache and counts hits and puts, so a test can see
// whether a rebuild reused layers or re-ran steps. It wraps DirCache rather than
// holding layers directly, because a Cache must capture content durably (a
// freshly built layer is backed by a temp file the build deletes afterward).
type countCache struct {
	inner      Cache
	hits, puts int
}

func (c *countCache) Get(key string) (v1.Layer, bool) {
	l, ok := c.inner.Get(key)
	if ok {
		c.hits++
	}
	return l, ok
}

func (c *countCache) Put(key string, layer v1.Layer) error {
	c.puts++
	return c.inner.Put(key, layer)
}

// TestBuildCache checks the layer cache: a first build populates it, an identical
// rebuild reuses every step (all hits, no new runs) and yields the same image,
// and changing a step misses it and everything after it.
func TestBuildCache(t *testing.T) {
	ctx := context.Background()
	if _, err := oci.Pull(ctx, "alpine:3.20", oci.Options{}); err != nil {
		t.Skipf("base image unavailable: %v", err)
	}
	df := `FROM alpine:3.20
RUN echo one > /a
RUN echo two > /b
`
	dc, _ := NewDirCache(t.TempDir())
	c := &countCache{inner: dc}
	h1, err := Build(ctx, strings.NewReader(df), Options{Tag: "laboon-cache:1", Cache: c})
	if err != nil {
		t.Fatal(err)
	}
	if c.puts != 2 || c.hits != 0 {
		t.Fatalf("first build: puts=%d hits=%d, want 2 puts / 0 hits", c.puts, c.hits)
	}

	// Identical rebuild: both RUN steps are cache hits, no new runs, same image.
	c.hits, c.puts = 0, 0
	h2, err := Build(ctx, strings.NewReader(df), Options{Tag: "laboon-cache:1", Cache: c})
	if err != nil {
		t.Fatal(err)
	}
	if h2 != h1 {
		t.Errorf("cached rebuild digest %v != %v", h2, h1)
	}
	if c.hits != 2 || c.puts != 0 {
		t.Errorf("rebuild: hits=%d puts=%d, want 2 hits / 0 puts", c.hits, c.puts)
	}

	// Change the first RUN: it misses, and the second RUN misses too (its chain
	// key changed), so both re-run.
	c.hits, c.puts = 0, 0
	df2 := `FROM alpine:3.20
RUN echo ONE > /a
RUN echo two > /b
`
	if _, err := Build(ctx, strings.NewReader(df2), Options{Tag: "laboon-cache:1", Cache: c}); err != nil {
		t.Fatal(err)
	}
	if c.hits != 0 || c.puts != 2 {
		t.Errorf("changed-step rebuild: hits=%d puts=%d, want 0 hits / 2 puts (cascade)", c.hits, c.puts)
	}
}
