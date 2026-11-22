package oci

import (
	"archive/tar"
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"

	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/registry"
	"github.com/google/go-containerregistry/pkg/v1/empty"
	"github.com/google/go-containerregistry/pkg/v1/mutate"
	"github.com/google/go-containerregistry/pkg/v1/remote"
)

// TestPullFetchesLayersOnce pulls an image from a local registry and counts
// the fetches of each layer: the cache keeps the blobs and unpacks from them,
// so a cold pull downloads every layer once.
func TestPullFetchesLayersOnce(t *testing.T) {
	var mu sync.Mutex
	gets := map[string]int{}
	reg := registry.New()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet && strings.Contains(r.URL.Path, "/blobs/") {
			mu.Lock()
			gets[r.URL.Path[strings.LastIndex(r.URL.Path, "/")+1:]]++
			mu.Unlock()
		}
		reg.ServeHTTP(w, r)
	}))
	defer srv.Close()

	img, err := mutate.AppendLayers(empty.Image,
		mkLayer(t, ent{"bin/", "", tar.TypeDir, 0o755}, ent{"bin/sh", "sh", tar.TypeReg, 0o755}),
		mkLayer(t, ent{"etc/motd", "hello", tar.TypeReg, 0o644}),
	)
	if err != nil {
		t.Fatal(err)
	}
	cf, err := img.ConfigFile()
	if err != nil {
		t.Fatal(err)
	}
	cf.OS, cf.Architecture = "linux", "amd64"
	if img, err = mutate.ConfigFile(img, cf); err != nil {
		t.Fatal(err)
	}
	ref := strings.TrimPrefix(srv.URL, "http://") + "/test/app:latest"
	r, err := name.ParseReference(ref)
	if err != nil {
		t.Fatal(err)
	}
	if err := remote.Write(r, img); err != nil {
		t.Fatal(err)
	}
	mu.Lock()
	clear(gets)
	mu.Unlock()

	got, err := Pull(context.Background(), ref, Options{CacheDir: t.TempDir(), Arch: "amd64"})
	if err != nil {
		t.Fatal(err)
	}
	if b, err := os.ReadFile(filepath.Join(got.Root, "etc", "motd")); err != nil || string(b) != "hello" {
		t.Fatalf("etc/motd: %q %v", b, err)
	}
	layers, err := img.Layers()
	if err != nil {
		t.Fatal(err)
	}
	for _, l := range layers {
		d, err := l.Digest()
		if err != nil {
			t.Fatal(err)
		}
		if n := gets[d.String()]; n != 1 {
			t.Errorf("layer %s fetched %d times, want 1", d, n)
		}
	}
}

// TestPullRefetchesBrokenLayer cuts the first download of a layer halfway, as a
// CDN may: the pull fetches it again and the rootfs is whole.
func TestPullRefetchesBrokenLayer(t *testing.T) {
	big := strings.Repeat("laboon ", 64<<10)
	img, err := mutate.AppendLayers(empty.Image,
		mkLayer(t, ent{"etc/big", big, tar.TypeReg, 0o644}))
	if err != nil {
		t.Fatal(err)
	}
	cf, err := img.ConfigFile()
	if err != nil {
		t.Fatal(err)
	}
	cf.OS, cf.Architecture = "linux", "amd64"
	if img, err = mutate.ConfigFile(img, cf); err != nil {
		t.Fatal(err)
	}
	layers, err := img.Layers()
	if err != nil {
		t.Fatal(err)
	}
	ld, err := layers[0].Digest()
	if err != nil {
		t.Fatal(err)
	}

	var mu sync.Mutex
	gets, cut := 0, false
	reg := registry.New()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet || !strings.HasSuffix(r.URL.Path, "/blobs/"+ld.String()) {
			reg.ServeHTTP(w, r)
			return
		}
		mu.Lock()
		gets++
		first := !cut
		cut = true
		mu.Unlock()
		if !first {
			reg.ServeHTTP(w, r)
			return
		}
		rec := httptest.NewRecorder()
		reg.ServeHTTP(rec, r)
		body := rec.Body.Bytes()
		w.Header().Set("Content-Length", strconv.Itoa(len(body)))
		w.WriteHeader(rec.Code)
		w.Write(body[:len(body)/2])
		w.(http.Flusher).Flush()
		panic(http.ErrAbortHandler)
	}))
	defer srv.Close()

	ref := strings.TrimPrefix(srv.URL, "http://") + "/test/big:latest"
	r, err := name.ParseReference(ref)
	if err != nil {
		t.Fatal(err)
	}
	if err := remote.Write(r, img); err != nil {
		t.Fatal(err)
	}
	mu.Lock()
	gets, cut = 0, false
	mu.Unlock()

	got, err := Pull(context.Background(), ref, Options{CacheDir: t.TempDir(), Arch: "amd64"})
	if err != nil {
		t.Fatal(err)
	}
	if b, err := os.ReadFile(filepath.Join(got.Root, "etc", "big")); err != nil || string(b) != big {
		t.Fatalf("etc/big: %d bytes, %v", len(b), err)
	}
	if gets != 2 {
		t.Errorf("layer fetched %d times, want 2", gets)
	}
}
