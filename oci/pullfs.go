package oci

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/empty"
	"github.com/google/go-containerregistry/pkg/v1/layout"
	"github.com/google/go-containerregistry/pkg/v1/remote"

	"github.com/samyfodil/laboon/core"
)

// PullFS is Pull without extraction: it resolves ref (reusing a cached pull) and
// returns a copy-on-write FileSystem composed from the image's layers over a
// fresh on-disk writable upper, the image's run Config, and a close that removes
// the upper and the staged layer tars. The layer blobs are cached as an OCI
// layout, so a second run of the same ref needs no network.
func PullFS(ctx context.Context, ref string, opt Options) (core.FileSystem, Config, func() error, error) {
	arch := opt.Arch
	if arch == "" {
		arch = runtime.GOARCH
	}
	if arch != "amd64" && arch != "arm64" {
		return nil, Config{}, nil, fmt.Errorf("no linux/%s images: the sandbox runs amd64 and arm64", arch)
	}
	dir, err := cacheDir(opt.CacheDir)
	if err != nil {
		return nil, Config{}, nil, err
	}
	r, err := name.ParseReference(ref)
	if err != nil {
		return nil, Config{}, nil, err
	}
	refFile := refFileFor(dir, r, arch)
	img, cfg, err := imageForFS(ctx, dir, refFile, r, ref, arch, opt)
	if err != nil {
		return nil, Config{}, nil, err
	}
	return composeRun(img, cfg)
}

// RunFS composes a FileSystem from an already-resolved v1.Image, for a built
// image (the build -> run path) that never touches a registry.
func RunFS(img v1.Image) (core.FileSystem, Config, func() error, error) {
	cf, err := img.ConfigFile()
	if err != nil {
		return nil, Config{}, nil, err
	}
	return composeRun(img, configOf(cf))
}

func composeRun(img v1.Image, cfg Config) (core.FileSystem, Config, func() error, error) {
	upper, err := os.MkdirTemp("", "laboon-upper-")
	if err != nil {
		return nil, Config{}, nil, err
	}
	fsys, closeLayers, err := ImageFS(img, upper)
	if err != nil {
		os.RemoveAll(upper)
		return nil, Config{}, nil, err
	}
	cleanup := func() error {
		e := closeLayers()
		if err := os.RemoveAll(upper); err != nil && e == nil {
			e = err
		}
		return e
	}
	return fsys, cfg, cleanup, nil
}

func imageForFS(ctx context.Context, dir, refFile string, r name.Reference, ref, arch string, opt Options) (v1.Image, Config, error) {
	if !opt.Refresh {
		if img, cfg, err := loadLayout(dir, refFile); err == nil {
			return img, cfg, nil
		}
	}
	img, err := remote.Image(r,
		remote.WithContext(ctx),
		remote.WithAuthFromKeychain(authn.DefaultKeychain),
		remote.WithPlatform(v1.Platform{OS: "linux", Architecture: arch}))
	if err != nil {
		return nil, Config{}, fmt.Errorf("pull %s: %w", ref, err)
	}
	cf, err := img.ConfigFile()
	if err != nil {
		return nil, Config{}, err
	}
	if cf.OS != "linux" || cf.Architecture != arch {
		return nil, Config{}, fmt.Errorf("%s is %s/%s, need linux/%s", ref, cf.OS, cf.Architecture, arch)
	}
	cfg := configOf(cf)
	if err := saveLayout(dir, refFile, img, cfg); err != nil {
		return nil, Config{}, err
	}
	return img, cfg, nil
}

func configOf(cf *v1.ConfigFile) Config {
	return Config{
		Entrypoint: cf.Config.Entrypoint,
		Cmd:        cf.Config.Cmd,
		Env:        cf.Config.Env,
		WorkingDir: cf.Config.WorkingDir,
		User:       cf.Config.User,
	}
}

func layoutDir(dir, hex string) string { return filepath.Join(dir, hex, "image") }

// saveLayout writes the image's blobs as an OCI layout (and its run Config
// beside it) under the digest, so the same ref runs offline next time.
func saveLayout(dir, refFile string, img v1.Image, cfg Config) error {
	digest, err := img.ConfigName()
	if err != nil {
		return err
	}
	ld := layoutDir(dir, digest.Hex)
	if _, err := os.Stat(ld); err != nil {
		if err := os.MkdirAll(filepath.Join(dir, digest.Hex), 0o700); err != nil {
			return err
		}
		tmp, err := os.MkdirTemp(filepath.Join(dir, digest.Hex), ".layout-*")
		if err != nil {
			return err
		}
		p, err := layout.Write(tmp, empty.Index)
		if err != nil {
			os.RemoveAll(tmp)
			return err
		}
		if err := p.AppendImage(img); err != nil {
			os.RemoveAll(tmp)
			return err
		}
		b, _ := json.Marshal(cfg)
		if err := os.WriteFile(filepath.Join(tmp, "config.json"), b, 0o600); err != nil {
			os.RemoveAll(tmp)
			return err
		}
		if err := os.Rename(tmp, ld); err != nil && !os.IsExist(err) {
			os.RemoveAll(tmp)
			return err
		}
	}
	return remember(refFile, digest.Hex)
}

// loadLayout reopens a cached image layout without the network.
func loadLayout(dir, refFile string) (v1.Image, Config, error) {
	hexb, err := os.ReadFile(refFile)
	if err != nil {
		return nil, Config{}, err
	}
	hex := strings.TrimSpace(string(hexb))
	if !validHex(hex) {
		return nil, Config{}, fmt.Errorf("corrupt ref entry")
	}
	ld := layoutDir(dir, hex)
	p, err := layout.FromPath(ld)
	if err != nil {
		return nil, Config{}, err
	}
	ii, err := p.ImageIndex()
	if err != nil {
		return nil, Config{}, err
	}
	mf, err := ii.IndexManifest()
	if err != nil {
		return nil, Config{}, err
	}
	if len(mf.Manifests) == 0 {
		return nil, Config{}, fmt.Errorf("empty image layout")
	}
	img, err := ii.Image(mf.Manifests[0].Digest)
	if err != nil {
		return nil, Config{}, err
	}
	var cfg Config
	if b, err := os.ReadFile(filepath.Join(ld, "config.json")); err == nil {
		json.Unmarshal(b, &cfg)
	}
	now := time.Now()
	os.Chtimes(filepath.Join(dir, hex), now, now) // LRU touch, as local does
	return img, cfg, nil
}
