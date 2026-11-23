// Package oci pulls container images and unpacks them into a root
// filesystem for the sandbox.
//
// Unpacking treats layers as hostile: every write goes through an os.Root,
// so "../" names and symlinks cannot reach outside the rootfs; device nodes
// and FIFOs are skipped; setuid/setgid bits are dropped; and the total
// unpacked size is capped.
package oci

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/mutate"
	"github.com/google/go-containerregistry/pkg/v1/remote"

	"github.com/samyfodil/laboon/filesystems/hostfs"
)

// Image is an unpacked image.
type Image struct {
	Ref    string
	Digest string // config digest; identifies the unpacked contents
	Root   string // rootfs directory
	Config Config
	img    v1.Image // the image's layers, for FS() -- composes without extraction
}

// Config is the part of the image config the sandbox uses.
type Config struct {
	Entrypoint []string `json:"entrypoint,omitempty"`
	Cmd        []string `json:"cmd,omitempty"`
	Env        []string `json:"env,omitempty"`
	WorkingDir string   `json:"workingDir,omitempty"`
	User       string   `json:"user,omitempty"` // USER: "", a name, uid, uid:gid or name:group
}

// Options control Pull.
type Options struct {
	// CacheDir holds unpacked images. Empty uses the user cache directory.
	CacheDir string
	// MaxSize caps the unpacked size in bytes. Zero means 16 GiB.
	MaxSize int64
	// Refresh asks the registry even if ref was pulled before; otherwise
	// a previously pulled ref is used offline, as docker run does.
	Refresh bool
	// Arch is the image's Linux architecture, "amd64" or "arm64". Empty
	// means the host's: the sandbox runs guests of its own architecture.
	Arch string
}

// Pull fetches ref for linux/<opt.Arch> and unpacks it, reusing a previous
// unpack of the same image.
func Pull(ctx context.Context, ref string, opt Options) (*Image, error) {
	arch := opt.Arch
	if arch == "" {
		arch = runtime.GOARCH
	}
	if arch != "amd64" && arch != "arm64" {
		return nil, fmt.Errorf("no linux/%s images: the sandbox runs amd64 and arm64", arch)
	}
	dir, err := cacheDir(opt.CacheDir)
	if err != nil {
		return nil, err
	}
	r, err := name.ParseReference(ref)
	if err != nil {
		return nil, err
	}
	// A ref names one image per architecture; amd64's entries keep the
	// names they had before there were others.
	refFile := refFileFor(dir, r, arch)
	if !opt.Refresh {
		if out, err := local(dir, refFile, ref); err == nil {
			return out, nil
		}
	}
	img, err := remote.Image(r,
		remote.WithContext(ctx),
		remote.WithAuthFromKeychain(authn.DefaultKeychain),
		remote.WithPlatform(v1.Platform{OS: "linux", Architecture: arch}))
	if err != nil {
		return nil, fmt.Errorf("pull %s: %w", ref, err)
	}
	cf, err := img.ConfigFile()
	if err != nil {
		return nil, err
	}
	if cf.OS != "linux" || cf.Architecture != arch {
		return nil, fmt.Errorf("%s is %s/%s, need linux/%s", ref, cf.OS, cf.Architecture, arch)
	}
	return store(dir, refFile, ref, refetchImage{img, ctx}, opt.MaxSize)
}

// Store places a locally built image in the cache under ref, so laboon runs it
// (laboon -image ref) without a registry — the build -> run path, keyed by the
// image's own architecture so a host-arch -image lookup finds it.
func Store(img v1.Image, ref string, opt Options) (*Image, error) {
	dir, err := cacheDir(opt.CacheDir)
	if err != nil {
		return nil, err
	}
	r, err := name.ParseReference(ref)
	if err != nil {
		return nil, err
	}
	cf, err := img.ConfigFile()
	if err != nil {
		return nil, err
	}
	return store(dir, refFileFor(dir, r, cf.Architecture), ref, img, opt.MaxSize)
}

// store unpacks img into the cache at dir/<config-digest> and points refFile at
// it, the shared tail of Pull (a registry fetch) and Store (a local build), so a
// built image runs the same offline path a pulled one does.
func store(dir, refFile, ref string, img v1.Image, maxSize int64) (*Image, error) {
	digest, err := img.ConfigName()
	if err != nil {
		return nil, err
	}
	cf, err := img.ConfigFile()
	if err != nil {
		return nil, err
	}
	out := &Image{
		Ref:    ref,
		Digest: digest.String(),
		Root:   filepath.Join(dir, digest.Hex, "rootfs"),
		Config: Config{
			Entrypoint: cf.Config.Entrypoint,
			Cmd:        cf.Config.Cmd,
			Env:        cf.Config.Env,
			WorkingDir: cf.Config.WorkingDir,
			User:       cf.Config.User,
		},
	}
	unlock, err := lockImage(dir, digest.Hex)
	if err != nil {
		return nil, err
	}
	defer unlock()
	if err := saveLayout(dir, digest.Hex, img); err != nil {
		return nil, err
	}
	// From here on the image is the cached copy: unpacking the one given
	// would fetch a pulled image's layers a second time.
	img, err = loadLayoutImage(dir, digest.Hex)
	if err != nil {
		return nil, err
	}
	out.img = img
	// The rootfs is unpacked in place, under the image's lock, and the config
	// written once it is whole: a rootfs without it is one an unpack or a
	// removal left half done, and goes. A directory is never renamed, which
	// Windows refuses while anything, an antivirus scan say, holds a file in it.
	cfgFile := filepath.Join(dir, digest.Hex, "config.json")
	if _, err := os.Stat(cfgFile); err == nil {
		if _, err := os.Stat(out.Root); err == nil {
			return out, remember(refFile, digest.Hex)
		}
		if err := os.Remove(cfgFile); err != nil {
			return nil, err
		}
	}
	if err := os.RemoveAll(out.Root); err != nil {
		return nil, err
	}
	if err := os.Remove(out.Root + hostfs.MetaSuffix); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return nil, err
	}
	if err := os.MkdirAll(out.Root, 0o700); err != nil {
		return nil, err
	}
	flat := mutate.Extract(img)
	defer flat.Close()
	if maxSize == 0 {
		maxSize = 16 << 30
	}
	if err := Unpack(flat, out.Root, maxSize); err != nil {
		os.RemoveAll(out.Root)
		os.Remove(out.Root + hostfs.MetaSuffix)
		return nil, fmt.Errorf("unpack %s: %w", ref, err)
	}
	cfg, err := json.Marshal(out.Config)
	if err != nil {
		return nil, err
	}
	if err := writeAtomic(cfgFile, cfg); err != nil {
		return nil, err
	}
	return out, remember(refFile, digest.Hex)
}

// local returns a previously pulled ref without touching the network.
func local(dir, refFile, ref string) (*Image, error) {
	hex, err := os.ReadFile(refFile)
	if err != nil {
		return nil, err
	}
	h := strings.TrimSpace(string(hex))
	if !validHex(h) {
		return nil, errors.New("corrupt ref entry")
	}
	b, err := os.ReadFile(filepath.Join(dir, h, "config.json"))
	if err != nil {
		return nil, err
	}
	out := &Image{Ref: ref, Digest: "sha256:" + h, Root: filepath.Join(dir, h, "rootfs")}
	if err := json.Unmarshal(b, &out.Config); err != nil {
		return nil, err
	}
	if im, err := loadLayoutImage(dir, h); err == nil {
		out.img = im // the layers, for FS(); absent on a pre-layout cache entry
	}
	if _, err := os.Stat(out.Root); err != nil {
		return nil, err
	}
	now := time.Now()
	os.Chtimes(filepath.Join(dir, h), now, now) // mark used, for Sweep's least-recently-used order
	return out, nil
}

// lockImage holds the lock that orders storing and removing the image hex.
// Its lock file stays when the image goes: one removed while another process
// waits on it would let a third take a lock of its own.
func lockImage(dir, hex string) (unlock func(), err error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	return lockFile(filepath.Join(dir, hex+".lock"))
}

// writeAtomic writes p whole or not at all.
func writeAtomic(p string, b []byte) error {
	f, err := os.CreateTemp(filepath.Dir(p), "."+filepath.Base(p)+"-*")
	if err != nil {
		return err
	}
	_, err = f.Write(b)
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err == nil {
		err = os.Rename(f.Name(), p)
	}
	if err != nil {
		os.Remove(f.Name())
	}
	return err
}

func remember(refFile, hex string) error {
	if err := os.MkdirAll(filepath.Dir(refFile), 0o700); err != nil {
		return err
	}
	return os.WriteFile(refFile, []byte(hex+"\n"), 0o600)
}

func validHex(s string) bool {
	if len(s) != 64 {
		return false
	}
	for _, c := range s {
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return false
		}
	}
	return true
}

func cacheDir(dir string) (string, error) {
	if dir != "" {
		return dir, nil
	}
	d, err := os.UserCacheDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(d, "laboon", "images"), nil
}

// clean turns a tar path into a relative path inside the rootfs.
func clean(name string) (string, bool) {
	name = path.Clean("/" + strings.TrimPrefix(name, "./"))
	if name == "/" {
		return "", false
	}
	return name[1:], true
}

var errTooLarge = errors.New("image exceeds the unpack size limit")
