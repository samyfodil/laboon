package sandbox

import (
	"archive/tar"
	"bufio"
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"testing"

	"github.com/samyfodil/laboon/oci"
)

// guestPath returns a Linux guest built from testdata/<name>.c. With
// LC_GUEST_DIR set it is the build staged there for this arch
// (scripts/guests.sh); otherwise it is built here with gcc, which only a Linux
// host can do. Both build it static-PIE unless the source names its own flags on
// a "// build:" line. A guest that is neither staged nor buildable fails the
// test: it is a broken setup, not a reason to skip.
func guestPath(t testing.TB, name string) string {
	t.Helper()
	if dir := os.Getenv("LC_GUEST_DIR"); dir != "" {
		exe := filepath.Join(dir, name)
		if _, err := os.Stat(exe); err != nil {
			t.Fatalf("guest %s is not staged in LC_GUEST_DIR=%s (scripts/guests.sh)", name, dir)
		}
		return exe
	}
	if runtime.GOOS != "linux" {
		t.Fatalf("Linux guests are not built on %s: stage them with scripts/guests.sh and set LC_GUEST_DIR", runtime.GOOS)
	}
	base, musl := strings.CutSuffix(name, "+musl")
	src := filepath.Join("..", "..", "testdata", base+".c")
	if _, err := os.Stat(src); err != nil {
		src = filepath.Join("testdata", base+".c")
	}
	flags := guestFlags(t, src)
	cc := []string{"gcc"}
	if musl {
		z := zigCC()
		if z == "" {
			t.Fatalf("%s needs zig to build against musl (set ZIG)", name)
		}
		cc = []string{z, "cc", "-target", map[string]string{"amd64": "x86_64", "arm64": "aarch64"}[runtime.GOARCH] + "-linux-musl"}
		if slices.Contains(flags, "-static-pie") {
			flags = append(flags, "-fPIE")
		}
	}
	exe := filepath.Join(t.TempDir(), name)
	args := append(append(cc[1:], "-O2", "-pthread", "-w", "-I", "testdata"), flags...)
	if b, err := exec.Command(cc[0], append(args, "-o", exe, src)...).CombinedOutput(); err != nil {
		t.Fatalf("build %s: %v\n%s", name, err, b)
	}
	return exe
}

// zigCC returns a zig binary for building musl guests, or "" if none.
func zigCC() string {
	for _, z := range []string{os.Getenv("ZIG"), "zig", "/tmp/zig-linux-x86_64-0.13.0/zig", os.ExpandEnv("$HOME/zig-0.13.0/zig")} {
		if p, err := exec.LookPath(z); z != "" && err == nil {
			return p
		}
	}
	return ""
}

// goGuest returns the Go guest testdata/<src> (a file or a package directory)
// built for linux/GOARCH with -buildmode=mode: staged in LC_GUEST_DIR as
// go-<name>-<mode>, else built here.
func goGuest(t *testing.T, src, mode string) string {
	t.Helper()
	name := "go-" + strings.TrimSuffix(filepath.Base(src), ".go") + "-" + mode
	if dir := os.Getenv("LC_GUEST_DIR"); dir != "" {
		exe := filepath.Join(dir, name)
		if _, err := os.Stat(exe); err != nil {
			t.Fatalf("guest %s is not staged in LC_GUEST_DIR=%s (scripts/guests.sh)", name, dir)
		}
		return exe
	}
	exe := filepath.Join(t.TempDir(), name)
	cmd := exec.Command("go", "build", "-buildmode="+mode, "-o", exe, filepath.Join("..", "..", "testdata", src))
	cmd.Env = append(os.Environ(), "CGO_ENABLED=0", "GOOS=linux", "GOARCH="+runtime.GOARCH)
	if b, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("go build %s: %v\n%s", name, err, b)
	}
	return exe
}

// guestFlags is a guest source's "// build:" flags, or -static-pie. The
// staging script reads the same line, and builds a source with a
// "// libc: musl" line against musl too, as <name>+musl.
func guestFlags(t testing.TB, src string) []string {
	f, err := os.Open(src)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		if flags, ok := strings.CutPrefix(sc.Text(), "// build: "); ok {
			return strings.Fields(flags)
		}
	}
	return []string{"-static-pie"}
}

// guestRoot puts the guest testdata/<name>.c at /<name> in a fresh root
// directory that also holds an empty /tmp and /mnt, as a Linux root does, and
// returns the root and the guest's path in it. Run it with RootFS:
// HostRoot(root); it works the same on every host.
func guestRoot(t testing.TB, name string) (root, prog string) {
	t.Helper()
	root = t.TempDir()
	for _, d := range []string{"tmp", "mnt"} {
		if err := os.Mkdir(filepath.Join(root, d), 0o777); err != nil {
			t.Fatal(err)
		}
	}
	copyGuest(t, filepath.Join(root, name), name)
	return root, "/" + name
}

// copyGuest puts the guest testdata/<name>.c at dst.
func copyGuest(t testing.TB, dst, name string) {
	t.Helper()
	b, err := os.ReadFile(guestPath(t, name))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(dst, b, 0o755); err != nil {
		t.Fatal(err)
	}
}

// addGuest puts the guest testdata/<name>.c at /<name> in root too.
func addGuest(t *testing.T, root, name string) string {
	t.Helper()
	copyGuest(t, filepath.Join(root, name), name)
	return "/" + name
}

// copyFile copies the host file src to dst, executable.
func copyFile(t *testing.T, src, dst string) {
	t.Helper()
	b, err := os.ReadFile(src)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(dst, b, 0o755); err != nil {
		t.Fatal(err)
	}
}

// putGuest puts the host file exe at /<name> in root.
func putGuest(t *testing.T, root, name, exe string) string {
	t.Helper()
	b, err := os.ReadFile(exe)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, name), b, 0o755); err != nil {
		t.Fatal(err)
	}
	return "/" + name
}

// tarEntry is one regular file of a root built by unpackRoot.
type tarEntry struct {
	name string
	mode int64
	body []byte
}

// unpackRoot is a fresh root holding entries, unpacked as an image layer is,
// so their modes are the ones the guest sees on every host: a Windows file
// holds none of its own.
func unpackRoot(t *testing.T, entries ...tarEntry) string {
	t.Helper()
	var img bytes.Buffer
	tw := tar.NewWriter(&img)
	for _, e := range entries {
		if err := tw.WriteHeader(&tar.Header{Name: e.name, Typeflag: tar.TypeReg, Mode: e.mode, Size: int64(len(e.body))}); err != nil {
			t.Fatal(err)
		}
		if _, err := tw.Write(e.body); err != nil {
			t.Fatal(err)
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	root := filepath.Join(t.TempDir(), "rootfs")
	if err := os.Mkdir(root, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := oci.Unpack(&img, root, 1<<30); err != nil {
		t.Fatal(err)
	}
	return root
}

// busyboxRoot is a fresh root holding Alpine's static busybox at /bin/busybox and
// /bin/sh, an empty /tmp and /mnt.
func busyboxRoot(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	for _, d := range []string{"tmp", "mnt"} {
		if err := os.Mkdir(filepath.Join(root, d), 0o777); err != nil {
			t.Fatal(err)
		}
	}
	withBusybox(t, root)
	return root
}

// busyboxPins is Alpine's static busybox, per arch.
var busyboxPins = map[string]pin{
	"amd64": {"https://dl-cdn.alpinelinux.org/alpine/v3.20/main/x86_64/busybox-static-1.36.1-r31.apk", "1ca8a2894b073edea2a04231f335ad48795f92617c5eacae59458c51202068ed"},
	"arm64": {"https://dl-cdn.alpinelinux.org/alpine/v3.20/main/aarch64/busybox-static-1.36.1-r31.apk", "1d8e7a7fc2ed69bdb8eb7be9d962489c21a0f75b72d8a325437c8a09d4cfac70"},
}

// withBusybox adds Alpine's static busybox at /bin/busybox and /bin/sh to a
// root, the same build on every host.
func withBusybox(t *testing.T, root string) {
	t.Helper()
	b := apkFile(t, busyboxPins[runtime.GOARCH], "bin/busybox.static")
	if err := os.MkdirAll(filepath.Join(root, "bin"), 0o755); err != nil {
		t.Fatal(err)
	}
	for _, n := range []string{"busybox", "sh"} {
		if err := os.WriteFile(filepath.Join(root, "bin", n), b, 0o755); err != nil {
			t.Fatal(err)
		}
	}
}

// A pin is a download the tests use, by URL and sha256.
type pin struct{ url, sum string }

// fetchPinned returns a local copy of p, checked against its sha256: the one
// staged in LC_GUEST_DIR under its file name, else one downloaded once into
// the user cache directory.
func fetchPinned(t *testing.T, p pin) string {
	t.Helper()
	name := path.Base(p.url)
	if dir := os.Getenv("LC_GUEST_DIR"); dir != "" {
		if f := filepath.Join(dir, name); sumOK(f, p.sum) {
			return f
		}
	}
	cache, err := os.UserCacheDir()
	if err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(cache, "laboon-test")
	f := filepath.Join(dir, p.sum+"-"+name)
	if sumOK(f, p.sum) {
		return f
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	resp, err := http.Get(p.url)
	if err != nil {
		t.Fatalf("fetch %s: %v", p.url, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("fetch %s: %s", p.url, resp.Status)
	}
	b, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("fetch %s: %v", p.url, err)
	}
	if got := fmt.Sprintf("%x", sha256.Sum256(b)); got != p.sum {
		t.Fatalf("fetch %s: sha256 %s, want %s", p.url, got, p.sum)
	}
	tmp, err := os.CreateTemp(dir, name)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := tmp.Write(b); err != nil {
		t.Fatal(err)
	}
	if err := tmp.Close(); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(tmp.Name(), f); err != nil {
		t.Fatal(err)
	}
	return f
}

func sumOK(f, sum string) bool {
	b, err := os.ReadFile(f)
	return err == nil && fmt.Sprintf("%x", sha256.Sum256(b)) == sum
}

func gunzip(t *testing.T, r io.Reader) io.Reader {
	t.Helper()
	z, err := gzip.NewReader(r)
	if err != nil {
		t.Fatal(err)
	}
	return z
}

// apkFile returns the file at member in the Alpine package p.
func apkFile(t *testing.T, p pin, member string) []byte {
	t.Helper()
	f, err := os.Open(fetchPinned(t, p))
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	// An apk is gzip streams one after another; the last holds the files.
	tr := tar.NewReader(gunzip(t, f))
	for {
		h, err := tr.Next()
		if err != nil {
			t.Fatalf("%s: no %s: %v", path.Base(p.url), member, err)
		}
		if h.Name == member {
			b, err := io.ReadAll(tr)
			if err != nil {
				t.Fatal(err)
			}
			return b
		}
	}
}

// dynRoot is a fresh root holding testdata/hello.c built as a dynamic glibc
// program at /hello, with the loader and libraries it names: the tree staged
// in LC_GUEST_DIR/dynroot, else built here.
func dynRoot(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	if dir := os.Getenv("LC_GUEST_DIR"); dir != "" {
		if err := os.CopyFS(root, os.DirFS(filepath.Join(dir, "dynroot"))); err != nil {
			t.Fatalf("dynroot is not staged in LC_GUEST_DIR=%s (scripts/guests.sh): %v", dir, err)
		}
		return root
	}
	if runtime.GOOS != "linux" {
		t.Fatalf("Linux guests are not built on %s: stage them with scripts/guests.sh and set LC_GUEST_DIR", runtime.GOOS)
	}
	exe := filepath.Join(root, "hello")
	if b, err := exec.Command("gcc", "-O2", "-o", exe, filepath.Join("..", "..", "testdata", "hello.c")).CombinedOutput(); err != nil {
		t.Fatalf("gcc: %v\n%s", err, b)
	}
	withLibs(t, root, exe)
	return root
}

// withLibs copies into root, each at its own path, the loader and shared
// libraries the dynamic Linux program exe loads on this host.
func withLibs(t *testing.T, root, exe string) {
	t.Helper()
	b, err := exec.Command("ldd", exe).Output()
	if err != nil {
		t.Fatalf("ldd %s: %v", exe, err)
	}
	for _, line := range strings.Split(string(b), "\n") {
		f := strings.Fields(line)
		var lib string
		switch {
		case len(f) >= 3 && f[1] == "=>" && strings.HasPrefix(f[2], "/"):
			lib = f[2]
		case len(f) >= 1 && strings.HasPrefix(f[0], "/"):
			lib = f[0]
		default:
			continue
		}
		body, err := os.ReadFile(lib)
		if err != nil {
			t.Fatal(err)
		}
		dst := filepath.Join(root, lib)
		if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(dst, body, 0o755); err != nil {
			t.Fatal(err)
		}
	}
}
