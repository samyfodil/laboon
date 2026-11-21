package sandbox

import (
	"os/exec"
	"path/filepath"
	"runtime"
	"testing"
)

// fileOffsetBins builds testdata/fileoffset.c against glibc and, with zig,
// musl.
func fileOffsetBins(t *testing.T) map[string]string {
	dir := t.TempDir()
	builds := map[string][]string{
		"glibc": {"gcc", "-O2", "-static", "-w", "-o", filepath.Join(dir, "glibc"), "../../testdata/fileoffset.c"},
	}
	if z := zigCC(); z != "" {
		target := map[string]string{"amd64": "x86_64", "arm64": "aarch64"}[runtime.GOARCH] + "-linux-musl"
		builds["musl"] = []string{z, "cc", "-target", target, "-O2", "-static", "-o", filepath.Join(dir, "musl"), "../../testdata/fileoffset.c"}
	}
	bins := map[string]string{}
	for libc, c := range builds {
		if b, err := exec.Command(c[0], c[1:]...).CombinedOutput(); err != nil {
			t.Skipf("build: %v\n%s", err, b)
		}
		bins[libc] = filepath.Join(dir, libc)
	}
	return bins
}
