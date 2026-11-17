//go:build linux

package sandbox

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// An image root has no /proc or /sys; the CPU files must still be there.
func TestCPUFilesInEmptyRoot(t *testing.T) {
	root := t.TempDir()
	exe := filepath.Join(root, "cpuinfo")
	if b, err := exec.Command("gcc", "-O2", "-static", "-o", exe, "../../testdata/cpuinfo.c").CombinedOutput(); err != nil {
		t.Skipf("static gcc unavailable: %v\n%s", err, b)
	}
	var out bytes.Buffer
	code, err := Run(context.Background(), "/cpuinfo", Config{Args: []string{"cpuinfo"}, Stdout: &out, Stderr: &out, Root: root})
	if err != nil || code != 0 {
		t.Fatalf("code = %d, err = %v, output %q", code, err, out.String())
	}
	online, _ := os.ReadFile("/sys/devices/system/cpu/online")
	n := strings.Count(mustRead(t, "/proc/stat"), "\ncpu")
	if want := fmt.Sprintf("stat=%d cpuinfo=%d online=%s", n, n, online); n < 1 || out.String() != want {
		t.Fatalf("output %q, want %q", out.String(), want)
	}
}

func mustRead(t *testing.T, p string) string {
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}
