package sandbox

import (
	"bytes"
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// TestEnvNotLeaked checks a nil Config.Env gives the guest an empty environment,
// not the supervisor's own (no host secrets via envp or /proc/self/environ).
func TestEnvNotLeaked(t *testing.T) {
	exe := filepath.Join(t.TempDir(), "envleak")
	if b, err := exec.Command("gcc", "-O2", "-static", "-o", exe, "../../testdata/envleak.c").CombinedOutput(); err != nil {
		t.Skipf("static gcc unavailable: %v\n%s", err, b)
	}
	os.Setenv("LABOON_SECRET_PROBE", "leaked") // a host var that must not reach the guest
	defer os.Unsetenv("LABOON_SECRET_PROBE")
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	var out bytes.Buffer
	code, err := Run(ctx, exe, Config{Args: []string{exe}, RootFS: HostRoot("/"), Stdout: &out, Stderr: &out}) // no Env
	s := out.String()
	if err != nil || code != 0 || !strings.Contains(s, "ENVLEAK-DONE") {
		t.Fatalf("code=%d err=%v out=%q", code, err, s)
	}
	t.Logf("envleak output:\n%s", s)
	if !strings.Contains(s, "envc=0") {
		t.Errorf("nil Config.Env must yield an empty environment: %q", s)
	}
	if !strings.Contains(s, "environ_bytes=0") {
		t.Errorf("/proc/self/environ must be empty with a nil Config.Env: %q", s)
	}
}
