package sandbox

import (
	"bytes"
	"context"
	"runtime"
	"strings"
	"testing"
	"time"
)

// What the supervisor lays out per guest architecture reads back as the
// guest's own ABI has it (testdata/abicheck.c). On macOS an arm64 supervisor
// also hosts the x86-64 build, whose ABI is not the supervisor's.
func TestGuestABI(t *testing.T) {
	names := []string{"abicheck"}
	if runtime.GOOS == "darwin" && runtime.GOARCH == "arm64" {
		names = append(names, "abicheck+x64")
	}
	for _, name := range names {
		t.Run(name, func(t *testing.T) {
			root, exe := guestRoot(t, name)
			ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
			defer cancel()
			var out bytes.Buffer
			code, err := Run(ctx, exe, Config{Args: []string{exe}, RootFS: HostRoot(root), Stdout: &out, Stderr: &out})
			if err != nil || code != 0 || !strings.Contains(out.String(), "ABI-OK") {
				t.Fatalf("code=%d err=%v out=%q", code, err, out.String())
			}
		})
	}
}
