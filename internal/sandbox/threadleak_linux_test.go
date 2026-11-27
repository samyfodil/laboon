package sandbox

import (
	"bufio"
	"bytes"
	"context"
	"io"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"
)

// TestThreadChurnHoldsNoMemory: threads and vfork children that come and go
// leave nothing behind in the stub process; what one needed on the way in is
// its slot's, reused by the next (testdata/threadleak.c).
func TestThreadChurnHoldsNoMemory(t *testing.T) {
	root, prog := guestRoot(t, "threadleak")
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	before := map[int]bool{}
	for _, pid := range descendants(os.Getpid()) {
		before[pid] = true
	}
	inR, inW := io.Pipe()
	outR, outW := io.Pipe()
	done := make(chan struct{})
	var code int
	var runErr error
	go func() {
		defer close(done)
		code, runErr = Run(ctx, prog, Config{Args: []string{prog}, RootFS: HostRoot(root), Stdin: inR, Stdout: outW, Stderr: outW})
		outW.Close()
	}()
	var out strings.Builder
	var sizes []uint64
	stub := 0
	sc := bufio.NewScanner(outR)
	for sc.Scan() {
		out.WriteString(sc.Text() + "\n")
		if sc.Text() == "ready" {
			if stub == 0 {
				stub = newStub(t, before)
			}
			sizes = append(sizes, outsideStubWindow(t, stub))
			inW.Write([]byte{0})
		}
	}
	<-done
	if runErr != nil || code != 0 || !strings.Contains(out.String(), "threadleak ok") || len(sizes) != 2 {
		t.Fatalf("code=%d err=%v out=%q", code, runErr, out.String())
	}
	t.Logf("outside the stub window: %d -> %d KiB", sizes[0]>>10, sizes[1]>>10)
	// 4000 threads and 240 vfork children: a page each would be ~16 MiB.
	if grew := int64(sizes[1]) - int64(sizes[0]); grew > 2<<20 {
		t.Errorf("the stub's memory outside its window grew by %d KiB over the churn (%d -> %d KiB)", grew>>10, sizes[0]>>10, sizes[1]>>10)
	}
}

// newStub is the stub this test's Run started: of this process's
// descendants absent from before that have a stub window, the first to
// start. A stub an exec'd child ran in can still be on its way out.
func newStub(t *testing.T, before map[int]bool) int {
	t.Helper()
	stub, first := 0, uint64(0)
	for _, pid := range descendants(os.Getpid()) {
		if before[pid] {
			continue
		}
		if _, in, ok := stubMaps(pid); !ok || in == 0 {
			continue
		}
		b, err := os.ReadFile("/proc/" + strconv.Itoa(pid) + "/stat")
		if err != nil {
			continue
		}
		f := strings.Fields(string(b[bytes.LastIndexByte(b, ')')+2:]))
		start, err := strconv.ParseUint(f[19], 10, 64)
		if err == nil && (stub == 0 || start < first) {
			stub, first = pid, start
		}
	}
	if stub == 0 {
		t.Fatal("no stub process of this run found")
	}
	return stub
}

// outsideStubWindow is the total size of pid's host mappings that lie
// outside the stub window: the guest's own and anything the stub maps for it
// there.
func outsideStubWindow(t *testing.T, pid int) uint64 {
	t.Helper()
	out, _, ok := stubMaps(pid)
	if !ok {
		t.Fatalf("stub %d is gone", pid)
	}
	return out
}

// stubMaps sums pid's host mappings outside and inside the stub window.
func stubMaps(pid int) (out, in uint64, ok bool) {
	f, err := os.Open("/proc/" + strconv.Itoa(pid) + "/maps")
	if err != nil {
		return 0, 0, false
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		lo, rest, _ := strings.Cut(sc.Text(), "-")
		hi, _, _ := strings.Cut(rest, " ")
		l, err1 := strconv.ParseUint(lo, 16, 64)
		h, err2 := strconv.ParseUint(hi, 16, 64)
		if err1 != nil || err2 != nil {
			continue
		}
		if l >= stubLo && h <= stubHi {
			in += h - l
		} else {
			out += h - l
		}
	}
	return out, in, true
}
