package sandbox

import (
	"bufio"
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
	sc := bufio.NewScanner(outR)
	for sc.Scan() {
		out.WriteString(sc.Text() + "\n")
		if sc.Text() == "ready" {
			sizes = append(sizes, largestStubOutsideWindow(t))
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

// largestStubOutsideWindow is, over this process's descendants, the largest
// total size of the host mappings that lie outside the stub window: the
// guest's own and anything the stub maps for it there.
func largestStubOutsideWindow(t *testing.T) uint64 {
	t.Helper()
	var best uint64
	for _, pid := range descendants(os.Getpid()) {
		f, err := os.Open("/proc/" + strconv.Itoa(pid) + "/maps")
		if err != nil {
			continue
		}
		var total uint64
		sc := bufio.NewScanner(f)
		for sc.Scan() {
			lo, rest, _ := strings.Cut(sc.Text(), "-")
			hi, _, _ := strings.Cut(rest, " ")
			l, err1 := strconv.ParseUint(lo, 16, 64)
			h, err2 := strconv.ParseUint(hi, 16, 64)
			if err1 != nil || err2 != nil || (l >= stubLo && h <= stubHi) {
				continue
			}
			total += h - l
		}
		f.Close()
		best = max(best, total)
	}
	if best == 0 {
		t.Fatal("no stub process found")
	}
	return best
}
