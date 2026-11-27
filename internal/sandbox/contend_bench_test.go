package sandbox

import (
	"bytes"
	"context"
	"fmt"
	"strconv"
	"strings"
	"testing"
)

// BenchmarkSyscallUnderChurn times one guest thread's cheap syscalls, alone
// and while other threads of its process churn mmap, madvise, mprotect and
// munmap: a call that has nothing to do with memory should not wait on them.
func BenchmarkSyscallUnderChurn(b *testing.B) {
	root, prog := guestRoot(b, "syscontend")
	for _, call := range []string{"getppid", "pread"} {
		for _, churners := range []int{0, 1, 3} {
			b.Run(fmt.Sprintf("%s/churn%d", call, churners), func(b *testing.B) {
				var total float64
				for range b.N {
					var o bytes.Buffer
					code, err := Run(context.Background(), prog, Config{RootFS: HostRoot(root),
						Args: []string{"syscontend", call, strconv.Itoa(churners), "200000"}, Stdout: &o, Stderr: &o})
					ns, ok := strings.CutPrefix(strings.TrimSpace(o.String()), "ns/call ")
					v, perr := strconv.ParseFloat(ns, 64)
					if err != nil || code != 0 || !ok || perr != nil {
						b.Fatalf("code=%d err=%v out=%q", code, err, o.String())
					}
					total += v
				}
				b.ReportMetric(total/float64(b.N), "ns/call")
				b.ReportMetric(1e9*float64(b.N)/total, "calls/s")
			})
		}
	}
}
