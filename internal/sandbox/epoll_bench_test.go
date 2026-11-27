package sandbox

import (
	"bytes"
	"context"
	"runtime"
	"strconv"
	"strings"
	"testing"
)

// BenchmarkEpollWait times the guest's epoll_wait on a ready fd among many,
// at several maxevents, and a blocking wait another thread wakes. allocs/call
// is the supervisor's heap allocations per guest call: the difference between
// a long and a short run, so the run's own setup cancels out.
func BenchmarkEpollWait(b *testing.B) {
	root, prog := guestRoot(b, "epollbench")
	run := func(b *testing.B, args []string) (float64, uint64) {
		var o bytes.Buffer
		var m0, m1 runtime.MemStats
		runtime.ReadMemStats(&m0)
		code, err := Run(context.Background(), prog, Config{RootFS: HostRoot(root), Args: append([]string{"epollbench"}, args...), Stdout: &o, Stderr: &o})
		runtime.ReadMemStats(&m1)
		ns, ok := strings.CutPrefix(strings.TrimSpace(o.String()), "ns/call ")
		v, perr := strconv.ParseFloat(ns, 64)
		if err != nil || code != 0 || !ok || perr != nil {
			b.Fatalf("code=%d err=%v out=%q", code, err, o.String())
		}
		return v, m1.Mallocs - m0.Mallocs
	}
	cases := []struct {
		name string
		args func(calls int) []string
	}{
		{"ready/fds16/max1", func(n int) []string { return []string{"ready", "16", "1", strconv.Itoa(n)} }},
		{"ready/fds16/max64", func(n int) []string { return []string{"ready", "16", "64", strconv.Itoa(n)} }},
		{"ready/fds16/max1024", func(n int) []string { return []string{"ready", "16", "1024", strconv.Itoa(n)} }},
		{"wake", func(n int) []string { return []string{"wake", strconv.Itoa(n)} }},
	}
	const short, long = 1000, 100000
	for _, c := range cases {
		b.Run(c.name, func(b *testing.B) {
			var ns, allocs float64
			for range b.N {
				_, a0 := run(b, c.args(short))
				v, a1 := run(b, c.args(long))
				ns += v
				allocs += (float64(a1) - float64(a0)) / (long - short)
			}
			b.ReportMetric(ns/float64(b.N), "ns/call")
			b.ReportMetric(allocs/float64(b.N), "allocs/call")
		})
	}
}
