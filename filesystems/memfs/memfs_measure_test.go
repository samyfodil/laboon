package memfs

import (
	"os"
	"runtime"
	"testing"
	"time"

	. "github.com/samyfodil/laboon/core"
)

// TestMemFSMeasure quantifies that memFS content lives in the Go heap and its
// raw read/write throughput at the vfs layer (no sandbox transport).
func TestMemFSMeasure(t *testing.T) {
	const mb = 1 << 20
	const N = 256
	buf := make([]byte, mb)

	var m0, m1 runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&m0)

	f := NewMemFS()
	n, err := f.Create(f.Root(), "big", CreateSpec{Kind: Reg, Mode: 0o644})
	if err != nil {
		t.Fatal(err)
	}
	h, err := n.Open(os.O_RDWR)
	if err != nil {
		t.Fatal(err)
	}

	start := time.Now()
	for i := 0; i < N; i++ {
		if _, err := h.WriteAt(buf, int64(i)*mb); err != nil {
			t.Fatal(err)
		}
	}
	wdur := time.Since(start)

	runtime.GC()
	runtime.ReadMemStats(&m1)

	rb := make([]byte, mb)
	start = time.Now()
	for i := 0; i < N; i++ {
		if _, err := h.ReadAt(rb, int64(i)*mb); err != nil {
			t.Fatal(err)
		}
	}
	rdur := time.Since(start)

	t.Logf("memFS %d MB file: HeapAlloc %d->%d MB (delta %d MB) — content is heap-resident, no size cap",
		N, m0.HeapAlloc>>20, m1.HeapAlloc>>20, int64(m1.HeapAlloc-m0.HeapAlloc)>>20)
	t.Logf("vfs-layer throughput: write %.0f MB/s, read %.0f MB/s",
		float64(N)/wdur.Seconds(), float64(N)/rdur.Seconds())
}
