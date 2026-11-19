//go:build linux

package hostfs

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"
)

// BenchmarkHReadDir lists a large host directory: the cost is one stat per entry
// in the old path, a single getdents stream in the new one.
func BenchmarkHReadDir(b *testing.B) {
	dir := b.TempDir()
	for i := 0; i < 5000; i++ {
		if err := os.WriteFile(filepath.Join(dir, fmt.Sprintf("f%05d", i)), nil, 0o644); err != nil {
			b.Fatal(err)
		}
	}
	fs := NewRawHostFS(dir)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		infos, err := fs.hReadDir(dir)
		if err != nil || len(infos) != 5000 {
			b.Fatalf("got %d err %v", len(infos), err)
		}
	}
}
