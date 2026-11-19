//go:build linux

package sandbox

import "testing"

// BenchmarkFdAllocChurn opens and closes the lowest free fd while many fds are
// already held -- the server pattern where allocLocked's linear scan is O(n).
func BenchmarkFdAllocChurn(b *testing.B) {
	t := &ftable{fds: map[int]*dfile{}, cloexec: map[int]bool{}}
	d := &dfile{}
	d.refs.Store(1 << 30) // never actually closed
	for i := 0; i < 2000; i++ {
		t.fds[i] = d
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		fd := t.add(d, 0)
		t.remove(fd)
	}
}
