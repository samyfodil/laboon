//go:build darwin || linux || windows

package sandbox

import "container/heap"

// indexPool hands out indexes below limit, lowest free first, so the live
// ones stay packed at the bottom: what a slot index addresses is only touched,
// and its stack chunk only mapped, once a thread uses it. It grows to the
// high-water mark instead of being sized to limit. Not safe for concurrent use.
type indexPool struct {
	used  []bool
	free  minInts
	limit int
}

func (p *indexPool) take() int {
	for p.free.Len() > 0 {
		i := heap.Pop(&p.free).(int)
		if !p.used[i] {
			p.used[i] = true
			return i
		}
	}
	if len(p.used) >= p.limit {
		return -1
	}
	p.used = append(p.used, true)
	return len(p.used) - 1
}

func (p *indexPool) put(i int) {
	if i < len(p.used) && p.used[i] {
		p.used[i] = false
		heap.Push(&p.free, i)
	}
}

type minInts []int

func (h minInts) Len() int           { return len(h) }
func (h minInts) Less(i, j int) bool { return h[i] < h[j] }
func (h minInts) Swap(i, j int)      { h[i], h[j] = h[j], h[i] }
func (h *minInts) Push(x any)        { *h = append(*h, x.(int)) }
func (h *minInts) Pop() any {
	old := *h
	x := old[len(old)-1]
	*h = old[:len(old)-1]
	return x
}
