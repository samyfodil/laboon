package sandbox

import (
	"math/bits"
	"sync"
)

// vcpuSet is the CPUs the run's threads with an rseq area on darwin and
// windows hold, one each. The stub's threads are not pinned, so the CPU an
// area names is a virtual one: held by one thread at a time, no two threads
// ever run a critical section for the same CPU, and only a signal can
// interrupt one, as Linux aborts one only on preemption, migration or a
// signal. A thread finding every CPU of its mask held has none:
// RSEQ_CPU_ID_REGISTRATION_FAILED, until one is put back.
type vcpuSet struct {
	mu   sync.Mutex
	held uint64
}

func (v *vcpuSet) take(mask uint64) int {
	v.mu.Lock()
	defer v.mu.Unlock()
	free := mask &^ v.held
	if free == 0 {
		return 0
	}
	c := bits.TrailingZeros64(free)
	v.held |= 1 << c
	return c + 1
}

func (v *vcpuSet) put(c int) {
	if c == 0 {
		return
	}
	v.mu.Lock()
	v.held &^= 1 << (c - 1)
	v.mu.Unlock()
}

func (v *vcpuSet) anyFree(mask uint64) bool {
	v.mu.Lock()
	defer v.mu.Unlock()
	return mask&^v.held != 0
}

func (g *dguest) dropVcpu() {
	g.dfs.vcpus.put(g.vcpu)
	g.vcpu = 0
}
