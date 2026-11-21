//go:build darwin || windows

package sandbox

import "sync/atomic"

const (
	rseqFlagUnregister = 1
	rseqOrigSize       = 32
	rseqCPUFailed      = 0xfffffffe // RSEQ_CPU_ID_REGISTRATION_FAILED
	rseqCPUUninit      = 0xffffffff // RSEQ_CPU_ID_UNINITIALIZED
)

// rseqEmulated serves rseq where the host kernel cannot (darwin, windows),
// with Linux's checks and results.
func (g *dguest) rseqEmulated(a [6]uint64) int64 {
	area, n, flags, sig := a[0], a[1]&0xffffffff, a[2]&0xffffffff, a[3]&0xffffffff
	r := g.rseqReg
	if flags&rseqFlagUnregister != 0 {
		switch {
		case flags != rseqFlagUnregister, r[0] == 0, r[0] != area, r[1] != n:
			return sErr(lxEINVAL)
		case r[2] != sig:
			return sErr(lxEPERM)
		}
		if e := g.writeRseq(0, rseqCPUUninit, 0); e != 0 {
			return sErr(e)
		}
		g.endRseq()
		return 0
	}
	if flags != 0 {
		return sErr(lxEINVAL)
	}
	if r[0] != 0 {
		switch {
		case r[0] != area, r[1] != n:
			return sErr(lxEINVAL)
		case r[2] != sig:
			return sErr(lxEPERM)
		}
		return sErr(lxEBUSY)
	}
	if n < rseqOrigSize || area%rseqOrigSize != 0 {
		return sErr(lxEINVAL)
	}
	if _, err := g.readMem(area, int(n)); err != nil {
		return sErr(lxEFAULT)
	}
	g.rseqReg = [3]uint64{area, n, sig}
	g.vcpu = g.dfs.vcpus.take(g.ps.cpus.Load())
	if e := g.syncRseq(); e != 0 {
		g.endRseq()
		return sErr(e)
	}
	return 0
}

// syncRseq writes the thread's CPU into its area, as the kernel does on the
// way back to user space, and publishes the registration to the stub.
func (g *dguest) syncRseq() lxErrno {
	if e := g.writeRseq(g.rseqVals()); e != 0 {
		return e
	}
	g.publishRseq()
	return 0
}

// rseqVals is the thread's cpu_id_start, cpu_id and mm_cid.
func (g *dguest) rseqVals() (start, cpu, cid uint32) {
	if g.vcpu != 0 {
		c := uint32(g.vcpu - 1)
		return c, c, c
	}
	return uint32(nthCPU(g.ps.cpus.Load(), 0)), rseqCPUFailed, 0
}

// writeRseq writes cpu_id_start, cpu_id, node_id (0) and mm_cid, leaving
// rseq_cs and flags as they are.
func (g *dguest) writeRseq(start, cpu, cid uint32) lxErrno {
	area := g.rseqReg[0]
	var lo, hi [8]byte
	put32(lo[:], start)
	put32(lo[4:], cpu)
	put32(hi[4:], cid)
	if g.writeMem(area, lo[:]) != nil || g.writeMem(area+20, hi[:]) != nil {
		return lxEFAULT
	}
	return 0
}

func (g *dguest) publishRseq() {
	if sr := g.sigs(); sr != nil {
		o := tOff(g.slot)
		sr.st(o+stRseq, g.rseqReg[0])
		atomic.StoreUint32(sr.p32(o+stRseqSig), uint32(g.rseqReg[2]))
	}
	syncStdio()
}

// endRseq ends the thread's registration, as an execve or an unregister
// does, and puts its CPU back.
func (g *dguest) endRseq() {
	if g.rseqReg[0] == 0 {
		return
	}
	g.rseqReg = [3]uint64{}
	g.dropVcpu()
	g.publishRseq()
}

// forkRseq gives a fork child the registration it inherits with a CPU of
// its own, which goes into the forking thread's area just before the child's
// copy of its memory is made, so the child starts with it; rseqForked puts
// the forking thread's own back once the copy is made, before it returns.
func (g *dguest) forkRseq(child *dguest) {
	if g.rseqReg[0] == 0 {
		return
	}
	child.vcpu = g.dfs.vcpus.take(child.ps.cpus.Load())
	if g.writeRseq(child.rseqVals()) == 0 {
		child.publishRseq()
	}
}

func (g *dguest) rseqForked() {
	if g.rseqReg[0] != 0 {
		g.writeRseq(g.rseqVals())
	}
}

// moveRseq runs at a syscall, where the thread is in no critical section: a
// CPU its affinity no longer allows is given up, and a thread without one
// takes one put back meanwhile.
func (g *dguest) moveRseq() {
	if g.rseqReg[0] == 0 {
		return
	}
	mask := g.ps.cpus.Load()
	if g.vcpu != 0 && mask&(1<<(g.vcpu-1)) != 0 || g.vcpu == 0 && !g.dfs.vcpus.anyFree(mask) {
		return
	}
	g.dropVcpu()
	g.vcpu = g.dfs.vcpus.take(mask)
	if g.syncRseq() != 0 {
		g.endRseq()
	}
}

// rseqCPU is the CPU the thread's rseq area names, which getcpu reports too.
func (g *dguest) rseqCPU() (int, bool) { return g.vcpu - 1, g.vcpu != 0 }
