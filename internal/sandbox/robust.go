package sandbox

// A thread's robust futex list (set_robust_list): its head and length, kept
// on the thread, which get_robust_list reports for it or a thread it names.
func init() {
	regSys(lxSetRobustList, func(g *dguest, a [6]uint64) int64 {
		if a[1] != 24 { // sizeof(struct robust_list_head) on 64-bit
			return sErr(lxEINVAL)
		}
		g.robust[0].Store(a[0])
		g.robust[1].Store(a[1])
		return 0
	})
	regSys(lxGetRobustList, func(g *dguest, a [6]uint64) int64 {
		t := g
		if p := int(int32(a[0])); p != 0 {
			tid, ok := g.nsToGlobal(p)
			if !ok {
				return sErr(lxESRCH)
			}
			g.dfs.mu.Lock()
			dp := g.dfs.procs[tid]
			g.dfs.mu.Unlock()
			if dp == nil || dp.g == nil {
				return sErr(lxESRCH)
			}
			t = dp.g
		}
		var b [8]byte
		put64(b[:], t.robust[0].Load())
		if g.writeMem(a[1], b[:]) != nil {
			return sErr(lxEFAULT)
		}
		put64(b[:], 24)
		if g.writeMem(a[2], b[:]) != nil {
			return sErr(lxEFAULT)
		}
		return 0
	})
}
