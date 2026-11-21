//go:build darwin || windows

package sandbox

// hopTable is Linux's per-process host-op state (hop_linux.go).
type hopTable struct{}

// leaderHoldsSlot: a leader that exits before its process keeps its slot,
// whose signal record the process goes on using, until the process ends. On
// Linux the slot is freed once the stub process is gone, which is then too.
const leaderHoldsSlot = true

// endStub is Linux's (hop_linux.go): elsewhere a stub ends with its last thread.
func (fs *dfs) endStub(ps *pstate) {}
